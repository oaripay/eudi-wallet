import CryptoKit
import Foundation
import IdentityDomain
import TrustDomain

public final class URLSessionWorkspaceTransport: NSObject, WorkspaceHTTPTransport, URLSessionTaskDelegate, @unchecked Sendable {
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    public override init() {}

    public func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data?
    ) async throws -> WorkspaceHTTPResponse {
        try Self.validatePublicHTTPS(url)
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = method
        request.httpBody = body
        request.allHTTPHeaderFields = headers
        let (bytes, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse,
              !(300..<400).contains(response.statusCode) else {
            throw WorkspaceBackendError.invalidResponse
        }
        var data = Data()
        data.reserveCapacity(max(0, min(Int(response.expectedContentLength), 1_048_576)))
        for try await byte in bytes {
            guard data.count < 1_048_576 else { throw WorkspaceBackendError.invalidResponse }
            data.append(byte)
        }
        let responseHeaders = response.allHeaderFields.reduce(into: [String: String]()) {
            if let key = $1.key as? String { $0[key] = String(describing: $1.value) }
        }
        return WorkspaceHTTPResponse(statusCode: response.statusCode, body: data, headers: responseHeaders)
    }

    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    private static func validatePublicHTTPS(_ url: URL) throws {
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased(),
              scheme == "https" || (scheme == "http" && (host == "127.0.0.1" || host == "localhost")),
              url.user == nil, url.password == nil, url.fragment == nil,
              host != "localhost", host != "::1", !host.hasSuffix(".local"),
              !Self.isPrivateIPv4Literal(host), !Self.isReservedIPv6Literal(host) else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
    }

    private static func isPrivateIPv4Literal(_ host: String) -> Bool {
        let parts = host.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return false }
        return parts[0] == 10 || parts[0] == 127 ||
            (parts[0] == 169 && parts[1] == 254) ||
            (parts[0] == 172 && (16...31).contains(parts[1])) ||
            (parts[0] == 192 && parts[1] == 168) || parts[0] >= 224
    }

    private static func isReservedIPv6Literal(_ host: String) -> Bool {
        guard host.contains(":") else { return false }
        let value = host.lowercased()
        return value == "::" || value == "::1" || value.hasPrefix("fc") ||
            value.hasPrefix("fd") || value.hasPrefix("fe8") || value.hasPrefix("fe9") ||
            value.hasPrefix("fea") || value.hasPrefix("feb") || value.hasPrefix("ff")
    }
}

public struct DevelopmentIssuerOriginTrustEvaluator: WorkspaceIssuerTrustEvaluating, Sendable {
    private let trustedOrigins: Set<String>
    private let evidenceSource: String

    public init(trustedOrigins: Set<String>, evidenceSource: String) {
        self.trustedOrigins = trustedOrigins
        self.evidenceSource = evidenceSource
    }

    public func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        guard let url = URL(string: issuer), let scheme = url.scheme, let host = url.host else {
            return .invalid(reasons: [.malformedEvidence], evidence: [])
        }
        let origin = "\(scheme.lowercased())://\(host.lowercased())" +
            (url.port.map { ":\($0)" } ?? "")
        let evidence = TrustEvidence(
            source: .ebsiRegistry,
            sourceIdentifier: evidenceSource,
            result: trustedOrigins.contains(origin) ? .valid : .notFound,
            checkedAt: date,
            expiresAt: date.addingTimeInterval(300),
            evidenceDigest: String(repeating: "0", count: 64)
        )
        return trustedOrigins.contains(origin)
            ? .trusted(evidence: [evidence])
            : .untrusted(reasons: [.issuerNotAccredited], evidence: [evidence])
    }
}

public struct WorkspaceTIRTrustEvaluator: WorkspaceIssuerTrustEvaluating, Sendable {
    private let tirBaseURL: URL
    private let transport: any WorkspaceHTTPTransport
    private let approvedIssuerDIDs: Set<String>

    public init(
        tirBaseURL: URL,
        transport: any WorkspaceHTTPTransport,
        approvedIssuerDIDs: Set<String> = []
    ) {
        self.tirBaseURL = tirBaseURL
        self.transport = transport
        self.approvedIssuerDIDs = approvedIssuerDIDs
    }

    public func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        guard issuer.hasPrefix("did:"),
              let encoded = issuer.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else {
            return .untrusted(reasons: [.issuerNotAccredited], evidence: [])
        }
        let url = tirBaseURL.appendingPathComponent(encoded)
        do {
            let response = try await transport.send(url: url, method: "GET", headers: [:], body: nil)
            let hasValidJSON = (try? JSONSerialization.jsonObject(with: response.body)) != nil
            if response.statusCode == 200, !hasValidJSON {
                return .indeterminate(reasons: [.malformedEvidence], evidence: [])
            }
            let isApproved = response.statusCode == 200 && approvedIssuerDIDs.contains(issuer)
            let result: TrustEvidenceResult = isApproved ? .valid : .notFound
            let digest = SHA256.hash(data: response.body).map { String(format: "%02x", $0) }.joined()
            let evidence = TrustEvidence(
                source: .ebsiRegistry,
                sourceIdentifier: tirBaseURL.absoluteString,
                result: result,
                checkedAt: date,
                expiresAt: date.addingTimeInterval(300),
                evidenceDigest: digest
            )
            return isApproved
                ? .trusted(evidence: [evidence])
                : .untrusted(reasons: [.issuerNotAccredited], evidence: [evidence])
        } catch {
            return .indeterminate(reasons: [.trustSourceUnavailable], evidence: [])
        }
    }
}

public struct NativeWorkspaceCredentialValidator: WorkspaceCredentialValidating, Sendable {
    private let resolver: any DIDResolver

    public init(resolver: any DIDResolver) { self.resolver = resolver }

    public func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedHolderDID: String,
        at date: Date
    ) async throws {
        let compact = String(decoding: rawCredential, as: UTF8.self)
        let credential = try EbsiCredentialInspector().inspectCompactJWT(compact, profile: profile)
        let issuer = try Self.issuer(from: credential)
        let document = try await resolver.resolve(issuer)
        let methods = try document.verificationMethod.map { method in
            let x = try Self.decodeBase64URL(method.publicKeyJwk.x)
            guard let encodedY = method.publicKeyJwk.y else {
                throw EbsiCredentialError.algorithmNotAllowed
            }
            let y = try Self.decodeBase64URL(encodedY)
            let key: EbsiVerificationKey = switch method.publicKeyJwk.crv {
            case "P-256": .p256(x: x, y: y)
            case "secp256k1": .secp256k1(x: x, y: y)
            default: throw EbsiCredentialError.algorithmNotAllowed
            }
            var relationships: Set<EbsiVerificationRelationship> = []
            if document.assertionMethod.contains(method.id) { relationships.insert(.assertionMethod) }
            if document.authentication.contains(method.id) { relationships.insert(.authentication) }
            return EbsiVerificationMethod(
                id: method.id,
                controller: method.controller,
                key: key,
                relationships: relationships
            )
        }
        _ = try EbsiJWSVerifier().verify(
            compactJWS: compact,
            methods: methods,
            requirements: EbsiJWSRequirements(
                allowedAlgorithms: profile.allowedAlgorithms,
                requiredRelationship: .assertionMethod,
                expectedController: issuer,
                expectedIssuer: issuer,
                validationDate: date
            )
        )
        guard Self.subjectID(from: credential) == expectedHolderDID else {
            throw EbsiCredentialError.verificationFailed
        }
    }

    private static func issuer(from credential: [String: AnySendableJSON]) throws -> String {
        if let issuer = credential["issuer"]?.string { return issuer }
        if let issuer = credential["issuer"]?.object?["id"]?.string { return issuer }
        throw EbsiCredentialError.profileMismatch
    }

    private static func subjectID(from credential: [String: AnySendableJSON]) -> String? {
        credential["credentialSubject"]?.object?["id"]?.string
    }

    private static func decodeBase64URL(_ value: String) throws -> Data {
        var value = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let result = Data(base64Encoded: value) else { throw EbsiCredentialError.malformedCredential }
        return result
    }
}
