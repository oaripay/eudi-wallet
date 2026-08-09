import CryptoKit
import Foundation
import TrustDomain

public struct ResolvedDID: Equatable, Sendable {
    public let document: DIDDocument
    public let evidence: TrustEvidence

    public init(document: DIDDocument, evidence: TrustEvidence) {
        self.document = document
        self.evidence = evidence
    }
}

public protocol EBSIRegistryClient: Sendable {
    func resolve(did: String, at date: Date) async throws -> ResolvedDID
}

public struct EBSIDIDResolver: DIDResolver, Sendable {
    private let client: any EBSIRegistryClient
    private let clock: @Sendable () -> Date

    public init(
        client: any EBSIRegistryClient,
        clock: @escaping @Sendable () -> Date = Date.init
    ) {
        self.client = client
        self.clock = clock
    }

    public func resolve(_ did: String) async throws -> DIDDocument {
        guard did.hasPrefix("did:ebsi:"), did.count > "did:ebsi:".count else {
            throw DIDResolutionError.unsupportedMethod
        }
        let result = try await client.resolve(did: did, at: clock())
        guard result.document.id == did,
              result.evidence.source == .ebsiRegistry,
              result.evidence.result == .valid else {
            throw DIDResolutionError.registryUnavailable
        }
        return result.document
    }
}

public struct URLSessionEBSIRegistryClient: EBSIRegistryClient, Sendable {
    private let registryBaseURL: URL
    private let httpClient: any BoundedHTTPSClient
    private let evidenceTTL: TimeInterval

    public init(
        registryBaseURL: URL,
        httpClient: any BoundedHTTPSClient = URLSessionBoundedHTTPSClient(),
        evidenceTTL: TimeInterval = 3_600
    ) throws {
        guard registryBaseURL.scheme?.lowercased() == "https", registryBaseURL.host != nil,
              registryBaseURL.user == nil, registryBaseURL.password == nil,
              registryBaseURL.query == nil, registryBaseURL.fragment == nil,
              registryBaseURL.lastPathComponent == "identifiers",
              evidenceTTL > 0 else {
            throw DIDResolutionError.registryUnavailable
        }
        self.registryBaseURL = registryBaseURL
        self.httpClient = httpClient
        self.evidenceTTL = evidenceTTL
    }

    public func resolve(did: String, at date: Date) async throws -> ResolvedDID {
        guard Self.isSafeEBSIDID(did) else { throw DIDResolutionError.invalidDID }
        // A DID is one path segment. Rejecting all delimiters rather than
        // accepting a pre-escaped value prevents traversal and query injection.
        let url = registryBaseURL.appendingPathComponent(did, isDirectory: false)
        let response = try await httpClient.get(url, maximumBytes: 1_048_576)
        guard response.statusCode == 200,
              response.finalURL == url else {
            throw DIDResolutionError.registryUnavailable
        }
        let data = response.data
        let document: DIDDocument
        do {
            document = try JSONDecoder().decode(DIDDocument.self, from: data)
        } catch {
            throw DIDResolutionError.malformedKey
        }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return ResolvedDID(
            document: document,
            evidence: TrustEvidence(
                source: .ebsiRegistry,
                sourceIdentifier: registryBaseURL.absoluteString,
                result: .valid,
                checkedAt: date,
                expiresAt: date.addingTimeInterval(evidenceTTL),
                evidenceDigest: digest
            )
        )
    }

    private static func isSafeEBSIDID(_ did: String) -> Bool {
        let prefix = "did:ebsi:"
        guard did.hasPrefix(prefix), did.count > prefix.count else { return false }
        return did.dropFirst(prefix.count).unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0)
        }
    }
}
