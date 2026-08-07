import Foundation
import IdentityDomain
import TrustDomain
import WalletDomain

public struct WorkspaceHTTPResponse: Equatable, Sendable {
    public let statusCode: Int
    public let body: Data
    public let headers: [String: String]

    public init(statusCode: Int, body: Data, headers: [String: String] = [:]) {
        self.statusCode = statusCode
        self.body = body
        self.headers = headers
    }
}

public protocol WorkspaceHTTPTransport: Sendable {
    func send(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data?
    ) async throws -> WorkspaceHTTPResponse
}

public protocol WorkspaceIssuerTrustEvaluating: Sendable {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict
}

public protocol WorkspaceCredentialValidating: Sendable {
    func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedHolderDID: String,
        at date: Date
    ) async throws
}

public struct WorkspaceResolvedOffer: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let issuer: String
    public let displayName: String?
    public let configurationIDs: [String]
    public let transactionCodeRequired: Bool
    public let trustOutcome: EbsiTrustGateOutcome
}

public struct WorkspaceIssuedCredential: Equatable, Sendable {
    public let id: UUID
    public let profileID: String
    public let representation: EbsiCredentialRepresentation
}

public enum WorkspaceBackendError: Error, Equatable, Sendable {
    case malformedOffer
    case unsafeEndpoint
    case unsupportedGrant
    case invalidTransactionCode
    case untrustedConsentRequired
    case rejectedTrust
    case invalidResponse
    case unknownTransaction
}

public actor OariWorkspaceW3CBackend {
    private struct Transaction: Sendable {
        let issuer: URL
        let issuerMetadata: IssuerMetadata
        let configurationIDs: [String]
        let preauthorizedCode: String
        let txCode: TxCode?
        let trustOutcome: EbsiTrustGateOutcome
    }

    private struct TxCode: Sendable {
        let length: Int?
        let numeric: Bool
    }

    private let transport: any WorkspaceHTTPTransport
    private let trustEvaluator: any WorkspaceIssuerTrustEvaluating
    private let keyProvider: any KeyProvider
    private let credentialStore: any EbsiCredentialStore
    private let credentialValidator: any WorkspaceCredentialValidating
    private let profile: EbsiCredentialProfile
    private let now: @Sendable () -> Date
    private var transactions: [UUID: Transaction] = [:]

    public init(
        transport: any WorkspaceHTTPTransport,
        trustEvaluator: any WorkspaceIssuerTrustEvaluating,
        keyProvider: any KeyProvider,
        credentialStore: any EbsiCredentialStore,
        credentialValidator: any WorkspaceCredentialValidating,
        profile: EbsiCredentialProfile,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.transport = transport
        self.trustEvaluator = trustEvaluator
        self.keyProvider = keyProvider
        self.credentialStore = credentialStore
        self.credentialValidator = credentialValidator
        self.profile = profile
        self.now = now
    }

    public func resolveOffer(_ value: String) async throws -> WorkspaceResolvedOffer {
        guard let url = URL(string: value), let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw WorkspaceBackendError.malformedOffer
        }
        let items = components.queryItems ?? []
        let data: Data
        if let embedded = items.first(where: { $0.name == "credential_offer" })?.value {
            data = Data(embedded.utf8)
        } else if let reference = items.first(where: { $0.name == "credential_offer_uri" })?.value,
                  let referenceURL = URL(string: reference) {
            try Self.validateHTTPS(referenceURL)
            data = try await successfulGET(
                referenceURL,
                allowedOrigins: [try Self.origin(of: referenceURL)]
            )
        } else {
            throw WorkspaceBackendError.malformedOffer
        }
        let offer = try JSONDecoder().decode(CredentialOffer.self, from: data)
        guard let issuer = URL(string: offer.credentialIssuer) else { throw WorkspaceBackendError.malformedOffer }
        try Self.validateHTTPS(issuer)
        guard let grant = offer.grants?.preauthorized else { throw WorkspaceBackendError.unsupportedGrant }
        let issuerMetadataURL = issuer.appendingPathComponent(".well-known/openid-credential-issuer")
        let issuerMetadata = try JSONDecoder().decode(
            IssuerMetadata.self,
            from: try await successfulGET(
                issuerMetadataURL,
                allowedOrigins: [try Self.origin(of: issuer)]
            )
        )
        let verdict = await trustEvaluator.evaluate(issuer: offer.credentialIssuer, at: now())
        let outcome = EbsiTrustGate().evaluate(
            verdict: verdict,
            environment: .development,
            counterpartyIdentifier: offer.credentialIssuer,
            role: .issuer
        )
        let id = UUID()
        transactions[id] = Transaction(
            issuer: issuer,
            issuerMetadata: issuerMetadata,
            configurationIDs: offer.credentialConfigurationIds,
            preauthorizedCode: grant.code,
            txCode: grant.txCode.map { TxCode(length: $0.length, numeric: $0.inputMode == "numeric") },
            trustOutcome: outcome
        )
        return WorkspaceResolvedOffer(
            id: id,
            issuer: offer.credentialIssuer,
            displayName: issuerMetadata.display?.first?.name,
            configurationIDs: offer.credentialConfigurationIds,
            transactionCodeRequired: grant.txCode != nil,
            trustOutcome: outcome
        )
    }

    public func issue(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> [WorkspaceIssuedCredential] {
        guard let transaction = transactions.removeValue(forKey: id) else {
            throw WorkspaceBackendError.unknownTransaction
        }
        switch transaction.trustOutcome {
        case .allow: break
        case .requireExplicitWarning:
            guard allowUntrusted else { throw WorkspaceBackendError.untrustedConsentRequired }
        case .reject: throw WorkspaceBackendError.rejectedTrust
        }
        try Self.validate(transactionCode, requirement: transaction.txCode)
        let issuerMetadata = transaction.issuerMetadata
        guard let authorizationServer = URL(
            string: issuerMetadata.authorizationServers?.first ?? transaction.issuer.absoluteString
        ) else { throw WorkspaceBackendError.unsafeEndpoint }
        let authMetadataURL = authorizationServer
            .appendingPathComponent(".well-known/oauth-authorization-server")
        let authMetadata = try JSONDecoder().decode(
            AuthorizationMetadata.self,
            from: try await successfulGET(
                authMetadataURL,
                allowedOrigins: [try Self.origin(of: authorizationServer)]
            )
        )
        let tokenBody = form([
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": transaction.preauthorizedCode,
            "tx_code": transactionCode,
        ])
        guard let tokenEndpoint = URL(string: authMetadata.tokenEndpoint) else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
        let tokenResponse = try await successfulRequest(
            tokenEndpoint,
            method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: tokenBody,
            allowedOrigins: [try Self.origin(of: authorizationServer)]
        )
        let token = try JSONDecoder().decode(TokenResponse.self, from: tokenResponse)
        let key = try await keyProvider.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: true,
            protection: .secureEnclavePreferred
        )
        let publicKey = try await keyProvider.publicKey(id: key.id)
        let holderDID = try KeyDIDResolver().derive(publicKeyX963: publicKey.x963Representation)
        let method = try await KeyDIDResolver().resolve(holderDID).assertionMethod.first!
        var results: [WorkspaceIssuedCredential] = []
        for configurationID in transaction.configurationIDs {
            let proof = try await proofJWT(
                key: key,
                kid: method,
                issuer: holderDID,
                audience: transaction.issuer.absoluteString,
                nonce: token.nonce
            )
            let request = CredentialRequest(
                credentialConfigurationId: configurationID,
                proofs: ["jwt": [proof]]
            )
            let data = try JSONEncoder().encode(request)
            guard let credentialEndpoint = URL(string: issuerMetadata.credentialEndpoint) else {
                throw WorkspaceBackendError.unsafeEndpoint
            }
            let response = try await successfulRequest(
                credentialEndpoint,
                method: "POST",
                headers: [
                    "Content-Type": "application/json",
                    "Authorization": "Bearer \(token.accessToken)",
                ],
                body: data,
                allowedOrigins: [try Self.origin(of: transaction.issuer)]
            )
            let credentials = try JSONDecoder().decode(CredentialResponse.self, from: response)
            guard !credentials.credentials.isEmpty else {
                throw WorkspaceBackendError.invalidResponse
            }
            for item in credentials.credentials {
                let raw = Data(item.credential.utf8)
                try await credentialValidator.validate(
                    rawCredential: raw,
                    profile: profile,
                    expectedHolderDID: holderDID,
                    at: now()
                )
                let stored = StoredEbsiCredential(
                    profileID: profile.id,
                    representation: profile.representation,
                    rawCredential: raw,
                    holderKeyReference: key.id.rawValue.uuidString,
                    receivedAt: now()
                )
                try await credentialStore.save(stored)
                results.append(WorkspaceIssuedCredential(
                    id: stored.id,
                    profileID: stored.profileID,
                    representation: stored.representation
                ))
            }
        }
        return results
    }

    public func cancel(id: UUID) { transactions[id] = nil }

    private func proofJWT(
        key: KeyRecord,
        kid: String,
        issuer: String,
        audience: String,
        nonce: String?
    ) async throws -> String {
        let header = try Self.base64JSON(["alg": "ES256", "kid": kid, "typ": "openid4vci-proof+jwt"])
        var payload: [String: Any] = [
            "iss": issuer,
            "aud": audience,
            "iat": Int(now().timeIntervalSince1970),
        ]
        if let nonce { payload["nonce"] = nonce }
        let encodedPayload = try Self.base64JSON(payload)
        let input = Data("\(header).\(encodedPayload)".utf8)
        let signature = try await keyProvider.sign(SigningRequest(
            keyID: key.id,
            payload: input,
            userAuthenticationReason: "Sign EBSI credential proof",
            signatureFormat: .joseRaw
        ))
        return "\(header).\(encodedPayload).\(signature.base64URLEncodedString())"
    }

    private func successfulGET(_ url: URL, allowedOrigins: Set<String>) async throws -> Data {
        try await successfulRequest(
            url,
            method: "GET",
            headers: [:],
            body: nil,
            allowedOrigins: allowedOrigins
        )
    }

    private func successfulRequest(
        _ url: URL,
        method: String,
        headers: [String: String],
        body: Data?,
        allowedOrigins: Set<String>
    ) async throws -> Data {
        try Self.validateHTTPS(url)
        guard allowedOrigins.contains(try Self.origin(of: url)) else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
        let response = try await transport.send(url: url, method: method, headers: headers, body: body)
        guard (200..<300).contains(response.statusCode), response.body.count <= 1_048_576 else {
            throw WorkspaceBackendError.invalidResponse
        }
        return response.body
    }

    private static func validateHTTPS(_ url: URL) throws {
        guard url.scheme?.lowercased() == "https", url.host != nil,
              url.user == nil, url.password == nil, url.fragment == nil else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
    }

    private static func origin(of url: URL) throws -> String {
        try validateHTTPS(url)
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased() else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
        return "\(scheme)://\(host)\(url.port.map { ":\($0)" } ?? "")"
    }

    private static func validate(_ value: String?, requirement: TxCode?) throws {
        guard let requirement else { return }
        guard let value, requirement.length.map({ value.count == $0 }) ?? true else {
            throw WorkspaceBackendError.invalidTransactionCode
        }
        guard !value.isEmpty,
              value.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 0x21 && $0.value <= 0x7e }),
              value.utf8.count == value.count else {
            throw WorkspaceBackendError.invalidTransactionCode
        }
        if requirement.numeric,
           !value.unicodeScalars.allSatisfy({ (48...57).contains(Int($0.value)) }) {
            throw WorkspaceBackendError.invalidTransactionCode
        }
    }

    private func form(_ values: [String: String?]) -> Data {
        var components = URLComponents()
        components.queryItems = values.compactMap { key, value in value.map { URLQueryItem(name: key, value: $0) } }
        return Data((components.percentEncodedQuery ?? "").utf8)
    }

    private static func base64JSON(_ value: Any) throws -> String {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).base64URLEncodedString()
    }

}

private struct CredentialOffer: Decodable {
    let credentialIssuer: String
    let credentialConfigurationIds: [String]
    let grants: Grants?
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case credentialConfigurationIds = "credential_configuration_ids"
        case grants
    }
}

private struct Grants: Decodable {
    let preauthorized: PreauthorizedGrant?
    enum CodingKeys: String, CodingKey {
        case preauthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}

private struct PreauthorizedGrant: Decodable {
    let code: String
    let txCode: TxCodeDefinition?
    enum CodingKeys: String, CodingKey {
        case code = "pre-authorized_code"
        case txCode = "tx_code"
    }
}

private struct TxCodeDefinition: Decodable {
    let inputMode: String?
    let length: Int?
    enum CodingKeys: String, CodingKey { case inputMode = "input_mode", length }
}

private struct IssuerMetadata: Decodable {
    struct Display: Decodable { let name: String? }
    let credentialEndpoint: String
    let authorizationServers: [String]?
    let display: [Display]?
    enum CodingKeys: String, CodingKey {
        case credentialEndpoint = "credential_endpoint"
        case authorizationServers = "authorization_servers"
        case display
    }
}

private struct AuthorizationMetadata: Decodable {
    let tokenEndpoint: String
    enum CodingKeys: String, CodingKey { case tokenEndpoint = "token_endpoint" }
}

private struct TokenResponse: Decodable {
    let accessToken: String
    let nonce: String?
    enum CodingKeys: String, CodingKey { case accessToken = "access_token", nonce = "c_nonce" }
}

private struct CredentialRequest: Encodable {
    let credentialConfigurationId: String
    let proofs: [String: [String]]
    enum CodingKeys: String, CodingKey { case credentialConfigurationId = "credential_configuration_id", proofs }
}

private struct CredentialResponse: Decodable {
    struct Item: Decodable { let credential: String }
    let credentials: [Item]
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
