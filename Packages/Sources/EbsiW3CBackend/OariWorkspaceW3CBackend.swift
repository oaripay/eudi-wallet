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
    public let authorizationRequired: Bool
    public let issuerState: String?
}

public struct WorkspacePresentationChallenge: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let authorizationEndpoint: URL
    public let authSession: String?
    public let interactionType: String
    public let responseMode: String
    public let responseURI: URL?
    public let nonce: String
    public let state: String?
    public let dcqlQuery: [String: AnySendableJSON]
    public let signedRequest: String?
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
    case presentationRequired
    case invalidPresentationResponse
    case authorizationFailed
}

public actor OariWorkspaceW3CBackend {
    private struct Transaction: Sendable {
        let issuer: URL
        let issuerMetadata: IssuerMetadata
        let configurationIDs: [String]
        let grant: Grant
        let trustOutcome: EbsiTrustGateOutcome
    }

    enum Grant: Sendable {
        case preAuthorized(code: String, txCode: TxCode?)
        case authorizationCode(issuerState: String)
    }

    struct TxCode: Sendable {
        let length: Int?
        let numeric: Bool
    }

    private let transport: any WorkspaceHTTPTransport
    private let trustEvaluator: any WorkspaceIssuerTrustEvaluating
    private let keyProvider: any KeyProvider
    private let credentialStore: any EbsiCredentialStore
    private let credentialValidator: any WorkspaceCredentialValidating
    private let profiles: [EbsiCredentialProfile]
    private let now: @Sendable () -> Date
    private var transactions: [UUID: Transaction] = [:]
    private var authorizationCodes: [UUID: String] = [:]
    private var trustConsents: Set<UUID> = []
    private var presentationChallenges: [UUID: WorkspacePresentationChallenge] = [:]

    public init(
        transport: any WorkspaceHTTPTransport,
        trustEvaluator: any WorkspaceIssuerTrustEvaluating,
        keyProvider: any KeyProvider,
        credentialStore: any EbsiCredentialStore,
        credentialValidator: any WorkspaceCredentialValidating,
        profile: EbsiCredentialProfile,
        additionalProfiles: [EbsiCredentialProfile] = [],
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.transport = transport
        self.trustEvaluator = trustEvaluator
        self.keyProvider = keyProvider
        self.credentialStore = credentialStore
        self.credentialValidator = credentialValidator
        self.profiles = [profile] + additionalProfiles
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
        let grant: Grant
        if let preauthorized = offer.grants?.preauthorized {
            grant = .preAuthorized(
                code: preauthorized.code,
                txCode: preauthorized.txCode.map { TxCode(length: $0.length, numeric: $0.inputMode == "numeric") }
            )
        } else if let authorization = offer.grants?.authorizationCode,
                  let issuerState = authorization.issuerState {
            grant = .authorizationCode(issuerState: issuerState)
        } else {
            throw WorkspaceBackendError.unsupportedGrant
        }
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
            grant: grant,
            trustOutcome: outcome
        )
        return WorkspaceResolvedOffer(
            id: id,
            issuer: offer.credentialIssuer,
            displayName: issuerMetadata.display?.first?.name,
            configurationIDs: offer.credentialConfigurationIds,
            transactionCodeRequired: ifCasePreAuthorizedTxCode(grant),
            trustOutcome: outcome,
            authorizationRequired: ifCaseAuthorization(grant),
            issuerState: ifCaseIssuerState(grant)
        )
    }

    public func beginPresentationRequired(
        id: UUID,
        allowUntrusted: Bool,
        interactionTypes: [String] = [
            "urn:openid:dcp:ia:openid4vp_presentation",
            "openid4vp_presentation",
        ]
    ) async throws -> WorkspacePresentationChallenge {
        guard let transaction = transactions[id],
              case let .authorizationCode(issuerState) = transaction.grant else {
            throw WorkspaceBackendError.presentationRequired
        }
        try authorizeTrust(transaction: transaction, id: id, allowUntrusted: allowUntrusted)
        let endpoint = transaction.issuer.appendingPathComponent("authorize-challenge")
        let body = form([
            "issuer_state": issuerState,
            "interaction_types_supported": interactionTypes.joined(separator: ","),
        ])
        guard try Self.origin(of: endpoint) == Self.origin(of: transaction.issuer) else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
        let raw = try await transport.send(
            url: endpoint,
            method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: body
        )
        guard raw.statusCode == 200 || raw.statusCode == 403,
              raw.body.count <= 1_048_576 else { throw WorkspaceBackendError.invalidResponse }
        let data = raw.body
        let response = try JSONDecoder().decode(PresentationChallengeResponse.self, from: data)
        guard let request = response.openid4vpRequest else { throw WorkspaceBackendError.invalidResponse }
        let challenge = WorkspacePresentationChallenge(
            id: id,
            authorizationEndpoint: endpoint,
            authSession: response.authSession,
            interactionType: response.interactionTypeRequired ?? "openid4vp_presentation",
            responseMode: request.responseMode,
            responseURI: request.responseURI.flatMap(URL.init(string:)),
            nonce: request.nonce,
            state: request.state,
            dcqlQuery: request.dcqlQuery,
            signedRequest: request.request
        )
        presentationChallenges[id] = challenge
        return challenge
    }

    public func submitPresentation(
        id: UUID,
        vpToken: String
    ) async throws -> String {
        guard let transaction = transactions[id],
              let challenge = presentationChallenges[id],
              trustConsents.contains(id) else {
            throw WorkspaceBackendError.unknownTransaction
        }
        var fields: [String: String?] = [
            "auth_session": challenge.authSession,
            "state": challenge.state,
        ]
        if challenge.responseMode == "iar-post" {
            fields["vp_token"] = vpToken
        } else {
            let wrapped = try JSONSerialization.data(withJSONObject: ["vp_token": vpToken])
            fields["openid4vp_response"] = String(decoding: wrapped, as: UTF8.self)
        }
        let response = try await successfulRequest(
            challenge.responseURI ?? challenge.authorizationEndpoint,
            method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: form(fields),
            allowedOrigins: [try Self.origin(of: transaction.issuer)]
        )
        let code = try JSONDecoder().decode(AuthorizationCodeResponse.self, from: response)
        guard let value = code.authorizationCode ?? code.code, !value.isEmpty else {
            throw WorkspaceBackendError.invalidPresentationResponse
        }
        authorizationCodes[id] = value
        presentationChallenges[id] = nil
        return value
    }

    public func acceptAuthorizationCode(id: UUID, code: String) throws {
        guard transactions[id] != nil, !code.isEmpty else {
            throw WorkspaceBackendError.unknownTransaction
        }
        authorizationCodes[id] = code
        presentationChallenges[id] = nil
    }

    public func issue(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> [WorkspaceIssuedCredential] {
        guard let transaction = transactions[id] else {
            throw WorkspaceBackendError.unknownTransaction
        }
        try authorizeTrust(transaction: transaction, id: id, allowUntrusted: allowUntrusted)
        let tokenValues: [String: String?]
        switch transaction.grant {
        case let .preAuthorized(code, txCode):
            try Self.validate(transactionCode, requirement: txCode)
            tokenValues = [
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": code,
                "tx_code": transactionCode,
            ]
        case .authorizationCode:
            guard let code = authorizationCodes[id] else {
                throw WorkspaceBackendError.presentationRequired
            }
            tokenValues = [
                "grant_type": "authorization_code",
                "code": code,
            ]
        }
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
        let tokenBody = form(tokenValues)
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
                let selectedProfile = try selectProfile(format: credentials.format ?? item.format)
                try await credentialValidator.validate(
                    rawCredential: raw,
                    profile: selectedProfile,
                    expectedHolderDID: holderDID,
                    at: now()
                )
                let stored = StoredEbsiCredential(
                    profileID: selectedProfile.id,
                    representation: selectedProfile.representation,
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
        transactions[id] = nil
        authorizationCodes[id] = nil
        trustConsents.remove(id)
        return results
    }

    private func selectProfile(format: String?) throws -> EbsiCredentialProfile {
        if format == "jwt_vc_json" || format == "jwt_vc_json-ld" {
            guard let profile = profiles.first(where: { $0.dataModel == .v1_1 }) else {
                throw EbsiCredentialError.unsupportedRepresentation
            }
            return profile
        }
        if format == "dc+sd-jwt" || format == "vcdm2_sd_jwt" {
            guard let profile = profiles.first(where: {
                $0.representation == .dcSdJwt || $0.representation == .vcdm2SdJwt
            }) else { throw EbsiCredentialError.unsupportedRepresentation }
            return profile
        }
        guard let profile = profiles.first(where: { $0.representation == .vcdm2Jwt }) else {
            throw EbsiCredentialError.unsupportedRepresentation
        }
        return profile
    }

    public func cancel(id: UUID) {
        transactions[id] = nil
        authorizationCodes[id] = nil
        presentationChallenges[id] = nil
        trustConsents.remove(id)
    }

    private func authorizeTrust(
        transaction: Transaction,
        id: UUID,
        allowUntrusted: Bool
    ) throws {
        switch transaction.trustOutcome {
        case .allow: trustConsents.insert(id)
        case .requireExplicitWarning:
            guard allowUntrusted || trustConsents.contains(id) else {
                throw WorkspaceBackendError.untrustedConsentRequired
            }
            trustConsents.insert(id)
        case .reject: throw WorkspaceBackendError.rejectedTrust
        }
    }

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
        guard let scheme = url.scheme?.lowercased(),
              scheme == "https" || (scheme == "http" && (url.host == "127.0.0.1" || url.host == "localhost")),
              url.host != nil,
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
    let authorizationCode: AuthorizationCodeGrant?
    enum CodingKeys: String, CodingKey {
        case preauthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        case authorizationCode = "authorization_code"
    }
}

private struct AuthorizationCodeGrant: Decodable {
    let issuerState: String?
    enum CodingKeys: String, CodingKey { case issuerState = "issuer_state" }
}

private struct PresentationChallengeResponse: Decodable {
    let authSession: String?
    let interactionTypeRequired: String?
    let openid4vpRequest: PresentationRequest?
    enum CodingKeys: String, CodingKey {
        case authSession = "auth_session"
        case interactionTypeRequired = "interaction_type_required"
        case openid4vpRequest = "openid4vp_request"
    }
}

private struct PresentationRequest: Decodable {
    let responseMode: String
    let responseURI: String?
    let nonce: String
    let state: String?
    let dcqlQuery: [String: AnySendableJSON]
    let request: String?
    enum CodingKeys: String, CodingKey {
        case responseMode = "response_mode"
        case responseURI = "response_uri"
        case nonce, state
        case dcqlQuery = "dcql_query"
        case request
    }
}

private struct AuthorizationCodeResponse: Decodable {
    let authorizationCode: String?
    let code: String?
    enum CodingKeys: String, CodingKey {
        case authorizationCode = "authorization_code"
        case code
    }
}

private func ifCasePreAuthorizedTxCode(_ grant: OariWorkspaceW3CBackend.Grant) -> Bool {
    if case let .preAuthorized(_, txCode) = grant { return txCode != nil }
    return false
}

private func ifCaseAuthorization(_ grant: OariWorkspaceW3CBackend.Grant) -> Bool {
    if case .authorizationCode = grant { return true }
    return false
}

private func ifCaseIssuerState(_ grant: OariWorkspaceW3CBackend.Grant) -> String? {
    if case let .authorizationCode(issuerState) = grant { return issuerState }
    return nil
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
    struct Item: Decodable {
        let credential: String
        let format: String?
    }
    let format: String?
    let credential: String?
    let credentials: [Item]

    private enum CodingKeys: String, CodingKey { case format, credential, credentials }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        format = try container.decodeIfPresent(String.self, forKey: .format)
        credential = try container.decodeIfPresent(String.self, forKey: .credential)
        let plural = try container.decodeIfPresent([Item].self, forKey: .credentials) ?? []
        if plural.isEmpty, let credential {
            credentials = [Item(credential: credential, format: format)]
        } else {
            credentials = plural
        }
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
