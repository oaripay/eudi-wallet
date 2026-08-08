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
    public let transactionCodeLength: Int?
    public let transactionCodeDescription: String?
    public let trustOutcome: EbsiTrustGateOutcome
    public let authorizationRequired: Bool
    public let issuerState: String?
    public let representations: [String]
    public let credentialDisplay: [String: WorkspaceCredentialDisplay]
}

public struct WorkspaceCredentialDisplay: Codable, Equatable, Sendable {
    public let name: String
    public let locale: String?
    public let description: String?
    public let backgroundColor: String?
    public let textColor: String?
    public let logoURL: URL?
    public let logoAlternativeText: String?
    public let backgroundImageURL: URL?
    public let claims: [WorkspaceCredentialClaim]
}

public struct WorkspaceCredentialClaim: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let path: [String]
    public let name: String?
    public let description: String?

    public init(id: String, path: [String], name: String?, description: String?) {
        self.id = id
        self.path = path
        self.name = name
        self.description = description
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        path = try values.decodeIfPresent([String].self, forKey: .path) ?? []
        name = try values.decodeIfPresent(String.self, forKey: .name)
        description = try values.decodeIfPresent(String.self, forKey: .description)
        id = path.joined(separator: ".")
    }

    private enum CodingKeys: String, CodingKey { case path, name, description }
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
    public let configurationID: String
    public let displayName: String
    public let profileID: String
    public let representation: EbsiCredentialRepresentation
    public let displayClaims: [CredentialDisplayClaim]
    public let display: CredentialDisplayMetadata?
}

public enum WorkspaceBackendError: Error, Equatable, Sendable {
    case malformedOffer
    case unsafeEndpoint
    case unsupportedGrant
    case invalidTransactionCode
    case untrustedConsentRequired
    case rejectedTrust
    case invalidResponse
    case missingCredentialNonce
    case missingCredentialAuthorization
    case credentialAuthorizationMismatch(offered: String, authorized: [String])
    case unknownTransaction
    case presentationRequired
    case invalidPresentationResponse
    case authorizationFailed
    case remoteOAuthError(code: String, detail: String?)
    case remoteHTTPError(status: Int, detail: String?)
    case clientSecurityUnavailable
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
        let description: String?
    }

    private let transport: any WorkspaceHTTPTransport
    private let trustEvaluator: any WorkspaceIssuerTrustEvaluating
    private let keyProvider: any KeyProvider
    private let credentialStore: any EbsiCredentialStore
    private let credentialValidator: any WorkspaceCredentialValidating
    private let profiles: [EbsiCredentialProfile]
    private let clientSecurity: (any OID4VCIClientSecurity)?
    private let transportProfileRegistry: OID4VCITransportProfileRegistry
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
        clientSecurity: (any OID4VCIClientSecurity)? = nil,
        transportProfileRegistry: OID4VCITransportProfileRegistry = .finalOnly,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.transport = transport
        self.trustEvaluator = trustEvaluator
        self.keyProvider = keyProvider
        self.credentialStore = credentialStore
        self.credentialValidator = credentialValidator
        self.profiles = [profile] + additionalProfiles
        self.clientSecurity = clientSecurity
        self.transportProfileRegistry = transportProfileRegistry
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
        } else if components.scheme?.lowercased() == "https" ||
                    (components.scheme?.lowercased() == "http" && components.host == "127.0.0.1") {
            try Self.validateHTTPS(url)
            data = try await successfulGET(
                url,
                allowedOrigins: [try Self.origin(of: url)]
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
                txCode: preauthorized.txCode.map {
                    TxCode(length: $0.length, numeric: $0.inputMode == "numeric", description: $0.description)
                }
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
        let selectedConfigurations = try offer.credentialConfigurationIds.map { configurationID in
            guard let configuration = issuerMetadata.credentialConfigurations[configurationID] else {
                throw WorkspaceBackendError.unsupportedGrant
            }
            return configuration
        }
        let representations = selectedConfigurations.map(\.format)
        guard representations.allSatisfy(Self.supportedRepresentation) else {
            throw WorkspaceBackendError.unsupportedGrant
        }
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
            transactionCodeLength: transactionCodeLength(grant),
            transactionCodeDescription: transactionCodeDescription(grant),
            trustOutcome: outcome,
            authorizationRequired: ifCaseAuthorization(grant),
            issuerState: ifCaseIssuerState(grant),
            representations: representations
            , credentialDisplay: issuerMetadata.credentialConfigurations.mapValues(\.display)
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
        let transportContract = OID4VCITransportContract.resolve(
            selectedProfile: transportProfileRegistry.profile(for: transaction.issuer),
            authorizationMetadata: OID4VCIAuthorizationMetadata(
                dpopSigningAlgorithms: authMetadata.dpopSigningAlgorithms,
                clientAttestationAlgorithms: authMetadata.clientAttestationAlgorithms,
                tokenEndpointAuthenticationMethods: authMetadata.tokenEndpointAuthenticationMethods
            )
        )
        guard transportContract.tokenEndpointAuthentication != .unsupported else {
            throw WorkspaceBackendError.clientSecurityUnavailable
        }
        let securityState: OID4VCIClientSecurityState?
        if transportContract.requiresDPoP || transportContract.requiresClientAttestation ||
            transportContract.requiresCredentialResponseEncryption {
            guard let clientSecurity else { throw WorkspaceBackendError.clientSecurityUnavailable }
            securityState = try await clientSecurity.state(for: transportContract.profile)
        } else {
            securityState = nil
        }
        let tokenBody = form(tokenValues)
        guard let tokenEndpoint = URL(string: authMetadata.tokenEndpoint) else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
        var tokenHeaders = ["Content-Type": "application/x-www-form-urlencoded"]
        if let securityState, let clientSecurity {
            if transportContract.requiresDPoP {
                tokenHeaders["DPoP"] = try await clientSecurity.dpopHeader(
                    state: securityState,
                    method: "POST",
                    targetURI: tokenEndpoint,
                    accessToken: nil
                )
            }
            if transportContract.requiresClientAttestation {
                let attestationHeaders = try await clientSecurity.clientAttestationHeaders(
                    state: securityState,
                    audience: tokenEndpoint
                )
                guard !attestationHeaders.isEmpty else {
                    throw WorkspaceBackendError.clientSecurityUnavailable
                }
                tokenHeaders.merge(attestationHeaders, uniquingKeysWith: { _, new in new })
            }
        }
        let tokenResponse = try await successfulRequest(
            tokenEndpoint,
            method: "POST",
            headers: tokenHeaders,
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
        let configurationIDs: [String]
        var draftAuthorizationDetails: [String: TokenResponse.AuthorizationDetail] = [:]
        var draftCredentialIdentifiers: [String: String] = [:]
        if transportContract.profile != .final {
            guard let nonce = token.nonce, !nonce.isEmpty else {
                throw WorkspaceBackendError.missingCredentialNonce
            }
            if let authorizationDetails = token.authorizationDetails {
                guard !authorizationDetails.isEmpty else {
                    throw WorkspaceBackendError.missingCredentialAuthorization
                }
                var matchedIndexes: Set<Int> = []
                for offeredID in transaction.configurationIDs {
                    var ranked = authorizationDetails.indices.compactMap { index -> (Int, Int, String)? in
                        guard let match = Self.draftAuthorizationMatch(
                            offeredID: offeredID,
                            detail: authorizationDetails[index],
                            configurations: transaction.issuerMetadata.credentialConfigurations
                        ) else { return nil }
                        return (index, match.score, match.credentialIdentifier)
                    }
                    if ranked.isEmpty, transaction.configurationIDs.count == 1 {
                        ranked = authorizationDetails.indices.compactMap { index in
                            guard let identifier = authorizationDetails[index].credentialIdentifiers?
                                .first(where: { !$0.isEmpty }) else { return nil }
                            return (index, 0, identifier)
                        }
                    }
                    let highestScore = ranked.map(\.1).max()
                    let candidates = ranked.filter { $0.1 == highestScore }
                    guard highestScore != nil, candidates.count == 1,
                          let candidate = candidates.first,
                          matchedIndexes.insert(candidate.0).inserted else {
                        throw WorkspaceBackendError.credentialAuthorizationMismatch(
                            offered: offeredID,
                            authorized: Self.authorizationIdentifiers(authorizationDetails)
                        )
                    }
                    let index = candidate.0
                    draftAuthorizationDetails[offeredID] = authorizationDetails[index]
                    draftCredentialIdentifiers[offeredID] = candidate.2
                }
            }
            configurationIDs = transaction.configurationIDs
        } else {
            let advertisedConfigurationIDs = Set(transaction.issuerMetadata.credentialConfigurations.keys)
            let authorizedConfigurationIDs = token.authorizationDetails?.compactMap(\.credentialConfigurationID)
                .filter { !$0.isEmpty && advertisedConfigurationIDs.contains($0) } ?? []
            configurationIDs = authorizedConfigurationIDs.isEmpty
                ? transaction.configurationIDs
                : authorizedConfigurationIDs
        }
        for configurationID in configurationIDs {
            let display = await offlineDisplayMetadata(
                transaction.issuerMetadata.credentialConfigurations[configurationID]?.display
            )
            let authorizationDetail = transportContract.profile == .final
                ? token.authorizationDetails?.first { $0.credentialConfigurationID == configurationID }
                : draftAuthorizationDetails[configurationID]
            let credentialIdentifier = draftCredentialIdentifiers[configurationID]
                ?? authorizationDetail?.credentialIdentifiers?.first(where: { !$0.isEmpty })
                ?? configurationID
            let proof = try await proofJWT(
                key: key,
                kid: method,
                issuer: holderDID,
                audience: transaction.issuer.absoluteString,
                nonce: token.nonce
            )
            let responseEncryption: CredentialResponseEncryptionRequest?
            if transportContract.requiresCredentialResponseEncryption,
               let securityState, let clientSecurity {
                let parameters = try await clientSecurity.responseEncryption(state: securityState)
                guard let jwk = try JSONSerialization.jsonObject(
                    with: Data(parameters.publicJWK.utf8)
                ) as? [String: String] else {
                    throw WorkspaceBackendError.clientSecurityUnavailable
                }
                responseEncryption = CredentialResponseEncryptionRequest(
                    jwk: jwk,
                    alg: parameters.algorithm,
                    enc: parameters.encryption
                )
            } else {
                responseEncryption = nil
            }
            let request = CredentialRequest(
                credentialConfigurationId: transportContract.credentialIdentifierField == .credentialConfigurationID ? configurationID : nil,
                credentialIdentifier: transportContract.credentialIdentifierField == .credentialIdentifier
                    ? credentialIdentifier
                    : nil,
                format: transportContract.credentialIdentifierField == .credentialIdentifier
                    ? nil
                    : transaction.issuerMetadata.credentialConfigurations[configurationID]?.format,
                proof: transportContract.proofShape == .draftProof
                    ? ProofValue(proofType: "jwt", jwt: proof)
                    : nil,
                proofs: transportContract.proofShape == .finalProofsJWT
                    ? ["jwt": [proof]]
                    : nil,
                credentialResponseEncryption: responseEncryption
            )
            let data = try JSONEncoder().encode(request)
            guard let credentialEndpoint = URL(string: issuerMetadata.credentialEndpoint) else {
                throw WorkspaceBackendError.unsafeEndpoint
            }
            var credentialHeaders = [
                "Content-Type": "application/json",
                "Authorization": "Bearer \(token.accessToken)",
            ]
            if transportContract.requiresDPoP,
               let securityState, let clientSecurity {
                credentialHeaders["DPoP"] = try await clientSecurity.dpopHeader(
                    state: securityState,
                    method: "POST",
                    targetURI: credentialEndpoint,
                    accessToken: token.accessToken
                )
                credentialHeaders["Authorization"] = "DPoP \(token.accessToken)"
            }
            var response = try await successfulRequest(
                credentialEndpoint,
                method: "POST",
                headers: credentialHeaders,
                body: data,
                allowedOrigins: [try Self.origin(of: transaction.issuer)]
            )
            if transportContract.requiresCredentialResponseEncryption,
               let securityState, let clientSecurity {
                response = try await clientSecurity.decryptCredentialResponse(
                    state: securityState,
                    compactJWE: response
                )
            }
            let credentials = try JSONDecoder().decode(CredentialResponse.self, from: response)
            guard !credentials.credentials.isEmpty else {
                throw WorkspaceBackendError.invalidResponse
            }
            for item in credentials.credentials {
                let raw = Data(item.credential.utf8)
                let selectedProfile = try selectProfile(
                    format: credentials.format
                        ?? item.format
                        ?? transaction.issuerMetadata.credentialConfigurations[configurationID]?.format,
                    rawCredential: raw
                )
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
                    configurationID: configurationID,
                    displayName: transaction.issuerMetadata.credentialConfigurations[configurationID]?.display.name
                        ?? "Credential",
                    profileID: stored.profileID,
                    representation: stored.representation,
                    displayClaims: Self.displayClaims(
                        raw: String(decoding: raw, as: UTF8.self),
                        profile: selectedProfile
                    ),
                    display: display
                ))
            }
            if let notificationID = credentials.notificationID,
               let notificationEndpoint = issuerMetadata.notificationEndpoint.flatMap(URL.init(string:)) {
                let notification = try JSONSerialization.data(withJSONObject: [
                    "event": "credential_accepted",
                    "notification_id": notificationID,
                ])
                _ = try await successfulRequest(
                    notificationEndpoint,
                    method: "POST",
                    headers: [
                        "Content-Type": "application/json",
                        "Authorization": "Bearer \(token.accessToken)",
                    ],
                    body: notification,
                    allowedOrigins: [try Self.origin(of: transaction.issuer)]
                )
            }
        }
        transactions[id] = nil
        authorizationCodes[id] = nil
        trustConsents.remove(id)
        return results
    }

    private func selectProfile(
        format: String?,
        rawCredential: Data
    ) throws -> EbsiCredentialProfile {
        let context = Self.jwtContext(rawCredential)
        if context == "https://www.w3.org/ns/credentials/v2",
           let profile = profiles.first(where: { $0.dataModel == .v2_0 }) {
            return profile
        }
        if context == "https://www.w3.org/2018/credentials/v1",
           let profile = profiles.first(where: { $0.dataModel == .v1_1 }) {
            return profile
        }
        if format == "jwt_vc_json" || format == "jwt_vc_json-ld" {
            guard let profile = profiles.first(where: { $0.dataModel == .v1_1 }) else {
                throw EbsiCredentialError.unsupportedRepresentation
            }
            return profile
        }
        if format == "dc+sd-jwt" {
            guard let profile = profiles.first(where: { $0.representation == .dcSdJwt }) else {
                throw EbsiCredentialError.unsupportedRepresentation
            }
            return profile
        }
        if format == "vcdm2_sd_jwt" {
            guard let profile = profiles.first(where: { $0.representation == .vcdm2SdJwt }) else {
                throw EbsiCredentialError.unsupportedRepresentation
            }
            return profile
        }
        guard let profile = profiles.first(where: { $0.representation == .vcdm2Jwt }) else {
            throw EbsiCredentialError.unsupportedRepresentation
        }
        return profile
    }

    private static func jwtContext(_ raw: Data) -> String? {
        let parts = String(decoding: raw, as: UTF8.self).split(separator: ".")
        guard parts.count >= 2 else { return nil }
        var value = String(parts[1]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: value),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        if let contexts = object["@context"] as? [String] { return contexts.first }
        return object["@context"] as? String
    }

    private static func supportedRepresentation(_ format: String) -> Bool {
        ["jwt_vc_json", "jwt_vc_json-ld", "dc+sd-jwt", "vcdm2_sd_jwt", "application/vc+jwt"]
            .contains(format)
    }

    private static func equivalentDraftConfiguration(
        offeredID: String,
        authorizedID: String,
        configurations: [String: SupportedConfiguration]
    ) -> Bool {
        if offeredID == authorizedID { return true }
        guard let offered = configurations[offeredID],
              let authorized = configurations[authorizedID],
              let offeredVCT = offered.vct, !offeredVCT.isEmpty,
              offeredVCT == authorized.vct else {
            return false
        }
        return offered.format == authorized.format
    }

    private static func draftAuthorizationMatch(
        offeredID: String,
        detail: TokenResponse.AuthorizationDetail,
        configurations: [String: SupportedConfiguration]
    ) -> (score: Int, credentialIdentifier: String)? {
        let identifiers = detail.credentialIdentifiers?.filter { !$0.isEmpty } ?? []
        guard !identifiers.isEmpty else { return nil }
        let equivalentIdentifier = identifiers.first {
            equivalentDraftConfiguration(
                offeredID: offeredID,
                authorizedID: $0,
                configurations: configurations
            )
        }
        if detail.credentialConfigurationID == offeredID {
            return (400, identifiers.first(where: { $0 == offeredID }) ?? equivalentIdentifier ?? identifiers[0])
        }
        if identifiers.contains(offeredID) {
            return (300, offeredID)
        }
        if let authorizedID = detail.credentialConfigurationID,
           equivalentDraftConfiguration(
               offeredID: offeredID,
               authorizedID: authorizedID,
               configurations: configurations
           ) {
            return (200, equivalentIdentifier ?? identifiers[0])
        }
        if let equivalentIdentifier {
            return (100, equivalentIdentifier)
        }
        return nil
    }

    private static func authorizationIdentifiers(
        _ details: [TokenResponse.AuthorizationDetail]
    ) -> [String] {
        var seen: Set<String> = []
        return details.flatMap { detail in
            [detail.credentialConfigurationID].compactMap { $0 } + (detail.credentialIdentifiers ?? [])
        }.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    private static func displayClaims(from credential: [String: AnySendableJSON]?) -> [CredentialDisplayClaim] {
        guard let credential else { return [] }
        let subject = credential["credentialSubject"]?.object ?? credential
        return subject.compactMap { key, value in
            guard let string = value.displayString else { return nil }
            return CredentialDisplayClaim(
                id: key,
                label: key.replacingOccurrences(of: "_", with: " ").capitalized,
                value: string,
                isSensitive: key.lowercased().contains("id") || key.lowercased().contains("name")
            )
        }.sorted { $0.label < $1.label }
    }

    private static func displayClaims(
        raw: String,
        profile: EbsiCredentialProfile
    ) -> [CredentialDisplayClaim] {
        if profile.representation == .dcSdJwt || profile.representation == .vcdm2SdJwt {
            var claims = (try? EbsiCredentialInspector().inspectSDJWT(raw)) ?? [:]
            for disclosure in raw.split(separator: "~").dropFirst() where !disclosure.isEmpty {
                var value = String(disclosure).replacingOccurrences(of: "-", with: "+")
                    .replacingOccurrences(of: "_", with: "/")
                value += String(repeating: "=", count: (4 - value.count % 4) % 4)
                guard let data = Data(base64Encoded: value),
                      let array = try? JSONDecoder().decode([AnySendableJSON].self, from: data),
                      array.count >= 3, let name = array[1].string else { continue }
                claims[name] = array[2]
            }
            let hidden = Set(["_sd", "_sd_alg", "cnf", "iss", "iat", "exp", "vct", "status"])
            return displayClaims(from: claims.filter { !hidden.contains($0.key) })
        }
        return displayClaims(from: try? EbsiCredentialInspector().inspectCompactJWT(raw, profile: profile))
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
        let issuedAt = Int(now().timeIntervalSince1970)
        let header = try Self.base64JSON(["alg": "ES256", "kid": kid, "typ": "openid4vci-proof+jwt"])
        var payload: [String: Any] = [
            "iss": issuer,
            "aud": audience,
            "iat": issuedAt,
            "exp": issuedAt + 300,
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

    private func offlineDisplayMetadata(
        _ display: WorkspaceCredentialDisplay?
    ) async -> CredentialDisplayMetadata? {
        guard let display else { return nil }
        async let logo = downloadDisplayImage(
            display.logoURL,
            alternativeText: display.logoAlternativeText
        )
        async let background = downloadDisplayImage(display.backgroundImageURL)
        let images = await (logo, background)
        return CredentialDisplayMetadata(
            locale: display.locale,
            description: display.description,
            backgroundColor: display.backgroundColor,
            textColor: display.textColor,
            logo: images.0,
            backgroundImage: images.1
        )
    }

    private func downloadDisplayImage(
        _ url: URL?,
        alternativeText: String? = nil
    ) async -> CredentialDisplayImage? {
        guard let url else { return nil }
        do {
            try Self.validateHTTPS(url)
            let response = try await transport.send(url: url, method: "GET", headers: [:], body: nil)
            guard (200..<300).contains(response.statusCode),
                  !response.body.isEmpty,
                  response.body.count <= 1_048_576,
                  let mediaType = Self.validatedImageMediaType(
                      response.headers.first { $0.key.caseInsensitiveCompare("Content-Type") == .orderedSame }?.value,
                      data: response.body
                  ) else { return nil }
            return CredentialDisplayImage(
                mediaType: mediaType,
                data: response.body,
                alternativeText: alternativeText
            )
        } catch {
            return nil
        }
    }

    private static func validatedImageMediaType(_ contentType: String?, data: Data) -> String? {
        let declared = contentType?.split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        let detected: String?
        if data.starts(with: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) {
            detected = "image/png"
        } else if data.starts(with: [0xff, 0xd8, 0xff]) {
            detected = "image/jpeg"
        } else if data.count >= 12,
                  String(decoding: data.prefix(4), as: UTF8.self) == "RIFF",
                  String(decoding: data.dropFirst(8).prefix(4), as: UTF8.self) == "WEBP" {
            detected = "image/webp"
        } else {
            detected = nil
        }
        guard let detected, declared == nil || declared == detected else { return nil }
        return detected
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
        guard response.body.count <= 1_048_576 else {
            throw WorkspaceBackendError.invalidResponse
        }
        guard (200..<300).contains(response.statusCode) else {
            if let error = try? JSONDecoder().decode(RemoteOAuthError.self, from: response.body) {
                throw WorkspaceBackendError.remoteOAuthError(code: error.error, detail: error.errorDetail)
            }
            let detail = (try? JSONDecoder().decode(RemoteHTTPError.self, from: response.body))?.detail
                ?? String(data: response.body, encoding: .utf8)
            throw WorkspaceBackendError.remoteHTTPError(status: response.statusCode, detail: detail)
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

private func transactionCodeLength(_ grant: OariWorkspaceW3CBackend.Grant) -> Int? {
    if case let .preAuthorized(_, requirement) = grant { return requirement?.length }
    return nil
}

private func transactionCodeDescription(_ grant: OariWorkspaceW3CBackend.Grant) -> String? {
    if case let .preAuthorized(_, requirement) = grant { return requirement?.description }
    return nil
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
    let description: String?
    enum CodingKeys: String, CodingKey { case inputMode = "input_mode", length, description }
}

private struct IssuerMetadata: Decodable {
    struct Display: Decodable { let name: String? }
    let credentialEndpoint: String
    let authorizationServers: [String]?
    let display: [Display]?
    let credentialConfigurations: [String: SupportedConfiguration]
    let notificationEndpoint: String?
    enum CodingKeys: String, CodingKey {
        case credentialEndpoint = "credential_endpoint"
        case authorizationServers = "authorization_servers"
        case display
        case credentialConfigurations = "credential_configurations_supported"
        case notificationEndpoint = "notification_endpoint"
    }

    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        credentialEndpoint = try values.decode(String.self, forKey: .credentialEndpoint)
        authorizationServers = try values.decodeIfPresent([String].self, forKey: .authorizationServers)
        display = try values.decodeIfPresent([Display].self, forKey: .display)
        credentialConfigurations = try values.decodeIfPresent(
            [String: SupportedConfiguration].self,
            forKey: .credentialConfigurations
        ) ?? [:]
        notificationEndpoint = try values.decodeIfPresent(String.self, forKey: .notificationEndpoint)
    }
}

private struct SupportedConfiguration: Decodable {
    let format: String
    let vct: String?
    let credentialMetadata: CredentialMetadata?
    let directDisplay: [CredentialDisplay]?
    let directClaims: [String: ClaimDefinition]?

    var display: WorkspaceCredentialDisplay {
        let display = (directDisplay ?? credentialMetadata?.display)?.first
        return WorkspaceCredentialDisplay(
            name: display?.name ?? "Credential",
            locale: display?.locale,
            description: display?.description,
            backgroundColor: display?.backgroundColor,
            textColor: display?.textColor,
            logoURL: display?.logo.flatMap { URL(string: $0.url) },
            logoAlternativeText: display?.logo?.alternativeText,
            backgroundImageURL: display?.backgroundImage.flatMap { URL(string: $0.url) },
            claims: directClaims?.map { key, value in
                WorkspaceCredentialClaim(
                    id: key,
                    path: [key],
                    name: value.display?.first?.name ?? key,
                    description: value.description
                )
            }.sorted { $0.id < $1.id } ?? credentialMetadata?.claims ?? []
        )
    }

    enum CodingKeys: String, CodingKey {
        case format, vct
        case credentialMetadata = "credential_metadata"
        case directDisplay = "display"
        case directClaims = "claims"
    }

    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        format = try values.decode(String.self, forKey: .format)
        vct = try values.decodeIfPresent(String.self, forKey: .vct)
        credentialMetadata = try values.decodeIfPresent(CredentialMetadata.self, forKey: .credentialMetadata)
        directDisplay = try values.decodeIfPresent([CredentialDisplay].self, forKey: .directDisplay)
        directClaims = try values.decodeIfPresent([String: ClaimDefinition].self, forKey: .directClaims)
    }
}

private struct CredentialMetadata: Decodable {
    let display: [CredentialDisplay]?
    let claims: [WorkspaceCredentialClaim]?
}

private struct CredentialDisplay: Decodable {
    let name: String?
    let locale: String?
    let description: String?
    let backgroundColor: String?
    let textColor: String?
    let logo: Logo?
    let backgroundImage: DisplayImage?

    enum CodingKeys: String, CodingKey {
        case name, locale, description
        case backgroundColor = "background_color"
        case textColor = "text_color"
        case logo
        case backgroundImage = "background_image"
    }
}

private struct ClaimDefinition: Decodable {
    let display: [CredentialDisplay]?
    let description: String?
}

private struct Logo: Decodable {
    let url: String
    let alternativeText: String?
    enum CodingKeys: String, CodingKey { case url, uri, alternativeText = "alt_text" }
    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        url = try values.decodeIfPresent(String.self, forKey: .url)
            ?? values.decode(String.self, forKey: .uri)
        alternativeText = try values.decodeIfPresent(String.self, forKey: .alternativeText)
    }
}

private struct DisplayImage: Decodable {
    let url: String
    enum CodingKeys: String, CodingKey { case url, uri }
    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        url = try values.decodeIfPresent(String.self, forKey: .url)
            ?? values.decode(String.self, forKey: .uri)
    }
}

private struct AuthorizationMetadata: Decodable {
    let tokenEndpoint: String
    let dpopSigningAlgorithms: [String]?
    let clientAttestationAlgorithms: [String]?
    let tokenEndpointAuthenticationMethods: [String]?
    enum CodingKeys: String, CodingKey {
        case tokenEndpoint = "token_endpoint"
        case dpopSigningAlgorithms = "dpop_signing_alg_values_supported"
        case clientAttestationAlgorithms = "client_attestation_signing_alg_values_supported"
        case tokenEndpointAuthenticationMethods = "token_endpoint_auth_methods_supported"
    }
}

private struct RemoteOAuthError: Decodable {
    let error: String
    let errorDetail: String?
    enum CodingKeys: String, CodingKey {
        case error
        case errorDetail = "error_detail"
    }
}

private struct RemoteHTTPError: Decodable { let detail: String? }

private struct TokenResponse: Decodable {
    struct AuthorizationDetail: Decodable {
        let credentialConfigurationID: String?
        let credentialIdentifiers: [String]?
        enum CodingKeys: String, CodingKey {
            case credentialConfigurationID = "credential_configuration_id"
            case credentialIdentifiers = "credential_identifiers"
        }
    }
    let accessToken: String
    let tokenType: String?
    let nonce: String?
    let authorizationDetails: [AuthorizationDetail]?
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case nonce = "c_nonce"
        case authorizationDetails = "authorization_details"
    }
}

private struct CredentialRequest: Encodable {
    let credentialConfigurationId: String?
    let credentialIdentifier: String?
    let format: String?
    let proof: ProofValue?
    let proofs: [String: [String]]?
    let credentialResponseEncryption: CredentialResponseEncryptionRequest?
    enum CodingKeys: String, CodingKey {
        case credentialConfigurationId = "credential_configuration_id"
        case credentialIdentifier = "credential_identifier"
        case format
        case proof, proofs
        case credentialResponseEncryption = "credential_response_encryption"
    }
}

private struct CredentialResponseEncryptionRequest: Encodable {
    let jwk: [String: String]
    let alg: String
    let enc: String
}

private struct ProofValue: Encodable {
    let proofType: String
    let jwt: String
    enum CodingKeys: String, CodingKey { case proofType = "proof_type", jwt }
}

private struct CredentialResponse: Decodable {
    struct Item: Decodable {
        let credential: String
        let format: String?
    }
    let format: String?
    let credential: String?
    let credentials: [Item]
    let notificationID: String?

    private enum CodingKeys: String, CodingKey {
        case format, credential, credentials
        case notificationID = "notification_id"
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        format = try container.decodeIfPresent(String.self, forKey: .format)
        credential = try container.decodeIfPresent(String.self, forKey: .credential)
        let plural = try container.decodeIfPresent([Item].self, forKey: .credentials) ?? []
        notificationID = try container.decodeIfPresent(String.self, forKey: .notificationID)
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
