import CryptoKit
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
        expectedIssuer: String,
        expectedHolderDID: String,
        at date: Date
    ) async throws -> String
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
        if values.contains(.path), !(try values.decodeNil(forKey: .path)) {
            var components = try values.nestedUnkeyedContainer(forKey: .path)
            var decodedPath: [String] = []
            while !components.isAtEnd {
                let componentDecoder = try components.superDecoder()
                let component = try componentDecoder.singleValueContainer()
                if component.decodeNil() {
                    decodedPath.append("*")
                } else if let value = try? component.decode(String.self) {
                    decodedPath.append(value)
                } else if let value = try? component.decode(Int.self) {
                    decodedPath.append("[\(value)]")
                } else {
                    throw DecodingError.dataCorruptedError(
                        in: component,
                        debugDescription: "Credential claim paths support string, integer, and null components."
                    )
                }
            }
            path = decodedPath
        } else {
            path = []
        }
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
    public let clientID: String?

    public init(
        id: UUID,
        authorizationEndpoint: URL,
        authSession: String?,
        interactionType: String,
        responseMode: String,
        responseURI: URL?,
        nonce: String,
        state: String?,
        dcqlQuery: [String: AnySendableJSON],
        signedRequest: String?,
        clientID: String? = nil
    ) {
        self.id = id
        self.authorizationEndpoint = authorizationEndpoint
        self.authSession = authSession
        self.interactionType = interactionType
        self.responseMode = responseMode
        self.responseURI = responseURI
        self.nonce = nonce
        self.state = state
        self.dcqlQuery = dcqlQuery
        self.signedRequest = signedRequest
        self.clientID = clientID
    }
}

public struct WorkspacePIDPresentationClaim: Equatable, Identifiable, Sendable {
    public let id: String
    public let path: [String]
    public let value: String
    public let required: Bool
}

public struct WorkspacePIDPresentationRequest: Equatable, Identifiable, Sendable {
    public let id: UUID
    public let verifierName: String?
    public let claims: [WorkspacePIDPresentationClaim]
}

public struct WorkspaceIssuedCredential: Equatable, Sendable {
    public let id: UUID
    public let configurationID: String
    public let displayName: String
    public let issuerIdentifier: String
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
    case presentationCredentialUnavailable
    case invalidPresentationChallenge(reason: String)
    case presentationSubmissionHTTPError(method: String, path: String, status: Int, detail: String?)
    case authorizationFailed
    case decodingFailed(stage: String, path: String, reason: String)
    case remoteOAuthError(code: String, detail: String?)
    case remoteHTTPError(status: Int, detail: String?)
    case clientSecurityUnavailable
    case holderIdentityRecoveryRequired
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
    private let holderIdentityProvider: any W3CHolderIdentityProviding
    private let authorizationClientID: String
    private let authorizationRedirectURI: URL
    private let now: @Sendable () -> Date
    private var transactions: [UUID: Transaction] = [:]
    private var authorizationCodes: [UUID: String] = [:]
    private var authorizationCodeVerifiers: [UUID: String] = [:]
    private var trustConsents: Set<UUID> = []
    private var presentationChallenges: [UUID: WorkspacePresentationChallenge] = [:]
    private var presentationChallengeTasks: [UUID: Task<WorkspacePresentationChallenge, Error>] = [:]
    private var interactiveAuthorizationContexts: [UUID: InteractiveAuthorizationContext] = [:]
    private var preparedPIDPresentations: [UUID: PreparedW3CPresentation] = [:]
    private var transactionHolderIdentities: [UUID: W3CHolderIdentity] = [:]

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
        holderIdentityProvider: (any W3CHolderIdentityProviding)? = nil,
        authorizationClientID: String = "oari-development-wallet",
        authorizationRedirectURI: URL = URL(string: "https://oari.io/oauth/callback")!,
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
        self.holderIdentityProvider = holderIdentityProvider ?? PersistentW3CHolderIdentityProvider(
            keyProvider: keyProvider,
            referenceStore: InMemoryW3CHolderKeyReferenceStore()
        )
        self.authorizationClientID = authorizationClientID
        self.authorizationRedirectURI = authorizationRedirectURI
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
        let offer = try Self.decode(CredentialOffer.self, from: data, stage: "credential offer")
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
        let issuerMetadataURL = try Self.wellKnownURL(
            name: "openid-credential-issuer",
            issuer: issuer
        )
        let issuerMetadata = try await discoverMetadata(
            IssuerMetadata.self,
            name: "openid-credential-issuer",
            issuer: issuer,
            standardURL: issuerMetadataURL,
            stage: "credential issuer metadata"
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
        ]
    ) async throws -> WorkspacePresentationChallenge {
        if let context = interactiveAuthorizationContexts[id] {
            return context.challenge
        }
        if let task = presentationChallengeTasks[id] {
            return try await task.value
        }
        let task = Task { [self] in
            try await createPresentationChallenge(
                id: id,
                allowUntrusted: allowUntrusted,
                interactionTypes: interactionTypes
            )
        }
        presentationChallengeTasks[id] = task
        do {
            let challenge = try await task.value
            let context = InteractiveAuthorizationContext(
                generationID: UUID(),
                challenge: challenge
            )
            interactiveAuthorizationContexts[id] = context
            presentationChallenges[id] = challenge
            presentationChallengeTasks[id] = nil
            return challenge
        } catch {
            presentationChallengeTasks[id] = nil
            authorizationCodeVerifiers[id] = nil
            throw error
        }
    }

    private func createPresentationChallenge(
        id: UUID,
        allowUntrusted: Bool,
        interactionTypes: [String] = [
            "urn:openid:dcp:ia:openid4vp_presentation",
        ]
    ) async throws -> WorkspacePresentationChallenge {
        guard let transaction = transactions[id],
              case let .authorizationCode(issuerState) = transaction.grant else {
            throw WorkspaceBackendError.presentationRequired
        }
        try authorizeTrust(transaction: transaction, id: id, allowUntrusted: allowUntrusted)
        let usesDraftInteraction = interactionTypes == ["openid4vp_presentation"]
        let endpoint: URL
        let requestMethod: String
        let requestURL: URL
        let requestBody: Data?
        let authorizationServer = URL(
            string: transaction.issuerMetadata.authorizationServers?.first ?? transaction.issuer.absoluteString
        ) ?? transaction.issuer
        let metadataURL = try Self.wellKnownURL(
            name: "oauth-authorization-server",
            issuer: authorizationServer
        )
        let metadata = try await discoverMetadata(
            AuthorizationMetadata.self,
            name: "oauth-authorization-server",
            issuer: authorizationServer,
            standardURL: metadataURL,
            stage: "authorization server metadata"
        )
        if let publishedEndpoint = metadata.authorizationChallengeEndpoint,
           let url = URL(string: publishedEndpoint),
           try Self.origin(of: url) == Self.origin(of: transaction.issuer) {
            endpoint = url
            requestMethod = "POST"
            requestURL = endpoint
            requestBody = try interactiveAuthorizationRequestBody(
                id: id,
                issuerState: issuerState,
                interactionTypes: interactionTypes,
                endpoint: endpoint,
                configurationIDs: transaction.configurationIDs
            )
        } else if let publishedEndpoint = transaction.issuerMetadata.interactiveAuthorizationEndpoint,
                  let url = URL(string: publishedEndpoint),
                  try Self.origin(of: url) == Self.origin(of: transaction.issuer) {
            endpoint = url
            requestMethod = "POST"
            requestURL = endpoint
            requestBody = try interactiveAuthorizationRequestBody(
                id: id,
                issuerState: issuerState,
                interactionTypes: interactionTypes,
                endpoint: endpoint,
                configurationIDs: transaction.configurationIDs
            )
        } else {
            if let value = metadata.authorizationEndpoint,
               let url = URL(string: value),
               try Self.origin(of: url) == Self.origin(of: transaction.issuer) {
                endpoint = url
                requestMethod = "GET"
                let fields = try interactiveAuthorizationRequestFields(
                    id: id,
                    issuerState: issuerState,
                    interactionTypes: interactionTypes,
                    endpoint: endpoint,
                    configurationIDs: transaction.configurationIDs
                )
                var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)
                components?.queryItems = fields.compactMap { key, value in
                    value.map { URLQueryItem(name: key, value: $0) }
                }
                guard let url = components?.url else { throw WorkspaceBackendError.unsafeEndpoint }
                requestURL = url
                requestBody = nil
            } else {
                endpoint = transaction.issuer.appendingPathComponent(
                    usesDraftInteraction ? "authorize" : "authorize-challenge"
                )
                requestMethod = "POST"
                requestURL = endpoint
                requestBody = form([
                    "issuer_state": issuerState,
                    "interaction_types_supported": interactionTypes.joined(separator: ","),
                ])
            }
        }
        guard try Self.origin(of: endpoint) == Self.origin(of: transaction.issuer) else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
        let raw = try await transport.send(
            url: requestURL,
            method: requestMethod,
            headers: requestMethod == "POST"
                ? ["Content-Type": "application/x-www-form-urlencoded"]
                : ["Accept": "application/json"],
            body: requestBody
        )
        guard raw.body.count <= 1_048_576 else {
            throw WorkspaceBackendError.invalidPresentationChallenge(reason: "response exceeded the 1 MB limit")
        }
        guard raw.statusCode == 200 || raw.statusCode == 403 else {
            let detail = Self.safeHTTPErrorDetail(raw.body)
            throw WorkspaceBackendError.invalidPresentationChallenge(
                reason: "\(requestMethod) \(endpoint.path) returned HTTP \(raw.statusCode)\(detail.map { ": \($0)" } ?? "")"
            )
        }
        let data = raw.body
        let response = try Self.decode(
            PresentationChallengeResponse.self,
            from: data,
            stage: "presentation challenge"
        )
        let expectedInteractionType = "urn:openid:dcp:ia:openid4vp_presentation"
        guard response.interactionTypeRequired == expectedInteractionType,
              interactionTypes.contains(expectedInteractionType),
              let authSession = response.authSession,
              !authSession.isEmpty else {
            throw WorkspaceBackendError.invalidPresentationChallenge(
                reason: "response did not contain the requested interaction type and auth_session"
            )
        }
        guard let request = response.openid4vpRequest else {
            throw WorkspaceBackendError.invalidPresentationChallenge(
                reason: "response did not contain openid4vp_request"
            )
        }
        let signedClaims = try request.requestJWT.map(Self.decodeSignedPresentationRequest)
        guard let responseMode = request.responseMode ?? request.requestObject?.responseMode ?? signedClaims?.responseMode,
              let nonce = request.nonce ?? request.requestObject?.nonce ?? signedClaims?.nonce,
              !nonce.isEmpty,
              let dcqlQuery = request.dcqlQuery ?? request.requestObject?.dcqlQuery ?? signedClaims?.dcqlQuery else {
            throw WorkspaceBackendError.invalidPresentationChallenge(
                reason: "request did not contain response_mode, nonce, and dcql_query"
            )
        }
        guard responseMode == "ia_post" else {
            throw WorkspaceBackendError.invalidPresentationChallenge(
                reason: responseMode == "ia_post.jwt"
                    ? "encrypted ia_post.jwt is not implemented"
                    : "unsupported response_mode \(responseMode)"
            )
        }
        let requestedResponseURI = request.responseURI ?? request.requestObject?.responseURI ?? signedClaims?.responseURI
        if let requestedResponseURI,
           let url = URL(string: requestedResponseURI),
           url != endpoint {
            throw WorkspaceBackendError.invalidPresentationChallenge(
                reason: "ia_post response_uri did not match authorization_challenge_endpoint"
            )
        }
        let challenge = WorkspacePresentationChallenge(
            id: id,
            authorizationEndpoint: endpoint,
            authSession: authSession,
            interactionType: expectedInteractionType,
            responseMode: responseMode,
            responseURI: endpoint,
            nonce: nonce,
            state: request.state ?? request.requestObject?.state ?? signedClaims?.state,
            dcqlQuery: dcqlQuery,
            signedRequest: request.request,
            clientID: request.clientID ?? request.requestObject?.clientID ?? signedClaims?.clientID
        )
        return challenge
    }

    public func prepareStoredPIDPresentation(id: UUID) async throws -> WorkspacePIDPresentationRequest {
        guard let context = interactiveAuthorizationContexts[id] else {
            throw WorkspaceBackendError.unknownTransaction
        }
        let challenge = context.challenge
        let holderIdentity = try await holderIdentity(for: id)
        let query = try Self.presentationQuery(from: challenge.dcqlQuery)
        let credentials = try await credentialStore.credentials()
        for credential in credentials where credential.holderKeyReference == holderIdentity.keyID.rawValue.uuidString {
            var claims: [WorkspacePIDPresentationClaim] = []
            let kind: PreparedW3CPresentation.Kind
            switch (query.format, credential.representation) {
            case ("dc+sd-jwt", .dcSdJwt):
                let parsed = try Self.parseStoredSDJWT(credential.rawCredential)
                guard query.vctValues.contains(parsed.vct) else { continue }
                var disclosures: [String: String] = [:]
                var satisfies = true
                for path in query.claimPaths {
                    guard path.count == 1, let name = path.first else {
                        satisfies = false
                        break
                    }
                    if let disclosure = parsed.disclosures[name] {
                        claims.append(Self.presentationClaim(path: path, value: disclosure.displayValue))
                        disclosures[path.joined(separator: ".")] = disclosure.encoded
                    } else if let value = parsed.payload[name]?.displayString {
                        claims.append(Self.presentationClaim(path: path, value: value))
                    } else {
                        satisfies = false
                        break
                    }
                }
                guard satisfies else { continue }
                kind = .sdJWT(issuerJWT: parsed.issuerJWT, disclosures: disclosures)
            case ("jwt_vc_json", .jwtVcJson):
                guard let profile = profiles.first(where: { $0.id == credential.profileID }) else { continue }
                let compact = String(decoding: credential.rawCredential, as: UTF8.self)
                let document = try EbsiCredentialInspector().inspectCompactJWT(compact, profile: profile)
                guard Self.matchesTypeValues(query.typeValues, document: document) else { continue }
                var satisfies = true
                for path in query.claimPaths {
                    guard let value = Self.value(at: path, in: document)?.displayString else {
                        satisfies = false
                        break
                    }
                    claims.append(Self.presentationClaim(path: path, value: value))
                }
                guard satisfies else { continue }
                kind = .jwtVC(compact)
            default:
                continue
            }
            preparedPIDPresentations[id] = PreparedW3CPresentation(
                credential: credential,
                authorizationGenerationID: context.generationID,
                kind: kind,
                requiredClaimIDs: Set(claims.map(\.id)),
                queryID: query.id
            )
            return WorkspacePIDPresentationRequest(
                id: id,
                verifierName: challenge.clientID,
                claims: claims
            )
        }
        throw WorkspaceBackendError.presentationCredentialUnavailable
    }

    private func holderIdentity(for transactionID: UUID) async throws -> W3CHolderIdentity {
        if let identity = transactionHolderIdentities[transactionID] { return identity }
        let identity = try await holderIdentityProvider.loadOrCreateIdentity()
        transactionHolderIdentities[transactionID] = identity
        return identity
    }

    public func storedPIDPresentationToken(
        id: UUID,
        selectedClaimIDs: Set<String>
    ) async throws -> String {
        guard let context = interactiveAuthorizationContexts[id],
              let prepared = preparedPIDPresentations.removeValue(forKey: id),
              prepared.authorizationGenerationID == context.generationID,
              prepared.requiredClaimIDs.isSubset(of: selectedClaimIDs),
              let keyUUID = UUID(uuidString: prepared.credential.holderKeyReference) else {
            throw WorkspaceBackendError.invalidPresentationResponse
        }
        let challenge = context.challenge
        let keyID = KeyID(rawValue: keyUUID)
        let presentation: String
        switch prepared.kind {
        case let .sdJWT(issuerJWT, disclosures):
            let audience = "ia:\(try Self.origin(of: challenge.authorizationEndpoint))"
            let selectedDisclosures = disclosures.keys.sorted().compactMap {
                selectedClaimIDs.contains($0) ? disclosures[$0] : nil
            }
            let withoutKeyBinding = ([issuerJWT] + selectedDisclosures).joined(separator: "~") + "~"
            presentation = withoutKeyBinding + (try await signedPresentationJWT(
                keyID: keyID,
                type: "kb+jwt",
                payload: [
                    "aud": audience,
                    "nonce": challenge.nonce,
                    "iat": Int(now().timeIntervalSince1970),
                    "sd_hash": Data(SHA256.hash(data: Data(withoutKeyBinding.utf8))).base64URLEncodedString(),
                ]
            ))
        case let .jwtVC(compactCredential):
            let audience = "ia:\(challenge.authorizationEndpoint.absoluteString)"
            let publicKey = try await keyProvider.publicKey(id: keyID)
            let holder = try KeyDIDResolver().derive(publicKeyX963: publicKey.x963Representation)
            let issuedAt = Int(now().timeIntervalSince1970)
            presentation = try await signedPresentationJWT(
                keyID: keyID,
                type: "JWT",
                payload: [
                    "iss": holder,
                    "jti": "urn:uuid:\(UUID().uuidString.lowercased())",
                    "aud": audience,
                    "nonce": challenge.nonce,
                    "nbf": issuedAt,
                    "iat": issuedAt,
                    "exp": issuedAt + 300,
                    "vp": [
                        "@context": ["https://www.w3.org/2018/credentials/v1"],
                        "type": ["VerifiablePresentation"],
                        "holder": holder,
                        "verifiableCredential": [compactCredential],
                    ],
                ]
            )
        }
        let object = try JSONSerialization.data(withJSONObject: [prepared.queryID: [presentation]])
        return String(decoding: object, as: UTF8.self)
    }

    public func submitPresentation(
        id: UUID,
        vpToken: String
    ) async throws -> String {
        guard let transaction = transactions[id],
              let context = interactiveAuthorizationContexts[id],
              trustConsents.contains(id) else {
            throw WorkspaceBackendError.unknownTransaction
        }
        let challenge = context.challenge
        var fields: [String: String?] = [:]
        if challenge.responseMode == "direct_post" {
            fields["state"] = challenge.state
            fields["vp_token"] = vpToken
        } else if challenge.responseMode == "iar-post" {
            fields["state"] = challenge.state
            fields["auth_session"] = challenge.authSession
            if case let .authorizationCode(issuerState) = transaction.grant {
                fields["issuer_state"] = issuerState
            }
            fields["response_type"] = "code"
            fields["client_id"] = challenge.clientID
            fields["code_challenge"] = authorizationCodeVerifiers[id].map {
                Data(SHA256.hash(data: Data($0.utf8))).base64URLEncodedString()
            }
            fields["code_challenge_method"] = "S256"
            fields["interaction_types_supported"] = "openid4vp_presentation"
            let authorizationDetails = try JSONSerialization.data(
                withJSONObject: transaction.configurationIDs.map { configurationID in
                    ["type": "openid_credential", "credential_configuration_id": configurationID]
                }
            )
            fields["authorization_details"] = String(decoding: authorizationDetails, as: UTF8.self)
            fields["openid4vp_presentation"] = vpToken
        } else if challenge.responseMode == "ia_post" {
            fields["auth_session"] = challenge.authSession
            guard let tokenObject = try JSONSerialization.jsonObject(with: Data(vpToken.utf8)) as? [String: Any] else {
                throw WorkspaceBackendError.invalidPresentationResponse
            }
            var responseObject: [String: Any] = ["vp_token": tokenObject]
            if let state = challenge.state { responseObject["state"] = state }
            let wrapped = try JSONSerialization.data(withJSONObject: responseObject)
            fields["openid4vp_response"] = String(decoding: wrapped, as: UTF8.self)
        } else if challenge.responseMode == "ia_post.jwt" {
            throw WorkspaceBackendError.invalidPresentationChallenge(
                reason: "encrypted ia_post.jwt response generation is not implemented"
            )
        } else {
            throw WorkspaceBackendError.invalidPresentationChallenge(
                reason: "unsupported response_mode \(challenge.responseMode)"
            )
        }
        let responseEndpoint = challenge.responseMode == "ia_post" || challenge.responseMode == "ia_post.jwt"
            ? challenge.authorizationEndpoint
            : (challenge.responseURI ?? challenge.authorizationEndpoint)
        let response: Data
        do {
            response = try await successfulRequest(
                responseEndpoint,
                method: "POST",
                headers: ["Content-Type": "application/x-www-form-urlencoded"],
                body: form(fields),
                allowedOrigins: [try Self.origin(of: transaction.issuer)]
            )
        } catch let error as WorkspaceBackendError {
            if case let .remoteHTTPError(status, detail) = error {
                throw WorkspaceBackendError.presentationSubmissionHTTPError(
                    method: "POST",
                    path: responseEndpoint.path,
                    status: status,
                    detail: detail
                )
            }
            throw error
        }
        let code = try Self.decode(
            AuthorizationCodeResponse.self,
            from: response,
            stage: "presentation authorization response"
        )
        guard let value = code.authorizationCode ?? code.code, !value.isEmpty else {
            throw WorkspaceBackendError.invalidPresentationResponse
        }
        authorizationCodes[id] = value
        presentationChallenges[id] = nil
        interactiveAuthorizationContexts[id] = nil
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
                "code_verifier": authorizationCodeVerifiers[id],
                "client_id": authorizationClientID,
                "redirect_uri": authorizationRedirectURI.absoluteString,
            ]
        }
        let issuerMetadata = transaction.issuerMetadata
        guard let authorizationServer = URL(
            string: issuerMetadata.authorizationServers?.first ?? transaction.issuer.absoluteString
        ) else { throw WorkspaceBackendError.unsafeEndpoint }
        let authMetadataURL = try Self.wellKnownURL(
            name: "oauth-authorization-server",
            issuer: authorizationServer
        )
        let authMetadata = try await discoverMetadata(
            AuthorizationMetadata.self,
            name: "oauth-authorization-server",
            issuer: authorizationServer,
            standardURL: authMetadataURL,
            stage: "authorization server metadata"
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
        let token = try Self.decode(TokenResponse.self, from: tokenResponse, stage: "token response")
        let holderIdentity = try await holderIdentity(for: id)
        let holderDID = holderIdentity.did
        let method = holderIdentity.assertionMethod
        var results: [WorkspaceIssuedCredential] = []
        let configurationIDs: [String]
        var draftAuthorizationDetails: [String: TokenResponse.AuthorizationDetail] = [:]
        var draftCredentialIdentifiers: [String: [String]] = [:]
        if transportContract.profile != .final {
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
                    let candidate = transaction.configurationIDs.count == 1
                        ? candidates.first
                        : (candidates.count == 1 ? candidates.first : nil)
                    guard highestScore != nil, let candidate,
                          matchedIndexes.insert(candidate.0).inserted else {
                        throw WorkspaceBackendError.credentialAuthorizationMismatch(
                            offered: offeredID,
                            authorized: Self.authorizationIdentifiers(authorizationDetails)
                        )
                    }
                    let index = candidate.0
                    draftAuthorizationDetails[offeredID] = authorizationDetails[index]
                    var identifiers = [candidate.2]
                    identifiers.append(contentsOf: authorizationDetails[index].credentialIdentifiers ?? [])
                    identifiers.append(contentsOf: authorizationDetails.flatMap { $0.credentialIdentifiers ?? [] })
                    draftCredentialIdentifiers[offeredID] = Self.uniqueNonEmpty(identifiers)
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
            let credentialIdentifier = draftCredentialIdentifiers[configurationID]?.first
                ?? authorizationDetail?.credentialIdentifiers?.first(where: { !$0.isEmpty })
                ?? configurationID
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
            guard let credentialEndpoint = URL(string: issuerMetadata.credentialEndpoint) else {
                throw WorkspaceBackendError.unsafeEndpoint
            }
            let identifierCandidates: [String?]
            if transportContract.credentialIdentifierField == .credentialIdentifier {
                var values = draftCredentialIdentifiers[configurationID] ?? [credentialIdentifier]
                values.append(configurationID)
                values = Self.uniqueNonEmpty(values)
                identifierCandidates = values.map(Optional.some)
            } else {
                identifierCandidates = [nil]
            }
            let proof = try await proofJWT(
                keyID: holderIdentity.keyID,
                kid: method,
                issuer: holderDID,
                audience: transaction.issuer.absoluteString,
                nonce: token.nonce
            )
            var successfulResponse: Data?
            for (index, candidate) in identifierCandidates.enumerated() {
                let request = CredentialRequest(
                    credentialConfigurationId: transportContract.credentialIdentifierField == .credentialConfigurationID ? configurationID : nil,
                    credentialIdentifier: candidate,
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
                do {
                    successfulResponse = try await successfulRequest(
                        credentialEndpoint,
                        method: "POST",
                        headers: credentialHeaders,
                        body: data,
                        allowedOrigins: [try Self.origin(of: transaction.issuer)]
                    )
                    break
                } catch let error as WorkspaceBackendError {
                    let canRetry = index + 1 < identifierCandidates.count &&
                        Self.isRetryableCredentialIdentifierError(error)
                    guard canRetry else { throw error }
                }
            }
            guard var response = successfulResponse else { throw WorkspaceBackendError.invalidResponse }
            if transportContract.requiresCredentialResponseEncryption,
               Self.looksLikeCompactJWE(response),
               let securityState, let clientSecurity {
                response = try await clientSecurity.decryptCredentialResponse(
                    state: securityState,
                    compactJWE: response
                )
            }
            let credentials = try Self.decode(
                CredentialResponse.self,
                from: response,
                stage: "credential response"
            )
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
                let signedIssuer = try await credentialValidator.validate(
                    rawCredential: raw,
                    profile: selectedProfile,
                    expectedIssuer: transaction.issuer.absoluteString,
                    expectedHolderDID: holderDID,
                    at: now()
                )
                let stored = StoredEbsiCredential(
                    profileID: selectedProfile.id,
                    representation: selectedProfile.representation,
                    rawCredential: raw,
                    holderKeyReference: holderIdentity.keyID.rawValue.uuidString,
                    receivedAt: now()
                )
                try await credentialStore.save(stored)
                results.append(WorkspaceIssuedCredential(
                    id: stored.id,
                    configurationID: configurationID,
                    displayName: transaction.issuerMetadata.credentialConfigurations[configurationID]?.display.name
                        ?? "Credential",
                    issuerIdentifier: signedIssuer,
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
        authorizationCodeVerifiers[id] = nil
        interactiveAuthorizationContexts[id] = nil
        presentationChallengeTasks.removeValue(forKey: id)?.cancel()
        transactionHolderIdentities[id] = nil
        trustConsents.remove(id)
        return results
    }

    private func selectProfile(
        format: String?,
        rawCredential: Data
    ) throws -> EbsiCredentialProfile {
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
        let context = Self.jwtContext(rawCredential)
        if context == "https://www.w3.org/ns/credentials/v2",
           let profile = profiles.first(where: { $0.representation == .vcdm2Jwt }) {
            return profile
        }
        if format == "jwt_vc_json" || format == "jwt_vc_json-ld" {
            guard let profile = profiles.first(where: { $0.dataModel == .v1_1 }) else {
                throw EbsiCredentialError.unsupportedRepresentation
            }
            return profile
        }
        if context == "https://www.w3.org/2018/credentials/v1",
           let profile = profiles.first(where: { $0.dataModel == .v1_1 }) {
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

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func safeHTTPErrorDetail(_ data: Data) -> String? {
        guard data.count <= 1_048_576,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        if let detail = object["detail"] as? String {
            if let nestedData = detail.data(using: .utf8),
               let failures = try? JSONSerialization.jsonObject(with: nestedData) as? [[String: Any]] {
                let values = failures.compactMap { failure -> String? in
                    let path = (failure["loc"] as? [Any])?.compactMap { $0 as? String }.joined(separator: ".")
                    let message = failure["msg"] as? String
                    guard let message else { return nil }
                    return path.map { "\($0): \(message)" } ?? message
                }
                return values.isEmpty ? nil : values.joined(separator: ", ")
            }
            return detail.count <= 200 && !detail.contains("eyJ") ? detail : nil
        }
        if let description = object["error_description"] as? String, description.count <= 200 {
            return description
        }
        if let error = object["error"] as? String, error.count <= 100 { return error }
        return nil
    }

    private static func decode<Value: Decodable>(
        _ type: Value.Type,
        from data: Data,
        stage: String
    ) throws -> Value {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch let error as DecodingError {
            let context: DecodingError.Context
            let reason: String
            switch error {
            case let .dataCorrupted(value):
                context = value
                reason = "invalid value"
            case let .keyNotFound(key, value):
                context = value
                reason = "missing key \(key.stringValue)"
            case let .typeMismatch(expected, value):
                context = value
                reason = "expected \(String(describing: expected))"
            case let .valueNotFound(expected, value):
                context = value
                reason = "missing \(String(describing: expected))"
            @unknown default:
                throw WorkspaceBackendError.decodingFailed(
                    stage: stage,
                    path: "$",
                    reason: "unknown decoding failure"
                )
            }
            let path = context.codingPath.reduce("$") { partial, key in
                if let index = key.intValue { return "\(partial)[\(index)]" }
                return "\(partial).\(key.stringValue)"
            }
            throw WorkspaceBackendError.decodingFailed(stage: stage, path: path, reason: reason)
        }
    }

    private static func looksLikeCompactJWE(_ data: Data) -> Bool {
        let compact = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return compact.split(separator: ".", omittingEmptySubsequences: false).count == 5
    }

    private static func wellKnownURL(name: String, issuer: URL) throws -> URL {
        guard let scheme = issuer.scheme, let host = issuer.host else {
            throw WorkspaceBackendError.unsafeEndpoint
        }
        var components = URLComponents()
        components.scheme = scheme
        components.host = host
        components.port = issuer.port
        let issuerPath = issuer.path == "/" ? "" : issuer.path
        components.path = "/.well-known/\(name)\(issuerPath)"
        guard let url = components.url else { throw WorkspaceBackendError.unsafeEndpoint }
        return url
    }

    private static func decodeSignedPresentationRequest(_ compactJWT: String) throws -> SignedPresentationRequest {
        let parts = compactJWT.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request was not a compact JWT")
        }
        var base64 = String(parts[1]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64) else {
            throw WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request payload was not valid base64url")
        }
        return try Self.decode(
            SignedPresentationRequest.self,
            from: data,
            stage: "signed presentation request"
        )
    }

    private static func presentationQuery(
        from dcqlQuery: [String: AnySendableJSON]
    ) throws -> (
        id: String,
        format: String,
        vctValues: Set<String>,
        typeValues: [[String]],
        claimPaths: [[String]]
    ) {
        guard case let .array(credentials)? = dcqlQuery["credentials"] else {
            throw WorkspaceBackendError.invalidResponse
        }
        for credential in credentials {
            guard case let .object(query) = credential,
                  let format = query["format"]?.string,
                  format == "dc+sd-jwt" || format == "jwt_vc_json",
                  let id = query["id"]?.string,
                  case let .array(claims)? = query["claims"] else { continue }
            let meta = query["meta"]?.object ?? [:]
            let vcts: Set<String>
            if case let .array(values)? = meta["vct_values"] {
                vcts = Set(values.compactMap(\.string))
            } else {
                vcts = []
            }
            let typeValues: [[String]]
            if case let .array(values)? = meta["type_values"] {
                typeValues = values.compactMap { value in
                    guard case let .array(types) = value else { return nil }
                    return types.compactMap(\.string)
                }
            } else {
                typeValues = []
            }
            let paths = claims.compactMap { claim -> [String]? in
                guard case let .object(value) = claim,
                      case let .array(path)? = value["path"] else { return nil }
                return path.compactMap(\.string)
            }
            guard paths.count == claims.count, !paths.isEmpty,
                  format != "dc+sd-jwt" || !vcts.isEmpty else {
                throw WorkspaceBackendError.invalidResponse
            }
            return (id, format, vcts, typeValues, paths)
        }
        throw WorkspaceBackendError.presentationCredentialUnavailable
    }

    private static func presentationClaim(
        path: [String],
        value: String
    ) -> WorkspacePIDPresentationClaim {
        WorkspacePIDPresentationClaim(
            id: path.joined(separator: "."),
            path: path,
            value: value,
            required: true
        )
    }

    private static func value(
        at path: [String],
        in document: [String: AnySendableJSON]
    ) -> AnySendableJSON? {
        guard let first = path.first, var value = document[first] else { return nil }
        for component in path.dropFirst() {
            guard let next = value.object?[component] else { return nil }
            value = next
        }
        return value
    }

    private static func matchesTypeValues(
        _ typeValues: [[String]],
        document: [String: AnySendableJSON]
    ) -> Bool {
        guard !typeValues.isEmpty else { return true }
        let types: Set<String>
        if let type = document["type"]?.string {
            types = [type]
        } else if case let .array(values)? = document["type"] {
            types = Set(values.compactMap(\.string))
        } else {
            types = []
        }
        return typeValues.contains { Set($0).isSubset(of: types) }
    }

    private static func parseStoredSDJWT(_ rawCredential: Data) throws -> (
        issuerJWT: String,
        vct: String,
        payload: [String: AnySendableJSON],
        disclosures: [String: (encoded: String, displayValue: String)]
    ) {
        let raw = String(decoding: rawCredential, as: UTF8.self)
        guard let issuerJWT = raw.split(separator: "~", omittingEmptySubsequences: false).first else {
            throw EbsiCredentialError.malformedCredential
        }
        let payload = try EbsiCredentialInspector().inspectSDJWT(raw)
        guard let vct = payload["vct"]?.string else { throw EbsiCredentialError.profileMismatch }
        let validDigests: Set<String>
        if case let .array(values)? = payload["_sd"] {
            validDigests = Set(values.compactMap(\.string))
        } else {
            validDigests = []
        }
        var disclosures: [String: (encoded: String, displayValue: String)] = [:]
        for encoded in raw.split(separator: "~").dropFirst() where !encoded.isEmpty {
            let digest = Data(SHA256.hash(data: Data(encoded.utf8))).base64URLEncodedString()
            guard validDigests.contains(digest) else { continue }
            var base64 = String(encoded).replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
            guard let data = Data(base64Encoded: base64),
                  let value = try? JSONSerialization.jsonObject(with: data) as? [Any],
                  value.count == 3, let name = value[1] as? String else { continue }
            let displayValue: String
            if let string = value[2] as? String { displayValue = string }
            else if let number = value[2] as? NSNumber { displayValue = number.stringValue }
            else { displayValue = "Available" }
            disclosures[name] = (String(encoded), displayValue)
        }
        return (String(issuerJWT), vct, payload, disclosures)
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

    private static func uniqueNonEmpty(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        return values.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    private static func isRetryableCredentialIdentifierError(_ error: WorkspaceBackendError) -> Bool {
        switch error {
        case .remoteOAuthError(code: "invalid_credential_request", detail: _),
             .remoteOAuthError(code: "unsupported_credential_type", detail: _):
            return true
        case let .remoteHTTPError(status: 400, detail):
            let value = detail?.lowercased() ?? ""
            return value.contains("invalid credential request") ||
                value.contains("unsupported credential type")
        default:
            return false
        }
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
        authorizationCodeVerifiers[id] = nil
        presentationChallenges[id] = nil
        presentationChallengeTasks.removeValue(forKey: id)?.cancel()
        interactiveAuthorizationContexts[id] = nil
        preparedPIDPresentations[id] = nil
        transactionHolderIdentities[id] = nil
        trustConsents.remove(id)
    }

    public func deleteStoredCredential(id: UUID) async throws {
        try await credentialStore.delete(id: id)
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

    private func interactiveAuthorizationRequestBody(
        id: UUID,
        issuerState: String,
        interactionTypes: [String],
        endpoint: URL,
        configurationIDs: [String]
    ) throws -> Data {
        form(try interactiveAuthorizationRequestFields(
            id: id,
            issuerState: issuerState,
            interactionTypes: interactionTypes,
            endpoint: endpoint,
            configurationIDs: configurationIDs
        ))
    }

    private func interactiveAuthorizationRequestFields(
        id: UUID,
        issuerState: String,
        interactionTypes: [String],
        endpoint: URL,
        configurationIDs: [String]
    ) throws -> [String: String?] {
        let verifier = Self.base64URL(Data((UUID().uuidString + UUID().uuidString).utf8))
        authorizationCodeVerifiers[id] = verifier
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        let authorizationDetails = try JSONSerialization.data(
            withJSONObject: configurationIDs.map { configurationID in
                ["type": "openid_credential", "credential_configuration_id": configurationID]
            }
        )
        return [
            "issuer_state": issuerState,
            "interaction_types_supported": interactionTypes.joined(separator: ","),
            "response_type": "code",
            "client_id": authorizationClientID,
            "redirect_uri": authorizationRedirectURI.absoluteString,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "authorization_details": String(decoding: authorizationDetails, as: UTF8.self),
        ]
    }

    private func proofJWT(
        keyID: KeyID,
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
            keyID: keyID,
            payload: input,
            userAuthenticationReason: "Sign EBSI credential proof",
            signatureFormat: .joseRaw
        ))
        return "\(header).\(encodedPayload).\(signature.base64URLEncodedString())"
    }

    private func signedPresentationJWT(
        keyID: KeyID,
        type: String,
        payload: [String: Any]
    ) async throws -> String {
        let header = try Self.base64JSON(["alg": "ES256", "typ": type])
        let encodedPayload = try Self.base64JSON(payload)
        let signingInput = Data("\(header).\(encodedPayload)".utf8)
        let signature = try await keyProvider.sign(SigningRequest(
            keyID: keyID,
            payload: signingInput,
            userAuthenticationReason: "Present approved identity claims",
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

    private func discoverMetadata<Value: Decodable>(
        _ type: Value.Type,
        name: String,
        issuer: URL,
        standardURL: URL,
        stage: String
    ) async throws -> Value {
        let allowedOrigins = Set([try Self.origin(of: issuer)])
        do {
            let data = try await successfulGET(standardURL, allowedOrigins: allowedOrigins)
            return try Self.decode(type, from: data, stage: stage)
        } catch let error as WorkspaceBackendError {
            let shouldTryLegacy = switch error {
            case .remoteHTTPError(status: 404, detail: _): true
            case .remoteOAuthError(code: "not_found", detail: _): true
            case .decodingFailed: true
            default: false
            }
            guard shouldTryLegacy else { throw error }
            let legacyURL = issuer
                .appendingPathComponent(".well-known")
                .appendingPathComponent(name)
            guard legacyURL != standardURL else { throw error }
            let data = try await successfulGET(legacyURL, allowedOrigins: allowedOrigins)
            return try Self.decode(type, from: data, stage: stage)
        }
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
    let responseMode: String?
    let responseURI: String?
    let clientID: String?
    let nonce: String?
    let state: String?
    let dcqlQuery: [String: AnySendableJSON]?
    let request: String?
    let requestJWT: String?
    let requestObject: PresentationRequestObject?
    enum CodingKeys: String, CodingKey {
        case responseMode = "response_mode"
        case responseURI = "response_uri"
        case clientID = "client_id"
        case nonce, state
        case dcqlQuery = "dcql_query"
        case request
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        responseMode = try values.decodeIfPresent(String.self, forKey: .responseMode)
        responseURI = try values.decodeIfPresent(String.self, forKey: .responseURI)
        clientID = try values.decodeIfPresent(String.self, forKey: .clientID)
        nonce = try values.decodeIfPresent(String.self, forKey: .nonce)
        state = try values.decodeIfPresent(String.self, forKey: .state)
        dcqlQuery = try values.decodeIfPresent([String: AnySendableJSON].self, forKey: .dcqlQuery)
        if let jwt = try? values.decode(String.self, forKey: .request) {
            request = jwt
            requestJWT = jwt
            requestObject = nil
        } else {
            request = nil
            requestJWT = nil
            requestObject = try values.decodeIfPresent(PresentationRequestObject.self, forKey: .request)
        }
    }
}

private struct PresentationRequestObject: Decodable {
    let clientID: String?
    let responseMode: String?
    let responseURI: String?
    let nonce: String?
    let state: String?
    let dcqlQuery: [String: AnySendableJSON]?

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id"
        case responseMode = "response_mode"
        case responseURI = "response_uri"
        case nonce, state
        case dcqlQuery = "dcql_query"
    }
}

private struct SignedPresentationRequest: Decodable {
    let clientID: String
    let responseMode: String
    let responseURI: String?
    let nonce: String
    let state: String?
    let dcqlQuery: [String: AnySendableJSON]
    enum CodingKeys: String, CodingKey {
        case responseMode = "response_mode"
        case responseURI = "response_uri"
        case clientID = "client_id"
        case nonce, state
        case dcqlQuery = "dcql_query"
    }
}

private struct PreparedW3CPresentation: Sendable {
    enum Kind: Sendable {
        case sdJWT(issuerJWT: String, disclosures: [String: String])
        case jwtVC(String)
    }

    let credential: StoredEbsiCredential
    let authorizationGenerationID: UUID
    let kind: Kind
    let requiredClaimIDs: Set<String>
    let queryID: String
}

private struct InteractiveAuthorizationContext: Sendable {
    let generationID: UUID
    let challenge: WorkspacePresentationChallenge
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
    let interactiveAuthorizationEndpoint: String?
    enum CodingKeys: String, CodingKey {
        case credentialEndpoint = "credential_endpoint"
        case authorizationServers = "authorization_servers"
        case display
        case credentialConfigurations = "credential_configurations_supported"
        case notificationEndpoint = "notification_endpoint"
        case interactiveAuthorizationEndpoint = "interactive_authorization_endpoint"
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
        interactiveAuthorizationEndpoint = try values.decodeIfPresent(String.self, forKey: .interactiveAuthorizationEndpoint)
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
    let authorizationEndpoint: String?
    let authorizationChallengeEndpoint: String?
    let dpopSigningAlgorithms: [String]?
    let clientAttestationAlgorithms: [String]?
    let tokenEndpointAuthenticationMethods: [String]?
    enum CodingKeys: String, CodingKey {
        case tokenEndpoint = "token_endpoint"
        case authorizationEndpoint = "authorization_endpoint"
        case authorizationChallengeEndpoint = "authorization_challenge_endpoint"
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
