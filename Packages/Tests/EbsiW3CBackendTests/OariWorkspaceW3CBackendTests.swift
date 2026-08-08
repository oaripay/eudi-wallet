import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing
import TrustDomain
import WalletDomain

struct OariWorkspaceW3CBackendTests {
    @Test("Draft issuance uses DPoP, identifier-only request and encrypted response", arguments: ["draft-13", "draft-18"])
    func draftIssuance(revision: String) async throws {
        let transport = Draft13WorkspaceTransport()
        let security = RecordingOID4VCIClientSecurity()
        let store = FixtureCredentialStore()
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: security,
            transportProfileRegistry: .developmentDraftCompatibility,
            now: { Date(timeIntervalSince1970: 1_800_000_000) }
        )
        let offerJSON = """
        {"credential_issuer":"https://issuer.example/service/\(revision)","credential_configuration_ids":["pid-config"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":4}}}}
        """
        let encoded = offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        let issued = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")

        #expect(issued.count == 1)
        #expect(try await store.credentials().count == 1)
        let requests = await transport.requests
        let token = try #require(requests.first { $0.url.path.hasSuffix("/token") })
        #expect(token.headers["DPoP"] == "dpop-token")
        #expect(token.headers["OAuth-Client-Attestation"] == nil)
        let credential = try #require(requests.first { $0.url.path.hasSuffix("/credential") })
        #expect(credential.headers["Authorization"] == "DPoP access-token")
        #expect(credential.headers["DPoP"] == "dpop-access-token")
        let credentialBody = try #require(credential.body)
        let body = try #require(
            JSONSerialization.jsonObject(with: credentialBody) as? [String: Any]
        )
        #expect(body["credential_identifier"] as? String == "authorized-pid")
        #expect(body["credential_configuration_id"] == nil)
        #expect(body["format"] == nil)
        #expect(body["proofs"] == nil)
        let proof = try #require(body["proof"] as? [String: Any])
        #expect(proof["proof_type"] as? String == "jwt")
        let proofPayload = try Self.jwtPayload(try #require(proof["jwt"] as? String))
        #expect(proofPayload["iat"] as? Int == 1_800_000_000)
        #expect(proofPayload["exp"] as? Int == 1_800_000_300)
        #expect(proofPayload["nonce"] as? String == "credential-nonce")
        #expect(body["credential_response_encryption"] != nil)
        #expect(await security.dpopAccessTokens == [nil, "access-token"])
        #expect(await security.decryptionCalls == 1)
        #expect(requests.contains { $0.url.path.hasSuffix("/notification") && $0.method == "POST" })
    }

    @Test("Draft issuance rejects a missing nonce before credential request")
    func draftMissingNonce() async throws {
        let response = #"{"access_token":"access-token","authorization_details":[{"credential_configuration_id":"pid-config","credential_identifiers":["authorized-pid"]}]}"#
        try await assertRejectedDraftToken(response, expected: .missingCredentialNonce)
    }

    @Test("Draft issuance accepts one token-authorized identifier despite configuration mismatch")
    func draftMismatchedAuthorization() async throws {
        let response = #"{"access_token":"access-token","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"other-config","credential_identifiers":["unauthorized-pid"]}]}"#
        let transport = Draft13WorkspaceTransport(tokenResponse: response)
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "unauthorized-pid")
    }

    @Test("Draft issuance accepts one metadata-proven configuration alias")
    func draftEquivalentConfigurationAlias() async throws {
        let response = #"{"access_token":"access-token","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"pid-alias","credential_identifiers":["authorized-alias"]}]}"#
        let transport = Draft13WorkspaceTransport(tokenResponse: response)
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        let issued = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "authorized-alias")
        #expect(issued.first?.configurationID == "pid-config")
    }

    @Test("Draft issuance matches an offered credential identifier when configuration ID is absent")
    func draftIdentifierWithoutConfigurationID() async throws {
        let response = #"{"access_token":"access-token","c_nonce":"credential-nonce","authorization_details":[{"credential_identifiers":["pid-config"]}]}"#
        let transport = Draft13WorkspaceTransport(tokenResponse: response)
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "pid-config")
    }

    @Test("Draft issuance prefers exact authorization and ignores additional aliases")
    func draftExactConfigurationWithAdditionalAliases() async throws {
        let response = #"{"access_token":"access-token","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"pid-config","credential_identifiers":["exact"]},{"credential_configuration_id":"pid-alias","credential_identifiers":["alias"]},{"credential_configuration_id":"other-config","credential_identifiers":["other"]}]}"#
        let transport = Draft13WorkspaceTransport(tokenResponse: response)
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "exact")
    }

    @Test("Draft issuance rejects multiple aliases when no exact authorization exists")
    func draftAmbiguousConfigurationAliases() async throws {
        let response = #"{"access_token":"access-token","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"pid-alias","credential_identifiers":["alias-one"]},{"credential_configuration_id":"pid-alias-two","credential_identifiers":["alias-two"]}]}"#
        try await assertRejectedDraftToken(
            response,
            expected: .credentialAuthorizationMismatch(
                offered: "pid-config",
                authorized: ["pid-alias", "alias-one", "pid-alias-two", "alias-two"]
            )
        )
    }

    @Test("Draft issuance rejects explicitly empty authorization details")
    func draftEmptyAuthorizationDetails() async throws {
        let response = #"{"access_token":"access-token","c_nonce":"credential-nonce","authorization_details":[]}"#
        try await assertRejectedDraftToken(response, expected: .missingCredentialAuthorization)
    }

    @Test("Draft issuance falls back to offered identifier only when authorization details are absent")
    func draftAbsentAuthorizationDetailsFallback() async throws {
        let response = #"{"access_token":"access-token","c_nonce":"credential-nonce"}"#
        let transport = Draft13WorkspaceTransport(tokenResponse: response)
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "pid-config")
    }

    @Test("Attestation-only draft fails before token request when attestation is unavailable")
    func unavailableClientAttestation() async throws {
        let transport = Draft13WorkspaceTransport(allowsAnonymousAuthentication: false)
        let security = RecordingOID4VCIClientSecurity(attestationHeaders: [:])
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: security,
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: WorkspaceBackendError.clientSecurityUnavailable) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
        #expect(!(await transport.requests).contains { $0.url.path.hasSuffix("/token") })
    }

    @Test("Unsupported required token authentication fails before token request")
    func unsupportedTokenAuthentication() async throws {
        let transport = Draft13WorkspaceTransport(
            allowsAnonymousAuthentication: false,
            supportsES256Attestation: false
        )
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: WorkspaceBackendError.clientSecurityUnavailable) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
        #expect(!(await transport.requests).contains { $0.url.path.hasSuffix("/token") })
    }

    @Test("Pre-authorized offer requires warning, signs proof, validates and stores credential")
    func preauthorizedIssuance() async throws {
        let transport = FixtureWorkspaceTransport()
        let keys = FixtureKeyProvider()
        let store = FixtureCredentialStore()
        let validator = FixtureCredentialValidator()
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: UntrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: store,
            credentialValidator: validator,
            profile: try .oariVcdm2Jwt(),
            now: { Date(timeIntervalSince1970: 1_800_000_000) }
        )
        let offerJSON = """
        {"credential_issuer":"https://issuer.example","credential_configuration_ids":["oari-v2"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}
        """
        let encoded = offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer=\(encoded)"
        )
        guard case .requireExplicitWarning = offer.trustOutcome else {
            Issue.record("Expected development warning")
            return
        }
        await #expect(throws: WorkspaceBackendError.invalidTransactionCode) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: true, transactionCode: "12ab56")
        }

        let second = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer=\(encoded)"
        )
        let issued = try await backend.issue(
            id: second.id,
            allowUntrusted: true,
            transactionCode: "123456"
        )
        #expect(issued.count == 1)
        #expect(issued.first?.configurationID == "oari-v2")
        #expect(issued.first?.displayName == "OARI Legal Person ID")
        #expect(issued.first?.display?.backgroundColor == "#003366")
        #expect(issued.first?.display?.textColor == "#ffffff")
        #expect(issued.first?.display?.logo?.alternativeText == "OARI mark")
        #expect(issued.first?.display?.logo?.data == FixtureWorkspaceTransport.png)
        #expect(issued.first?.display?.backgroundImage?.data == FixtureWorkspaceTransport.png)
        #expect(try await store.credentials().count == 1)
        #expect(await validator.calls == 1)
        let requests = await transport.requests
        #expect(requests.contains { $0.url.path == "/token" && String(decoding: $0.body ?? Data(), as: UTF8.self).contains("tx_code=123456") })
        #expect(requests.contains { $0.url.path == "/credential" && String(decoding: $0.body ?? Data(), as: UTF8.self).contains("proofs") })
    }

    @Test("Referenced offer and cancellation are bounded")
    func referencedAndCancel() async throws {
        let backend = OariWorkspaceW3CBackend(
            transport: FixtureWorkspaceTransport(),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .oariVcdm2Jwt()
        )
        let offer = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer"
        )
        await backend.cancel(id: offer.id)
        await #expect(throws: WorkspaceBackendError.unknownTransaction) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "123456")
        }
    }

    @Test("Authorization-code offer completes final PID presentation challenge")
    func authorizationPresentation() async throws {
        let backend = OariWorkspaceW3CBackend(
            transport: FixtureWorkspaceTransport(),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .oariVcdm2Jwt()
        )
        let json = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["oari-v2"],"grants":{"authorization_code":{"issuer_state":"issuer-state"}}}"#
        let encoded = json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        #expect(offer.authorizationRequired)
        let challenge = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false
        )
        #expect(challenge.responseMode == "ia_post")
        #expect(challenge.dcqlQuery["credentials"] != nil)
        #expect(try await backend.submitPresentation(id: offer.id, vpToken: "valid.pid.vp") == "auth-code")
        #expect(try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: nil).count == 1)
    }

    private static func jwtPayload(_ compact: String) throws -> [String: Any] {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw WorkspaceBackendError.invalidResponse }
        var base64 = String(parts[1]).replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        let data = try #require(Data(base64Encoded: base64))
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func assertRejectedDraftToken(
        _ tokenResponse: String,
        expected: WorkspaceBackendError
    ) async throws {
        let transport = Draft13WorkspaceTransport(tokenResponse: tokenResponse)
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            clientSecurity: RecordingOID4VCIClientSecurity(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await backend.resolveOffer(try Self.draftOffer())
        await #expect(throws: expected) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        }
        #expect(!(await transport.requests).contains { $0.url.path.hasSuffix("/credential") })
    }

    private static func draftOffer() throws -> String {
        let json = #"{"credential_issuer":"https://issuer.example/service/draft-13","credential_configuration_ids":["pid-config"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":4}}}}"#
        let encoded = try #require(json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        return "openid-credential-offer://?credential_offer=\(encoded)"
    }
}

private actor FixtureWorkspaceTransport: WorkspaceHTTPTransport {
    static let png = Data([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        0x00, 0x00, 0x00, 0x00,
    ])
    struct Request: Sendable { let url: URL; let method: String; let headers: [String: String]; let body: Data? }
    private(set) var requests: [Request] = []
    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> WorkspaceHTTPResponse {
        requests.append(Request(url: url, method: method, headers: headers, body: body))
        let response: String
        switch url.path {
        case "/offer":
            response = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["oari-v2"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}"#
        case "/.well-known/openid-credential-issuer":
            response = ##"{"credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example"],"credential_configurations_supported":{"oari-v2":{"format":"application/vc+jwt","display":[{"name":"OARI Legal Person ID","locale":"en","description":"Legal person credential","background_color":"#003366","text_color":"#ffffff","logo":{"uri":"https://assets.example/logo.png","alt_text":"OARI mark"},"background_image":{"uri":"https://assets.example/background.png"}}]}}}"##
        case "/.well-known/oauth-authorization-server":
            response = #"{"token_endpoint":"https://issuer.example/token"}"#
        case "/token":
            response = #"{"access_token":"access","c_nonce":"nonce-1"}"#
        case "/authorize-challenge", "/authorize":
            if String(decoding: body ?? Data(), as: UTF8.self).contains("issuer_state") {
                return WorkspaceHTTPResponse(statusCode: 403, body: Data(#"{"error":"insufficient_authorization","interaction_type_required":"urn:openid:dcp:ia:openid4vp_presentation","auth_session":"auth-session","openid4vp_request":{"response_type":"vp_token","response_mode":"ia_post","nonce":"vp-nonce","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}}}"#.utf8))
            }
            response = #"{"authorization_code":"auth-code","code":"auth-code"}"#
        case "/credential":
            response = #"{"credentials":[{"credential":"header.payload.signature"}]}"#
        case "/logo.png", "/background.png":
            return WorkspaceHTTPResponse(
                statusCode: 200,
                body: Self.png,
                headers: ["Content-Type": "image/png"]
            )
        default: throw WorkspaceBackendError.invalidResponse
        }
        return WorkspaceHTTPResponse(statusCode: 200, body: Data(response.utf8))
    }
}

private actor Draft13WorkspaceTransport: WorkspaceHTTPTransport {
    struct Request: Sendable {
        let url: URL
        let method: String
        let headers: [String: String]
        let body: Data?
    }
    private(set) var requests: [Request] = []
    private let tokenResponse: String
    private let allowsAnonymousAuthentication: Bool
    private let supportsES256Attestation: Bool

    init(
        tokenResponse: String = #"{"access_token":"access-token","token_type":"bearer","c_nonce":"credential-nonce","authorization_details":[{"type":"openid_credential","credential_configuration_id":"pid-config","credential_identifiers":["authorized-pid"]}]}"#,
        allowsAnonymousAuthentication: Bool = true,
        supportsES256Attestation: Bool = true
    ) {
        self.tokenResponse = tokenResponse
        self.allowsAnonymousAuthentication = allowsAnonymousAuthentication
        self.supportsES256Attestation = supportsES256Attestation
    }

    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> WorkspaceHTTPResponse {
        requests.append(Request(url: url, method: method, headers: headers, body: body))
        let response: String
        let statusCode: Int
        if url.path.hasSuffix("/.well-known/openid-credential-issuer") {
            response = #"{"credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example/service/draft-13"],"credential_configurations_supported":{"pid-config":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"pid-alias":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"pid-alias-two":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"other-config":{"format":"dc+sd-jwt","vct":"urn:example:legal-person"}},"notification_endpoint":"https://issuer.example/notification"}"#
            statusCode = 200
        } else if url.path.hasSuffix("/.well-known/oauth-authorization-server") {
            let methods = allowsAnonymousAuthentication
                ? #"["attest_jwt_client_auth","none"]"#
                : #"["attest_jwt_client_auth"]"#
            let algorithms = supportsES256Attestation ? #"["ES256"]"# : #"["ES384"]"#
            response = """
            {"token_endpoint":"https://issuer.example/token","token_endpoint_auth_methods_supported":\(methods),"client_attestation_signing_alg_values_supported":\(algorithms),"dpop_signing_alg_values_supported":["ES256"]}
            """
            statusCode = 200
        } else if url.path.hasSuffix("/token") {
            response = tokenResponse
            statusCode = 200
        } else if url.path.hasSuffix("/credential") {
            response = #"{"credentials":[{"credential":"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnRlc3QifQ.signature~"}],"notification_id":"notification-id"}"#
            statusCode = 200
        } else if url.path.hasSuffix("/notification") {
            response = ""
            statusCode = 204
        } else {
            throw WorkspaceBackendError.invalidResponse
        }
        return WorkspaceHTTPResponse(statusCode: statusCode, body: Data(response.utf8))
    }
}

private actor RecordingOID4VCIClientSecurity: OID4VCIClientSecurity {
    private(set) var dpopAccessTokens: [String?] = []
    private(set) var decryptionCalls = 0
    private let attestationHeaders: [String: String]

    init(attestationHeaders: [String: String] = ["test-attestation": "available"]) {
        self.attestationHeaders = attestationHeaders
    }

    func state(for profile: OID4VCITransportProfile) async throws -> OID4VCIClientSecurityState {
        OID4VCIClientSecurityState(
            dpopKeyID: KeyID(),
            clientAttestationKeyID: nil,
            responseEncryptionKeyID: KeyID()
        )
    }

    func dpopHeader(
        state: OID4VCIClientSecurityState,
        method: String,
        targetURI: URL,
        accessToken: String?
    ) async throws -> String {
        dpopAccessTokens.append(accessToken)
        return accessToken == nil ? "dpop-token" : "dpop-access-token"
    }

    func clientAttestationHeaders(
        state: OID4VCIClientSecurityState,
        audience: URL
    ) async throws -> [String: String] {
        attestationHeaders
    }

    func responseEncryption(
        state: OID4VCIClientSecurityState
    ) async throws -> OID4VCIResponseEncryptionParameters {
        OID4VCIResponseEncryptionParameters(
            publicJWK: #"{"alg":"ECDH-ES","crv":"P-256","enc":"A128CBC-HS256","kty":"EC","use":"enc","x":"x","y":"y"}"#
        )
    }

    func decryptCredentialResponse(
        state: OID4VCIClientSecurityState,
        compactJWE: Data
    ) async throws -> Data {
        decryptionCalls += 1
        return compactJWE
    }
}

private struct UntrustedIssuerEvaluator: WorkspaceIssuerTrustEvaluating {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        .untrusted(reasons: [.issuerNotAccredited], evidence: [])
    }
}

private struct TrustedIssuerEvaluator: WorkspaceIssuerTrustEvaluating {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict { .trusted(evidence: []) }
}

private actor FixtureCredentialStore: EbsiCredentialStore {
    private var values: [StoredEbsiCredential] = []
    func credentials() async throws -> [StoredEbsiCredential] { values }
    func save(_ credential: StoredEbsiCredential) async throws { values.append(credential) }
    func delete(id: UUID) async throws { values.removeAll { $0.id == id } }
}

private actor FixtureCredentialValidator: WorkspaceCredentialValidating {
    private(set) var calls = 0
    func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedHolderDID: String,
        at date: Date
    ) async throws {
        calls += 1
        #expect(!expectedHolderDID.isEmpty)
    }
}

private actor FixtureKeyProvider: KeyProvider {
    private let key = P256.Signing.PrivateKey()
    private let id = KeyID()
    func createKey(
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
        requiresUserPresence: Bool,
        protection: KeyProtectionPolicy
    ) async throws -> KeyRecord {
        KeyRecord(
            id: id,
            purpose: purpose,
            algorithm: algorithm,
            assurance: .keychainSoftware,
            applicationTag: "fixture",
            createdAt: Date()
        )
    }
    func sign(_ request: SigningRequest) async throws -> Data {
        try key.signature(for: request.payload).rawRepresentation
    }
    func publicKey(id: KeyID) async throws -> PublicKeyMaterial {
        PublicKeyMaterial(algorithm: .es256, x963Representation: key.publicKey.x963Representation)
    }
    func deleteKey(id: KeyID) async throws {}
}
