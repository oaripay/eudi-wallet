import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing
import TrustDomain
import WalletDomain

struct OariWorkspaceW3CBackendTests {
    @Test("Draft 17 QESAC uses token identifier, proofs, DPoP and response encryption")
    func draft17QESACRequest() async throws {
        let transport = Draft13WorkspaceTransport()
        let security = RecordingOID4VCIClientSecurity()
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
        let json = #"{"credential_issuer":"https://issuer.example/service/draft-17","credential_configuration_ids":["pid-config"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code"}}}"#
        let encoded = try #require(json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: nil)

        let requests = await transport.requests
        let credential = try #require(requests.first { $0.url.path.hasSuffix("/credential") })
        let body = try #require(JSONSerialization.jsonObject(with: credential.body ?? Data()) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "authorized-pid")
        #expect(body["credential_configuration_id"] == nil)
        #expect(body["format"] == nil)
        #expect(body["proof"] == nil)
        #expect((body["proofs"] as? [String: Any])?["jwt"] != nil)
        #expect(body["credential_response_encryption"] != nil)
        #expect(credential.headers["Authorization"] == "DPoP access-token")
        #expect(credential.headers["DPoP"] != nil)
    }

    @Test("Draft issuance uses DPoP, identifier-only request and encrypted response", arguments: ["draft-13", "draft-18"])
    func draftIssuance(revision: String) async throws {
        let usesLegacyDiscovery = revision == "draft-18"
        let transport = Draft13WorkspaceTransport(legacyWellKnownOnly: usesLegacyDiscovery)
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
        #expect(issued.first?.profileID == "ietf-dc-sd-jwt-vc")
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
        #expect(await security.decryptionCalls == 0)
        let issuerMetadataPath = usesLegacyDiscovery
            ? "/service/\(revision)/.well-known/openid-credential-issuer"
            : "/.well-known/openid-credential-issuer/service/\(revision)"
        let authorizationMetadataPath = usesLegacyDiscovery
            ? "/service/draft-13/.well-known/oauth-authorization-server"
            : "/.well-known/oauth-authorization-server/service/draft-13"
        #expect(requests.contains { $0.url.path == issuerMetadataPath })
        #expect(requests.contains { $0.url.path == authorizationMetadataPath })
        #expect(requests.contains { $0.url.path.hasSuffix("/notification") && $0.method == "POST" })
    }

    @Test("Draft issuance signs a proof without nonce when token omits c_nonce")
    func draftMissingNonce() async throws {
        let response = #"{"access_token":"access-token","authorization_details":[{"credential_configuration_id":"pid-config","credential_identifiers":["authorized-pid"]}]}"#
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
        #expect(try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234").count == 1)
        let request = try #require((await transport.requests).first { $0.url.path.hasSuffix("/credential") })
        let requestBody = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: requestBody) as? [String: Any])
        let proof = try #require(body["proof"] as? [String: Any])
        let payload = try Self.jwtPayload(try #require(proof["jwt"] as? String))
        #expect(payload["nonce"] == nil)
    }

    @Test("Draft issuance reports the stage and coding path for malformed token JSON")
    func draftMalformedTokenValue() async throws {
        let response = #"{"access_token":"access-token","c_nonce":123}"#
        try await assertRejectedDraftToken(
            response,
            expected: .decodingFailed(
                stage: "token response",
                path: "$.c_nonce",
                reason: "expected String"
            )
        )
    }

    @Test("Draft issuance accepts one token-authorized identifier despite configuration mismatch")
    func draftMismatchedAuthorization() async throws {
        let response = #"{"access_token":"access-token","c_nonce":"credential-nonce","authorization_details":[{"credential_configuration_id":"other-config","credential_identifiers":["unauthorized-pid","authorized-fallback"]}]}"#
        let transport = Draft13WorkspaceTransport(
            tokenResponse: response,
            rejectedCredentialIdentifier: "unauthorized-pid"
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
        _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "1234")
        let credentialRequests = (await transport.requests).filter { $0.url.path.hasSuffix("/credential") }
        let request = try #require(credentialRequests.last)
        let data = try #require(request.body)
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "authorized-fallback")
        #expect(credentialRequests.count == 2)
        let firstData = try #require(credentialRequests.first?.body)
        let firstBody = try #require(JSONSerialization.jsonObject(with: firstData) as? [String: Any])
        let firstProof = try #require(firstBody["proof"] as? [String: Any])
        let lastProof = try #require(body["proof"] as? [String: Any])
        #expect(firstProof["jwt"] as? String == lastProof["jwt"] as? String)
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

    @Test("VCDM2 credential context overrides a legacy jwt_vc_json metadata label")
    func vcdm2ContextSelection() async throws {
        let credential = try Self.compactJWT(payload: [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "LegalPersonIdentificationData"],
            "issuer": "did:key:issuer",
            "credentialSubject": ["id": "did:key:holder"],
        ])
        let backend = OariWorkspaceW3CBackend(
            transport: FixtureWorkspaceTransport(
                credentialFormat: "jwt_vc_json",
                credentialResponse: credential
            ),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .oariVcdm2Jwt(),
            additionalProfiles: [try .vcdm11Jwt()]
        )
        let offer = try await backend.resolveOffer("https://issuer.example/offer")
        let issued = try await backend.issue(
            id: offer.id,
            allowUntrusted: false,
            transactionCode: "123456"
        )
        #expect(issued.first?.profileID == "oari-ebsi-vcdm2-vc-jwt")
        #expect(issued.first?.representation == .vcdm2Jwt)
    }

    @Test("Credential metadata paths normalize wildcard and array index components")
    func credentialMetadataPathComponents() throws {
        let claim = try JSONDecoder().decode(
            WorkspaceCredentialClaim.self,
            from: Data(#"{"path":["credentialSubject","items",null,2,"name"],"name":"Item name"}"#.utf8)
        )
        #expect(claim.path == ["credentialSubject", "items", "*", "[2]", "name"])
        #expect(claim.id == "credentialSubject.items.*.[2].name")
    }

    @Test("Complete issuer metadata tolerates unrelated Portable Document wildcard paths")
    func portableDocumentWildcardMetadata() async throws {
        let backend = OariWorkspaceW3CBackend(
            transport: WildcardIssuerMetadataTransport(),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC()
        )
        let offerJSON = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["selected"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code"}}}"#
        let encoded = try #require(offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        #expect(offer.configurationIDs == ["selected"])
        #expect(offer.representations == ["dc+sd-jwt"])
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
        let transport = FixtureWorkspaceTransport()
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
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
        let initial = try #require((await transport.requests).first { request in
            request.url.path == "/authorize-challenge" &&
                String(decoding: request.body ?? Data(), as: UTF8.self).contains("issuer_state=")
        })
        let initialBody = String(decoding: try #require(initial.body), as: UTF8.self)
        let initialFields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(initialBody)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        #expect(initialFields["interaction_types_supported"] == "urn:openid:dcp:ia:openid4vp_presentation")
        #expect(initialFields["client_id"] == "oari-development-wallet")
        #expect(initialFields["redirect_uri"] == "https://oari.io/oauth/callback")
        #expect(try await backend.submitPresentation(
            id: offer.id,
            vpToken: #"{"pid":["valid.pid.vp"]}"#
        ) == "auth-code")
        let post = try #require((await transport.requests).last { request in
            request.url.path == "/authorize-challenge" &&
                String(decoding: request.body ?? Data(), as: UTF8.self).contains("openid4vp_response=")
        })
        let formBody = String(decoding: try #require(post.body), as: UTF8.self)
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(formBody)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        let wrapped = try #require(fields["openid4vp_response"])
        let response = try #require(JSONSerialization.jsonObject(with: Data(wrapped.utf8)) as? [String: Any])
        let vpToken = try #require(response["vp_token"] as? [String: [String]])
        #expect(vpToken == ["pid": ["valid.pid.vp"]])
        #expect(response["state"] as? String == "vp-state")
        #expect(fields["auth_session"] == "auth-session")
        #expect(fields["vp_token"] == nil)
        #expect(fields["openid4vp_presentation"] == nil)
        #expect(Set(fields.keys) == ["auth_session", "openid4vp_response"])
        #expect(try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: nil).count == 1)
    }

    @Test("Authorization-code offer resolves signed draft PID presentation challenge")
    func authorizationDraftPresentation() async throws {
        let transport = FixtureWorkspaceTransport()
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .oariVcdm2Jwt()
        )
        let json = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["oari-v2"],"grants":{"authorization_code":{"issuer_state":"issuer-state"}}}"#
        let encoded = json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        let challenge = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false,
            interactionTypes: ["openid4vp_presentation"]
        )
        #expect(challenge.responseMode == "direct_post")
        #expect(challenge.responseURI == URL(string: "https://issuer.example/authorize"))
        #expect(challenge.signedRequest != nil)
        #expect(challenge.dcqlQuery["credentials"] != nil)
        _ = try await backend.submitPresentation(
            id: offer.id,
            vpToken: #"{"pid":["presentation"]}"#
        )
        let post = try #require((await transport.requests).last { request in
            request.url.path == "/authorize" &&
                String(decoding: request.body ?? Data(), as: UTF8.self).contains("vp_token=")
        })
        let body = String(decoding: try #require(post.body), as: UTF8.self)
        #expect(body.contains("vp_token="))
        #expect(!body.contains("openid4vp_response="))
        #expect(!body.contains("auth_session="))
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(body)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        #expect(fields == [
            "state": "auth-session",
            "vp_token": #"{"pid":["presentation"]}"#,
        ])
    }

    @Test("IAR compact signed request exposes iGrant DCQL challenge fields")
    func iGrantCompactChallenge() async throws {
        let transport = FixtureWorkspaceTransport(iGrantCompactPresentation: true)
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let offer = try await Self.authorizationOffer(backend)
        let challenge = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false,
            interactionTypes: ["openid4vp_presentation"]
        )
        #expect(challenge.responseMode == "iar-post")
        #expect(challenge.responseURI?.path == "/service/iar")
        #expect(challenge.clientID?.hasPrefix("redirect_uri:") == true)
        #expect(challenge.dcqlQuery["credentials"] != nil)
    }

    @Test("Draft authorization uses published GET endpoint and never guesses IAR")
    func draftAuthorizationEndpoint() async throws {
        let transport = DraftIARFallbackTransport()
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC(),
            transportProfileRegistry: .developmentDraftCompatibility
        )
        let json = #"{"credential_issuer":"https://issuer.example/service/draft-13","credential_configuration_ids":["pid"],"grants":{"authorization_code":{"issuer_state":"issuer-state"}}}"#
        let encoded = json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
        let challenge = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false,
            interactionTypes: ["openid4vp_presentation"]
        )
        #expect(challenge.authorizationEndpoint.path == "/service/draft-13/authorize")
        #expect(challenge.responseMode == "iar-post")
        let requests = await transport.requests
        let authorization = try #require(requests.first { $0.url.path == "/service/draft-13/authorize" })
        #expect(authorization.method == "GET")
        let query = URLComponents(url: authorization.url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        #expect(query.contains { $0.name == "response_type" && $0.value == "code" })
        #expect(query.contains { $0.name == "code_challenge" && !($0.value ?? "").isEmpty })
        #expect(query.contains { $0.name == "authorization_details" })
        #expect(!requests.contains { $0.url.path == "/service/iar" })
    }

    @Test("Stored W3C SD-JWT PID creates a selective DCQL key-bound presentation")
    func storedSDJWTPresentation() async throws {
        let transport = FixtureWorkspaceTransport()
        let keys = FixtureKeyProvider()
        let key = try await keys.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: false,
            protection: .keychainSoftware
        )
        let disclosures = try [
            Self.disclosure(name: "given_name", value: "Ada"),
            Self.disclosure(name: "family_name", value: "Lovelace"),
            Self.disclosure(name: "email", value: "ada@example.test"),
        ]
        let issuer = try Self.compactJWT(payload: [
            "iss": "did:key:issuer",
            "vct": "urn:eu.europa.ec.eudi:pid:1",
            "cnf": ["jwk": ["kty": "EC"]],
            "_sd": disclosures.map {
                Data(SHA256.hash(data: Data($0.utf8))).base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
            },
        ])
        let stored = StoredEbsiCredential(
            profileID: "ietf-dc-sd-jwt-vc",
            representation: .dcSdJwt,
            rawCredential: Data((issuer + "~" + disclosures.joined(separator: "~") + "~").utf8),
            holderKeyReference: key.id.rawValue.uuidString
        )
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: FixtureCredentialStore(values: [stored]),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .dcSdJWTVC()
        )
        let offer = try await Self.authorizationOffer(backend)
        _ = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false,
            interactionTypes: ["urn:openid:dcp:ia:openid4vp_presentation"]
        )
        let request = try await backend.prepareStoredPIDPresentation(id: offer.id)
        #expect(request.claims.count == 3)
        let token = try await backend.storedPIDPresentationToken(
            id: offer.id,
            selectedClaimIDs: Set(request.claims.map(\.id))
        )
        let object = try #require(JSONSerialization.jsonObject(with: Data(token.utf8)) as? [String: [String]])
        let presentation = try #require(object["pid"]?.first)
        let components = presentation.split(separator: "~", omittingEmptySubsequences: false)
        #expect(components.count == 5)
        let keyBinding = String(components[4])
        let keyBindingPayload = try Self.jwtPayload(keyBinding)
        #expect(keyBindingPayload["nonce"] as? String == "vp-nonce")
        #expect(keyBindingPayload["aud"] as? String == "ia:https://issuer.example")
        let withoutKeyBinding = components.dropLast().joined(separator: "~") + "~"
        let expectedHash = Data(SHA256.hash(data: Data(withoutKeyBinding.utf8))).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        #expect(keyBindingPayload["sd_hash"] as? String == expectedHash)
        _ = try await backend.submitPresentation(id: offer.id, vpToken: token)
        let post = try #require((await transport.requests).last { request in
            String(decoding: request.body ?? Data(), as: UTF8.self).contains("openid4vp_response=")
        })
        let form = String(decoding: try #require(post.body), as: UTF8.self)
        let fields = Dictionary(uniqueKeysWithValues: try #require(
            URLComponents(string: "?\(form)")?.queryItems
        ).compactMap { item in item.value.map { (item.name, $0) } })
        let wrapped = try #require(fields["openid4vp_response"])
        let response = try #require(JSONSerialization.jsonObject(with: Data(wrapped.utf8)) as? [String: Any])
        let vpToken = try #require(response["vp_token"] as? [String: [String]])
        #expect(vpToken["pid"]?.first == presentation)
    }

    @Test("Stored jwt_vc_json credential creates a holder-signed JWT VP")
    func storedJWTVCPresentation() async throws {
        let keys = FixtureKeyProvider()
        let key = try await keys.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: false,
            protection: .keychainSoftware
        )
        let holder = try KeyDIDResolver().derive(
            publicKeyX963: try await keys.publicKey(id: key.id).x963Representation
        )
        let credential = try Self.compactJWT(payload: [
            "iss": "did:key:issuer",
            "sub": holder,
            "vc": [
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "PersonIdentificationData"],
                "issuer": "did:key:issuer",
                "credentialSubject": [
                    "id": holder,
                    "given_name": "Ada",
                    "family_name": "Lovelace",
                ],
            ],
        ])
        let stored = StoredEbsiCredential(
            profileID: "ebsi-vcdm11-jwt-vc",
            representation: .jwtVcJson,
            rawCredential: Data(credential.utf8),
            holderKeyReference: key.id.rawValue.uuidString
        )
        let backend = OariWorkspaceW3CBackend(
            transport: FixtureWorkspaceTransport(presentationFormat: "jwt_vc_json"),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: FixtureCredentialStore(values: [stored]),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .vcdm11Jwt()
        )
        let offer = try await Self.authorizationOffer(backend)
        _ = try await backend.beginPresentationRequired(
            id: offer.id,
            allowUntrusted: false
        )
        let request = try await backend.prepareStoredPIDPresentation(id: offer.id)
        let token = try await backend.storedPIDPresentationToken(
            id: offer.id,
            selectedClaimIDs: Set(request.claims.map(\.id))
        )
        let object = try #require(JSONSerialization.jsonObject(with: Data(token.utf8)) as? [String: [String]])
        let vpJWT = try #require(object["pid"]?.first)
        let payload = try Self.jwtPayload(vpJWT)
        #expect(payload["nonce"] as? String == "vp-nonce")
        #expect(payload["aud"] as? String == "ia:https://issuer.example/authorize-challenge")
        let vp = try #require(payload["vp"] as? [String: Any])
        #expect(vp["@context"] as? [String] == ["https://www.w3.org/2018/credentials/v1"])
        let presentedCredentials = try #require(vp["verifiableCredential"] as? [String])
        #expect(presentedCredentials == [credential])
    }

    @Test("Stored W3C credential deletion is idempotent")
    func storedCredentialDeletion() async throws {
        let credential = StoredEbsiCredential(
            profileID: "oari-ebsi-vcdm2-vc-jwt",
            representation: .vcdm2Jwt,
            rawCredential: Data("credential".utf8),
            holderKeyReference: UUID().uuidString
        )
        let store = FixtureCredentialStore(values: [credential])
        let backend = OariWorkspaceW3CBackend(
            transport: FixtureWorkspaceTransport(),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: store,
            credentialValidator: FixtureCredentialValidator(),
            profile: try .oariVcdm2Jwt()
        )
        try await backend.deleteStoredCredential(id: credential.id)
        try await backend.deleteStoredCredential(id: credential.id)
        #expect(try await store.credentials().isEmpty)
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

    private static func authorizationOffer(
        _ backend: OariWorkspaceW3CBackend
    ) async throws -> WorkspaceResolvedOffer {
        let json = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["oari-v2"],"grants":{"authorization_code":{"issuer_state":"issuer-state"}}}"#
        let encoded = try #require(json.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed))
        return try await backend.resolveOffer("openid-credential-offer://?credential_offer=\(encoded)")
    }

    private static func compactJWT(payload: [String: Any]) throws -> String {
        func encode(_ object: Any) throws -> String {
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
                .base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        return try "\(encode(["alg": "ES256"])).\(encode(payload)).signature"
    }

    private static func disclosure(name: String, value: String) throws -> String {
        try JSONSerialization.data(withJSONObject: [UUID().uuidString, name, value])
            .base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
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

    @Test("Manual live QESAC redemption emits only redacted interoperability diagnostics")
    func manualLiveQESACRedemption() async throws {
        guard let offerURI = ProcessInfo.processInfo.environment["OARI_LIVE_QESAC_OFFER"] else {
            return
        }
        let transport = URLSessionWorkspaceTransport()
        let keyProvider = FixtureKeyProvider()
        let store = FixtureCredentialStore()
        let validator = LiveDiagnosticCredentialValidator(
            validator: NativeWorkspaceCredentialValidator(
                resolver: LiveRejectingDIDResolver(),
                transport: transport
            )
        )
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: keyProvider,
            credentialStore: store,
            credentialValidator: validator,
            profile: try .oariVcdm2Jwt(),
            additionalProfiles: [try .vcdm11Jwt(), try .dcSdJWTVC(), try .vcdm2SdJWT()],
            clientSecurity: DefaultOID4VCIClientSecurity(keyProvider: keyProvider),
            transportProfileRegistry: .developmentDraftCompatibility
        )

        let offer = try await backend.resolveOffer(offerURI)
        let issued = try await backend.issue(
            id: offer.id,
            allowUntrusted: false,
            transactionCode: nil
        )
        #expect(issued.count == 1)
        #expect(try await store.credentials().count == 1)
        print("LIVE_QESAC stored=true format=dc+sd-jwt configuration_count=\(offer.configurationIDs.count)")
    }
}

private struct LiveRejectingDIDResolver: DIDResolver {
    func resolve(_ did: String) async throws -> DIDDocument {
        throw DIDResolutionError.unsupportedMethod
    }
}

private struct LiveDiagnosticCredentialValidator: WorkspaceCredentialValidating {
    let validator: NativeWorkspaceCredentialValidator

    func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedIssuer: String,
        expectedHolderDID: String,
        at date: Date
    ) async throws -> String {
        let compact = String(decoding: rawCredential, as: UTF8.self)
        let issuerJWS = compact.split(separator: "~", maxSplits: 1).first.map(String.init) ?? ""
        let parts = issuerJWS.split(separator: ".", omittingEmptySubsequences: false)
        var headerNames: [String] = []
        var kidKind = "absent"
        var certificateCount = 0
        var signatureBytes = 0
        if parts.count == 3,
           let headerData = Self.base64URLData(String(parts[0])),
           let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] {
            headerNames = header.keys.sorted()
            if let kid = header["kid"] as? String {
                kidKind = kid == "None" ? "sentinel" : "present"
            }
            certificateCount = (header["x5c"] as? [String])?.count ?? 0
            signatureBytes = Self.base64URLData(String(parts[2]))?.count ?? 0
        }
        print(
            "LIVE_QESAC protected_header_keys=\(headerNames.joined(separator: ",")) " +
            "kid=\(kidKind) x5c_count=\(certificateCount) signature_bytes=\(signatureBytes)"
        )
        return try await validator.validate(
            rawCredential: rawCredential,
            profile: profile,
            expectedIssuer: expectedIssuer,
            expectedHolderDID: expectedHolderDID,
            at: date
        )
    }

    private static func base64URLData(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }
}

private actor WildcardIssuerMetadataTransport: WorkspaceHTTPTransport {
    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> WorkspaceHTTPResponse {
        guard url.path == "/.well-known/openid-credential-issuer" else {
            return WorkspaceHTTPResponse(statusCode: 404, body: Data())
        }
        return WorkspaceHTTPResponse(statusCode: 200, body: Data(#"""
        {
          "credential_endpoint":"https://issuer.example/credential",
          "credential_configurations_supported":{
            "selected":{
              "format":"dc+sd-jwt",
              "vct":"UniversityDegree",
              "credential_metadata":{"display":[{"name":"University Degree"}],"claims":[{"path":["degree","name"]}]}
            },
            "PortableDocumentA1bDEeedcj":{
              "format":"jwt_vc_json",
              "credential_metadata":{
                "display":[{"name":"Portable Document A1"}],
                "claims":[
                  {"path":["credentialSubject","section5","workPlaceAddresses",null,"address","countryCode"]},
                  {"path":["credentialSubject","items",0,"name"]}
                ]
              }
            }
          }
        }
        """#.utf8))
    }
}

private actor DraftIARFallbackTransport: WorkspaceHTTPTransport {
    struct Request: Sendable { let url: URL; let method: String; let body: Data? }
    private(set) var requests: [Request] = []

    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> WorkspaceHTTPResponse {
        requests.append(Request(url: url, method: method, body: body))
        switch url.path {
        case "/.well-known/openid-credential-issuer/service/draft-13":
            return WorkspaceHTTPResponse(statusCode: 200, body: Data(#"{"credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example/service/draft-13"],"credential_configurations_supported":{"pid":{"format":"dc+sd-jwt","vct":"urn:example:pid"}}}"#.utf8))
        case "/.well-known/oauth-authorization-server/service/draft-13":
            return WorkspaceHTTPResponse(statusCode: 200, body: Data(#"{"issuer":"https://issuer.example/service/draft-13","authorization_endpoint":"https://issuer.example/service/draft-13/authorize","token_endpoint":"https://issuer.example/token"}"#.utf8))
        case "/service/draft-13/authorize":
            guard method == "GET" else {
                return WorkspaceHTTPResponse(statusCode: 405, body: Data(#"{"detail":"method not allowed"}"#.utf8))
            }
            let payload = Self.base64URL(#"{"client_id":"redirect_uri:https://issuer.example/service/draft-13/authorize","response_type":"vp_token","response_mode":"iar-post","response_uri":"https://issuer.example/service/draft-13/authorize","nonce":"nonce","state":"state","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[{"path":["given_name"]}]}]}}"#)
            let response = """
            {"status":"require_interaction","type":"openid4vp_presentation","openid4vp_request":{"request":"header.\(payload).signature"}}
            """
            return WorkspaceHTTPResponse(statusCode: 200, body: Data(response.utf8))
        default:
            return WorkspaceHTTPResponse(statusCode: 404, body: Data())
        }
    }

    private static func base64URL(_ value: String) -> String {
        Data(value.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private actor FixtureWorkspaceTransport: WorkspaceHTTPTransport {
    static let png = Data([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        0x00, 0x00, 0x00, 0x00,
    ])
    struct Request: Sendable { let url: URL; let method: String; let headers: [String: String]; let body: Data? }
    private(set) var requests: [Request] = []
    private let presentationFormat: String
    private let credentialFormat: String
    private let credentialResponse: String
    private let iGrantCompactPresentation: Bool

    init(
        presentationFormat: String = "dc+sd-jwt",
        credentialFormat: String = "application/vc+jwt",
        credentialResponse: String = "header.payload.signature",
        iGrantCompactPresentation: Bool = false
    ) {
        self.presentationFormat = presentationFormat
        self.credentialFormat = credentialFormat
        self.credentialResponse = credentialResponse
        self.iGrantCompactPresentation = iGrantCompactPresentation
    }
    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> WorkspaceHTTPResponse {
        requests.append(Request(url: url, method: method, headers: headers, body: body))
        let response: String
        switch url.path {
        case "/offer":
            response = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["oari-v2"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}"#
        case "/.well-known/openid-credential-issuer":
            response = """
            {"credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example"],"credential_configurations_supported":{"oari-v2":{"format":"\(credentialFormat)","display":[{"name":"OARI Legal Person ID","locale":"en","description":"Legal person credential","background_color":"#003366","text_color":"#ffffff","logo":{"uri":"https://assets.example/logo.png","alt_text":"OARI mark"},"background_image":{"uri":"https://assets.example/background.png"}}]}}}
            """
        case "/.well-known/oauth-authorization-server":
            response = #"{"authorization_challenge_endpoint":"https://issuer.example/authorize-challenge","token_endpoint":"https://issuer.example/token"}"#
        case "/token":
            response = #"{"access_token":"access","c_nonce":"nonce-1"}"#
        case "/authorize-challenge", "/authorize":
            if String(decoding: body ?? Data(), as: UTF8.self).contains("issuer_state") {
                if url.path == "/authorize" {
                    if iGrantCompactPresentation {
                        return WorkspaceHTTPResponse(
                            statusCode: 200,
                            body: Data(#"{"status":"require_interaction","type":"openid4vp_presentation","openid4vp_request":{"request":"header.eyJjbGllbnRfaWQiOiJyZWRpcmVjdF91cmk6aHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS9zZXJ2aWNlL3ZlcnNpb24tMDEiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV9tb2RlIjoiaWFyLXBvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwczovL2lzc3Vlci5leGFtcGxlL3NlcnZpY2UvaWFyIiwibm9uY2UiOiJub25jZSIsInN0YXRlIjoic3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7ImNyZWRlbnRpYWxzIjpbeyJpZCI6IlByZXNlbnRhdGlvbiBEZWZpbml0aW9uIDEiLCJmb3JtYXQiOiJkYytzZC1qd3QifV19fQ.signature"}}"#.utf8)
                        )
                    }
                    return WorkspaceHTTPResponse(
                        statusCode: 200,
                        body: Data(#"{"status":"require_interaction","type":"openid4vp_presentation","auth_session":"auth-session","openid4vp_request":{"request":"PLACEHOLDER"}}"#.replacingOccurrences(of: "PLACEHOLDER", with: Self.signedPresentationRequest(format: presentationFormat)).utf8)
                    )
                }
                let query = Self.credentialQuery(format: presentationFormat)
                return WorkspaceHTTPResponse(
                    statusCode: 403,
                    body: Data("""
                    {"error":"insufficient_authorization","interaction_type_required":"urn:openid:dcp:ia:openid4vp_presentation","auth_session":"auth-session","openid4vp_request":{"response_type":"vp_token","response_mode":"ia_post","nonce":"vp-nonce","state":"vp-state","dcql_query":{"credentials":[\(query)]}}}
                    """.utf8)
                )
            }
            response = #"{"authorization_code":"auth-code","code":"auth-code"}"#
        case "/credential":
            response = """
            {"credentials":[{"credential":"\(credentialResponse)"}]}
            """
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

    private static func signedPresentationRequest(format: String) -> String {
        func encode(_ value: String) -> String {
            Data(value.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let header = encode(#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#)
        let query = credentialQuery(format: format)
        let payload = encode("""
        {"client_id":"redirect_uri:https://issuer.example/authorize","response_type":"vp_token","response_mode":"direct_post","response_uri":"https://issuer.example/authorize","nonce":"vp-nonce","state":"auth-session","dcql_query":{"credentials":[\(query)]}}
        """)
        return "\(header).\(payload).signature"
    }

    private static func credentialQuery(format: String) -> String {
        format == "jwt_vc_json"
            ? #"{"id":"pid","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential","PersonIdentificationData"]]},"claims":[{"path":["credentialSubject","given_name"]},{"path":["credentialSubject","family_name"]}]}"#
            : #"{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eu.europa.ec.eudi:pid:1"]},"claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["email"]}]}"#
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
    private let legacyWellKnownOnly: Bool
    private let rejectedCredentialIdentifier: String?

    init(
        tokenResponse: String = #"{"access_token":"access-token","token_type":"bearer","c_nonce":"credential-nonce","authorization_details":[{"type":"openid_credential","credential_configuration_id":"pid-config","credential_identifiers":["authorized-pid"]}]}"#,
        allowsAnonymousAuthentication: Bool = true,
        supportsES256Attestation: Bool = true,
        legacyWellKnownOnly: Bool = false,
        rejectedCredentialIdentifier: String? = nil
    ) {
        self.tokenResponse = tokenResponse
        self.allowsAnonymousAuthentication = allowsAnonymousAuthentication
        self.supportsES256Attestation = supportsES256Attestation
        self.legacyWellKnownOnly = legacyWellKnownOnly
        self.rejectedCredentialIdentifier = rejectedCredentialIdentifier
    }

    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> WorkspaceHTTPResponse {
        requests.append(Request(url: url, method: method, headers: headers, body: body))
        let response: String
        let statusCode: Int
        if url.path.contains("/.well-known/openid-credential-issuer") {
            let isLegacy = url.path.hasSuffix("/.well-known/openid-credential-issuer")
            if legacyWellKnownOnly != isLegacy {
                response = "Demo issuer landing page"
                statusCode = 200
            } else {
                response = #"{"credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example/service/draft-13"],"credential_configurations_supported":{"pid-config":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"pid-alias":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"pid-alias-two":{"format":"dc+sd-jwt","vct":"urn:example:pid"},"other-config":{"format":"dc+sd-jwt","vct":"urn:example:legal-person"}},"notification_endpoint":"https://issuer.example/notification"}"#
                statusCode = 200
            }
        } else if url.path.contains("/.well-known/oauth-authorization-server") {
            let isLegacy = url.path.hasSuffix("/.well-known/oauth-authorization-server")
            if legacyWellKnownOnly != isLegacy {
                response = "Demo issuer landing page"
                statusCode = 200
            } else {
                let methods = allowsAnonymousAuthentication
                    ? #"["attest_jwt_client_auth","none"]"#
                    : #"["attest_jwt_client_auth"]"#
                let algorithms = supportsES256Attestation ? #"["ES256"]"# : #"["ES384"]"#
                response = """
                {"token_endpoint":"https://issuer.example/token","token_endpoint_auth_methods_supported":\(methods),"client_attestation_signing_alg_values_supported":\(algorithms),"dpop_signing_alg_values_supported":["ES256"]}
                """
                statusCode = 200
            }
        } else if url.path.hasSuffix("/token") {
            response = tokenResponse
            statusCode = 200
        } else if url.path.hasSuffix("/credential") {
            let bodyObject = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            if bodyObject?["credential_identifier"] as? String == rejectedCredentialIdentifier {
                response = #"{"error":"invalid_credential_request","error_detail":"identifier rejected"}"#
                statusCode = 400
            } else {
                response = #"{"credentials":[{"credential":"eyJhbGciOiJFUzI1NiJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiaXNzIjoiZGlkOmtleTppc3N1ZXIiLCJ2Y3QiOiJ1cm46ZXhhbXBsZTpwaWQifQ.signature~"}],"notification_id":"notification-id"}"#
                statusCode = 200
            }
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
    init(values: [StoredEbsiCredential] = []) { self.values = values }
    func credentials() async throws -> [StoredEbsiCredential] { values }
    func save(_ credential: StoredEbsiCredential) async throws { values.append(credential) }
    func delete(id: UUID) async throws { values.removeAll { $0.id == id } }
}

private actor FixtureCredentialValidator: WorkspaceCredentialValidating {
    private(set) var calls = 0
    func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedIssuer: String,
        expectedHolderDID: String,
        at date: Date
    ) async throws -> String {
        calls += 1
        #expect(!expectedIssuer.isEmpty)
        #expect(!expectedHolderDID.isEmpty)
        return expectedIssuer
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
