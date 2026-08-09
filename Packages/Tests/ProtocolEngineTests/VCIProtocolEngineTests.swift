import Foundation
import CryptoKit
import ProfileDomain
import ProtocolEngine
import Testing

struct VCIProtocolEngineTests {
    @Test("Offer parser supports authorization-code and pre-authorized grants")
    func offerParsing() throws {
        let auth = Data("""
        {"credential_issuer":"https://issuer.example","credential_configuration_ids":["provisionalOariLPID"],"grants":{"authorization_code":{"authorization_server":"https://issuer.example"}}}
        """.utf8)
        guard case .authorizationCode = try CredentialOfferParser().parse(json: auth).grant else {
            Issue.record("Expected authorization grant")
            return
        }
        let pre = Data("""
        {"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"sensitive-code","tx_code":{}}}}
        """.utf8)
        guard case let .preAuthorizedCode(code, txCodeRequired) = try CredentialOfferParser().parse(json: pre).grant else {
            Issue.record("Expected pre-authorized grant")
            return
        }
        #expect(txCodeRequired)
        #expect(code == "sensitive-code")
    }

    @Test("Issuance validation rejects issuer and configuration mismatches")
    func issuanceValidation() throws {
        let issuer = URL(string: "https://issuer.example")!
        let offer = CredentialOffer(
            credentialIssuer: issuer,
            configurationIDs: ["pid"],
            grant: .preAuthorizedCode(code: "code", txCodeRequired: false)
        )
        let metadata = IssuerMetadata(
            issuer: issuer,
            authorizationEndpoint: nil,
            tokenEndpoint: issuer.appendingPathComponent("token"),
            credentialEndpoint: issuer.appendingPathComponent("credential"),
            deferredCredentialEndpoint: nil,
            supportedConfigurations: ["pid"]
        )
        let profile = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: Date())
        let request = try IssuanceValidator().validate(
            offer: offer,
            metadata: metadata,
            profile: profile,
            configurationID: "pid"
        )
        #expect(request.configurationID == "pid")

        #expect(throws: IssuanceError.unsupportedConfiguration) {
            try IssuanceValidator().validate(offer: offer, metadata: metadata, profile: profile, configurationID: "other")
        }
    }

    @Test("Pre-authorized grant requires its sensitive code")
    func missingPreAuthorizedCode() {
        let missing = Data("""
        {"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"tx_code":{}}}}
        """.utf8)
        #expect(throws: IssuanceError.missingField("pre-authorized_code")) {
            try CredentialOfferParser().parse(json: missing)
        }
    }

    @Test("Unsupported grant and malformed issuer are rejected")
    func malformedOffer() throws {
        let unsupported = Data("""
        {"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{"unknown":{}}}
        """.utf8)
        #expect(throws: IssuanceError.unsupportedGrant) {
            try CredentialOfferParser().parse(json: unsupported)
        }
        let http = Data("""
        {"credential_issuer":"http://issuer.example","credential_configuration_ids":["pid"],"grants":{"unknown":{}}}
        """.utf8)
        #expect(throws: IssuanceError.invalidURL) {
            try CredentialOfferParser().parse(json: http)
        }
        let opaque = Data("""
        {"credential_issuer":"https:issuer","credential_configuration_ids":["pid"],"grants":{"authorization_code":{"authorization_server":"https:issuer"}}}
        """.utf8)
        #expect(throws: IssuanceError.invalidURL) {
            try CredentialOfferParser().parse(json: opaque)
        }
    }

    @Test("Metadata rejects hostless HTTPS endpoints")
    func malformedMetadata() {
        let issuer = URL(string: "https://issuer.example")!
        let offer = CredentialOffer(
            credentialIssuer: issuer,
            configurationIDs: ["pid"],
            grant: .preAuthorizedCode(code: "code", txCodeRequired: false)
        )
        let metadata = IssuerMetadata(
            issuer: issuer,
            authorizationEndpoint: nil,
            tokenEndpoint: URL(string: "https:token")!,
            credentialEndpoint: issuer.appendingPathComponent("credential"),
            deferredCredentialEndpoint: nil,
            supportedConfigurations: ["pid"]
        )
        #expect(throws: IssuanceError.invalidURL) {
            try IssuanceValidator().validate(
                offer: offer,
                metadata: metadata,
                profile: BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: Date()),
                configurationID: "pid"
            )
        }
    }

    @Test("PKCE verifier requires RFC 7636 S256 challenge")
    func pkce() async throws {
        let verifier = String(repeating: "a", count: 43)
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8)))
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        try IssuanceValidator().validatePKCE(verifier: verifier, challenge: challenge)
        #expect(throws: IssuanceError.invalidPKCE) {
            try IssuanceValidator().validatePKCE(verifier: "short", challenge: challenge)
        }
        let transport = FixtureIssuanceTransport()
        let context = AuthorizationCodeContext(
            verifier: verifier,
            challenge: challenge,
            method: .s256,
            state: "state"
        )
        _ = try await AuthorizationCodeExchangeCoordinator().exchange(
            code: "authorization-code",
            returnedState: "state",
            context: context,
            metadata: fixtureMetadata(),
            transport: transport
        )
        await #expect(throws: IssuanceError.authorizationStateMismatch) {
            try await AuthorizationCodeExchangeCoordinator().exchange(
                code: "authorization-code",
                returnedState: "wrong",
                context: context,
                metadata: fixtureMetadata(),
                transport: transport
            )
        }
    }

    private func fixtureMetadata() -> IssuerMetadata {
        let issuer = URL(string: "https://issuer.example")!
        return IssuerMetadata(
            issuer: issuer,
            authorizationEndpoint: issuer.appendingPathComponent("authorize"),
            tokenEndpoint: issuer.appendingPathComponent("token"),
            credentialEndpoint: issuer.appendingPathComponent("credential"),
            deferredCredentialEndpoint: nil,
            supportedConfigurations: ["pid"]
        )
    }
}

actor FixtureIssuanceTransport: IssuanceTransport {
    func fetchIssuerMetadata(issuer: URL) async throws -> IssuerMetadata { fatalError() }
    func exchangeAuthorizationCode(_ code: String, verifier: String, metadata: IssuerMetadata) async throws -> TokenResponse {
        TokenResponse(accessToken: "token", cNonce: nil, expiresAt: Date().addingTimeInterval(60))
    }
    func exchangePreAuthorizedCode(_ code: String, txCode: String?, metadata: IssuerMetadata) async throws -> TokenResponse { fatalError() }
    func requestCredential(_ request: CredentialRequest, token: TokenResponse, metadata: IssuerMetadata) async throws -> CredentialResponse { fatalError() }
}
