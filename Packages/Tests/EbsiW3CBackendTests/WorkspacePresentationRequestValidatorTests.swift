import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing

struct WorkspacePresentationRequestValidatorTests {
    @Test("Signed presentation request is verified before claims are trusted")
    func verifiesRequest() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: [
                "iss": did,
                "client_id": "redirect_uri:https://verifier.example/callback",
                "response_type": "vp_token",
                "response_mode": "ia_post",
                "nonce": "nonce-value",
                "exp": Int(Date().timeIntervalSince1970) + 300,
                "dcql_query": ["credentials": [["id": "pid", "format": "dc+sd-jwt"]]],
            ]
        )
        let request = try await NativeWorkspacePresentationRequestValidator(
            resolver: KeyDIDResolver()
        ).validate(compactJWT: jwt, at: Date())
        #expect(request.nonce == "nonce-value")
        #expect(request.responseMode == "ia_post")
    }

    @Test("Tampered presentation request is rejected")
    func rejectsTampering() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: [
                "iss": did,
                "client_id": "redirect_uri:https://verifier.example/callback",
                "response_type": "vp_token",
                "response_mode": "ia_post",
                "nonce": "nonce-value",
                "exp": Int(Date().timeIntervalSince1970) + 300,
                "dcql_query": ["credentials": [["id": "pid"]]],
            ]
        )
        let tampered = String(jwt.dropLast()) + (jwt.last == "A" ? "B" : "A")
        await #expect(throws: WorkspaceBackendError.invalidPresentationChallenge(reason: "signed request signature was invalid")) {
            _ = try await NativeWorkspacePresentationRequestValidator(
                resolver: KeyDIDResolver()
            ).validate(compactJWT: tampered, at: Date())
        }
    }

    private static func sign(
        key: P256.Signing.PrivateKey,
        header: [String: Any],
        payload: [String: Any]
    ) throws -> String {
        func encode(_ object: [String: Any]) throws -> String {
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let encodedHeader = try encode(header)
        let encodedPayload = try encode(payload)
        let input = Data("\(encodedHeader).\(encodedPayload)".utf8)
        let signature = try key.signature(for: input).rawRepresentation.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "\(encodedHeader).\(encodedPayload).\(signature)"
    }
}
