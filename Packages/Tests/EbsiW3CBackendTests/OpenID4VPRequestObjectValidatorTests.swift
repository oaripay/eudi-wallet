import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing

struct OpenID4VPRequestObjectValidatorTests {
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
        let request = try await NativeOpenID4VPRequestObjectValidator(
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
        var parts = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let first = try #require(parts[2].first)
        parts[2].replaceSubrange(parts[2].startIndex...parts[2].startIndex, with: first == "A" ? "B" : "A")
        let tampered = parts.joined(separator: ".")
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request signature was invalid")) {
            _ = try await NativeOpenID4VPRequestObjectValidator(
                resolver: KeyDIDResolver()
            ).validate(compactJWT: tampered, at: Date())
        }
    }

    @Test("decentralized_identifier client ID is bound to the signing DID")
    func rejectsMismatchedDecentralizedIdentifier() async throws {
        let key = P256.Signing.PrivateKey()
        let did = try KeyDIDResolver().derive(publicKeyX963: key.publicKey.x963Representation)
        let document = try await KeyDIDResolver().resolve(did)
        let kid = try #require(document.authentication.first)
        let jwt = try Self.sign(
            key: key,
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid],
            payload: [
                "iss": did,
                "client_id": "decentralized_identifier:did:key:another-verifier",
                "response_mode": "direct_post",
                "nonce": "nonce-value",
                "exp": Int(Date().timeIntervalSince1970) + 300,
                "dcql_query": ["credentials": [["id": "pid"]]],
            ]
        )
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(
            reason: "decentralized_identifier client_id was not bound to the signing DID"
        )) {
            _ = try await NativeOpenID4VPRequestObjectValidator(
                resolver: KeyDIDResolver()
            ).validate(compactJWT: jwt, at: Date())
        }
    }

    @Test("Replay store atomically consumes both request digest and nonce")
    func replayStoreRejectsDigestAndNonceReuse() async throws {
        let store = InMemoryOpenID4VPReplayStore(maximumEntries: 4, maximumRetention: 300)
        let now = Date()
        try await store.consume(requestDigest: "digest-1", nonce: "nonce-1", expiresAt: now.addingTimeInterval(60), at: now)
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request was replayed")) {
            try await store.consume(requestDigest: "digest-1", nonce: "nonce-2", expiresAt: now.addingTimeInterval(60), at: now)
        }
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request was replayed")) {
            try await store.consume(requestDigest: "digest-2", nonce: "nonce-1", expiresAt: now.addingTimeInterval(60), at: now)
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
