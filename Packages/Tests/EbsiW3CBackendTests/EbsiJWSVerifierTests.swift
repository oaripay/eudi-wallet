import CryptoKit
import EbsiW3CBackend
import Foundation
import Security
import Testing

struct EbsiJWSVerifierTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test("ES256 verifies key relationship and claims and rejects forgery")
    func es256() throws {
        let key = P256.Signing.PrivateKey()
        let publicBytes = key.publicKey.x963Representation
        let method = EbsiVerificationMethod(
            id: "did:key:p256#key-1",
            controller: "did:key:p256",
            key: .p256(x: publicBytes.subdata(in: 1..<33), y: publicBytes.subdata(in: 33..<65)),
            relationships: [.assertionMethod]
        )
        let token = try compactJWS(algorithm: "ES256", kid: method.id) { input in
            try key.signature(for: input).rawRepresentation
        }
        let verified = try EbsiJWSVerifier().verify(
            compactJWS: token,
            methods: [method],
            requirements: requirements(algorithm: .es256, controller: "did:key:p256")
        )
        #expect(verified.methodID == method.id)

        let attacker = P256.Signing.PrivateKey()
        let forged = try compactJWS(algorithm: "ES256", kid: method.id) { input in
            try attacker.signature(for: input).rawRepresentation
        }
        #expect(throws: EbsiCredentialError.verificationFailed) {
            _ = try EbsiJWSVerifier().verify(
                compactJWS: forged,
                methods: [method],
                requirements: requirements(algorithm: .es256, controller: "did:key:p256")
            )
        }
    }

    @Test("RS256 verifies runtime RSA key and rejects wrong relationship")
    func rs256() throws {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        let privateKey = try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        let publicData = try #require(SecKeyCopyExternalRepresentation(publicKey, &error) as Data?)
        let method = EbsiVerificationMethod(
            id: "did:ebsi:rsa#key-1",
            controller: "did:ebsi:rsa",
            key: .rsaPKCS1DER(publicData),
            relationships: [.assertionMethod]
        )
        let token = try compactJWS(algorithm: "RS256", kid: method.id) { input in
            try #require(SecKeyCreateSignature(
                privateKey,
                .rsaSignatureMessagePKCS1v15SHA256,
                input as CFData,
                &error
            ) as Data?)
        }
        _ = try EbsiJWSVerifier().verify(
            compactJWS: token,
            methods: [method],
            requirements: requirements(algorithm: .rs256, controller: "did:ebsi:rsa")
        )
        #expect(throws: EbsiCredentialError.verificationFailed) {
            _ = try EbsiJWSVerifier().verify(
                compactJWS: token,
                methods: [method],
                requirements: EbsiJWSRequirements(
                    allowedAlgorithms: [.rs256],
                    requiredRelationship: .authentication,
                    validationDate: now
                )
            )
        }
    }

    private func requirements(
        algorithm: EbsiKeyAlgorithm,
        controller: String
    ) -> EbsiJWSRequirements {
        EbsiJWSRequirements(
            allowedAlgorithms: [algorithm],
            requiredRelationship: .assertionMethod,
            expectedController: controller,
            expectedIssuer: controller,
            expectedAudience: "https://verifier.example",
            expectedNonce: "nonce-1",
            validationDate: now
        )
    }

    private func compactJWS(
        algorithm: String,
        kid: String,
        signer: (Data) throws -> Data
    ) throws -> String {
        let header = try encode(["alg": algorithm, "kid": kid, "typ": "JWT"])
        let payload = try encode([
            "iss": kid.components(separatedBy: "#")[0],
            "aud": "https://verifier.example",
            "nonce": "nonce-1",
            "iat": Int(now.timeIntervalSince1970),
            "exp": Int(now.addingTimeInterval(300).timeIntervalSince1970),
        ] as [String: Any])
        let input = Data("\(header).\(payload)".utf8)
        return "\(header).\(payload).\(base64URL(try signer(input)))"
    }

    private func encode(_ value: Any) throws -> String {
        base64URL(try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
