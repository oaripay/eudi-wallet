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

    @Test("iGrant x5c sentinel selects the one issuer-published key that verifies")
    func igrantX5CSentinel() throws {
        let signingKey = P256.Signing.PrivateKey()
        let otherKey = P256.Signing.PrivateKey()
        let methods = [
            method(id: "issuer-key-1", key: otherKey.publicKey),
            method(id: "issuer-key-2", key: signingKey.publicKey),
        ]
        let token = try compactJWS(
            algorithm: "ES256",
            kid: "None",
            headerAdditions: ["x5c": ["certificate-placeholder"]],
            issuer: "did:key:p256"
        ) { input in
            try signingKey.signature(for: input).rawRepresentation
        }

        let verified = try EbsiJWSVerifier().verify(
            compactJWS: token,
            methods: methods,
            requirements: requirements(algorithm: .es256, controller: "did:key:p256")
        )
        #expect(verified.methodID == "issuer-key-2")

        let unbound = try compactJWS(
            algorithm: "ES256",
            kid: "None",
            issuer: "did:key:p256"
        ) { input in
            try signingKey.signature(for: input).rawRepresentation
        }
        #expect(throws: EbsiCredentialError.verificationFailed) {
            _ = try EbsiJWSVerifier().verify(
                compactJWS: unbound,
                methods: methods,
                requirements: requirements(algorithm: .es256, controller: "did:key:p256")
            )
        }
    }

    @Test("VC-JOSE requires vc+jwt typ and rejects malformed, unknown, and registered critical headers")
    func vcJOSEProtectedHeaders() throws {
        let key = P256.Signing.PrivateKey()
        let method = method(id: "did:key:p256#key-1", key: key.publicKey)
        let vcRequirements = EbsiJWSRequirements(
            allowedAlgorithms: [.es256],
            requiredRelationship: .assertionMethod,
            expectedController: "did:key:p256",
            expectedType: "vc+jwt",
            validationDate: now
        )

        let valid = try compactJWS(
            algorithm: "ES256",
            kid: method.id,
            headerAdditions: ["typ": "vc+jwt"]
        ) { try key.signature(for: $0).rawRepresentation }
        _ = try EbsiJWSVerifier().verify(compactJWS: valid, methods: [method], requirements: vcRequirements)

        for additions: [String: Any] in [
            ["typ": "JWT"],
            ["typ": "vc+jwt", "crit": "custom", "custom": true],
            ["typ": "vc+jwt", "crit": ["missing"]],
            ["typ": "vc+jwt", "crit": ["custom"], "custom": true],
            ["typ": "vc+jwt", "crit": ["typ"]],
            ["typ": "vc+jwt", "crit": ["custom", "custom"], "custom": true],
        ] {
            let token = try compactJWS(
                algorithm: "ES256",
                kid: method.id,
                headerAdditions: additions
            ) { try key.signature(for: $0).rawRepresentation }
            #expect(throws: EbsiCredentialError.verificationFailed) {
                _ = try EbsiJWSVerifier().verify(
                    compactJWS: token,
                    methods: [method],
                    requirements: vcRequirements
                )
            }
        }

        let understood = try compactJWS(
            algorithm: "ES256",
            kid: method.id,
            headerAdditions: ["typ": "vc+jwt", "crit": ["custom"], "custom": true]
        ) { try key.signature(for: $0).rawRepresentation }
        _ = try EbsiJWSVerifier().verify(
            compactJWS: understood,
            methods: [method],
            requirements: EbsiJWSRequirements(
                allowedAlgorithms: [.es256],
                requiredRelationship: .assertionMethod,
                expectedController: "did:key:p256",
                expectedType: "vc+jwt",
                understoodCriticalHeaders: ["custom"],
                validationDate: now
            )
        )
    }

    @Test("Registered NumericDate claims reject wrong JSON types")
    func malformedNumericDate() throws {
        let key = P256.Signing.PrivateKey()
        let method = method(id: "did:key:p256#key-1", key: key.publicKey)
        let token = try compactJWS(
            algorithm: "ES256",
            kid: method.id,
            headerAdditions: [:],
            payloadAdditions: ["exp": "never"]
        ) { try key.signature(for: $0).rawRepresentation }
        #expect(throws: EbsiCredentialError.verificationFailed) {
            _ = try EbsiJWSVerifier().verify(
                compactJWS: token,
                methods: [method],
                requirements: requirements(algorithm: .es256, controller: "did:key:p256")
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

    private func method(id: String, key: P256.Signing.PublicKey) -> EbsiVerificationMethod {
        let bytes = key.x963Representation
        return EbsiVerificationMethod(
            id: id,
            controller: "did:key:p256",
            key: .p256(x: bytes.subdata(in: 1..<33), y: bytes.subdata(in: 33..<65)),
            relationships: [.assertionMethod]
        )
    }

    private func compactJWS(
        algorithm: String,
        kid: String,
        headerAdditions: [String: Any] = [:],
        issuer: String? = nil,
        payloadAdditions: [String: Any] = [:],
        signer: (Data) throws -> Data
    ) throws -> String {
        var headerValue: [String: Any] = ["alg": algorithm, "kid": kid, "typ": "JWT"]
        headerValue.merge(headerAdditions) { _, new in new }
        let header = try encode(headerValue)
        var payloadValue: [String: Any] = [
            "iss": issuer ?? kid.components(separatedBy: "#")[0],
            "aud": "https://verifier.example",
            "nonce": "nonce-1",
            "iat": Int(now.timeIntervalSince1970),
            "exp": Int(now.addingTimeInterval(300).timeIntervalSince1970),
        ]
        payloadValue.merge(payloadAdditions) { _, new in new }
        let payload = try encode(payloadValue)
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
