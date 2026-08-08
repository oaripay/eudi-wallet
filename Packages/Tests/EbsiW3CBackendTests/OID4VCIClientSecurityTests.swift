import CryptoKit
import EbsiW3CBackend
import Foundation
import JOSESwift
import Testing
import WalletDomain

struct OID4VCIClientSecurityTests {
    @Test("Credential DPoP binds the access token and token DPoP does not")
    func dpopAccessTokenBinding() async throws {
        let security = DefaultOID4VCIClientSecurity(keyProvider: SecurityFixtureKeyProvider())
        let state = try await security.state(for: .draft13)
        let endpoint = URL(string: "https://issuer.example/credential")!
        let tokenProof = try await security.dpopHeader(
            state: state,
            method: "POST",
            targetURI: endpoint,
            accessToken: nil
        )
        let tokenPayload = try Self.jwtObject(tokenProof, part: 1)
        #expect(tokenPayload["ath"] == nil)
        #expect(tokenPayload["htm"] as? String == "POST")
        #expect(tokenPayload["htu"] as? String == endpoint.absoluteString)

        let credentialProof = try await security.dpopHeader(
            state: state,
            method: "POST",
            targetURI: endpoint,
            accessToken: "access-token"
        )
        let credentialPayload = try Self.jwtObject(credentialProof, part: 1)
        let digest = Data(SHA256.hash(data: Data("access-token".utf8)))
        #expect(credentialPayload["ath"] as? String == Self.base64URL(digest))
        #expect(tokenPayload["jti"] as? String != credentialPayload["jti"] as? String)
        try Self.verify(credentialProof)
    }

    @Test("ECDH-ES parameters decrypt an A128CBC-HS256 response")
    func encryptedResponse() async throws {
        let security = DefaultOID4VCIClientSecurity(keyProvider: SecurityFixtureKeyProvider())
        let state = try await security.state(for: .draft13)
        let parameters = try await security.responseEncryption(state: state)
        let publicKey = try ECPublicKey(data: Data(parameters.publicJWK.utf8))
        let encrypter = try #require(Encrypter(
            keyManagementAlgorithm: .ECDH_ES,
            contentEncryptionAlgorithm: .A128CBCHS256,
            encryptionKey: publicKey
        ))
        let plaintext = Data(#"{"credential":"issuer~disclosure~"}"#.utf8)
        let jwe = try JWE(
            header: JWEHeader(
                keyManagementAlgorithm: .ECDH_ES,
                contentEncryptionAlgorithm: .A128CBCHS256
            ),
            payload: Payload(plaintext),
            encrypter: encrypter
        )
        #expect(try await security.decryptCredentialResponse(
            state: state,
            compactJWE: Data(jwe.compactSerializedString.utf8)
        ) == plaintext)
    }

    private static func jwtObject(_ compact: String, part: Int) throws -> [String: Any] {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false)
        let data = try #require(base64URLData(String(parts[part])))
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private static func verify(_ compact: String) throws {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false)
        let header = try jwtObject(compact, part: 0)
        let jwk = try #require(header["jwk"] as? [String: Any])
        let encodedX = try #require(jwk["x"] as? String)
        let encodedY = try #require(jwk["y"] as? String)
        let x = try #require(base64URLData(encodedX))
        let y = try #require(base64URLData(encodedY))
        let publicKey = try P256.Signing.PublicKey(x963Representation: Data([0x04]) + x + y)
        let signatureData = try #require(base64URLData(String(parts[2])))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
        let input = Data("\(parts[0]).\(parts[1])".utf8)
        #expect(publicKey.isValidSignature(signature, for: input))
    }

    private static func base64URLData(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

private actor SecurityFixtureKeyProvider: KeyProvider {
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
