import CryptoKit
import EbsiW3CBackend
import Foundation
import JOSESwift
import Testing
import WalletDomain

struct OID4VCIClientSecurityTests {
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
