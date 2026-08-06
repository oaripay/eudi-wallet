import CryptoKit
import Foundation
import Testing
import WalletDomain
@testable import WalletVault

struct DeviceBoundKeyProviderTests {
    @Test("Software fallback is explicit, signs JOSE ES256 and deletes")
    func softwareKeyLifecycle() async throws {
        let prefix = "io.oari.wallet.tests.\(UUID().uuidString)"
        let provider = DeviceBoundKeyProvider(
            applicationTagPrefix: prefix,
            clock: { Date(timeIntervalSince1970: 1_700_000_000) }
        )
        let record = try await provider.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: false,
            protection: .keychainSoftware
        )
        #expect(record.assurance == .keychainSoftware)
        #expect(record.purpose == .credentialBinding)

        let message = Data("openid4vci proof".utf8)
        let signature = try await provider.sign(
            SigningRequest(
                keyID: record.id,
                payload: message,
                userAuthenticationReason: "Test credential proof"
            )
        )
        #expect(signature.count == 64)

        let material = try await provider.publicKey(id: record.id)
        let publicKey = try P256.Signing.PublicKey(x963Representation: material.x963Representation)
        let parsedSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        #expect(publicKey.isValidSignature(parsedSignature, for: message))

        try await provider.deleteKey(id: record.id)
        await #expect(throws: WalletRepositoryError.keyNotFound) {
            _ = try await provider.sign(
                SigningRequest(
                    keyID: record.id,
                    payload: message,
                    userAuthenticationReason: "Test deleted key"
                )
            )
        }
    }

    @Test("Signature conversion rejects malformed DER")
    func malformedSignature() {
        let malformed: [Data] = [
            Data([0x30, 0x01, 0x00]),
            Data([0x30, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            Data([0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            Data([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01]),
            Data([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]),
            oversizedIntegerDER(),
        ]

        for der in malformed {
            #expect(throws: DeviceKeyError.malformedSignature) {
                try ECDSASignatureCodec.joseRaw(fromX962DER: der, coordinateSize: 32)
            }
        }
    }

    @Test("Canonical DER converts to fixed-width JOSE signature")
    func canonicalSignature() throws {
        let raw = try ECDSASignatureCodec.joseRaw(
            fromX962DER: Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
            coordinateSize: 32
        )

        #expect(raw.count == 64)
        #expect(raw[31] == 1)
        #expect(raw[63] == 2)
    }

    private func oversizedIntegerDER() -> Data {
        var der = Data([0x30, 0x26, 0x02, 0x21])
        der.append(Data(repeating: 0x01, count: 33))
        der.append(contentsOf: [0x02, 0x01, 0x01])
        return der
    }
}
