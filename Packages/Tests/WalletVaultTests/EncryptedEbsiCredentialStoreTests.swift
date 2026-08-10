import CryptoKit
import EbsiW3CBackend
import Foundation
import Testing
@testable import WalletVault

struct EncryptedEbsiCredentialStoreTests {
    @Test("Raw W3C credential survives restart encrypted and deletes")
    func restartAndDelete() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        let credential = StoredEbsiCredential(
            profileID: "ebsi-vcdm2-jwt-vc",
            representation: .vcdm2Jwt,
            rawCredential: Data("header.payload.signature".utf8),
            holderKeyReference: "ebsi-holder-key-1",
            receivedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        var store = try EncryptedEbsiCredentialStore(directory: directory, keyStore: keyStore)
        try await store.save(credential)
        let file = try #require(FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        ).first)
        let disk = try Data(contentsOf: file)
        #expect(!disk.contains(credential.rawCredential))
        #expect(!disk.contains(Data(credential.holderKeyReference.utf8)))

        store = try EncryptedEbsiCredentialStore(directory: directory, keyStore: keyStore)
        #expect(try await store.credentials() == [credential])
        try await store.delete(id: credential.id)
        #expect(try await store.credentials().isEmpty)
    }
}
