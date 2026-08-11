import CryptoKit
import Foundation
import Testing
import WalletDomain
@testable import WalletVault

struct EncryptedDeferredIssuanceRepositoryTests {
    @Test("Deferred issuance survives restart, replacement, and deletion")
    func roundTripReplaceAndDelete() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        let original = fixture()
        var repository = try EncryptedDeferredIssuanceRepository(directory: root, keyStore: keyStore)

        try await repository.saveDeferredIssuance(original)
        repository = try EncryptedDeferredIssuanceRepository(directory: root, keyStore: keyStore)
        #expect(try await repository.deferredIssuances() == [original])

        let updated = fixture(
            id: original.id,
            attempts: 1,
            state: .authorizationRequired
        )
        try await repository.replaceDeferredIssuance(updated)
        #expect(try await repository.deferredIssuances() == [updated])

        try await repository.deleteDeferredIssuance(id: original.id)
        #expect(try await repository.deferredIssuances().isEmpty)
    }

    @Test("Deferred issuance ciphertext hides secrets and tampering fails closed")
    func encryptionAndTampering() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedDeferredIssuanceRepository(
            directory: root,
            keyStore: StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        )
        let issuance = fixture()
        try await repository.saveDeferredIssuance(issuance)

        let file = try #require(FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).first)
        var bytes = try Data(contentsOf: file)
        #expect(!bytes.contains(issuance.continuation))
        #expect(!bytes.contains(Data("secret-access-token".utf8)))
        bytes[bytes.startIndex] ^= 0x01
        try bytes.write(to: file, options: .atomic)

        await #expect(throws: VaultError.corruptCiphertext) {
            _ = try await repository.deferredIssuances()
        }
    }

    @Test("Deferred workflow states remain durable")
    func stateTransitions() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = try EncryptedDeferredIssuanceRepository(
            directory: root,
            keyStore: StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        )
        var value = fixture()
        try await repository.saveDeferredIssuance(value)
        for state in DeferredIssuanceState.allCasesForTests {
            value = fixture(id: value.id, attempts: value.attempts + 1, state: state)
            try await repository.replaceDeferredIssuance(value)
            #expect(try await repository.deferredIssuances() == [value])
        }
    }

    private func fixture(
        id: UUID = UUID(),
        attempts: Int = 0,
        state: DeferredIssuanceState = .pending
    ) -> DeferredIssuance {
        let created = Date(timeIntervalSince1970: 1_700_000_000)
        return DeferredIssuance(
            id: id,
            continuation: Data("secret-access-token/transaction".utf8),
            issuerIdentifier: "https://issuer.example",
            configurationIDs: ["pid"],
            displayName: "PID",
            display: CredentialDisplayMetadata(locale: "en", description: "Identity credential"),
            nextAttemptAt: created.addingTimeInterval(5),
            attempts: attempts,
            state: state,
            createdAt: created,
            updatedAt: created.addingTimeInterval(TimeInterval(attempts))
        )
    }
}

private extension DeferredIssuanceState {
    static var allCasesForTests: [Self] {
        [.pending, .authorizationRequired, .signerTrustRequired, .completing, .failed]
    }
}
