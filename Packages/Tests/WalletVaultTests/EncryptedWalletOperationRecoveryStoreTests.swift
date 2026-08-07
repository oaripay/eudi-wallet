import CryptoKit
import Foundation
import Testing
import WalletDomain
@testable import WalletVault

struct EncryptedWalletOperationRecoveryStoreTests {
    @Test("Recovery journal survives restart, replaces atomically, and deletes")
    func restartReplaceAndDelete() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        let original = WalletOperationRecovery(
            kind: .pendingIssuance,
            baselineDocumentIDs: ["existing-document"]
        )
        var store = try EncryptedWalletOperationRecoveryStore(directory: root, keyStore: keyStore)
        try await store.saveRecovery(original)

        store = try EncryptedWalletOperationRecoveryStore(directory: root, keyStore: keyStore)
        #expect(try await store.recoveries() == [original])

        let updated = WalletOperationRecovery(
            id: original.id,
            kind: .pendingIssuance,
            baselineDocumentIDs: original.baselineDocumentIDs,
            affectedDocuments: [WalletDocumentRecoveryReference(id: "new-document", status: "issued")],
            metadataCommitted: true,
            pendingAuditEvent: AuditEvent(
                operation: .issuance,
                outcome: .completed,
                occurredAt: Date(timeIntervalSince1970: 1_700_000_000),
                policy: .development,
                policyVersion: AuditPolicyVersion(rawValue: 1)
            ),
            createdAt: original.createdAt
        )
        try await store.replaceRecovery(updated)
        store = try EncryptedWalletOperationRecoveryStore(directory: root, keyStore: keyStore)
        #expect(try await store.recoveries() == [updated])

        try await store.deleteRecovery(id: original.id)
        #expect(try await store.recoveries().isEmpty)
    }

    @Test("Recovery journal ciphertext tampering fails closed")
    func tamperingFailsClosed() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = try EncryptedWalletOperationRecoveryStore(
            directory: root,
            keyStore: StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        )
        try await store.saveRecovery(WalletOperationRecovery(kind: .deletion))
        let file = try #require(FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).first)
        var bytes = try Data(contentsOf: file)
        bytes[bytes.startIndex] ^= 0x01
        try bytes.write(to: file, options: .atomic)

        await #expect(throws: (any Error).self) {
            _ = try await store.recoveries()
        }
    }

    @Test("Committed redacted audit outbox survives restart")
    func auditOutboxSurvivesRestart() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        let event = AuditEvent(
            operation: .presentation,
            outcome: .completed,
            occurredAt: Date(timeIntervalSince1970: 1_700_000_000),
            counterpartyIdentifierDigest: .sha256("verifier"),
            disclosedClaimDigests: [.sha256("claim")],
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        )
        let recovery = WalletOperationRecovery(
            kind: .audit,
            metadataCommitted: true,
            pendingAuditEvent: event
        )
        var store = try EncryptedWalletOperationRecoveryStore(directory: root, keyStore: keyStore)
        try await store.saveRecovery(recovery)
        store = try EncryptedWalletOperationRecoveryStore(directory: root, keyStore: keyStore)
        #expect(try await store.recoveries() == [recovery])

        let disk = try Data(contentsOf: #require(FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).first))
        #expect(!disk.contains(Data("verifier".utf8)))
        #expect(!disk.contains(Data("claim".utf8)))
    }
}
