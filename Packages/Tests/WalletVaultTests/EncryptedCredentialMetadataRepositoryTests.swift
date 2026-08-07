import CryptoKit
import Foundation
import Testing
import WalletDomain
@testable import WalletVault

struct EncryptedCredentialMetadataRepositoryTests {
    @Test("Production metadata repository has no raw document input or retrieval")
    func metadataOnlyRoundTrip() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let repository = try EncryptedCredentialMetadataRepository(
            directory: root,
            keyStore: StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        )
        let record = CredentialRecord(
            configurationID: "pid",
            displayName: "PID",
            format: .sdJWTVC,
            profileID: "test-profile",
            issuerIdentifier: "issuer-reference",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        try await repository.saveMetadata(record)
        #expect(try await repository.credentials() == [record])
        let bytes = try Data(contentsOf: #require(
            FileManager.default.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: nil
            ).first
        ))
        #expect(!bytes.contains(Data("issuer-reference".utf8)))

        try await repository.deleteMetadata(id: record.id)
        #expect(try await repository.credentials().isEmpty)
    }
}
