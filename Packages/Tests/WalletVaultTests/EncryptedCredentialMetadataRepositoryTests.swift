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
        let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        let repository = try EncryptedCredentialMetadataRepository(
            directory: root,
            keyStore: keyStore
        )
        let record = CredentialRecord(
            configurationID: "pid",
            displayName: "PID",
            format: .sdJWTVC,
            profileID: "test-profile",
            issuerIdentifier: "issuer-reference",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            display: CredentialDisplayMetadata(
                backgroundColor: "#003366",
                textColor: "#ffffff",
                logo: CredentialDisplayImage(
                    mediaType: "image/png",
                    data: Data([0x89, 0x50, 0x4e, 0x47, 0x01, 0x02]),
                    alternativeText: "Issuer mark"
                )
            )
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
        #expect(!bytes.contains(Data([0x89, 0x50, 0x4e, 0x47, 0x01, 0x02])))

        let updated = CredentialRecord(
            id: record.id,
            configurationID: record.configurationID,
            walletDocumentID: "wallet-kit-document-1",
            displayName: "Updated PID",
            format: record.format,
            profileID: record.profileID,
            issuerIdentifier: record.issuerIdentifier,
            status: .valid,
            createdAt: record.createdAt
        )
        try await repository.replaceMetadata(updated)
        let restartedRepository = try EncryptedCredentialMetadataRepository(
            directory: root,
            keyStore: keyStore
        )
        #expect(try await restartedRepository.credentials() == [updated])

        try await restartedRepository.deleteMetadata(id: record.id)
        #expect(try await restartedRepository.credentials().isEmpty)
    }
}
