import CryptoKit
import Foundation
import Testing
import WalletDomain
@testable import WalletVault

struct EncryptedCredentialRepositoryTests {
    @Test("Credential survives repository restart without plaintext on disk")
    func encryptedRestart() async throws {
        let fixture = try Fixture()
        let envelope = fixture.credential(payload: "sensitive-credential-value")
        let first = try EncryptedCredentialRepository(
            directory: fixture.credentialsDirectory,
            keyStore: fixture.keyStore
        )
        try await first.save(envelope)

        let onDisk = try fixture.onlyFile(in: fixture.credentialsDirectory).readData()
        #expect(!onDisk.contains(Data("sensitive-credential-value".utf8)))
        #expect(!onDisk.contains(Data("did:ebsi:issuer".utf8)))

        let restarted = try EncryptedCredentialRepository(
            directory: fixture.credentialsDirectory,
            keyStore: fixture.keyStore
        )
        #expect(try await restarted.credential(id: envelope.record.id) == envelope)
    }

    @Test("Deletion removes the encrypted credential file")
    func deletion() async throws {
        let fixture = try Fixture()
        let envelope = fixture.credential(payload: "credential")
        let repository = try EncryptedCredentialRepository(
            directory: fixture.credentialsDirectory,
            keyStore: fixture.keyStore
        )
        try await repository.save(envelope)
        try await repository.delete(id: envelope.record.id)

        #expect(try await repository.credential(id: envelope.record.id) == nil)
        #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.credentialsDirectory.path).isEmpty)
    }

    @Test("Tampered ciphertext fails closed")
    func tamperDetection() async throws {
        let fixture = try Fixture()
        let envelope = fixture.credential(payload: "credential")
        let repository = try EncryptedCredentialRepository(
            directory: fixture.credentialsDirectory,
            keyStore: fixture.keyStore
        )
        try await repository.save(envelope)
        let file = try fixture.onlyFile(in: fixture.credentialsDirectory)
        var ciphertext = try file.readData()
        ciphertext[ciphertext.startIndex] ^= 0xff
        try ciphertext.write(to: file, options: .atomic)

        await #expect(throws: VaultError.corruptCiphertext) {
            _ = try await repository.credential(id: envelope.record.id)
        }
    }

    @Test("Valid ciphertext cannot be substituted between credential identifiers")
    func substitutionDetection() async throws {
        let fixture = try Fixture()
        let first = fixture.credential(payload: "first")
        let second = fixture.credential(payload: "second")
        let repository = try EncryptedCredentialRepository(
            directory: fixture.credentialsDirectory,
            keyStore: fixture.keyStore
        )
        try await repository.save(first)
        try await repository.save(second)

        let firstFile = fixture.credentialFile(first.record.id)
        let secondFile = fixture.credentialFile(second.record.id)
        try firstFile.readData().write(to: secondFile, options: .atomic)

        await #expect(throws: VaultError.corruptCiphertext) {
            _ = try await repository.credential(id: second.record.id)
        }
    }

    @Test("Unavailable keychain remains distinguishable from ciphertext corruption")
    func lockedKeyStoreError() throws {
        let context = Data("context".utf8)
        let sealingCipher = VaultCipher(
            keyStore: StaticVaultKeyStore(key: SymmetricKey(size: .bits256))
        )
        let ciphertext = try sealingCipher.seal(Data("credential".utf8), authenticating: context)
        let lockedCipher = VaultCipher(keyStore: FailingVaultKeyStore())

        #expect(throws: VaultError.keychain(errSecInteractionNotAllowed)) {
            _ = try lockedCipher.open(ciphertext, authenticating: context)
        }
    }
}

struct StaticVaultKeyStore: VaultKeyStore {
    let key: SymmetricKey

    func loadOrCreateKey() throws -> SymmetricKey { key }
}

struct FailingVaultKeyStore: VaultKeyStore {
    func loadOrCreateKey() throws -> SymmetricKey {
        throw VaultError.keychain(errSecInteractionNotAllowed)
    }
}

struct Fixture {
    let root: URL
    let credentialsDirectory: URL
    let auditDirectory: URL
    let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        credentialsDirectory = root.appendingPathComponent("credentials", isDirectory: true)
        auditDirectory = root.appendingPathComponent("audit", isDirectory: true)
    }

    func credential(payload: String) -> CredentialEnvelope {
        CredentialEnvelope(
            record: CredentialRecord(
                configurationID: "provisionalOariLPID",
                displayName: "Legal person identity",
                format: .jwtVC,
                profileID: "oari-development-v1",
                issuerIdentifier: "did:ebsi:issuer",
                createdAt: Date(timeIntervalSince1970: 1_700_000_000)
            ),
            encodedCredential: Data(payload.utf8)
        )
    }

    func onlyFile(in directory: URL) throws -> URL {
        try #require(
            FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: nil
            ).first
        )
    }

    func credentialFile(_ id: CredentialID) -> URL {
        credentialsDirectory
            .appendingPathComponent(id.rawValue.uuidString)
            .appendingPathExtension("credential")
    }
}

extension URL {
    func readData() throws -> Data { try Data(contentsOf: self) }
}
