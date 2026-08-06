import Foundation
import WalletDomain

public actor EncryptedCredentialRepository: CredentialRepository {
    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL, keyStore: any VaultKeyStore) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        try files.prepare()
    }

    public func credentials() async throws -> [CredentialRecord] {
        try files.files(withExtension: "credential")
            .map { file in
                guard let uuid = UUID(uuidString: file.deletingPathExtension().lastPathComponent) else {
                    throw VaultError.corruptCiphertext
                }
                return try load(file, expectedID: CredentialID(rawValue: uuid))
            }
            .map(\.record)
            .sorted { $0.createdAt > $1.createdAt }
    }

    public func credential(id: CredentialID) async throws -> CredentialEnvelope? {
        let file = fileURL(id)
        guard files.exists(file) else { return nil }
        return try load(file, expectedID: id)
    }

    public func save(_ credential: CredentialEnvelope) async throws {
        let file = fileURL(credential.record.id)
        guard !files.exists(file) else {
            throw WalletRepositoryError.duplicateCredential
        }
        do {
            let plaintext = try encoder.encode(PersistedCredential(credential))
            try files.write(
                cipher.seal(plaintext, authenticating: context(for: credential.record.id)),
                to: file
            )
        } catch let error as WalletRepositoryError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    public func delete(id: CredentialID) async throws {
        let file = fileURL(id)
        guard files.exists(file) else {
            throw WalletRepositoryError.credentialNotFound
        }
        do {
            try files.remove(file)
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    private func fileURL(_ id: CredentialID) -> URL {
        files.directory
            .appendingPathComponent(id.rawValue.uuidString, isDirectory: false)
            .appendingPathExtension("credential")
    }

    private func context(for id: CredentialID) -> Data {
        Data("oari.credential.v1:\(id.rawValue.uuidString)".utf8)
    }

    private func load(_ file: URL, expectedID: CredentialID) throws -> CredentialEnvelope {
        do {
            let plaintext = try cipher.open(
                files.read(file),
                authenticating: context(for: expectedID)
            )
            let envelope = try decoder.decode(PersistedCredential.self, from: plaintext).envelope
            guard envelope.record.id == expectedID else {
                throw VaultError.corruptCiphertext
            }
            return envelope
        } catch let error as VaultError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }
}

private struct PersistedCredential: Codable {
    let record: CredentialRecord
    let encodedCredential: Data

    init(_ envelope: CredentialEnvelope) {
        record = envelope.record
        encodedCredential = envelope.encodedCredential
    }

    var envelope: CredentialEnvelope {
        CredentialEnvelope(record: record, encodedCredential: encodedCredential)
    }
}
