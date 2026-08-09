import Foundation
import WalletDomain

/// Persists only application-owned metadata. Wallet Kit remains the source of truth
/// for raw documents and their document-bound keys.
public actor EncryptedCredentialMetadataRepository: CredentialMetadataRepository {
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
        try files.files(withExtension: "metadata")
            .map { file in
                guard let uuid = UUID(uuidString: file.deletingPathExtension().lastPathComponent) else {
                    throw VaultError.corruptCiphertext
                }
                return try load(file, expectedID: CredentialID(rawValue: uuid))
            }
            .sorted { $0.createdAt > $1.createdAt }
    }

    public func saveMetadata(_ credential: CredentialRecord) async throws {
        let file = fileURL(credential.id)
        guard !files.exists(file) else { throw WalletRepositoryError.duplicateCredential }
        do {
            let plaintext = try encoder.encode(credential)
            try files.write(
                cipher.seal(plaintext, authenticating: context(for: credential.id)),
                to: file
            )
        } catch let error as WalletRepositoryError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    public func replaceMetadata(_ credential: CredentialRecord) async throws {
        let file = fileURL(credential.id)
        guard files.exists(file) else { throw WalletRepositoryError.credentialNotFound }
        do {
            let plaintext = try encoder.encode(credential)
            try files.write(
                cipher.seal(plaintext, authenticating: context(for: credential.id)),
                to: file
            )
        } catch let error as WalletRepositoryError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    public func deleteMetadata(id: CredentialID) async throws {
        let file = fileURL(id)
        guard files.exists(file) else { throw WalletRepositoryError.credentialNotFound }
        do { try files.remove(file) } catch { throw WalletRepositoryError.storageFailure }
    }

    private func load(_ file: URL, expectedID: CredentialID) throws -> CredentialRecord {
        do {
            let plaintext = try cipher.open(
                files.read(file),
                authenticating: context(for: expectedID)
            )
            let record = try decoder.decode(CredentialRecord.self, from: plaintext)
            guard record.id == expectedID else { throw VaultError.corruptCiphertext }
            return record
        } catch let error as VaultError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    private func fileURL(_ id: CredentialID) -> URL {
        files.directory.appendingPathComponent(id.rawValue.uuidString).appendingPathExtension("metadata")
    }

    private func context(for id: CredentialID) -> Data {
        Data("oari.credential-metadata.v1:\(id.rawValue.uuidString)".utf8)
    }
}
