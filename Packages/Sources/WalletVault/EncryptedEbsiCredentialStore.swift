import EbsiW3CBackend
import Foundation
import WalletDomain

public actor EncryptedEbsiCredentialStore: EbsiCredentialStore {
    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL, keyStore: any VaultKeyStore) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        try files.prepare()
    }

    public func credentials() async throws -> [StoredEbsiCredential] {
        try files.files(withExtension: "ebsi-vc").map { file in
            guard let id = UUID(uuidString: file.deletingPathExtension().lastPathComponent) else {
                throw VaultError.corruptCiphertext
            }
            let plaintext = try cipher.open(files.read(file), authenticating: context(id))
            let credential = try decoder.decode(StoredEbsiCredential.self, from: plaintext)
            guard credential.id == id else { throw VaultError.corruptCiphertext }
            return credential
        }.sorted { $0.receivedAt > $1.receivedAt }
    }

    public func save(_ credential: StoredEbsiCredential) async throws {
        let file = fileURL(credential.id)
        guard !files.exists(file) else { throw WalletRepositoryError.duplicateCredential }
        do {
            try files.write(
                cipher.seal(try encoder.encode(credential), authenticating: context(credential.id)),
                to: file
            )
        } catch let error as WalletRepositoryError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    public func delete(id: UUID) async throws {
        let file = fileURL(id)
        guard files.exists(file) else { throw WalletRepositoryError.credentialNotFound }
        do { try files.remove(file) } catch { throw WalletRepositoryError.storageFailure }
    }

    private func fileURL(_ id: UUID) -> URL {
        files.directory.appendingPathComponent(id.uuidString).appendingPathExtension("ebsi-vc")
    }

    private func context(_ id: UUID) -> Data {
        Data("oari.ebsi-credential.v1:\(id.uuidString)".utf8)
    }
}
