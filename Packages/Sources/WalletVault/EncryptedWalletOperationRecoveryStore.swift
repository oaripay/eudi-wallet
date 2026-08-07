import Foundation
import WalletDomain

public actor EncryptedWalletOperationRecoveryStore: WalletOperationRecoveryStore {
    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL, keyStore: any VaultKeyStore) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        try files.prepare()
    }

    public func recoveries() async throws -> [WalletOperationRecovery] {
        try files.files(withExtension: "wallet-recovery").map { file in
            guard let id = UUID(uuidString: file.deletingPathExtension().lastPathComponent) else {
                throw VaultError.corruptCiphertext
            }
            let plaintext = try cipher.open(files.read(file), authenticating: context(id))
            let recovery = try decoder.decode(WalletOperationRecovery.self, from: plaintext)
            guard recovery.id == id else { throw VaultError.corruptCiphertext }
            return recovery
        }
    }

    public func saveRecovery(_ recovery: WalletOperationRecovery) async throws {
        let file = fileURL(recovery.id)
        guard !files.exists(file) else { throw WalletRepositoryError.duplicateCredential }
        try write(recovery, to: file)
    }

    public func replaceRecovery(_ recovery: WalletOperationRecovery) async throws {
        let file = fileURL(recovery.id)
        guard files.exists(file) else { throw WalletRepositoryError.credentialNotFound }
        try write(recovery, to: file)
    }

    private func write(_ recovery: WalletOperationRecovery, to file: URL) throws {
        do {
            try files.write(
                cipher.seal(try encoder.encode(recovery), authenticating: context(recovery.id)),
                to: file
            )
        } catch let error as WalletRepositoryError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    public func deleteRecovery(id: UUID) async throws {
        let file = fileURL(id)
        guard files.exists(file) else { throw WalletRepositoryError.credentialNotFound }
        do { try files.remove(file) } catch { throw WalletRepositoryError.storageFailure }
    }

    private func fileURL(_ id: UUID) -> URL {
        files.directory.appendingPathComponent(id.uuidString).appendingPathExtension("wallet-recovery")
    }

    private func context(_ id: UUID) -> Data {
        Data("oari.wallet-operation-recovery.v1:\(id.uuidString)".utf8)
    }
}
