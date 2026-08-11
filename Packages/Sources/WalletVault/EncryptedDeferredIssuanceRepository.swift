import CryptoKit
import Foundation
import WalletDomain

public actor EncryptedDeferredIssuanceRepository: DeferredIssuanceRepository {
    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL, keyStore: any VaultKeyStore) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        try files.prepare()
    }

    public func deferredIssuances() async throws -> [DeferredIssuance] {
        try files.files(withExtension: "deferred-issuance")
            .map { file in
                let digest = file.deletingPathExtension().lastPathComponent
                do {
                    let plaintext = try cipher.open(files.read(file), authenticating: context(digest))
                    let issuance = try decoder.decode(DeferredIssuance.self, from: plaintext)
                    guard issuanceDigest(issuance.id) == digest else {
                        throw VaultError.corruptCiphertext
                    }
                    return issuance
                } catch let error as VaultError {
                    throw error
                } catch {
                    throw WalletRepositoryError.storageFailure
                }
            }
            .sorted { $0.createdAt > $1.createdAt }
    }

    public func saveDeferredIssuance(_ issuance: DeferredIssuance) async throws {
        let file = fileURL(issuance.id)
        guard !files.exists(file) else { throw WalletRepositoryError.duplicateDeferredIssuance }
        try write(issuance, to: file)
    }

    public func replaceDeferredIssuance(_ issuance: DeferredIssuance) async throws {
        let file = fileURL(issuance.id)
        guard files.exists(file) else { throw WalletRepositoryError.deferredIssuanceNotFound }
        try write(issuance, to: file)
    }

    public func deleteDeferredIssuance(id: UUID) async throws {
        let file = fileURL(id)
        guard files.exists(file) else { throw WalletRepositoryError.deferredIssuanceNotFound }
        do { try files.remove(file) } catch { throw WalletRepositoryError.storageFailure }
    }

    private func write(_ issuance: DeferredIssuance, to file: URL) throws {
        do {
            let digest = issuanceDigest(issuance.id)
            try files.write(
                cipher.seal(try encoder.encode(issuance), authenticating: context(digest)),
                to: file
            )
        } catch let error as WalletRepositoryError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    private func fileURL(_ id: UUID) -> URL {
        files.directory
            .appendingPathComponent(issuanceDigest(id))
            .appendingPathExtension("deferred-issuance")
    }

    private func issuanceDigest(_ id: UUID) -> String {
        SHA256.hash(data: Data(id.uuidString.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func context(_ digest: String) -> Data {
        Data("oari.deferred-issuance.v1:\(digest)".utf8)
    }
}
