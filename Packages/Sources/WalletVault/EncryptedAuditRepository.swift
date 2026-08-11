import Foundation
import WalletDomain

public actor EncryptedAuditRepository: AuditRepository {
    private static let authenticatedContext = Data("oari.audit.v1:events".utf8)
    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let file: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL, keyStore: any VaultKeyStore) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        file = directory.appendingPathComponent("events.audit", isDirectory: false)
        try files.prepare()
    }

    public func events() async throws -> [AuditEvent] {
        guard files.exists(file) else { return [] }
        do {
            return try decoder.decode(
                [AuditEvent].self,
                from: cipher.open(files.read(file), authenticating: Self.authenticatedContext)
            )
        } catch let error as VaultError {
            throw error
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    public func append(_ event: AuditEvent) async throws {
        var current = try await events()
        guard !current.contains(where: { $0.id == event.id }) else { return }
        current.append(event)
        try write(current)
    }

    public func delete(id: AuditEventID) async throws {
        let current = try await events()
        let remaining = current.filter { $0.id != id }
        guard remaining.count != current.count else { return }
        if remaining.isEmpty {
            try await deleteAll()
        } else {
            try write(remaining)
        }
    }

    private func write(_ events: [AuditEvent]) throws {
        do {
            try files.write(
                cipher.seal(
                    encoder.encode(events),
                    authenticating: Self.authenticatedContext
                ),
                to: file
            )
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }

    public func deleteAll() async throws {
        guard files.exists(file) else { return }
        do {
            try files.remove(file)
        } catch {
            throw WalletRepositoryError.storageFailure
        }
    }
}
