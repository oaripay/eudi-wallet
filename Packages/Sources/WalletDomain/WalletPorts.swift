import Foundation

public protocol CredentialRepository: Sendable {
    func credentials() async throws -> [CredentialRecord]
    func credential(id: CredentialID) async throws -> CredentialEnvelope?
    func save(_ credential: CredentialEnvelope) async throws
    func delete(id: CredentialID) async throws
}

public protocol AuditRepository: Sendable {
    func events() async throws -> [AuditEvent]
    func append(_ event: AuditEvent) async throws
    func deleteAll() async throws
}

public protocol KeyProvider: Sendable {
    func createKey(
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
        requiresUserPresence: Bool
    ) async throws -> KeyRecord

    func sign(_ request: SigningRequest) async throws -> Data
    func deleteKey(id: KeyID) async throws
}

public protocol CredentialLifecycle: Sendable {
    func deleteCredential(id: CredentialID, at date: Date) async throws
}

public enum WalletRepositoryError: Error, Equatable, Sendable {
    case duplicateCredential
    case credentialNotFound
    case keyNotFound
    case unsupportedAlgorithm
    case userAuthenticationRequired
    case storageFailure
}
