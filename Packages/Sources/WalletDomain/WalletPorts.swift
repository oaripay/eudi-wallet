import Foundation

/// OARI-owned display and policy metadata. Raw Wallet Kit document bytes and
/// document-bound keys must never cross this boundary.
public protocol CredentialMetadataRepository: Sendable {
    func credentials() async throws -> [CredentialRecord]
    func saveMetadata(_ credential: CredentialRecord) async throws
    func deleteMetadata(id: CredentialID) async throws
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
        requiresUserPresence: Bool,
        protection: KeyProtectionPolicy
    ) async throws -> KeyRecord

    func sign(_ request: SigningRequest) async throws -> Data
    func publicKey(id: KeyID) async throws -> PublicKeyMaterial
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
