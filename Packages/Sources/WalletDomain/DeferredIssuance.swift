import Foundation

public enum DeferredIssuanceState: String, Codable, Equatable, Sendable {
    case pending
    case authorizationRequired
    case signerTrustRequired
    case completing
    case failed
}

/// App-facing metadata around an opaque protocol continuation. The repository
/// encrypts the complete envelope, including `continuation`.
public struct DeferredIssuance: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let continuation: Data
    public let issuerIdentifier: String
    public let configurationIDs: [String]
    public let displayName: String
    public let display: CredentialDisplayMetadata?
    public let nextAttemptAt: Date
    public let attempts: Int
    public let state: DeferredIssuanceState
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        id: UUID = UUID(), continuation: Data, issuerIdentifier: String,
        configurationIDs: [String], displayName: String,
        display: CredentialDisplayMetadata? = nil, nextAttemptAt: Date,
        attempts: Int = 0, state: DeferredIssuanceState = .pending,
        createdAt: Date, updatedAt: Date
    ) {
        self.id = id
        self.continuation = continuation
        self.issuerIdentifier = issuerIdentifier
        self.configurationIDs = configurationIDs
        self.displayName = displayName
        self.display = display
        self.nextAttemptAt = nextAttemptAt
        self.attempts = attempts
        self.state = state
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public protocol DeferredIssuanceRepository: Sendable {
    func deferredIssuances() async throws -> [DeferredIssuance]
    func saveDeferredIssuance(_ issuance: DeferredIssuance) async throws
    func replaceDeferredIssuance(_ issuance: DeferredIssuance) async throws
    func deleteDeferredIssuance(id: UUID) async throws
}
