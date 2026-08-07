import Foundation
import ProfileDomain
import WalletDomain

public enum IssuanceExecutionResult: Equatable, Sendable {
    case stored(CredentialID)
    case deferred(transactionID: String, retryAfter: TimeInterval)
}

public struct IssuanceExecutionCoordinator: Sendable {
    private let repository: any CredentialMetadataRepository
    private let auditRepository: any AuditRepository

    public init(
        repository: any CredentialMetadataRepository,
        auditRepository: any AuditRepository
    ) {
        self.repository = repository
        self.auditRepository = auditRepository
    }

    public func process(
        response: CredentialResponse,
        request: IssuanceRequest,
        profile: InteroperabilityProfile,
        policy: AuditPolicy,
        policyVersion: AuditPolicyVersion,
        at date: Date
    ) async throws -> IssuanceExecutionResult {
        switch response {
        case let .deferred(transactionID, interval):
            guard !transactionID.isEmpty, interval > 0 else {
                throw ProtocolExecutionError.invalidCredential
            }
            return .deferred(transactionID: transactionID, retryAfter: interval)
        case let .issued(metadata):
            guard metadata.configurationID == request.configurationID,
                  metadata.profileID == profile.id.rawValue,
                  metadata.issuerIdentifier == request.issuer.absoluteString,
                  metadata.cryptographicValidity == .valid else {
                throw ProtocolExecutionError.invalidCredential
            }
            try await repository.saveMetadata(metadata)
            try await auditRepository.append(
                AuditEvent(
                    operation: .issuance,
                    outcome: .completed,
                    occurredAt: date,
                    counterpartyIdentifierDigest: .sha256(request.issuer.absoluteString),
                    credentialIDs: [metadata.id],
                    policy: policy,
                    policyVersion: policyVersion
                )
            )
            return .stored(metadata.id)
        }
    }
}
