import Foundation
import ProfileDomain
import WalletDomain

public enum IssuanceExecutionResult: Equatable, Sendable {
    case stored(CredentialID)
    case deferred(transactionID: String, retryAfter: TimeInterval)
}

public struct IssuanceExecutionCoordinator: Sendable {
    private let validator: any IssuedCredentialValidator
    private let repository: any CredentialRepository
    private let auditRepository: any AuditRepository

    public init(
        validator: any IssuedCredentialValidator,
        repository: any CredentialRepository,
        auditRepository: any AuditRepository
    ) {
        self.validator = validator
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
        case let .issued(encodedCredential):
            guard !encodedCredential.isEmpty else {
                throw ProtocolExecutionError.invalidCredential
            }
            let envelope = try await validator.validate(
                encodedCredential: encodedCredential,
                request: request,
                profile: profile,
                at: date
            )
            try await repository.save(envelope)
            try await auditRepository.append(
                AuditEvent(
                    operation: .issuance,
                    outcome: .completed,
                    occurredAt: date,
                    counterpartyIdentifierDigest: .sha256(request.issuer.absoluteString),
                    credentialIDs: [envelope.record.id],
                    policy: policy,
                    policyVersion: policyVersion
                )
            )
            return .stored(envelope.record.id)
        }
    }
}
