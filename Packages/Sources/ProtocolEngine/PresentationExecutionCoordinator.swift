import Foundation
import PresentationDomain
import WalletDomain

public struct PresentationExecutionCoordinator: Sendable {
    private let authenticator: any LocalAuthenticator
    private let signer: any PresentationSigner
    private let delivery: any PresentationDelivery
    private let auditRepository: any AuditRepository
    private let clock: @Sendable () -> Date

    public init(
        authenticator: any LocalAuthenticator,
        signer: any PresentationSigner,
        delivery: any PresentationDelivery,
        auditRepository: any AuditRepository,
        clock: @escaping @Sendable () -> Date = Date.init
    ) {
        self.authenticator = authenticator
        self.signer = signer
        self.delivery = delivery
        self.auditRepository = auditRepository
        self.clock = clock
    }

    public func execute(
        session: PresentationSession,
        request: PresentationRequest,
        authenticationReason: String,
        policy: AuditPolicy,
        policyVersion: AuditPolicyVersion
    ) async throws {
        let date = clock()
        guard !authenticationReason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ProtocolExecutionError.emptyAuthenticationReason
        }
        let reviewed = session.request
        let queryIdentifiers = request.dcqlCredentialIDs.isEmpty
            ? [request.presentationDefinitionID].compactMap { $0 }
            : request.dcqlCredentialIDs
        guard reviewed.protocolRequestID == request.id,
              reviewed.requesterIdentifier == request.clientID,
              reviewed.origin.normalizedOrigin == request.responseURI.normalizedOrigin,
              reviewed.profileID == request.profileID,
              reviewed.nonce == request.nonce,
              reviewed.expiresAt == request.expiresAt,
              request.expiresAt > date,
              reviewed.state == request.state,
              reviewed.requestedClaimIdentifiers == queryIdentifiers else {
            throw ProtocolExecutionError.invalidDeliveryOrigin
        }
        try await authenticator.authenticate(reason: authenticationReason)
        try await session.authenticate()

        guard request.expiresAt > clock() else {
            throw ProtocolExecutionError.invalidDeliveryOrigin
        }
        let credentialIDs = await session.selectedCredentialIDs
        let signed = try await signer.sign(request: request, credentialIDs: credentialIDs)
        guard !signed.payload.isEmpty else { throw ProtocolExecutionError.emptyPresentation }
        try await session.markSigned()

        guard request.responseURI.scheme == "https", request.responseURI.host != nil else {
            throw ProtocolExecutionError.invalidDeliveryOrigin
        }
        guard request.expiresAt > clock() else {
            throw ProtocolExecutionError.invalidDeliveryOrigin
        }
        try await delivery.deliver(signed, to: request.responseURI, state: request.state)
        try await session.markDelivered()

        let event = AuditEvent(
            operation: .presentation,
            outcome: .completed,
            occurredAt: date,
            counterpartyIdentifierDigest: .sha256(request.clientID),
            credentialIDs: credentialIDs,
            disclosedClaimDigests: request.dcqlCredentialIDs.map(AuditDigest.sha256),
            policy: policy,
            policyVersion: policyVersion
        )
        try await auditRepository.append(event)
        try await session.markRecorded()
    }
}
