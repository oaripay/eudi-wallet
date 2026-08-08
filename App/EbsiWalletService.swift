import EbsiW3CBackend
import Foundation
import WalletDomain

enum EbsiInteractionKind: Equatable, Sendable {
    case issuance
    case presentation
}

struct EbsiResolvedInteraction: Equatable, Identifiable, Sendable {
    let id: UUID
    let kind: EbsiInteractionKind
    let counterpartyIdentifier: String
    let displayName: String?
    let trustOutcome: EbsiTrustGateOutcome
    let transactionCodeRequired: Bool
    let transactionCodeLength: Int?
    let transactionCodeDescription: String?
    let configurationIDs: [String]
    let authorizationRequired: Bool
    let representations: [String]
    let credentialDisplay: [String: WorkspaceCredentialDisplay]
}

enum EbsiInteractionCompletion: Equatable, Sendable {
    case completed(String)
    case pending(String)
    case presentationRequired(WorkspacePresentationChallenge)
}

protocol EbsiW3COperating: Sendable {
    func resolveInteraction(uri: String) async throws -> EbsiResolvedInteraction
    func continueInteraction(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> EbsiInteractionCompletion
    func cancelInteraction(id: UUID) async
    func submitPIDPresentation(id: UUID, vpToken: String) async throws -> EbsiInteractionCompletion
    func completeAuthorization(id: UUID, code: String) async throws -> EbsiInteractionCompletion
}

actor LiveWorkspaceEbsiWalletService: EbsiW3COperating {
    private let backend: OariWorkspaceW3CBackend
    private let metadata: any CredentialMetadataRepository
    private let audit: any AuditRepository
    private var issuers: [UUID: String] = [:]
    private var authorizationRequired: Set<UUID> = []

    init(
        backend: OariWorkspaceW3CBackend,
        metadata: any CredentialMetadataRepository,
        audit: any AuditRepository
    ) {
        self.backend = backend
        self.metadata = metadata
        self.audit = audit
    }

    func resolveInteraction(uri: String) async throws -> EbsiResolvedInteraction {
        let offer = try await backend.resolveOffer(uri)
        issuers[offer.id] = offer.issuer
        if offer.authorizationRequired { authorizationRequired.insert(offer.id) }
        return EbsiResolvedInteraction(
            id: offer.id,
            kind: .issuance,
            counterpartyIdentifier: offer.issuer,
            displayName: offer.displayName,
            trustOutcome: offer.trustOutcome,
            transactionCodeRequired: offer.transactionCodeRequired,
            transactionCodeLength: offer.transactionCodeLength,
            transactionCodeDescription: offer.transactionCodeDescription,
            configurationIDs: offer.configurationIDs
            , authorizationRequired: offer.authorizationRequired,
            representations: offer.representations
            , credentialDisplay: offer.credentialDisplay
        )
    }

    func continueInteraction(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> EbsiInteractionCompletion {
        if authorizationRequired.contains(id) {
            return .presentationRequired(try await backend.beginPresentationRequired(
                id: id,
                allowUntrusted: allowUntrusted
            ))
        }
        let credentials = try await backend.issue(
            id: id,
            allowUntrusted: allowUntrusted,
            transactionCode: transactionCode
        )
        let issuer = issuers.removeValue(forKey: id) ?? "unknown"
        authorizationRequired.remove(id)
        var credentialIDs: [CredentialID] = []
        for credential in credentials {
            let record = CredentialRecord(
                configurationID: credential.configurationID,
                backendID: "oari-workspace-w3c",
                backendDocumentID: credential.id.uuidString,
                displayName: credential.displayName,
                format: credential.representation == .dcSdJwt || credential.representation == .vcdm2SdJwt
                    ? .sdJWTVC
                    : .jwtVC,
                 profileID: credential.profileID,
                 issuerIdentifier: issuer,
                 cryptographicValidity: .valid,
                issuerTrust: allowUntrusted ? .untrusted : .trusted,
                status: .notEvaluated,
                legalClassification: .oariProvisional,
                 createdAt: Date(),
                 displayClaims: credential.displayClaims,
                 display: credential.display
            )
            try await metadata.saveMetadata(record)
            credentialIDs.append(record.id)
        }
        try await audit.append(AuditEvent(
            operation: .issuance,
            outcome: .completed,
            occurredAt: Date(),
            counterpartyIdentifierDigest: .sha256(issuer),
            credentialIDs: credentialIDs,
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        ))
        return .completed("Issued and stored \(credentials.count) W3C credential(s).")
    }

    func cancelInteraction(id: UUID) async {
        issuers[id] = nil
        authorizationRequired.remove(id)
        await backend.cancel(id: id)
    }

    func submitPIDPresentation(id: UUID, vpToken: String) async throws -> EbsiInteractionCompletion {
        _ = try await backend.submitPresentation(id: id, vpToken: vpToken)
        return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
    }
    func completeAuthorization(id: UUID, code: String) async throws -> EbsiInteractionCompletion {
        try await backend.acceptAuthorizationCode(id: id, code: code)
        return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
    }
}
