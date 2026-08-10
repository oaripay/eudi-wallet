import EbsiW3CBackend
import EudiWalletKitAdapter
import Foundation
import WalletDomain

enum OpenID4VCInteractionKind: Equatable, Sendable {
    case issuance
    case presentation
}

struct OpenID4VCResolvedInteraction: Equatable, Identifiable, Sendable {
    let id: UUID
    let kind: OpenID4VCInteractionKind
    let counterpartyIdentifier: String
    let displayName: String?
    let trustOutcome: EbsiTrustGateOutcome
    let transactionCodeRequired: Bool
    let transactionCodeLength: Int?
    let transactionCodeDescription: String?
    let configurationIDs: [String]
    let authorizationRequired: Bool
    let representations: [String]
    let credentialDisplay: [String: CredentialConfigurationDisplay]
}

enum OpenID4VCInteractionCompletion: Equatable, Sendable {
    case completed(String)
    case pending(String)
    case presentationRequired(OpenID4VPPresentationRequest)
    case credentialSignerTrustWarning(EbsiTrustWarning)
}

protocol OpenID4VCOperating: Sendable {
    func resolveInteraction(uri: String) async throws -> OpenID4VCResolvedInteraction
    func beginPresentation(uri: String) async throws -> EudiPresentationRequest
    func completePresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> URL?
    func continueInteraction(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> OpenID4VCInteractionCompletion
    func cancelInteraction(id: UUID) async
    func preparePIDPresentation(id: UUID) async throws -> EudiPresentationRequest
    func completePIDPresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> OpenID4VCInteractionCompletion
    func completeAuthorization(id: UUID, code: String) async throws -> OpenID4VCInteractionCompletion
    func deleteCredential(
        backendID: UUID,
        metadataID: CredentialID,
        issuerIdentifier: String
    ) async throws
}

actor LiveOpenID4VCService: OpenID4VCOperating {
    private let backend: OpenID4VCW3CBackend
    private let metadata: any CredentialMetadataRepository
    private let audit: any AuditRepository
    private var issuers: [UUID: String] = [:]
    private var authorizationRequired: Set<UUID> = []

    init(
        backend: OpenID4VCW3CBackend,
        metadata: any CredentialMetadataRepository,
        audit: any AuditRepository
    ) {
        self.backend = backend
        self.metadata = metadata
        self.audit = audit
    }

    func resolveInteraction(uri: String) async throws -> OpenID4VCResolvedInteraction {
        let offer = try await backend.resolveOffer(uri)
        issuers[offer.id] = offer.issuer
        if offer.authorizationRequired { authorizationRequired.insert(offer.id) }
        return OpenID4VCResolvedInteraction(
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

    func beginPresentation(uri: String) async throws -> EudiPresentationRequest {
        let request = try await backend.beginStoredOpenID4VPPresentation(uri: uri)
        return presentationRequest(request)
    }

    func completePresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> URL? {
        let redirectURI = try await backend.completeStoredOpenID4VPPresentation(
            id: id,
            selectedClaimIDs: selectedClaimIDs,
            userAccepted: userAccepted
        )
        try await audit.append(AuditEvent(
            operation: .presentation,
            outcome: userAccepted ? .completed : .cancelled,
            occurredAt: Date(),
            counterpartyIdentifierDigest: .sha256("openid4vp"),
            credentialIDs: [],
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        ))
        return redirectURI
    }

    func continueInteraction(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> OpenID4VCInteractionCompletion {
        if authorizationRequired.contains(id) {
            return .presentationRequired(try await backend.beginPresentationRequired(
                id: id,
                allowUntrusted: allowUntrusted,
                interactionTypes: ["urn:openid:dcp:ia:openid4vp_presentation"]
            ))
        }
        let credentials: [IssuedW3CCredential]
        do {
            credentials = try await backend.issue(
                id: id,
                allowUntrusted: allowUntrusted,
                transactionCode: transactionCode
            )
        } catch OpenID4VCBackendError.credentialSignerTrustWarning(let warning) {
            return .credentialSignerTrustWarning(warning)
        }
        let issuer = issuers.removeValue(forKey: id) ?? "unknown"
        authorizationRequired.remove(id)
        var credentialIDs: [CredentialID] = []
        for credential in credentials {
            let record = CredentialRecord(
                configurationID: credential.configurationID,
                backendID: W3CBackendComposition.backendID,
                backendDocumentID: credential.id.uuidString,
                displayName: credential.displayName,
                format: credential.representation == .dcSdJwt || credential.representation == .vcdm2SdJwt
                    ? .sdJWTVC
                    : .jwtVC,
                 profileID: credential.profileID,
                 issuerIdentifier: credential.issuerIdentifier,
                cryptographicValidity: .valid,
                issuerTrust: allowUntrusted ? .untrusted : .trusted,
                status: credential.hasStatusReference ? .notEvaluated : .notProvided,
                legalClassification: .provisional,
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

    func preparePIDPresentation(id: UUID) async throws -> EudiPresentationRequest {
        let request = try await backend.prepareStoredPIDPresentation(id: id)
        return presentationRequest(request)
    }

    private func presentationRequest(_ request: DCQLCredentialPresentationRequest) -> EudiPresentationRequest {
        return EudiPresentationRequest(
            id: request.id,
            verifierName: request.verifierName,
            verifierLegalName: nil,
            verifierCertificateValid: nil,
            claims: request.claims.map { claim in
                EudiRequestedClaim(
                    id: claim.id,
                    documentID: request.id.uuidString,
                    documentType: "W3C credential",
                    displayName: "PID",
                    claimPath: claim.path,
                    displayValue: claim.value,
                    required: claim.required,
                    intentToRetain: false
                )
            },
            warningCount: 0
        )
    }

    func completePIDPresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> OpenID4VCInteractionCompletion {
        guard userAccepted else {
            await cancelInteraction(id: id)
            return .completed("PID request declined. Nothing was shared.")
        }
        let token = try await backend.storedPIDPresentationToken(
            id: id,
            selectedClaimIDs: selectedClaimIDs
        )
        return try await submitPIDPresentation(id: id, vpToken: token)
    }

    private func submitPIDPresentation(id: UUID, vpToken: String) async throws -> OpenID4VCInteractionCompletion {
        _ = try await backend.submitPresentation(id: id, vpToken: vpToken)
        authorizationRequired.remove(id)
        return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
    }
    func completeAuthorization(id: UUID, code: String) async throws -> OpenID4VCInteractionCompletion {
        try await backend.acceptAuthorizationCode(id: id, code: code)
        authorizationRequired.remove(id)
        return try await continueInteraction(id: id, allowUntrusted: true, transactionCode: nil)
    }

    func deleteCredential(
        backendID: UUID,
        metadataID: CredentialID,
        issuerIdentifier: String
    ) async throws {
        try await backend.deleteStoredCredential(id: backendID)
        try await metadata.deleteMetadata(id: metadataID)
        try await audit.append(AuditEvent(
            operation: .credentialDeletion,
            outcome: .completed,
            occurredAt: Date(),
            counterpartyIdentifierDigest: .sha256(issuerIdentifier),
            credentialIDs: [metadataID],
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        ))
    }
}
