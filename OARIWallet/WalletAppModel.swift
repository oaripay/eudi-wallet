import Foundation
import EudiWalletKitAdapter
import EbsiW3CBackend
import ProtocolEngine
import SwiftUI
import WalletDomain
import OariDesignSystem

@MainActor
final class WalletAppModel: ObservableObject {
    enum Tab: Hashable {
        case wallet
        case scan
        case history
        case settings
    }

    @Published private(set) var credentials: [CredentialRecord] = []
    @Published private(set) var auditEvents: [AuditEvent] = []
    @Published var theme: OariTheme = .dark
    @Published var scanInput = ""
    @Published private(set) var scanResult: ScanResult = .idle
    @Published private(set) var loadingState: LoadingState = .idle
    @Published private(set) var isPrivacyCoverVisible = false
    @Published var selectedTab: Tab = .wallet
    @Published private(set) var eudiFlow: EudiFlow = .idle
    @Published var selectedIssuanceConfigurationIDs: Set<String> = []
    @Published var selectedClaimIDs: Set<String> = []
    @Published var transactionCode = ""
    @Published var selectedCredential: CredentialRecord?
    @Published private(set) var walletDocumentSummaries: [String: EudiWalletDocumentSummary] = [:]
    @Published private(set) var credentialActionState: CredentialActionState = .idle
    @Published var showsOnboarding: Bool
    @Published private(set) var eudiAvailability: EudiWalletAvailability = .configurationRequired("Loading wallet profile…")
    @Published var ebsiTrustWarning: EbsiTrustWarning?
    @Published var ebsiTransactionCode = ""
    private let allowedHosts: Set<String>
    private var eudiWallet: (any EudiWalletOperating)?
    private var ebsiWallet: (any EbsiW3COperating)?
    private var activeEbsiInteractionID: UUID?
    private var activeEbsiChallenge: WorkspacePresentationChallenge?
    private var activeEbsiInteraction: EbsiResolvedInteraction?
    private var activeEbsiAllowsUntrusted = false
    private var repositories: (credentials: any CredentialMetadataRepository, audit: any AuditRepository)?
    private var activePendingIssuanceID: UUID?
    private var activePendingIssuance: EudiPendingIssuance?

    init(
        allowedHosts: Set<String> = ["wallet.dev.oari.io"],
        showsOnboarding: Bool = false
    ) {
        self.allowedHosts = allowedHosts
        self.showsOnboarding = showsOnboarding
    }

    enum LoadingState: Equatable {
        case idle
        case loading
        case loaded
        case failed(String)
    }

    enum ScanResult: Equatable {
        case idle
        case presentation
        case issuance
        case unsupported
        case rejected(String)
    }

    enum EudiFlow: Equatable {
        case idle
        case working(String)
        case issuanceReview(EudiIssuanceOffer)
        case presentationConsent(EudiPresentationRequest)
        case pending(EudiPendingIssuance)
        case completed(String)
        case failed(String)
        case configurationRequired(String)
        case ebsiIssuanceReview(EbsiResolvedInteraction)
        case ebsiPresentationRequired(WorkspacePresentationChallenge)
    }

    enum CredentialActionState: Equatable {
        case idle
        case working(String)
        case completed(String)
        case failed(String)
    }

    var credentialCountDescription: String {
        switch credentials.count {
        case 0: "No credentials"
        case 1: "1 credential"
        default: "\(credentials.count) credentials"
        }
    }

    func load(
        credentials repository: any CredentialMetadataRepository,
        audit auditRepository: any AuditRepository
    ) async throws {
        credentials = try await repository.credentials()
        auditEvents = try await auditRepository.events().sorted { $0.occurredAt > $1.occurredAt }
    }

    func load(_ dependencies: Result<WalletAppDependencies, Error>) async {
        loadingState = .loading
        do {
            let dependencies = try dependencies.get()
            eudiWallet = dependencies.eudiWallet
            eudiAvailability = dependencies.eudiAvailability
            ebsiWallet = dependencies.ebsiWallet
            repositories = (dependencies.credentials, dependencies.audit)
            try await load(credentials: dependencies.credentials, audit: dependencies.audit)
            if isEudiOperational, let eudiWallet {
                try await eudiWallet.reconcilePendingOperations()
                walletDocumentSummaries = Dictionary(
                    uniqueKeysWithValues: try await eudiWallet.loadDocumentSummaries().map { ($0.id, $0) }
                )
                if let pending = try await eudiWallet.loadPendingIssuances().first {
                    activePendingIssuanceID = pending.id
                    activePendingIssuance = pending
                    eudiFlow = .pending(pending)
                }
            } else if case let .configurationRequired(message) = dependencies.eudiAvailability {
                eudiFlow = .configurationRequired(message)
            }
            loadingState = .loaded
        } catch {
            loadingState = .failed("Development wallet setup failed: \(Self.developmentErrorMessage(error))")
        }
    }

    func classifyScan() {
        do {
            switch try ProtocolInputClassifier(allowedHosts: allowedHosts).classify(scanInput) {
            case .openID4VP: scanResult = .presentation
            case .openID4VCI: scanResult = .issuance
            case .unsupported: scanResult = .unsupported
            }
        } catch {
            scanResult = .rejected("The code is malformed or is not from an approved host.")
        }
    }

    func handleIncomingURL(_ url: URL) {
        handleScannedCode(url.absoluteString)
    }

    func handleScannedCode(_ code: String) {
        scanInput = code
        classifyScan()
        selectedTab = .scan
    }

    func reviewScannedRequest() async {
        classifyScan()
        guard isEudiOperational, let eudiWallet else {
            eudiFlow = .configurationRequired(eudiConfigurationMessage)
            return
        }
        do {
            switch scanResult {
            case .issuance:
                eudiFlow = .working("Checking the issuer and credential offer…")
                var w3cRoutingError: Error?
                if let ebsiWallet {
                    do {
                        let interaction = try await ebsiWallet.resolveInteraction(uri: scanInput)
                        activeEbsiInteractionID = interaction.id
                        activeEbsiInteraction = interaction
                        switch interaction.trustOutcome {
                        case .allow: prepareEbsiInteraction(allowUntrusted: false)
                        case let .requireExplicitWarning(warning): ebsiTrustWarning = warning; eudiFlow = .idle
                        case .reject: throw WorkspaceBackendError.rejectedTrust
                        }
                        return
                    } catch {
                        if case WorkspaceBackendError.unsupportedGrant = error {
                            // The offer advertises a non-W3C format; let Wallet Kit claim it.
                        } else {
                            w3cRoutingError = error
                        }
                    }
                }
                do {
                    let offer = try await eudiWallet.resolveIssuanceOffer(uri: scanInput)
                    selectedIssuanceConfigurationIDs = Set(offer.documents.map(\.configurationID))
                    transactionCode = ""
                    eudiFlow = .issuanceReview(offer)
                } catch {
                    if let w3cRoutingError { throw w3cRoutingError }
                    guard let ebsiWallet else { throw error }
                    let interaction = try await ebsiWallet.resolveInteraction(uri: scanInput)
                    activeEbsiInteractionID = interaction.id
                    activeEbsiInteraction = interaction
                    switch interaction.trustOutcome {
                    case .allow: prepareEbsiInteraction(allowUntrusted: false)
                    case let .requireExplicitWarning(warning): ebsiTrustWarning = warning; eudiFlow = .idle
                    case .reject: throw error
                    }
                }
            case .presentation:
                eudiFlow = .working("Checking the verifier and requested claims…")
                activePendingIssuanceID = nil
                let request = try await eudiWallet.beginOpenID4VPPresentation(requestURI: scanInput)
                selectedClaimIDs = Set(request.claims.filter(\.required).map(\.id))
                eudiFlow = .presentationConsent(request)
            case .idle, .unsupported, .rejected:
                break
            }
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func redeemScannedRequest() async {
        classifyScan()
        if !isEudiOperational {
            await reviewEbsiScannedRequest()
        } else {
            await reviewScannedRequest()
        }
    }

    var isEbsiDevelopmentAvailable: Bool { ebsiWallet != nil }

    func reviewEbsiScannedRequest() async {
        guard let ebsiWallet else {
            eudiFlow = .configurationRequired("No EBSI development backend is configured.")
            return
        }
        eudiFlow = .working("Checking EBSI issuer or verifier trust…")
        do {
            let interaction = try await ebsiWallet.resolveInteraction(uri: scanInput)
            activeEbsiInteractionID = interaction.id
            activeEbsiInteraction = interaction
            switch interaction.trustOutcome {
            case .allow:
                prepareEbsiInteraction(allowUntrusted: false)
            case let .requireExplicitWarning(warning):
                ebsiTrustWarning = warning
                eudiFlow = .idle
            case .reject:
                activeEbsiInteractionID = nil
                eudiFlow = .failed("The EBSI request failed cryptographic or trust-policy validation.")
            }
        } catch {
            activeEbsiInteractionID = nil
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func continueAfterEbsiTrustWarning() async {
        guard ebsiTrustWarning != nil,
              activeEbsiInteractionID != nil else { return }
        ebsiTrustWarning = nil
        prepareEbsiInteraction(allowUntrusted: true)
    }

    func cancelEbsiTrustWarning() async {
        let id = activeEbsiInteractionID
        ebsiTrustWarning = nil
        activeEbsiInteractionID = nil
        activeEbsiInteraction = nil
        if let id { await ebsiWallet?.cancelInteraction(id: id) }
        eudiFlow = .completed("EBSI request cancelled. Nothing was shared or stored.")
    }

    func issueReviewedEbsiCredential() async {
        do {
            try await continueEbsiInteraction()
            try await refreshWalletState()
        }
        catch {
            if let id = activeEbsiInteractionID { await ebsiWallet?.cancelInteraction(id: id) }
            activeEbsiInteractionID = nil
            activeEbsiInteraction = nil
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func startEudiPresentationForEbsi(_ challenge: WorkspacePresentationChallenge) async {
        guard let eudiWallet else {
            eudiFlow = .configurationRequired("EUDI Wallet Kit is not configured for PID presentation.")
            return
        }
        activeEbsiChallenge = challenge
        let requestObject: String
        if let signedRequest = challenge.signedRequest {
            requestObject = signedRequest
        } else {
            var object: [String: Any] = [
                "response_type": "vp_token",
                "response_mode": "direct_post",
                "response_uri": challenge.authorizationEndpoint.absoluteString,
                "nonce": challenge.nonce,
                "dcql_query": challenge.dcqlQuery,
            ]
            if let state = challenge.authSession ?? challenge.state { object["state"] = state }
            guard let data = try? JSONSerialization.data(withJSONObject: object),
                  let encoded = String(data: data, encoding: .utf8),
                  let escaped = encoded.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
                eudiFlow = .failed("The issuer returned an invalid PID presentation request.")
                return
            }
            requestObject = escaped
        }
        let requestURI = "openid4vp://authorize?request=\(requestObject)"
        do {
            eudiFlow = .working("Preparing PID presentation…")
            let request = try await eudiWallet.beginOpenID4VPPresentation(requestURI: requestURI)
            selectedClaimIDs = Set(request.claims.filter(\.required).map(\.id))
            eudiFlow = .presentationConsent(request)
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    private func prepareEbsiInteraction(allowUntrusted: Bool) {
        guard let interaction = activeEbsiInteraction else {
            eudiFlow = .failed("The EBSI transaction expired before consent.")
            return
        }
        activeEbsiAllowsUntrusted = allowUntrusted
        ebsiTransactionCode = ""
        eudiFlow = .ebsiIssuanceReview(interaction)
    }

    private func continueEbsiInteraction() async throws {
        guard let id = activeEbsiInteractionID, let ebsiWallet else {
            throw EbsiCredentialError.backendUnavailable
        }
        eudiFlow = .working("Continuing EBSI development flow…")
        let result = try await ebsiWallet.continueInteraction(
            id: id,
            allowUntrusted: activeEbsiAllowsUntrusted,
            transactionCode: ebsiTransactionCode.isEmpty ? nil : ebsiTransactionCode
        )
        activeEbsiInteractionID = nil
        activeEbsiInteraction = nil
        switch result {
        case let .completed(message), let .pending(message): eudiFlow = .completed(message)
        case let .presentationRequired(challenge): eudiFlow = .ebsiPresentationRequired(challenge)
        }
    }

    func acceptIssuance() async {
        guard isEudiOperational, case let .issuanceReview(offer) = eudiFlow, let eudiWallet else {
            eudiFlow = .configurationRequired(eudiConfigurationMessage)
            return
        }
        eudiFlow = .working("Adding the credential securely…")
        do {
            let result = try await eudiWallet.issueResolvedOffer(
                id: offer.id,
                profileID: "eudi-final-1",
                selectedConfigurationIDs: selectedIssuanceConfigurationIDs,
                transactionCode: transactionCode.isEmpty ? nil : transactionCode,
                promptMessage: "Authenticate to add this credential to OARI Wallet"
            )
            if let pending = result.pendingIssuances.first {
                activePendingIssuanceID = pending.id
                activePendingIssuance = pending
                eudiFlow = .pending(pending)
            } else {
                eudiFlow = .completed("Credential added to your wallet.")
            }
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func continuePendingIssuance() async {
        guard isEudiOperational, case let .pending(pending) = eudiFlow, let eudiWallet else {
            eudiFlow = .configurationRequired(eudiConfigurationMessage)
            return
        }
        eudiFlow = .working("Preparing PID verification…")
        do {
            activePendingIssuanceID = pending.id
            activePendingIssuance = pending
            let request = try await eudiWallet.beginPendingIssuancePresentation(id: pending.id)
            selectedClaimIDs = Set(request.claims.filter(\.required).map(\.id))
            eudiFlow = .presentationConsent(request)
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func submitPresentation(accepted: Bool) async {
        guard isEudiOperational, case let .presentationConsent(request) = eudiFlow, let eudiWallet else {
            eudiFlow = .configurationRequired(eudiConfigurationMessage)
            return
        }
        eudiFlow = .working(accepted ? "Sharing approved claims…" : "Declining the request…")
        do {
            let completion = try await eudiWallet.completePresentation(
                id: request.id,
                pendingIssuanceID: activePendingIssuanceID,
                selectedClaimIDs: accepted ? selectedClaimIDs : [],
                userAccepted: accepted
            )
            switch completion {
            case let .issuance(result):
                if let pending = result.pendingIssuances.first {
                    activePendingIssuanceID = pending.id
                    activePendingIssuance = pending
                    eudiFlow = .pending(pending)
                } else {
                    activePendingIssuanceID = nil
                    activePendingIssuance = nil
                    eudiFlow = .completed("Identity verified and credential added.")
                }
            case .pendingDeclined:
                if let activePendingIssuance {
                    eudiFlow = .pending(activePendingIssuance)
                } else {
                    eudiFlow = .failed("The pending credential could not be restored safely.")
                }
            case .presentation:
                activePendingIssuanceID = nil
                activePendingIssuance = nil
                eudiFlow = .completed(accepted ? "Approved claims were shared." : "Request declined. Nothing was shared.")
            case let .externalAuthorization(code):
                guard let id = activeEbsiInteractionID, let ebsiWallet else {
                    eudiFlow = .failed("The EBSI authorization transaction expired.")
                    return
                }
                let result = try await ebsiWallet.completeAuthorization(id: id, code: code)
                activeEbsiInteractionID = nil
                activeEbsiInteraction = nil
                activeEbsiChallenge = nil
                switch result {
                case let .completed(message), let .pending(message): eudiFlow = .completed(message)
                case .presentationRequired: eudiFlow = .failed("The issuer requested another unsupported presentation step.")
                }
            }
        } catch {
            eudiFlow = .failed(Self.safeMessage(error))
        }
    }

    func dismissEudiFlow() {
        eudiFlow = .idle
    }

    var hasRecoverablePendingIssuance: Bool { activePendingIssuance != nil }
    var isEudiOperational: Bool {
        eudiWallet != nil && eudiAvailability == .available
    }
    private var eudiConfigurationMessage: String {
        if case let .configurationRequired(message) = eudiAvailability { return message }
        return "EUDI wallet services are not configured for this environment."
    }
    var preventsInteractiveFlowDismissal: Bool {
        switch eudiFlow {
        case .working, .presentationConsent: true
        default: false
        }
    }

    func returnToPendingIssuance() {
        if let activePendingIssuance { eudiFlow = .pending(activePendingIssuance) }
    }

    func selectCredential(_ credential: CredentialRecord) {
        credentialActionState = .idle
        selectedCredential = credential
    }

    func deleteSelectedCredential() async {
        guard isEudiOperational, !credentialActionIsWorking,
              let credential = selectedCredential,
              let documentID = credential.walletDocumentID,
              let eudiWallet else { return }
        credentialActionState = .working("Removing credential…")
        do {
            try await eudiWallet.deleteDocument(
                id: documentID,
                status: walletDocumentSummaries[documentID]?.status ?? "issued"
            )
            try await refreshWalletState()
            credentialActionState = .completed("Credential removed.")
        } catch {
            credentialActionState = .failed(Self.safeMessage(error))
        }
    }

    func retrySelectedDeferredCredential() async {
        guard isEudiOperational, !credentialActionIsWorking,
              let credential = selectedCredential,
              let documentID = credential.walletDocumentID,
              let eudiWallet else { return }
        credentialActionState = .working("Checking deferred issuance…")
        do {
            let summary = try await eudiWallet.retryDeferredIssuance(
                issuerName: credential.issuerIdentifier,
                documentID: documentID
            )
            try await refreshWalletState()
            walletDocumentSummaries[summary.id] = summary
            credentialActionState = summary.status == "issued"
                ? .completed("Credential issuance completed.")
                : .completed("Credential is still pending at the issuer.")
        } catch {
            credentialActionState = .failed(Self.safeMessage(error))
        }
    }

    func dismissCredentialAction() { credentialActionState = .idle }
    var credentialActionIsWorking: Bool {
        if case .working = credentialActionState { true } else { false }
    }
    func acknowledgeCredentialAction() {
        if case .completed = credentialActionState,
           let selectedCredential,
           !credentials.contains(where: { $0.id == selectedCredential.id }) {
            self.selectedCredential = nil
        }
        credentialActionState = .idle
    }

    func documentStatus(for credential: CredentialRecord) -> String? {
        credential.walletDocumentID.flatMap { walletDocumentSummaries[$0]?.status }
    }

    func completeOnboarding() {
        UserDefaults.standard.set(true, forKey: "oari.onboarding.completed")
        showsOnboarding = false
    }

    private func refreshWalletState() async throws {
        guard let repositories else { return }
        try await load(credentials: repositories.credentials, audit: repositories.audit)
        if let eudiWallet {
            walletDocumentSummaries = Dictionary(
                uniqueKeysWithValues: try await eudiWallet.loadDocumentSummaries().map { ($0.id, $0) }
            )
        }
    }

    private static func safeMessage(_ error: Error) -> String {
        if let error = error as? WorkspaceBackendError {
            switch error {
            case .malformedOffer: return "The issuer offer is malformed or missing a credential offer payload."
            case .unsafeEndpoint: return "The issuer endpoint is not an allowed HTTPS development endpoint."
            case .unsupportedGrant: return "This issuer grant is not implemented by the development wallet yet."
            case .invalidTransactionCode: return "The transaction code is invalid for this offer."
            case .untrustedConsentRequired: return "Review the development trust warning before continuing."
            case .rejectedTrust: return "The issuer request failed trust or signature validation."
            case .invalidResponse: return "The issuer returned an invalid or incomplete OpenID4VCI response."
            case .unknownTransaction: return "The issuer transaction expired or was already used."
            case .presentationRequired: return "The issuer requires PID presentation before issuing this credential."
            case .invalidPresentationResponse: return "The issuer rejected the PID presentation response."
            case .authorizationFailed: return "The issuer authorization exchange failed."
            case let .remoteOAuthError(code, detail):
                if code == "invalid_grant" {
                    return "This credential offer has expired or was already redeemed. Scan a new offer from the issuer."
                }
                return detail.map { "The issuer returned \(code): \($0)" } ?? "The issuer returned \(code)."
            }
        }
        if let error = error as? EbsiCredentialError {
            switch error {
            case .invalidProfile: return "The issuer credential profile is invalid."
            case .malformedCredential: return "The issuer returned a malformed credential."
            case .profileMismatch: return "The credential does not match its advertised W3C profile."
            case .algorithmNotAllowed: return "The credential uses an unsupported signing algorithm."
            case .unsupportedRepresentation: return "The credential representation is not supported by this wallet."
            case .verificationFailed: return "The credential signature, issuer DID, or holder binding could not be verified."
            case .issuerDIDUnresolved: return "The issuer DID could not be resolved. Development trust override is required."
            case .invalidSignature: return "The credential signature is invalid. This cannot be overridden."
            case .invalidHolderBinding: return "The credential is not bound to this wallet. This cannot be overridden."
            case .backendUnavailable: return "The W3C credential backend is unavailable."
            }
        }
        guard let error = error as? EudiWalletKitAdapterError else {
            return "Development wallet error: \(String(describing: error))"
        }
        return switch error {
        case .unapprovedIssuer: "This issuer is not approved for the active wallet profile."
        case .unapprovedVerifier: "This verifier is not approved for the active wallet profile."
        case .invalidTransactionCode: "Check the transaction code and try again."
        case .requiredClaimMissing: "Required claims must remain selected."
        case .recoveryRequired: "Wallet recovery must finish before this action can continue."
        default: "Development EUDI Wallet Kit error: \(String(describing: error))"
        }
    }


    private static func developmentErrorMessage(_ error: Error) -> String {
        if let error = error as? EudiWalletKitAdapterError {
            return "EUDI Wallet Kit \(String(describing: error))"
        }
        if let error = error as? WorkspaceBackendError {
            return "EBSI backend \(String(describing: error))"
        }
        return String(describing: error)
    }

    func setPrivacyCoverVisible(_ visible: Bool) {
        isPrivacyCoverVisible = visible
    }
}
