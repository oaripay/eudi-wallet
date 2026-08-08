import Foundation
import EudiWalletKitAdapter
import EbsiW3CBackend
import ProtocolEngine
import Testing
import WalletDomain
@testable import OariWallet

@MainActor
struct WalletAppModelTests {
    @Test("Empty wallet never implies readiness or trust")
    func emptyState() {
        let model = WalletAppModel()
        #expect(model.credentialCountDescription == "No credentials")
        #expect(model.scanResult == .idle)
    }

    @Test("Scanner rejects unapproved hosts and classifies approved requests")
    func scanClassification() {
        let model = WalletAppModel()
        model.scanInput = "https://evil.example/present?request=x"
        model.classifyScan()
        guard case .rejected = model.scanResult else {
            Issue.record("Unapproved host must reject")
            return
        }
        model.scanInput = "https://wallet.dev.oari.io/present?request=x"
        model.classifyScan()
        #expect(model.scanResult == .presentation)
    }

    @Test("Incoming URL is classified through the same bounded scanner route")
    func incomingURL() {
        let model = WalletAppModel(allowedHosts: ["verifier.example"])
        model.handleIncomingURL(URL(string: "openid4vp://authorize?request=x")!)
        #expect(model.scanResult == .presentation)
        #expect(model.scanInput.hasPrefix("openid4vp://"))
        #expect(model.selectedTab == .scan)
    }

    @Test("Privacy cover state follows explicit lifecycle input")
    func privacyCover() {
        let model = WalletAppModel()
        model.setPrivacyCoverVisible(true)
        #expect(model.isPrivacyCoverVisible)
        model.setPrivacyCoverVisible(false)
        #expect(!model.isPrivacyCoverVisible)
    }

    @Test("Camera and pasted codes share the bounded classification route")
    func scannedCode() {
        let model = WalletAppModel(allowedHosts: ["issuer.example"])
        model.handleScannedCode(
            "https://issuer.example/offer?credential_offer=fixture"
        )
        #expect(model.scanResult == .issuance)
        #expect(model.selectedTab == .scan)
    }

    @Test("Repository failure is explicit and does not imply an empty loaded wallet")
    func repositoryFailure() async {
        let model = WalletAppModel()
        await model.load(.failure(TestFailure.unavailable))
        guard case let .failed(message) = model.loadingState else {
            Issue.record("Expected explicit loading failure")
            return
        }
        #expect(message.contains("unavailable"))
    }

    @Test("Issuance review delegates to EUDI service and reaches completion")
    func eudiIssuanceFlow() async {
        let service = FixtureEudiWallet()
        let model = WalletAppModel(allowedHosts: ["issuer.example"])
        let dependencies = WalletAppDependencies(
            credentials: EmptyMetadataRepository(),
            audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(),
            eudiWallet: service,
            eudiAvailability: .available,
            ebsiWallet: nil
        )
        await model.load(.success(dependencies))
        model.scanInput = "https://issuer.example/credential-offer?credential_offer=fixture"
        await model.reviewScannedRequest()
        guard case .issuanceReview = model.eudiFlow else {
            Issue.record("Expected issuance review")
            return
        }
        await model.acceptIssuance()
        #expect(model.eudiFlow == .idle)
        #expect(model.scanInput.isEmpty)
        #expect(model.selectedTab == .wallet)
        #expect(await service.issueCount == 1)
    }

    @Test("Presentation consent preselects required claims and completes")
    func eudiPresentationFlow() async {
        let required = EudiRequestedClaim(
            id: "required", documentID: "pid", documentType: "pid", displayName: "PID",
            claimPath: ["family_name"], displayValue: "Holder", required: true, intentToRetain: false
        )
        let optional = EudiRequestedClaim(
            id: "optional", documentID: "pid", documentType: "pid", displayName: "PID",
            claimPath: ["age_over_18"], displayValue: "true", required: false, intentToRetain: false
        )
        let service = FixtureEudiWallet(presentationRequest: EudiPresentationRequest(
            id: UUID(), verifierName: "Verifier", verifierLegalName: "Verifier Ltd",
            verifierCertificateValid: true, claims: [required, optional], warningCount: 0
        ))
        let model = WalletAppModel()
        await model.load(.success(testDependencies(service)))
        model.scanInput = "openid4vp://authorize?request_uri=https%3A%2F%2Fwallet.dev.oari.io%2Frequest"
        await model.reviewScannedRequest()
        #expect(model.selectedClaimIDs == ["required"])
        #expect(model.preventsInteractiveFlowDismissal)
        model.selectedClaimIDs.insert("optional")
        await model.submitPresentation(accepted: true)
        #expect(model.eudiFlow == .completed("Approved claims were shared."))
        #expect(await service.lastSelectedClaims == ["required", "optional"])
    }

    @Test("Restored pending issuance continues through consent and completion")
    func eudiPendingFlow() async {
        let pending = EudiPendingIssuance(
            id: UUID(),
            document: EudiWalletDocumentSummary(
                id: "wallet-document", documentType: "pid", displayName: "PID upgrade",
                format: "sjwt", status: "pending"
            )
        )
        let request = EudiPresentationRequest(
            id: UUID(), verifierName: "Issuer verifier", verifierLegalName: nil,
            verifierCertificateValid: true,
            claims: [EudiRequestedClaim(
                id: "pid-family", documentID: "pid", documentType: "pid", displayName: "PID",
                claimPath: ["family_name"], displayValue: "Holder", required: true, intentToRetain: false
            )], warningCount: 0
        )
        let service = FixtureEudiWallet(
            pendingAtLoad: [pending],
            presentationRequest: request,
            completion: .issuance(EudiIssuanceResult(
                documents: [], metadata: [], warningCount: 0, pendingIssuances: []
            ))
        )
        let model = WalletAppModel()
        await model.load(.success(testDependencies(service)))
        #expect(model.eudiFlow == .pending(pending))
        #expect(await service.operationCount == 1)
        await model.continuePendingIssuance()
        #expect(model.eudiFlow == .presentationConsent(request))
        await model.submitPresentation(accepted: true)
        #expect(model.eudiFlow == .idle)
    }

    @Test("Audit history is deferred and loaded once on demand")
    func lazyAuditHistory() async {
        let audit = CountingAuditRepository()
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(),
            audit: audit,
            localAuthenticator: FixtureAuthenticator(),
            eudiWallet: nil,
            eudiAvailability: .configurationRequired("Unavailable"),
            ebsiWallet: nil
        )))
        #expect(await audit.loadCount == 0)
        await model.loadAuditHistoryIfNeeded()
        await model.loadAuditHistoryIfNeeded()
        #expect(await audit.loadCount == 1)
        #expect(model.hasLoadedAuditHistory)
    }

    @Test("Declined or failed PID presentation preserves recoverable pending issuance")
    func pendingDeclineAndFailureRecovery() async {
        let pending = fixturePending()
        let request = fixturePresentationRequest()
        let declinedService = FixtureEudiWallet(
            pendingAtLoad: [pending], presentationRequest: request, completion: .pendingDeclined
        )
        let declinedModel = WalletAppModel()
        await declinedModel.load(.success(testDependencies(declinedService)))
        await declinedModel.continuePendingIssuance()
        await declinedModel.submitPresentation(accepted: false)
        #expect(declinedModel.eudiFlow == .pending(pending))

        let failingService = FixtureEudiWallet(
            pendingAtLoad: [pending], presentationRequest: request, failCompletion: true
        )
        let failingModel = WalletAppModel()
        await failingModel.load(.success(testDependencies(failingService)))
        await failingModel.continuePendingIssuance()
        await failingModel.submitPresentation(accepted: true)
        #expect(failingModel.hasRecoverablePendingIssuance)
        guard case .failed = failingModel.eudiFlow else {
            Issue.record("Expected redacted pending failure")
            return
        }
        failingModel.dismissEudiFlow()
        #expect(failingModel.eudiFlow == .idle)
        failingModel.returnToPendingIssuance()
        #expect(failingModel.eudiFlow == .pending(pending))
    }

    @Test("Missing production EUDI profile is explicit")
    func configurationRequired() async {
        let model = WalletAppModel()
        let dependencies = WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("Install approved profile"),
            ebsiWallet: nil
        )
        await model.load(.success(dependencies))
        #expect(model.eudiFlow == .configurationRequired("Install approved profile"))
        #expect(!model.isEudiOperational)

        let service = FixtureEudiWallet()
        let inconsistent = WalletAppModel()
        let record = CredentialRecord(
            configurationID: "pid", walletDocumentID: "wallet-pid", displayName: "PID",
            format: .sdJWTVC, profileID: "profile", issuerIdentifier: "https://issuer.example",
            createdAt: Date()
        )
        await inconsistent.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: service,
            eudiAvailability: .configurationRequired("Profile disabled"),
            ebsiWallet: nil
        )))
        #expect(await service.operationCount == 0)
        inconsistent.scanInput = "https://issuer.example/offer?credential_offer=fixture"
        await inconsistent.reviewScannedRequest()
        #expect(await service.operationCount == 0)
        inconsistent.selectCredential(record)
        await inconsistent.deleteSelectedCredential()
        #expect(await service.lastDeleted == nil)
        #expect(await service.operationCount == 0)
    }

    @Test("Credential lifecycle delegates deletion with Wallet Kit document status")
    func credentialDeletion() async {
        let record = CredentialRecord(
            configurationID: "pid", walletDocumentID: "wallet-pid", displayName: "PID",
            format: .sdJWTVC, profileID: "eudi-final-1", issuerIdentifier: "https://issuer.example",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let service = FixtureEudiWallet(summaries: [EudiWalletDocumentSummary(
            id: "wallet-pid", documentType: "pid", displayName: "PID",
            format: "sjwt", status: "issued"
        )])
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]),
            audit: EmptyAuditRepository(), localAuthenticator: FixtureAuthenticator(),
            eudiWallet: service, eudiAvailability: .available, ebsiWallet: nil
        )))
        model.selectCredential(record)
        await model.deleteSelectedCredential()
        #expect(model.selectedCredential == record)
        #expect(model.credentialActionState == .completed("Credential removed."))
        #expect(await service.lastDeleted == "wallet-pid:issued")
    }

    @Test("Onboarding completion is explicit and persisted")
    func onboardingCompletion() {
        let key = "oari.onboarding.completed"
        UserDefaults.standard.removeObject(forKey: key)
        defer { UserDefaults.standard.removeObject(forKey: key) }
        let model = WalletAppModel(showsOnboarding: true)
        #expect(model.showsOnboarding)
        model.completeOnboarding()
        #expect(!model.showsOnboarding)
        #expect(UserDefaults.standard.bool(forKey: key))
    }

    @Test("Untrusted EBSI flow requires explicit continue or cancel")
    func ebsiDevelopmentWarning() async {
        let warning = EbsiTrustWarning(
            counterpartyIdentifier: "did:ebsi:unregistered-issuer",
            role: .issuer,
            reasons: [.issuerNotAccredited],
            evidenceSources: ["https://ebsi.oari.io"],
            nextAction: "Continue credential issuance. Nothing is stored yet."
        )
        let service = FixtureEbsiWallet(outcome: .requireExplicitWarning(warning))
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("EUDI unavailable"), ebsiWallet: service
        )))
        model.scanInput = "openid-credential-offer://?credential_offer=fixture"
        await model.reviewEbsiScannedRequest()
        #expect(model.ebsiTrustWarning == warning)
        #expect(await service.continueCalls == [])
        await model.continueAfterEbsiTrustWarning()
        #expect(await service.continueCalls.isEmpty)
        model.ebsiTransactionCode = "123456"
        await model.issueReviewedEbsiCredential()
        #expect(await service.continueCalls == [true])
        #expect(model.eudiFlow == .idle)
        #expect(model.scanInput.isEmpty)
        #expect(model.selectedTab == .wallet)

        let cancelService = FixtureEbsiWallet(outcome: .requireExplicitWarning(warning))
        let cancelModel = WalletAppModel()
        await cancelModel.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("EUDI unavailable"), ebsiWallet: cancelService
        )))
        cancelModel.scanInput = model.scanInput
        await cancelModel.reviewEbsiScannedRequest()
        await cancelModel.cancelEbsiTrustWarning()
        #expect(await cancelService.cancelCount == 1)
        #expect(await cancelService.continueCalls.isEmpty)

        let replayService = FixtureEbsiWallet(
            outcome: .requireExplicitWarning(warning),
            continuationDelayNanoseconds: 50_000_000
        )
        let replayModel = WalletAppModel()
        await replayModel.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: nil,
            eudiAvailability: .configurationRequired("EUDI unavailable"), ebsiWallet: replayService
        )))
        replayModel.scanInput = model.scanInput
        await replayModel.reviewEbsiScannedRequest()
        async let first: Void = replayModel.continueAfterEbsiTrustWarning()
        async let second: Void = replayModel.continueAfterEbsiTrustWarning()
        _ = await (first, second)
        replayModel.ebsiTransactionCode = "123456"
        await replayModel.issueReviewedEbsiCredential()
        #expect(await replayService.continueCalls == [true])
    }

    @Test("Signed workspace PID challenge reaches consent and retains authorization transaction")
    func ebsiPIDPresentationBridge() async {
        let request = fixturePresentationRequest()
        let challenge = WorkspacePresentationChallenge(
            id: UUID(),
            authorizationEndpoint: URL(string: "https://wallet.dev.oari.io/openid/authorize")!,
            authSession: "auth-session",
            interactionType: "openid4vp_presentation",
            responseMode: "direct_post",
            responseURI: URL(string: "https://wallet.dev.oari.io/openid/authorize")!,
            nonce: "nonce",
            state: "auth-session",
            dcqlQuery: ["credentials": .array([.object([
                "id": .string("pid"),
                "format": .string("dc+sd-jwt"),
                "meta": .object([
                    "vct_values": .array([.string("urn:eu.europa.ec.eudi:pid:1")]),
                ]),
            ])])],
            signedRequest: "header.payload.signature"
        )
        let ebsi = FixtureEbsiWallet(
            outcome: .allow,
            continuation: .presentationRequired(challenge)
        )
        let eudi = FixtureEudiWallet(
            presentationRequest: request,
            completion: .externalAuthorization("authorization-code"),
            summaries: [EudiWalletDocumentSummary(
                id: "pid-document",
                documentType: "urn:eu.europa.ec.eudi:pid:1",
                displayName: "PID",
                format: "sdjwt",
                status: "issued"
            )]
        )
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: eudi,
            eudiAvailability: .available, ebsiWallet: ebsi
        )))
        model.scanInput = "openid-credential-offer://?credential_offer=fixture"
        await model.reviewEbsiScannedRequest()
        await model.issueReviewedEbsiCredential()
        guard case let .ebsiPresentationRequired(received) = model.eudiFlow else {
            Issue.record("Expected PID presentation challenge")
            return
        }
        await model.startEudiPresentationForEbsi(received)
        #expect(model.eudiFlow == .presentationConsent(request))
        #expect((await eudi.lastPresentationRequestURI)?.contains("request=header.payload.signature") == true)
        await model.submitPresentation(accepted: true)
        #expect(await ebsi.completedAuthorizationCodes == ["authorization-code"])
        #expect(model.eudiFlow == .idle)
    }

    @Test("Workspace PID challenge presents a credential from the W3C backend")
    func ebsiW3CPIDPresentation() async {
        let challenge = WorkspacePresentationChallenge(
            id: UUID(),
            authorizationEndpoint: URL(string: "https://wallet.dev.oari.io/openid/authorize")!,
            authSession: "auth-session",
            interactionType: "openid4vp_presentation",
            responseMode: "direct_post",
            responseURI: URL(string: "https://wallet.dev.oari.io/openid/authorize")!,
            nonce: "nonce",
            state: "auth-session",
            dcqlQuery: ["credentials": .array([.object([
                "id": .string("pid"),
                "format": .string("dc+sd-jwt"),
                "meta": .object(["vct_values": .array([.string("urn:eu.europa.ec.eudi:pid:1")])]),
            ])])],
            signedRequest: "header.payload.signature"
        )
        let consent = fixturePresentationRequest()
        let ebsi = FixtureEbsiWallet(
            outcome: .allow,
            continuation: .presentationRequired(challenge),
            pidPresentationRequest: consent
        )
        let eudi = FixtureEudiWallet()
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: eudi,
            eudiAvailability: .available, ebsiWallet: ebsi
        )))
        model.scanInput = "openid-credential-offer://?credential_offer=fixture"
        await model.reviewEbsiScannedRequest()
        await model.issueReviewedEbsiCredential()
        await model.startEudiPresentationForEbsi(challenge)
        #expect(model.eudiFlow == .presentationConsent(consent))
        await model.submitPresentation(accepted: true)
        #expect(await ebsi.completedPIDClaimIDs == [Set(["required-pid"])])
        #expect(model.eudiFlow == .idle)
    }

    @Test("Deferred credential retry forwards issuer and document and reports outcome")
    func deferredCredentialRetry() async {
        let record = CredentialRecord(
            configurationID: "deferred", walletDocumentID: "deferred-document", displayName: "Deferred credential",
            format: .sdJWTVC, profileID: "eudi-final-1", issuerIdentifier: "https://issuer.example",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let deferred = EudiWalletDocumentSummary(
            id: "deferred-document", documentType: "credential", displayName: "Deferred credential",
            format: "sjwt", status: "deferred"
        )
        let issued = EudiWalletDocumentSummary(
            id: "deferred-document", documentType: "credential", displayName: "Deferred credential",
            format: "sjwt", status: "issued"
        )
        let service = FixtureEudiWallet(summaries: [deferred], retryResult: issued)
        let model = WalletAppModel()
        await model.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: service, eudiAvailability: .available, ebsiWallet: nil
        )))
        model.selectCredential(record)
        await model.retrySelectedDeferredCredential()
        #expect(await service.lastRetried == "https://issuer.example:deferred-document")
        #expect(model.documentStatus(for: record) == "issued")
        #expect(model.credentialActionState == .completed("Credential issuance completed."))

        let pendingService = FixtureEudiWallet(summaries: [deferred], retryResult: deferred)
        let pendingModel = WalletAppModel()
        await pendingModel.load(.success(WalletAppDependencies(
            credentials: FixedMetadataRepository(records: [record]), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: pendingService, eudiAvailability: .available, ebsiWallet: nil
        )))
        pendingModel.selectCredential(record)
        await pendingModel.retrySelectedDeferredCredential()
        #expect(pendingModel.documentStatus(for: record) == "deferred")
        #expect(pendingModel.credentialActionState == .completed("Credential is still pending at the issuer."))
    }

    private func testDependencies(_ service: FixtureEudiWallet) -> WalletAppDependencies {
        WalletAppDependencies(
            credentials: EmptyMetadataRepository(), audit: EmptyAuditRepository(),
            localAuthenticator: FixtureAuthenticator(), eudiWallet: service, eudiAvailability: .available, ebsiWallet: nil
        )
    }


    private func fixturePending() -> EudiPendingIssuance {
        EudiPendingIssuance(
            id: UUID(),
            document: EudiWalletDocumentSummary(
                id: "pending-wallet-document", documentType: "pid", displayName: "PID upgrade",
                format: "sjwt", status: "pending"
            )
        )
    }

    private func fixturePresentationRequest() -> EudiPresentationRequest {
        EudiPresentationRequest(
            id: UUID(), verifierName: "Issuer verifier", verifierLegalName: nil,
            verifierCertificateValid: true,
            claims: [EudiRequestedClaim(
                id: "required-pid", documentID: "pid", documentType: "pid", displayName: "PID",
                claimPath: ["family_name"], displayValue: "Holder", required: true, intentToRetain: false
            )], warningCount: 0
        )
    }
}

private enum TestFailure: Error { case unavailable }

private actor FixtureEbsiWallet: EbsiW3COperating {
    let outcome: EbsiTrustGateOutcome
    private(set) var continueCalls: [Bool] = []
    private(set) var cancelCount = 0
    let continuationDelayNanoseconds: UInt64
    let continuation: EbsiInteractionCompletion
    private(set) var completedAuthorizationCodes: [String] = []
    private(set) var completedPIDClaimIDs: [Set<String>] = []
    let pidPresentationRequest: EudiPresentationRequest?
    init(
        outcome: EbsiTrustGateOutcome,
        continuationDelayNanoseconds: UInt64 = 0,
        continuation: EbsiInteractionCompletion = .completed("EBSI development flow completed."),
        pidPresentationRequest: EudiPresentationRequest? = nil
    ) {
        self.outcome = outcome
        self.continuationDelayNanoseconds = continuationDelayNanoseconds
        self.continuation = continuation
        self.pidPresentationRequest = pidPresentationRequest
    }
    func resolveInteraction(uri: String) async throws -> EbsiResolvedInteraction {
        EbsiResolvedInteraction(
            id: UUID(), kind: .issuance,
            counterpartyIdentifier: "did:ebsi:unregistered-issuer",
            displayName: "Development issuer", trustOutcome: outcome,
            transactionCodeRequired: true,
            transactionCodeLength: 6,
            transactionCodeDescription: "Enter test PIN",
            configurationIDs: ["oari-v2"], authorizationRequired: true,
            representations: ["application/vc+jwt"], credentialDisplay: [:]
        )
    }
    func continueInteraction(
        id: UUID,
        allowUntrusted: Bool,
        transactionCode: String?
    ) async throws -> EbsiInteractionCompletion {
        continueCalls.append(allowUntrusted)
        if continuationDelayNanoseconds > 0 {
            try await Task.sleep(nanoseconds: continuationDelayNanoseconds)
        }
        return continuation
    }
    func cancelInteraction(id: UUID) async { cancelCount += 1 }
    func preparePIDPresentation(id: UUID) async throws -> EudiPresentationRequest {
        guard let pidPresentationRequest else { throw TestFailure.unavailable }
        return pidPresentationRequest
    }
    func completePIDPresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EbsiInteractionCompletion {
        completedPIDClaimIDs.append(selectedClaimIDs)
        return .completed(userAccepted ? "W3C PID submitted" : "PID request declined")
    }
    func submitPIDPresentation(id: UUID, vpToken: String) async throws -> EbsiInteractionCompletion {
        .completed("PID submitted")
    }
    func completeAuthorization(id: UUID, code: String) async throws -> EbsiInteractionCompletion {
        completedAuthorizationCodes.append(code)
        return .completed("Authorization completed")
    }
}

private actor FixtureEudiWallet: EudiWalletOperating {
    private(set) var issueCount = 0
    private(set) var operationCount = 0
    private(set) var lastSelectedClaims: Set<String> = []
    private let pendingAtLoad: [EudiPendingIssuance]
    private let presentationRequest: EudiPresentationRequest?
    private let completion: EudiPresentationCompletion
    private let failCompletion: Bool
    private let summaries: [EudiWalletDocumentSummary]
    private let retryResult: EudiWalletDocumentSummary?
    private(set) var lastDeleted: String?
    private(set) var lastRetried: String?
    private(set) var lastPresentationRequestURI: String?

    init(
        pendingAtLoad: [EudiPendingIssuance] = [],
        presentationRequest: EudiPresentationRequest? = nil,
        completion: EudiPresentationCompletion = .presentation,
        failCompletion: Bool = false,
        summaries: [EudiWalletDocumentSummary] = [],
        retryResult: EudiWalletDocumentSummary? = nil
    ) {
        self.pendingAtLoad = pendingAtLoad
        self.presentationRequest = presentationRequest
        self.completion = completion
        self.failCompletion = failCompletion
        self.summaries = summaries
        self.retryResult = retryResult
    }
    func resolveIssuanceOffer(uri: String) async throws -> EudiIssuanceOffer {
        operationCount += 1
        return EudiIssuanceOffer(
            id: UUID(),
            issuerName: "Fixture issuer",
            issuerLogoURL: nil,
            documents: [EudiIssuanceOfferDocument(
                configurationID: "pid",
                documentType: "urn:eu.europa.ec.eudi:pid:1",
                displayName: "PID",
                supportedAlgorithms: ["ES256"]
            )],
            transactionCode: nil
        )
    }
    func issueResolvedOffer(
        id: UUID,
        profileID: String,
        selectedConfigurationIDs: Set<String>,
        transactionCode: String?,
        promptMessage: String
    ) async throws -> EudiIssuanceResult {
        operationCount += 1
        issueCount += 1
        return EudiIssuanceResult(documents: [], metadata: [], warningCount: 0, pendingIssuances: [])
    }
    func beginOpenID4VPPresentation(requestURI: String) async throws -> EudiPresentationRequest {
        operationCount += 1
        lastPresentationRequestURI = requestURI
        guard let presentationRequest else { throw TestFailure.unavailable }
        return presentationRequest
    }
    func submitPresentation(
        id: UUID,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EudiPresentationResult { throw TestFailure.unavailable }
    func beginPendingIssuancePresentation(id: UUID) async throws -> EudiPresentationRequest {
        operationCount += 1
        guard let presentationRequest else { throw TestFailure.unavailable }
        return presentationRequest
    }
    func completePresentation(
        id: UUID,
        pendingIssuanceID: UUID?,
        selectedClaimIDs: Set<String>,
        userAccepted: Bool
    ) async throws -> EudiPresentationCompletion {
        operationCount += 1
        if failCompletion { throw TestFailure.unavailable }
        lastSelectedClaims = selectedClaimIDs
        return completion
    }
    func loadPendingIssuances() async throws -> [EudiPendingIssuance] { operationCount += 1; return pendingAtLoad }
    func loadDocumentSummaries() async throws -> [EudiWalletDocumentSummary] { operationCount += 1; return summaries }
    func loadStartupSnapshot() async throws -> EudiWalletStartupSnapshot {
        operationCount += 1
        return EudiWalletStartupSnapshot(
            metadata: [],
            documents: summaries,
            pendingIssuances: pendingAtLoad
        )
    }
    func deleteDocument(id: String, status: String) async throws {
        operationCount += 1; lastDeleted = "\(id):\(status)"
    }
    func retryDeferredIssuance(issuerName: String, documentID: String) async throws -> EudiWalletDocumentSummary {
        operationCount += 1; lastRetried = "\(issuerName):\(documentID)"
        guard let retryResult else { throw TestFailure.unavailable }
        return retryResult
    }
    func reconcilePendingOperations() async throws { operationCount += 1 }
}

private actor EmptyMetadataRepository: CredentialMetadataRepository {
    func credentials() async throws -> [CredentialRecord] { [] }
    func saveMetadata(_ credential: CredentialRecord) async throws {}
    func replaceMetadata(_ credential: CredentialRecord) async throws {}
    func deleteMetadata(id: CredentialID) async throws {}
}

private actor FixedMetadataRepository: CredentialMetadataRepository {
    private var records: [CredentialRecord]
    init(records: [CredentialRecord]) { self.records = records }
    func credentials() async throws -> [CredentialRecord] { records }
    func saveMetadata(_ credential: CredentialRecord) async throws { records.append(credential) }
    func replaceMetadata(_ credential: CredentialRecord) async throws {
        records.removeAll { $0.id == credential.id }; records.append(credential)
    }
    func deleteMetadata(id: CredentialID) async throws { records.removeAll { $0.id == id } }
}

private actor EmptyAuditRepository: AuditRepository {
    func events() async throws -> [AuditEvent] { [] }
    func append(_ event: AuditEvent) async throws {}
    func deleteAll() async throws {}
}

private actor CountingAuditRepository: AuditRepository {
    private(set) var loadCount = 0
    func events() async throws -> [AuditEvent] { loadCount += 1; return [] }
    func append(_ event: AuditEvent) async throws {}
    func deleteAll() async throws {}
}

private struct FixtureAuthenticator: LocalAuthenticator {
    func authenticate(reason: String) async throws {}
}
