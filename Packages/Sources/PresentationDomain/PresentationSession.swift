import Foundation
import TrustDomain
import WalletDomain

public actor PresentationSession {
    public nonisolated let id: PresentationSessionID
    public nonisolated let request: PresentationRequestSummary

    public private(set) var state: PresentationState = .received
    public private(set) var trustDecision: TrustDecision?
    public private(set) var selectedCredentialIDs: [CredentialID] = []

    public init(
        id: PresentationSessionID = PresentationSessionID(),
        request: PresentationRequestSummary
    ) {
        self.id = id
        self.request = request
    }

    public func markParsed() throws {
        try require(.received, operation: .parse)
        state = .parsed
    }

    public func markTransportValidated() throws {
        try require(.parsed, operation: .validateTransport)
        state = .transportValidated
    }

    public func evaluateRequester(_ decision: TrustDecision) throws {
        try require(.transportValidated, operation: .evaluateRequester)
        trustDecision = decision
        guard decision.isConsistent else {
            state = .rejected
            throw PresentationSessionError.inconsistentTrustDecision
        }
        if decision.action == .reject {
            state = .rejected
            throw PresentationSessionError.requesterRejected
        }
        state = .requesterEvaluated
    }

    public func evaluateCandidates(_ credentialIDs: [CredentialID]) throws {
        try require(.requesterEvaluated, operation: .evaluateCandidates)
        guard !credentialIDs.isEmpty else {
            state = .rejected
            throw PresentationSessionError.noSelectedCredentials
        }
        selectedCredentialIDs = credentialIDs
        state = .candidatesEvaluated
    }

    public func beginReview() throws {
        try require(.candidatesEvaluated, operation: .beginReview)
        state = .review
    }

    public func approveReview() throws {
        try require(.review, operation: .approveReview)
        guard let trustDecision else {
            state = .failed
            throw PresentationSessionError.invalidTransition(from: .review, operation: .approveReview)
        }
        state = trustDecision.action == .requireOneTimeConsent ? .warningConsent : .reviewApproved
    }

    public func grantOneTimeConsent() throws {
        try require(.warningConsent, operation: .grantConsent)
        state = .consentGranted
    }

    public func authenticate() throws {
        guard state == .reviewApproved || state == .consentGranted else {
            throw PresentationSessionError.invalidTransition(from: state, operation: .authenticate)
        }
        state = .authenticated
    }

    public func markSigned() throws {
        try require(.authenticated, operation: .sign)
        state = .signed
    }

    public func markDelivered() throws {
        try require(.signed, operation: .deliver)
        state = .delivered
    }

    public func markRecorded() throws {
        try require(.delivered, operation: .record)
        state = .recorded
    }

    public func cancel() throws {
        guard !isTerminal else {
            throw PresentationSessionError.invalidTransition(from: state, operation: .cancel)
        }
        state = .cancelled
    }

    private var isTerminal: Bool {
        [.recorded, .cancelled, .rejected, .failed, .expired].contains(state)
    }

    private func require(_ expected: PresentationState, operation: PresentationOperation) throws {
        guard state == expected else {
            throw PresentationSessionError.invalidTransition(from: state, operation: operation)
        }
    }
}
