import Foundation
import ProfileDomain
import WalletDomain

public struct PresentationSessionID: RawRepresentable, Hashable, Sendable {
    public let rawValue: UUID

    public init(rawValue: UUID) {
        self.rawValue = rawValue
    }

    public init() {
        self.init(rawValue: UUID())
    }
}

public struct PresentationRequestSummary: Equatable, Sendable {
    public let requesterName: String
    public let protocolRequestID: String
    public let requesterIdentifier: String
    public let origin: URL
    public let purpose: String
    public let requestedClaimIdentifiers: [String]
    public let nonce: String
    public let expiresAt: Date
    public let state: String?
    public let profileID: ProfileID

    public init(
        requesterName: String,
        protocolRequestID: String,
        requesterIdentifier: String,
        origin: URL,
        purpose: String,
        requestedClaimIdentifiers: [String],
        nonce: String,
        expiresAt: Date,
        state: String?,
        profileID: ProfileID
    ) {
        self.requesterName = requesterName
        self.protocolRequestID = protocolRequestID
        self.requesterIdentifier = requesterIdentifier
        self.origin = origin
        self.purpose = purpose
        self.requestedClaimIdentifiers = requestedClaimIdentifiers
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.state = state
        self.profileID = profileID
    }
}

public enum PresentationState: String, Equatable, Sendable {
    case received
    case parsed
    case transportValidated
    case requesterEvaluated
    case candidatesEvaluated
    case review
    case reviewApproved
    case warningConsent
    case consentGranted
    case authenticated
    case signed
    case delivered
    case recorded
    case cancelled
    case rejected
    case failed
    case expired
}

public enum PresentationSessionError: Error, Equatable, Sendable {
    case invalidTransition(from: PresentationState, operation: PresentationOperation)
    case requesterRejected
    case inconsistentTrustDecision
    case noSelectedCredentials
}

public enum PresentationOperation: String, Equatable, Sendable {
    case parse
    case validateTransport
    case evaluateRequester
    case evaluateCandidates
    case beginReview
    case approveReview
    case grantConsent
    case authenticate
    case sign
    case deliver
    case record
    case cancel
}
