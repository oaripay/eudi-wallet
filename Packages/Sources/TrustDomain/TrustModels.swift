import Foundation
import ProfileDomain

public enum TrustEvidenceResult: String, Codable, Sendable {
    case valid
    case invalid
    case notFound
    case unavailable
}

public struct TrustEvidence: Codable, Equatable, Sendable {
    public let source: TrustSourceKind
    public let sourceIdentifier: String
    public let result: TrustEvidenceResult
    public let checkedAt: Date
    public let expiresAt: Date
    public let evidenceDigest: String

    public init(
        source: TrustSourceKind,
        sourceIdentifier: String,
        result: TrustEvidenceResult,
        checkedAt: Date,
        expiresAt: Date,
        evidenceDigest: String
    ) {
        self.source = source
        self.sourceIdentifier = sourceIdentifier
        self.result = result
        self.checkedAt = checkedAt
        self.expiresAt = expiresAt
        self.evidenceDigest = evidenceDigest
    }
}

public enum TrustReason: String, Codable, Sendable {
    case invalidSignature
    case expiredCertificate
    case revoked
    case requesterNotRegistered
    case issuerNotAccredited
    case statusInvalid
    case missingEvidence
    case staleEvidence
    case trustSourceUnavailable
    case unsupportedProfile
    case conflictingEvidence
    case malformedEvidence
}

public enum TrustVerdict: Equatable, Sendable {
    case trusted(evidence: [TrustEvidence])
    case untrusted(reasons: [TrustReason], evidence: [TrustEvidence])
    case invalid(reasons: [TrustReason], evidence: [TrustEvidence])
    case indeterminate(reasons: [TrustReason], evidence: [TrustEvidence])
}

public enum TrustAction: String, Codable, Sendable {
    case allow
    case requireOneTimeConsent
    case reject
}

public struct TrustDecision: Equatable, Sendable {
    public let effectiveVerdict: TrustVerdict
    public let action: TrustAction

    package init(effectiveVerdict: TrustVerdict, action: TrustAction) {
        self.effectiveVerdict = effectiveVerdict
        self.action = action
    }

    public var isConsistent: Bool {
        switch (effectiveVerdict, action) {
        case (.trusted, .allow),
             (.untrusted, .requireOneTimeConsent),
             (.untrusted, .reject),
             (.invalid, .reject),
             (.indeterminate, .reject):
            true
        default:
            false
        }
    }
}

public protocol TrustEvaluator: Sendable {
    associatedtype Input: Sendable
    func evaluate(_ input: Input, profile: InteroperabilityProfile) async -> TrustVerdict
}
