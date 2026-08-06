import Foundation
import ProfileDomain

public struct TrustPolicyEvaluator: Sendable {
    public init() {}

    public func decide(
        verdict: TrustVerdict,
        profile: InteroperabilityProfile,
        at date: Date
    ) -> TrustDecision {
        let effective = normalized(verdict, profile: profile, at: date)

        switch effective {
        case .trusted:
            return TrustDecision(effectiveVerdict: effective, action: .allow)
        case .invalid, .indeterminate:
            return TrustDecision(effectiveVerdict: effective, action: .reject)
        case .untrusted:
            let mayContinue = profile.trustPolicyMode != .regulatedStrict
                && profile.permitsUntrustedOneTimeConsent
            return TrustDecision(
                effectiveVerdict: effective,
                action: mayContinue ? .requireOneTimeConsent : .reject
            )
        }
    }

    private func normalized(
        _ verdict: TrustVerdict,
        profile: InteroperabilityProfile,
        at date: Date
    ) -> TrustVerdict {
        guard case let .trusted(evidence) = verdict else { return verdict }

        let evidenceBySource = Dictionary(grouping: evidence, by: \.source)
        for requiredSource in profile.requiredTrustSources {
            guard let matching = evidenceBySource[requiredSource], !matching.isEmpty else {
                return .indeterminate(reasons: [.missingEvidence], evidence: evidence)
            }
            if matching.contains(where: { $0.result == .invalid }) {
                return .invalid(reasons: [.conflictingEvidence], evidence: evidence)
            }
            if matching.contains(where: { $0.result == .notFound }) {
                return .indeterminate(reasons: [.conflictingEvidence], evidence: evidence)
            }
            if matching.contains(where: { $0.result == .unavailable }) {
                return .indeterminate(reasons: [.trustSourceUnavailable], evidence: evidence)
            }
            guard let freshness = profile.trustFreshness[requiredSource],
                  freshness.maximumAge > 0,
                  freshness.maximumValidity > 0,
                  let newest = matching.max(by: { $0.checkedAt < $1.checkedAt }) else {
                return .indeterminate(reasons: [.missingEvidence], evidence: evidence)
            }
            guard newest.result == .valid,
                  newest.checkedAt <= date,
                  newest.expiresAt > newest.checkedAt else {
                return .indeterminate(reasons: [.malformedEvidence], evidence: evidence)
            }
            guard date.timeIntervalSince(newest.checkedAt) <= freshness.maximumAge,
                  newest.expiresAt.timeIntervalSince(newest.checkedAt) <= freshness.maximumValidity,
                  newest.expiresAt > date else {
                return .indeterminate(reasons: [.staleEvidence], evidence: evidence)
            }
        }
        return verdict
    }
}
