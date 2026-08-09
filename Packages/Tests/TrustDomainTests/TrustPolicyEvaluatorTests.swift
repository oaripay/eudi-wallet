import Foundation
import ProfileDomain
import Testing
import TrustDomain

struct TrustPolicyEvaluatorTests {
    private let now = Date(timeIntervalSince1970: 1_754_524_800)

    @Test("Trusted requires fresh valid evidence for every configured source")
    func evidenceCompleteness() {
        let profile = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: now)
        let evaluator = TrustPolicyEvaluator()
        let incomplete = TrustVerdict.trusted(evidence: [evidence(for: .signedMetadata)])

        let decision = evaluator.decide(verdict: incomplete, profile: profile, at: now)

        #expect(decision.action == .reject)
        guard case let .indeterminate(reasons, _) = decision.effectiveVerdict else {
            Issue.record("Missing trust evidence must become indeterminate")
            return
        }
        #expect(reasons == [.missingEvidence])
    }

    @Test("Expired evidence fails closed")
    func staleEvidence() {
        let profile = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: now)
        let evidence = profile.requiredTrustSources.map {
            self.evidence(for: $0, expiresAt: now)
        }

        let decision = TrustPolicyEvaluator().decide(
            verdict: .trusted(evidence: evidence),
            profile: profile,
            at: now
        )

        #expect(decision.action == .reject)
        guard case let .indeterminate(reasons, _) = decision.effectiveVerdict else {
            Issue.record("Stale trust evidence must become indeterminate")
            return
        }
        #expect(reasons == [.staleEvidence])
    }

    @Test("Warning consent never converts an untrusted verdict into trusted")
    func warningConsentPreservesVerdict() {
        let profile = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: now)
        let verdict = TrustVerdict.untrusted(
            reasons: [.requesterNotRegistered],
            evidence: []
        )

        let decision = TrustPolicyEvaluator().decide(
            verdict: verdict,
            profile: profile,
            at: now
        )

        #expect(decision.action == .requireOneTimeConsent)
        #expect(decision.effectiveVerdict == verdict)
    }

    @Test("Contradictory evidence always fails closed")
    func contradictoryEvidence() {
        let profile = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: now)
        let evaluator = TrustPolicyEvaluator()

        for conflictingResult in [TrustEvidenceResult.invalid, .notFound] {
            var evidence = profile.requiredTrustSources.map { self.evidence(for: $0) }
            evidence.append(self.evidence(for: .credentialStatus, result: conflictingResult))
            let decision = evaluator.decide(
                verdict: .trusted(evidence: evidence),
                profile: profile,
                at: now
            )
            #expect(decision.action == .reject)
        }
    }

    @Test("Profile maximum age rejects old but unexpired evidence")
    func maximumAge() {
        let profile = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: now)
        let evidence = profile.requiredTrustSources.map { source in
            self.evidence(
                for: source,
                checkedAt: now.addingTimeInterval(-100_000),
                expiresAt: now.addingTimeInterval(60)
            )
        }

        let decision = TrustPolicyEvaluator().decide(
            verdict: .trusted(evidence: evidence),
            profile: profile,
            at: now
        )
        #expect(decision.action == .reject)
        guard case let .indeterminate(reasons, _) = decision.effectiveVerdict else {
            Issue.record("Old evidence must become indeterminate")
            return
        }
        #expect(reasons == [.staleEvidence])
    }

    @Test("Malformed timestamp ordering rejects")
    func malformedTimestampOrdering() {
        let profile = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: now)
        var evidence = profile.requiredTrustSources.map { self.evidence(for: $0) }
        evidence.removeAll { $0.source == .credentialStatus }
        evidence.append(self.evidence(
            for: .credentialStatus,
            checkedAt: now.addingTimeInterval(60),
            expiresAt: now.addingTimeInterval(-60)
        ))

        let decision = TrustPolicyEvaluator().decide(
            verdict: .trusted(evidence: evidence),
            profile: profile,
            at: now
        )
        #expect(decision.action == .reject)
        guard case let .indeterminate(reasons, _) = decision.effectiveVerdict else {
            Issue.record("Malformed evidence must become indeterminate")
            return
        }
        #expect(reasons == [.malformedEvidence])
    }

    @Test("Strict and invalid verdicts always reject")
    func mandatoryRejection() {
        var strict = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: now)
        strict = InteroperabilityProfile(
            id: strict.id,
            openID4VCI: strict.openID4VCI,
            openID4VP: strict.openID4VP,
            dcql: strict.dcql,
            vcdm: strict.vcdm,
            credentialFormats: strict.credentialFormats,
            identifierMethods: strict.identifierMethods,
            signingAlgorithms: strict.signingAlgorithms,
            keyProtection: strict.keyProtection,
            requiredTrustSources: strict.requiredTrustSources,
            trustFreshness: strict.trustFreshness,
            trustPolicyMode: .regulatedStrict,
            permitsUntrustedOneTimeConsent: true,
            ebsiProfile: strict.ebsiProfile,
            retirementRule: strict.retirementRule
        )
        let evaluator = TrustPolicyEvaluator()

        #expect(evaluator.decide(
            verdict: .untrusted(reasons: [.requesterNotRegistered], evidence: []),
            profile: strict,
            at: now
        ).action == .reject)
        #expect(evaluator.decide(
            verdict: .invalid(reasons: [.invalidSignature], evidence: []),
            profile: BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: now),
            at: now
        ).action == .reject)
    }

    private func evidence(
        for source: TrustSourceKind,
        result: TrustEvidenceResult = .valid,
        checkedAt: Date? = nil,
        expiresAt: Date? = nil
    ) -> TrustEvidence {
        TrustEvidence(
            source: source,
            sourceIdentifier: "fixture:\(source.rawValue)",
            result: result,
            checkedAt: checkedAt ?? now.addingTimeInterval(-60),
            expiresAt: expiresAt ?? now.addingTimeInterval(3_600),
            evidenceDigest: String(repeating: "a", count: 64)
        )
    }
}
