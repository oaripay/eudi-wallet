import Foundation
import PresentationDomain
import ProfileDomain
import Testing
import TrustDomain
import WalletDomain

struct PresentationSessionTests {
    @Test("Trusted presentation cannot sign before review and authentication")
    func signingGate() async throws {
        let session = PresentationSession(request: request())

        await #expect(throws: PresentationSessionError.invalidTransition(
            from: .received,
            operation: .sign
        )) {
            try await session.markSigned()
        }

        try await session.markParsed()
        try await session.markTransportValidated()
        try await session.evaluateRequester(
            TrustDecision(effectiveVerdict: .trusted(evidence: []), action: .allow)
        )
        try await session.evaluateCandidates([CredentialID()])
        try await session.beginReview()
        try await session.approveReview()

        await #expect(throws: PresentationSessionError.invalidTransition(
            from: .reviewApproved,
            operation: .sign
        )) {
            try await session.markSigned()
        }
        try await session.authenticate()
        try await session.markSigned()
        try await session.markDelivered()
        try await session.markRecorded()
        #expect(await session.state == .recorded)
    }

    @Test("Untrusted warning requires one-time consent before authentication")
    func warningConsentGate() async throws {
        let session = PresentationSession(request: request())
        try await session.markParsed()
        try await session.markTransportValidated()
        let verdict = TrustVerdict.untrusted(reasons: [.requesterNotRegistered], evidence: [])
        try await session.evaluateRequester(
            TrustDecision(effectiveVerdict: verdict, action: .requireOneTimeConsent)
        )
        try await session.evaluateCandidates([CredentialID()])
        try await session.beginReview()
        try await session.approveReview()
        #expect(await session.state == .warningConsent)

        await #expect(throws: PresentationSessionError.invalidTransition(
            from: .warningConsent,
            operation: .authenticate
        )) {
            try await session.authenticate()
        }
        try await session.grantOneTimeConsent()
        try await session.authenticate()
        #expect(await session.state == .authenticated)
    }

    @Test("Rejected requester and empty candidates terminate fail closed")
    func rejectionPaths() async throws {
        let rejected = PresentationSession(request: request())
        try await rejected.markParsed()
        try await rejected.markTransportValidated()
        await #expect(throws: PresentationSessionError.requesterRejected) {
            try await rejected.evaluateRequester(
                TrustDecision(
                    effectiveVerdict: .invalid(reasons: [.invalidSignature], evidence: []),
                    action: .reject
                )
            )
        }
        #expect(await rejected.state == .rejected)

        let empty = PresentationSession(request: request())
        try await empty.markParsed()
        try await empty.markTransportValidated()
        try await empty.evaluateRequester(
            TrustDecision(effectiveVerdict: .trusted(evidence: []), action: .allow)
        )
        await #expect(throws: PresentationSessionError.noSelectedCredentials) {
            try await empty.evaluateCandidates([])
        }
        #expect(await empty.state == .rejected)
    }

    @Test("Contradictory trust decisions reject without review bypass")
    func contradictoryTrustDecision() async throws {
        let verdicts: [TrustVerdict] = [
            .untrusted(reasons: [.requesterNotRegistered], evidence: []),
            .invalid(reasons: [.invalidSignature], evidence: []),
            .indeterminate(reasons: [.trustSourceUnavailable], evidence: []),
        ]

        for verdict in verdicts {
            let session = PresentationSession(request: request())
            try await session.markParsed()
            try await session.markTransportValidated()
            await #expect(throws: PresentationSessionError.inconsistentTrustDecision) {
                try await session.evaluateRequester(
                    TrustDecision(effectiveVerdict: verdict, action: .allow)
                )
            }
            #expect(await session.state == .rejected)
        }
    }

    @Test("Terminal recorded session cannot resume or cancel")
    func terminalState() async throws {
        let session = PresentationSession(request: request())
        try await session.markParsed()
        try await session.markTransportValidated()
        try await session.evaluateRequester(
            TrustDecision(effectiveVerdict: .trusted(evidence: []), action: .allow)
        )
        try await session.evaluateCandidates([CredentialID()])
        try await session.beginReview()
        try await session.approveReview()
        try await session.authenticate()
        try await session.markSigned()
        try await session.markDelivered()
        try await session.markRecorded()

        await #expect(throws: PresentationSessionError.invalidTransition(
            from: .recorded,
            operation: .cancel
        )) {
            try await session.cancel()
        }
    }

    private func request() -> PresentationRequestSummary {
        PresentationRequestSummary(
            requesterName: "Example requester",
            protocolRequestID: "request",
            requesterIdentifier: "did:example:requester",
            origin: URL(string: "https://verifier.example")!,
            purpose: "Confirm organisation identity",
            requestedClaimIdentifiers: ["legal_person_name"],
            nonce: "1234567890123456",
            expiresAt: Date(timeIntervalSince1970: 1_754_524_860),
            state: nil,
            profileID: BuiltInProfiles.vcdm2OpenID4VCProfileID
        )
    }
}
