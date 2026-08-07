import EbsiW3CBackend
import Foundation
import Testing
import TrustDomain

struct EbsiTrustGateTests {
    @Test("Development permits only explicit one-time continuation for untrusted counterparties")
    func developmentWarning() {
        let outcome = EbsiTrustGate().evaluate(
            verdict: .untrusted(reasons: [.issuerNotAccredited], evidence: [evidence]),
            environment: .development,
            counterpartyIdentifier: "did:ebsi:issuer",
            role: .issuer
        )
        guard case let .requireExplicitWarning(warning) = outcome else {
            Issue.record("Expected explicit warning")
            return
        }
        #expect(warning.reasons == [.issuerNotAccredited])
        #expect(warning.evidenceSources == ["https://ebsi.oari.io"])
        #expect(warning.nextAction.contains("No credential has been stored"))
    }

    @Test("Production and cryptographically invalid requests remain fail closed")
    func failClosed() {
        let gate = EbsiTrustGate()
        #expect(gate.evaluate(
            verdict: .untrusted(reasons: [.requesterNotRegistered], evidence: []),
            environment: .production,
            counterpartyIdentifier: "did:ebsi:verifier",
            role: .verifier
        ) == .reject([.requesterNotRegistered]))
        #expect(gate.evaluate(
            verdict: .invalid(reasons: [.invalidSignature], evidence: []),
            environment: .development,
            counterpartyIdentifier: "did:ebsi:issuer",
            role: .issuer
        ) == .reject([.invalidSignature]))
        let indeterminate = gate.evaluate(
            verdict: .indeterminate(reasons: [.trustSourceUnavailable], evidence: []),
            environment: .development,
            counterpartyIdentifier: "did:ebsi:issuer",
            role: .issuer
        )
        guard case .requireExplicitWarning = indeterminate else {
            Issue.record("Development registry outage should warn, not block valid protocol flow")
            return
        }
    }

    private var evidence: TrustEvidence {
        TrustEvidence(
            source: .ebsiRegistry,
            sourceIdentifier: "https://ebsi.oari.io",
            result: .notFound,
            checkedAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_060),
            evidenceDigest: String(repeating: "a", count: 64)
        )
    }
}
