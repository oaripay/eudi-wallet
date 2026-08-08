import Testing
@testable import WalletVault

struct SystemLocalAuthenticatorTests {
    @Test("App lock exposes device authentication capability")
    func appLockCapability() async throws {
        let authenticator = SystemLocalAuthenticator(
            evaluator: { _ in true },
            availability: { .faceID }
        )
        #expect(authenticator.availability() == .faceID)
        try await authenticator.authenticateAppLock(reason: "Unlock Oari Wallet")
    }

    @Test("Authentication requires a transaction-specific reason")
    func reasonRequired() async {
        let authenticator = SystemLocalAuthenticator(evaluator: { _ in true })
        await #expect(throws: LocalAuthenticationError.missingReason) {
            try await authenticator.authenticate(reason: "  ")
        }
    }

    @Test("Authentication evaluator denial fails closed")
    func denied() async {
        let authenticator = SystemLocalAuthenticator(evaluator: { _ in false })
        await #expect(throws: LocalAuthenticationError.denied) {
            try await authenticator.authenticate(reason: "Present selected credentials")
        }
    }

    @Test("Authentication forwards the reviewed operation reason")
    func reasonForwarded() async throws {
        let expected = "Delete Legal Person ID"
        let authenticator = SystemLocalAuthenticator(evaluator: { reason in
            #expect(reason == expected)
            return true
        })
        try await authenticator.authenticate(reason: expected)
    }
}
