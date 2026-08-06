import Testing
@testable import OARIWallet

struct WalletHomeModelTests {
    @Test("Initial state does not imply readiness or trust")
    func initialStateIsExplicitlyUnconfigured() {
        let model = WalletHomeModel.initial

        #expect(model.status == "Wallet setup required")
        #expect(model.detail.contains("No credentials are stored"))
        #expect(model.detail.contains("disabled"))
    }
}
