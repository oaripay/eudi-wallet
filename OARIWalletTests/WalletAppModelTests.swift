import Foundation
import Testing
import WalletDomain
@testable import OARIWallet

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
}

private enum TestFailure: Error { case unavailable }
