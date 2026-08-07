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
        model.classifyScan(allowedHosts: ["wallet.dev.oari.io"])
        guard case .rejected = model.scanResult else {
            Issue.record("Unapproved host must reject")
            return
        }
        model.scanInput = "https://wallet.dev.oari.io/present?request=x"
        model.classifyScan(allowedHosts: ["wallet.dev.oari.io"])
        #expect(model.scanResult == .presentation)
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
