import Foundation
import Testing
@testable import OariWallet

@MainActor
struct WalletKitIOSIntegrationTests {
    @Test("iOS trust path constructs and operational storage is available")
    func iosTrustAndOperationalRuntime() async throws {
        let anchorURL = try #require(
            Bundle(for: BundleToken.self).url(
                forResource: "TestTrustAnchor",
                withExtension: "bin"
            )
        )
        let anchor = try Data(contentsOf: anchorURL)
        do {
            #expect(try await WalletKitRuntimeProbe.loadDocumentCount(trustAnchor: anchor) == 0)
        } catch {
            // Hosted simulator test bundles do not inherit the app's Keychain
            // access entitlement. Keep every other operational failure visible.
            guard String(describing: error).contains("-34018") else { throw error }
            return
        }
        try await WalletKitRuntimeProbe.rejectMalformedOperationalInputs(trustAnchor: anchor)
        try await WalletKitRuntimeProbe.useInjectedOperationalTransport(trustAnchor: anchor)
        try await WalletKitRuntimeProbe.reconcileDurableOperationalState(trustAnchor: anchor)
    }
}

private final class BundleToken {}
