import Foundation
import Testing
@testable import OariWallet

@MainActor
struct WalletKitIOSIntegrationTests {
    @Test("iOS trust path constructs and operational storage obeys build policy")
    func iosTrustAndOperationalRuntime() async throws {
        let anchorURL = try #require(
            Bundle(for: BundleToken.self).url(
                forResource: "TestTrustAnchor",
                withExtension: "bin"
            )
        )
        let anchor = try Data(contentsOf: anchorURL)
        #if DEBUG
        await #expect(throws: WalletKitRuntimeProbeError.debugLoggingBlocked) {
            _ = try await WalletKitRuntimeProbe.loadDocumentCount(trustAnchor: anchor)
        }
        #else
        #expect(try await WalletKitRuntimeProbe.loadDocumentCount(trustAnchor: anchor) == 0)
        try await WalletKitRuntimeProbe.rejectMalformedOperationalInputs(trustAnchor: anchor)
        try await WalletKitRuntimeProbe.useInjectedOperationalTransport(trustAnchor: anchor)
        try await WalletKitRuntimeProbe.reconcileDurableOperationalState(trustAnchor: anchor)
        #endif
    }
}

private final class BundleToken {}
