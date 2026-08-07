import EudiWalletKitAdapter
import Foundation

enum WalletKitRuntimeProbe {
    static func loadDocumentCount(trustAnchor: Data) async throws -> Int {
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.ios-integration-tests"
        )
        let trustSource = try EudiTrustAnchorSource(
            profileID: "ios-integration-test",
            anchors: [trustAnchor],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: trustAnchor)]
        )
        let adapter = try baseline.makeWallet(trustSource: trustSource)
        do {
            return try await adapter.loadDocumentSummaries().count
        } catch EudiWalletKitAdapterError.unsafeDebugLogging {
            throw WalletKitRuntimeProbeError.debugLoggingBlocked
        }
    }
}

enum WalletKitRuntimeProbeError: Error, Equatable {
    case debugLoggingBlocked
}
