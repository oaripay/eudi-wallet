import EudiWalletKitAdapter
import Foundation
import Security
import Testing

struct EudiWalletKitAdapterTests {
    @Test("Selected Wallet Kit revision is immutable and explicit")
    func selectedRevision() {
        #expect(EudiWalletKitBaseline.selectedVersion == "0.39.1")
        #expect(EudiWalletKitBaseline.selectedCommit == "79005ab4bf0399238c1c9ebff9ee7d8a42c521f9")
    }

    @Test("Wallet configuration disables SDK file logging and requires authentication")
    func safeConfiguration() throws {
        let baseline = try EudiWalletKitBaseline(serviceName: "io.oari.wallet.documents")
        let configuration = baseline.walletConfiguration()

        #expect(configuration.serviceName == "io.oari.wallet.documents")
        #expect(configuration.userAuthenticationRequired)
        #expect(configuration.logFileName == nil)
    }

    @Test("Invalid Keychain service names fail before Wallet Kit initialization")
    func invalidServiceName() {
        #expect(throws: EudiWalletKitAdapterError.invalidServiceName) {
            try EudiWalletKitBaseline(serviceName: "io.oari:wallet")
        }
        #expect(throws: EudiWalletKitAdapterError.invalidServiceName) {
            try EudiWalletKitBaseline(serviceName: "  ")
        }
    }

    @Test("Wallet construction requires explicit trust anchors")
    func trustAnchorsRequired() {
        #expect(throws: EudiWalletKitAdapterError.missingTrustAnchors) {
            try EudiTrustAnchorSource(
                profileID: "test",
                anchors: [],
                approvedSHA256Digests: []
            )
        }
    }

    @Test("Wallet Kit initializes behind the adapter with explicit trust input")
    func walletInitialization() throws {
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.adapter-tests"
        )
        _ = try baseline.makeWallet(trustSource: try approvedSystemTrustSource())
    }

    @Test("Operational Wallet Kit flows are blocked in Debug logging builds")
    func debugLoggingGate() throws {
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.debug-gate-tests"
        )
        let adapter = try baseline.makeWallet(trustSource: try approvedSystemTrustSource())
        #expect(throws: EudiWalletKitAdapterError.unsafeDebugLogging) {
            try adapter.requireOperationalRuntime()
        }
    }

    @Test("Every exposed Wallet Kit operation is gated in Debug")
    func allOperationsAreGated() async throws {
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.operation-gate-tests"
        )
        let adapter = try baseline.makeWallet(trustSource: try approvedSystemTrustSource())
        await #expect(throws: EudiWalletKitAdapterError.unsafeDebugLogging) {
            _ = try await adapter.loadDocumentSummaries()
        }
        await #expect(throws: EudiWalletKitAdapterError.unsafeDebugLogging) {
            try await adapter.deleteAllDocuments()
        }
    }

    @Test("Malformed trust anchors fail before Wallet Kit initialization")
    func malformedTrustAnchor() throws {
        let baseline = try EudiWalletKitBaseline(
            serviceName: "io.oari.wallet.invalid-anchor-tests"
        )
        let malformed = Data([0x30, 0x00])
        let source = try EudiTrustAnchorSource(
            profileID: "test",
            anchors: [malformed],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: malformed)]
        )
        #expect(throws: EudiWalletKitAdapterError.invalidTrustAnchor) {
            try baseline.makeWallet(trustSource: source)
        }
    }

    @Test("Valid leaf and unapproved CA certificates cannot become trust anchors")
    func trustAnchorAuthorization() throws {
        let baseline = try EudiWalletKitBaseline(serviceName: "io.oari.wallet.anchor-policy-tests")
        let leaf = try #require(Data(
            base64Encoded: Self.nonCABase64,
            options: .ignoreUnknownCharacters
        ))
        let leafSource = try EudiTrustAnchorSource(
            profileID: "test",
            anchors: [leaf],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: leaf)]
        )
        #expect(throws: EudiWalletKitAdapterError.invalidTrustAnchor) {
            try baseline.makeWallet(trustSource: leafSource)
        }

        let root = try systemRootCertificate()
        let unapproved = try EudiTrustAnchorSource(
            profileID: "test",
            anchors: [root],
            approvedSHA256Digests: [String(repeating: "0", count: 64)]
        )
        #expect(throws: EudiWalletKitAdapterError.unapprovedTrustAnchor) {
            try baseline.makeWallet(trustSource: unapproved)
        }
    }

    private func approvedSystemTrustSource() throws -> EudiTrustAnchorSource {
        let anchor = try systemRootCertificate()
        return try EudiTrustAnchorSource(
            profileID: "adapter-tests",
            anchors: [anchor],
            approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: anchor)]
        )
    }

    private func systemRootCertificate() throws -> Data {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try Data(contentsOf: repositoryRoot
            .appendingPathComponent("OARIWalletTests/Resources/TestTrustAnchor.bin"))
    }

    private static let nonCABase64 = """
    MIIDBDCCAeygAwIBAgIUTpdNHxMBD4Gy1dDs4XgGszteYUgwDQYJKoZIhvcNAQELBQAwEzERMA8G
    A1UEAwwITm90IEEgQ0EwHhcNMjYwODA3MTMzMzM1WhcNMzYwODA0MTMzMzM1WjATMREwDwYDVQQD
    DAhOb3QgQSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKxtDT7YJYlTRcOqLrB3
    GFT0vI3a1Pm3imIbguZCR/n8Op0oGcQGx3iacRG9qSo14JSfO4Um1YoOTjyDqPjhGo3Li7ml2ntL
    LMZqhycob0G2pp0ZJWG48VEqT/ip0UlTXSp+vZnYzXJ7PySw3GoTcfHX7DPMed5ztQTFJNxOPc+a
    L2zCFW0Bfp+cRCXdMRyKx0YYPTSLrDjVAgMUnZ0WZmcDTHZ0Flf0+qFgifYj1Qbz52XjW4yvmOL1
    Ryv9K2UdpCFseOQLwKnset7F2npUTx0kByfeskMKksRdtfuokIu6C2NMAzIRsYXHCcld5BDndaXr
    yGfd+rzPsMwreUGrO/cCAwEAAaNQME4wHQYDVR0OBBYEFCPr2JCU6xvfMnPAMSWgKRxtfnpmMB8G
    A1UdIwQYMBaAFCPr2JCU6xvfMnPAMSWgKRxtfnpmMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
    BQADggEBAEltT0gjhiIrf80gEHnBxEcZMM/lNhAhuzXLIyP7D4yn0G8UimtktGhHS8vkqtlHvx9T
    Yy8XSa6kwRbRkczr9jaN5opItOBoHGSffpuKiDcjJr50gmJLTXp60ay5xCxkP6aBzMUvocal2asg
    sTeYgMrSVvYeXPihCcviN9nhJA/73HeOoQuf4r3cre2+8W6yggIxEWpXS9MsXHmRys9KnhRqm/u8
    H6E78TkGq1BoyW0HZfILX8VVvxrczMuyp/VAZP48QE9eWkge6OQCjUtSv1FWeQlFMot1Wjdj0rq+
    OZaxuJKYgGezcJamUYOXmj+gvlknAVOvuPeg2wwk/Sq988g=
    """
}
