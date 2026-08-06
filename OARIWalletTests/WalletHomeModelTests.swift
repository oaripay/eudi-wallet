import Foundation
import Testing
import WalletDomain
@testable import OARIWallet

struct WalletHomeModelTests {
    @Test("Initial state does not imply readiness or trust")
    func initialStateIsExplicitlyUnconfigured() {
        let model = WalletHomeModel.initial

        #expect(model.status == "Wallet setup required")
        #expect(model.detail.contains("No credentials are stored"))
        #expect(model.detail.contains("disabled"))
    }

    @Test("Home model consumes domain records without inspecting credential values")
    func credentialCountUsesDomainMetadata() {
        let record = CredentialRecord(
            configurationID: "provisionalOariLPID",
            displayName: "Legal person identity",
            format: .jwtVC,
            profileID: "oari-development-v1",
            issuerIdentifier: "did:ebsi:issuer",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(WalletHomeModel.credentialCountDescription([record]) == "1 credential")
    }
}
