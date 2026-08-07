import Foundation
import WalletDomain
import WalletVault

struct WalletAppDependencies: Sendable {
    let credentials: any CredentialRepository
    let audit: any AuditRepository

    static func make() -> Result<WalletAppDependencies, Error> {
        Result {
            let root = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            ).appendingPathComponent("OARIWallet", isDirectory: true)
            let keyStore = KeychainVaultKeyStore(service: "io.oari.wallet.vault")
            return try WalletAppDependencies(
                credentials: EncryptedCredentialRepository(
                    directory: root.appendingPathComponent("credentials", isDirectory: true),
                    keyStore: keyStore
                ),
                audit: EncryptedAuditRepository(
                    directory: root.appendingPathComponent("audit", isDirectory: true),
                    keyStore: keyStore
                )
            )
        }
    }
}
