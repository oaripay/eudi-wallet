import CryptoKit
import Foundation
import Testing
@testable import WalletVault

struct StaticVaultKeyStore: VaultKeyStore {
    let key: SymmetricKey
    func loadOrCreateKey() throws -> SymmetricKey { key }
}

struct Fixture {
    let root: URL
    let auditDirectory: URL
    let keyStore = StaticVaultKeyStore(key: SymmetricKey(size: .bits256))

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        auditDirectory = root.appendingPathComponent("audit", isDirectory: true)
    }

    func onlyFile(in directory: URL) throws -> URL {
        try #require(FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        ).first)
    }
}

extension URL {
    func readData() throws -> Data { try Data(contentsOf: self) }
}
