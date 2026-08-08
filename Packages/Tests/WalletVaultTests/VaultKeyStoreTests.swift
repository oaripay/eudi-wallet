import CryptoKit
import Foundation
import Testing
@testable import WalletVault

struct VaultKeyStoreTests {
    @Test("Cached vault key store reads its wrapped store once")
    func cachesKey() throws {
        let wrapped = CountingVaultKeyStore()
        let cached = CachedVaultKeyStore(wrapping: wrapped)
        let first = try cached.loadOrCreateKey()
        let second = try cached.loadOrCreateKey()
        #expect(first.withUnsafeBytes { Data($0) } == second.withUnsafeBytes { Data($0) })
        #expect(wrapped.loadCount == 1)
    }
}

private final class CountingVaultKeyStore: VaultKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private let key = SymmetricKey(size: .bits256)
    private(set) var loadCount = 0

    func loadOrCreateKey() throws -> SymmetricKey {
        lock.withLock { loadCount += 1 }
        return key
    }
}
