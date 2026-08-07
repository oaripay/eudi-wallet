import CryptoKit
import Foundation
import ProtocolEngine
import Testing
@testable import WalletVault

struct EncryptedReplayProtectionStoreTests {
    @Test("Nonce replay remains rejected after store restart without plaintext on disk")
    func persistentReplay() async throws {
        let fixture = try Fixture()
        let directory = fixture.root.appendingPathComponent("replay", isDirectory: true)
        let now = Date(timeIntervalSince1970: 1_754_524_800)
        let first = try EncryptedReplayProtectionStore(directory: directory, keyStore: fixture.keyStore)
        try await first.claim(nonce: "sensitive-nonce", expiresAt: now.addingTimeInterval(60), now: now)

        let file = try fixture.onlyFile(in: directory)
        let disk = try file.readData()
        #expect(!disk.contains(Data("sensitive-nonce".utf8)))

        let restarted = try EncryptedReplayProtectionStore(directory: directory, keyStore: fixture.keyStore)
        await #expect(throws: ReplayError.replayed) {
            try await restarted.claim(
                nonce: "sensitive-nonce",
                expiresAt: now.addingTimeInterval(60),
                now: now
            )
        }
    }
}
