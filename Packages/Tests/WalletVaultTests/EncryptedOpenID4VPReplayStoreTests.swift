import CryptoKit
import EbsiW3CBackend
import Foundation
import Testing
@testable import WalletVault

struct EncryptedOpenID4VPReplayStoreTests {
    @Test("Wallet request digest and nonce are replay protected across restart without storing the nonce")
    func persistsBothReplayKeys() async throws {
        let fixture = try Fixture()
        let directory = fixture.root.appendingPathComponent("openid4vp-replay", isDirectory: true)
        let now = Date(timeIntervalSince1970: 1_754_524_800)
        let first = try EncryptedOpenID4VPReplayStore(directory: directory, keyStore: fixture.keyStore)

        try await first.consume(
            requestDigest: "request-digest-1",
            nonce: "sensitive-nonce",
            expiresAt: now.addingTimeInterval(60),
            at: now
        )

        let disk = try fixture.onlyFile(in: directory).readData()
        #expect(!disk.contains(Data("sensitive-nonce".utf8)))

        let restarted = try EncryptedOpenID4VPReplayStore(directory: directory, keyStore: fixture.keyStore)
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request was replayed")) {
            try await restarted.consume(
                requestDigest: "request-digest-1",
                nonce: "different-nonce",
                expiresAt: now.addingTimeInterval(60),
                at: now
            )
        }
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request was replayed")) {
            try await restarted.consume(
                requestDigest: "request-digest-2",
                nonce: "sensitive-nonce",
                expiresAt: now.addingTimeInterval(60),
                at: now
            )
        }
    }

    @Test("Wallet replay records are purged and capacity and retention are enforced")
    func enforcesRetentionCapacityAndPurgesExpiredRecords() async throws {
        let fixture = try Fixture()
        let now = Date(timeIntervalSince1970: 1_754_524_800)
        let store = try EncryptedOpenID4VPReplayStore(
            directory: fixture.root.appendingPathComponent("openid4vp-replay", isDirectory: true),
            keyStore: fixture.keyStore,
            maximumEntries: 1,
            maximumRetention: 60
        )

        try await store.consume(
            requestDigest: "expired-request",
            nonce: "expired-nonce",
            expiresAt: now.addingTimeInterval(10),
            at: now
        )
        try await store.consume(
            requestDigest: "replacement-request",
            nonce: "replacement-nonce",
            expiresAt: now.addingTimeInterval(30),
            at: now.addingTimeInterval(11)
        )
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request replay store is at capacity")) {
            try await store.consume(
                requestDigest: "over-capacity-request",
                nonce: "over-capacity-nonce",
                expiresAt: now.addingTimeInterval(30),
                at: now.addingTimeInterval(11)
            )
        }
        await #expect(throws: OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request replay lifetime was invalid")) {
            try await store.consume(
                requestDigest: "long-request",
                nonce: "long-nonce",
                expiresAt: now.addingTimeInterval(61),
                at: now
            )
        }
    }
}
