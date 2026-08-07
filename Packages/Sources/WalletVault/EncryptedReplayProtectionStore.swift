import CryptoKit
import Foundation
import ProtocolEngine

public actor EncryptedReplayProtectionStore: ReplayProtection {
    private static let context = Data("oari.replay.v1:nonce-digests".utf8)
    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let file: URL

    public init(directory: URL, keyStore: any VaultKeyStore) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        file = directory.appendingPathComponent("nonces.replay")
        try files.prepare()
    }

    public func claim(nonce: String, expiresAt: Date, now: Date) async throws {
        guard !nonce.isEmpty, expiresAt > now else { throw ReplayError.expired }
        var records = try load().filter { $0.value > now }
        let digest = SHA256.hash(data: Data(nonce.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        guard records[digest] == nil else { throw ReplayError.replayed }
        records[digest] = expiresAt
        let encoded = try JSONEncoder().encode(records)
        try files.write(
            cipher.seal(encoded, authenticating: Self.context),
            to: file
        )
    }

    private func load() throws -> [String: Date] {
        guard files.exists(file) else { return [:] }
        let plaintext = try cipher.open(
            files.read(file),
            authenticating: Self.context
        )
        return try JSONDecoder().decode([String: Date].self, from: plaintext)
    }
}
