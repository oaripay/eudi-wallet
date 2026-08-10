import CryptoKit
import EbsiW3CBackend
import Foundation

/// Encrypted, persistent replay protection for OpenID4VP Request Objects.
///
/// A single encrypted document contains each request-digest/nonce-digest pair, so
/// accepting either value is committed atomically with accepting the other.
public actor EncryptedOpenID4VPReplayStore: OpenID4VPReplayProtecting {
    private static let authenticatedContext = Data("oari.presentation-replay.v1".utf8)

    private struct Record: Codable, Sendable {
        let requestDigest: String
        let nonceDigest: String
        let expiresAt: Date
    }

    private let files: ProtectedFileStore
    private let cipher: VaultCipher
    private let file: URL
    private let maximumEntries: Int
    private let maximumRetention: TimeInterval
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(
        directory: URL,
        keyStore: any VaultKeyStore,
        maximumEntries: Int = 1_024,
        maximumRetention: TimeInterval = 600
    ) throws {
        files = ProtectedFileStore(directory: directory)
        cipher = VaultCipher(keyStore: keyStore)
        file = directory.appendingPathComponent("presentation-replay", isDirectory: false)
        self.maximumEntries = max(1, maximumEntries)
        self.maximumRetention = max(1, maximumRetention)
        try files.prepare()
    }

    public func consume(
        requestDigest: String,
        nonce: String,
        expiresAt: Date,
        at date: Date
    ) throws {
        guard !requestDigest.isEmpty, !nonce.isEmpty, expiresAt > date,
              expiresAt.timeIntervalSince(date) <= maximumRetention else {
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "signed request replay lifetime was invalid"
            )
        }

        let records = try load()
        let unexpiredRecords = records.filter { $0.expiresAt > date }
        let needsPurge = unexpiredRecords.count != records.count

        let nonceDigest = Self.digest(nonce)
        guard !unexpiredRecords.contains(where: {
            $0.requestDigest == requestDigest || $0.nonceDigest == nonceDigest
        }) else {
            // A rejected request must not prevent expired entries from being purged.
            if needsPurge { try persist(unexpiredRecords) }
            throw OpenID4VCBackendError.invalidPresentationChallenge(reason: "signed request was replayed")
        }
        guard unexpiredRecords.count < maximumEntries else {
            if needsPurge { try persist(unexpiredRecords) }
            throw OpenID4VCBackendError.invalidPresentationChallenge(
                reason: "signed request replay store is at capacity"
            )
        }

        var updatedRecords = unexpiredRecords
        updatedRecords.append(Record(
            requestDigest: requestDigest,
            nonceDigest: nonceDigest,
            expiresAt: expiresAt
        ))
        try persist(updatedRecords)
    }

    private func load() throws -> [Record] {
        guard files.exists(file) else { return [] }
        return try decoder.decode(
            [Record].self,
            from: cipher.open(files.read(file), authenticating: Self.authenticatedContext)
        )
    }

    private func persist(_ records: [Record]) throws {
        try files.write(
            cipher.seal(try encoder.encode(records), authenticating: Self.authenticatedContext),
            to: file
        )
    }

    private static func digest(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
