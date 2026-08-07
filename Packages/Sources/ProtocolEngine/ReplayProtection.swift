import Foundation

public protocol ReplayProtection: Sendable {
    func claim(nonce: String, expiresAt: Date, now: Date) async throws
}

public actor ReplayProtectionStore: ReplayProtection {
    private var nonces: [String: Date] = [:]

    public init() {}

    public func claim(nonce: String, expiresAt: Date, now: Date) throws {
        guard !nonce.isEmpty, expiresAt > now else { throw ReplayError.expired }
        nonces = nonces.filter { $0.value > now }
        guard nonces[nonce] == nil else { throw ReplayError.replayed }
        nonces[nonce] = expiresAt
    }
}

public enum ReplayError: Error, Equatable, Sendable {
    case expired
    case replayed
}
