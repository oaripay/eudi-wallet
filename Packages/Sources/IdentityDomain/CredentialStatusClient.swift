import CryptoKit
import Foundation
import TrustDomain

public enum CredentialStatusValue: String, Equatable, Sendable {
    case valid
    case suspended
    case revoked
}

public struct CredentialStatusReference: Equatable, Sendable {
    public let statusListURL: URL
    public let index: Int

    public init(statusListURL: URL, index: Int) {
        self.statusListURL = statusListURL
        self.index = index
    }
}

public struct VerifiedCredentialStatus: Equatable, Sendable {
    public let value: CredentialStatusValue
    public let evidence: TrustEvidence
}

public protocol StatusListTokenVerifier: Sendable {
    func verify(compactToken: String, index: Int, at date: Date) async throws -> CredentialStatusValue
}

public protocol CredentialStatusClient: Sendable {
    func check(_ reference: CredentialStatusReference, at date: Date) async throws -> VerifiedCredentialStatus
}

public struct URLSessionCredentialStatusClient: CredentialStatusClient, Sendable {
    private let allowedHosts: Set<String>
    private let verifier: any StatusListTokenVerifier
    private let httpClient: any BoundedHTTPSClient
    private let evidenceTTL: TimeInterval

    public init(
        allowedHosts: Set<String>,
        verifier: any StatusListTokenVerifier,
        httpClient: any BoundedHTTPSClient = URLSessionBoundedHTTPSClient(),
        evidenceTTL: TimeInterval = 300
    ) throws {
        guard !allowedHosts.isEmpty, evidenceTTL > 0 else {
            throw DIDResolutionError.registryUnavailable
        }
        self.allowedHosts = allowedHosts
        self.verifier = verifier
        self.httpClient = httpClient
        self.evidenceTTL = evidenceTTL
    }

    public func check(
        _ reference: CredentialStatusReference,
        at date: Date
    ) async throws -> VerifiedCredentialStatus {
        guard reference.index >= 0,
              reference.statusListURL.scheme == "https",
              let host = reference.statusListURL.host,
              reference.statusListURL.user == nil,
              reference.statusListURL.password == nil,
              allowedHosts.contains(host) else {
            throw DIDResolutionError.registryUnavailable
        }
        let response = try await httpClient.get(reference.statusListURL, maximumBytes: 1_048_576)
        let data = response.data
        guard response.statusCode == 200,
              response.finalURL.scheme == "https",
              response.finalURL.host == host,
              (response.finalURL.port ?? 443) == (reference.statusListURL.port ?? 443),
              let token = String(data: data, encoding: .utf8),
              !token.isEmpty else {
            throw DIDResolutionError.registryUnavailable
        }
        let value = try await verifier.verify(compactToken: token, index: reference.index, at: date)
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return VerifiedCredentialStatus(
            value: value,
            evidence: TrustEvidence(
                source: .credentialStatus,
                sourceIdentifier: reference.statusListURL.absoluteString,
                result: value == .valid ? .valid : .invalid,
                checkedAt: date,
                expiresAt: date.addingTimeInterval(evidenceTTL),
                evidenceDigest: digest
            )
        )
    }
}
