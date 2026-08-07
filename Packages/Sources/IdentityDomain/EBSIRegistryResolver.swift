import CryptoKit
import Foundation
import TrustDomain

public struct ResolvedDID: Equatable, Sendable {
    public let document: DIDDocument
    public let evidence: TrustEvidence

    public init(document: DIDDocument, evidence: TrustEvidence) {
        self.document = document
        self.evidence = evidence
    }
}

public protocol EBSIRegistryClient: Sendable {
    func resolve(did: String, at date: Date) async throws -> ResolvedDID
}

public struct EBSIDIDResolver: DIDResolver, Sendable {
    private let client: any EBSIRegistryClient
    private let clock: @Sendable () -> Date

    public init(
        client: any EBSIRegistryClient,
        clock: @escaping @Sendable () -> Date = Date.init
    ) {
        self.client = client
        self.clock = clock
    }

    public func resolve(_ did: String) async throws -> DIDDocument {
        guard did.hasPrefix("did:ebsi:"), did.count > "did:ebsi:".count else {
            throw DIDResolutionError.unsupportedMethod
        }
        let result = try await client.resolve(did: did, at: clock())
        guard result.document.id == did,
              result.evidence.source == .ebsiRegistry,
              result.evidence.result == .valid else {
            throw DIDResolutionError.registryUnavailable
        }
        return result.document
    }
}

public struct URLSessionEBSIRegistryClient: EBSIRegistryClient, Sendable {
    private let registryBaseURL: URL
    private let httpClient: any BoundedHTTPSClient
    private let evidenceTTL: TimeInterval

    public init(
        registryBaseURL: URL,
        httpClient: any BoundedHTTPSClient = URLSessionBoundedHTTPSClient(),
        evidenceTTL: TimeInterval = 3_600
    ) throws {
        guard registryBaseURL.scheme == "https", registryBaseURL.host != nil,
              evidenceTTL > 0 else {
            throw DIDResolutionError.registryUnavailable
        }
        self.registryBaseURL = registryBaseURL
        self.httpClient = httpClient
        self.evidenceTTL = evidenceTTL
    }

    public func resolve(did: String, at date: Date) async throws -> ResolvedDID {
        let url = registryBaseURL.appendingPathComponent(did)
        let response = try await httpClient.get(url, maximumBytes: 1_048_576)
        guard response.statusCode == 200,
              response.finalURL.scheme == "https",
              response.finalURL.host == registryBaseURL.host,
              (response.finalURL.port ?? 443) == (registryBaseURL.port ?? 443) else {
            throw DIDResolutionError.registryUnavailable
        }
        let data = response.data
        let document: DIDDocument
        do {
            document = try JSONDecoder().decode(DIDDocument.self, from: data)
        } catch {
            throw DIDResolutionError.malformedKey
        }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return ResolvedDID(
            document: document,
            evidence: TrustEvidence(
                source: .ebsiRegistry,
                sourceIdentifier: registryBaseURL.absoluteString,
                result: .valid,
                checkedAt: date,
                expiresAt: date.addingTimeInterval(evidenceTTL),
                evidenceDigest: digest
            )
        )
    }
}
