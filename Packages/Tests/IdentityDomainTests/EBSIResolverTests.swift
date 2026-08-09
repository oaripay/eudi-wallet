import Foundation
import IdentityDomain
import Testing
import TrustDomain

struct EBSIResolverTests {
    @Test("EBSI resolver requires matching registry-backed evidence")
    func registryEvidence() async throws {
        let did = "did:ebsi:fixture"
        let document = DIDDocument(id: did, verificationMethod: [], authentication: [], assertionMethod: [])
        let resolver = EBSIDIDResolver(
            client: FixtureEBSIClient(document: document),
            clock: { Date(timeIntervalSince1970: 1_754_524_800) }
        )
        #expect(try await resolver.resolve(did) == document)
    }

    @Test("EBSI resolver rejects other methods")
    func wrongMethod() async {
        let document = DIDDocument(id: "did:ebsi:x", verificationMethod: [], authentication: [], assertionMethod: [])
        let resolver = EBSIDIDResolver(client: FixtureEBSIClient(document: document))
        await #expect(throws: DIDResolutionError.unsupportedMethod) {
            try await resolver.resolve("did:key:z6Mk")
        }
    }

    @Test("Registry and status clients reject unsafe configuration before network")
    func unsafeConfiguration() async throws {
        #expect(throws: DIDResolutionError.registryUnavailable) {
            try URLSessionEBSIRegistryClient(registryBaseURL: URL(string: "http://registry.example")!)
        }
        #expect(throws: DIDResolutionError.registryUnavailable) {
            try URLSessionCredentialStatusClient(
                allowedHosts: [],
                verifier: FixtureStatusVerifier()
            )
        }
        let client = try URLSessionCredentialStatusClient(
            allowedHosts: ["status.example"],
            verifier: FixtureStatusVerifier()
        )
        await #expect(throws: DIDResolutionError.registryUnavailable) {
            try await client.check(
                CredentialStatusReference(
                    statusListURL: URL(string: "https://status.example/list")!,
                    index: -1
                ),
                at: Date()
            )
        }
    }

    @Test("Status client invokes verifier only for bounded successful response")
    func statusVerifierBoundary() async throws {
        let verifier = RecordingStatusVerifier()
        let url = URL(string: "https://status.example/list")!
        let client = try URLSessionCredentialStatusClient(
            allowedHosts: ["status.example"],
            verifier: verifier,
            httpClient: FixtureHTTPClient(
                response: BoundedHTTPResponse(
                    data: Data("signed.status.token".utf8),
                    statusCode: 200,
                    finalURL: url
                )
            )
        )
        let result = try await client.check(
            CredentialStatusReference(statusListURL: url, index: 4),
            at: Date(timeIntervalSince1970: 1_754_524_800)
        )
        #expect(result.value == .valid)
        #expect(await verifier.calls == 1)
    }

    @Test("Registry resolver constructs one exact DID path segment")
    func safeRegistryPath() async throws {
        let did = "did:ebsi:zSafe123"
        let document = DIDDocument(id: did, verificationMethod: [], authentication: [], assertionMethod: [])
        let data = try JSONEncoder().encode(document)
        let http = RecordingEBSIHTTPClient(data: data)
        let client = try URLSessionEBSIRegistryClient(
            registryBaseURL: URL(string: "https://ebsi.oari.io/did-registry/v5/identifiers")!,
            httpClient: http
        )
        _ = try await client.resolve(did: did, at: Date())
        #expect(await http.requestedURL?.absoluteString ==
            "https://ebsi.oari.io/did-registry/v5/identifiers/did:ebsi:zSafe123")

        await #expect(throws: DIDResolutionError.invalidDID) {
            _ = try await client.resolve(did: "did:ebsi:x/../../attack?next=http://evil.example", at: Date())
        }
        #expect(await http.calls == 1)
    }
}

private struct FixtureEBSIClient: EBSIRegistryClient {
    let document: DIDDocument
    func resolve(did: String, at date: Date) async throws -> ResolvedDID {
        ResolvedDID(
            document: document,
            evidence: TrustEvidence(
                source: .ebsiRegistry,
                sourceIdentifier: "fixture:ebsi",
                result: .valid,
                checkedAt: date,
                expiresAt: date.addingTimeInterval(60),
                evidenceDigest: String(repeating: "a", count: 64)
            )
        )
    }
}

private struct FixtureStatusVerifier: StatusListTokenVerifier {
    func verify(compactToken: String, index: Int, at date: Date) async throws -> CredentialStatusValue {
        .valid
    }
}

private struct FixtureHTTPClient: BoundedHTTPSClient {
    let response: BoundedHTTPResponse
    func get(_ url: URL, maximumBytes: Int) async throws -> BoundedHTTPResponse { response }
}

private actor RecordingStatusVerifier: StatusListTokenVerifier {
    private(set) var calls = 0
    func verify(compactToken: String, index: Int, at date: Date) async throws -> CredentialStatusValue {
        calls += 1
        return .valid
    }
}

private actor RecordingEBSIHTTPClient: BoundedHTTPSClient {
    let data: Data
    private(set) var requestedURL: URL?
    private(set) var calls = 0

    init(data: Data) { self.data = data }

    func get(_ url: URL, maximumBytes: Int) async throws -> BoundedHTTPResponse {
        calls += 1
        requestedURL = url
        return BoundedHTTPResponse(data: data, statusCode: 200, finalURL: url)
    }
}
