import CryptoKit
import EbsiW3CBackend
import Foundation
import IdentityDomain
import Testing
import TrustDomain
import WalletDomain

struct OariWorkspaceW3CBackendTests {
    @Test("Pre-authorized offer requires warning, signs proof, validates and stores credential")
    func preauthorizedIssuance() async throws {
        let transport = FixtureWorkspaceTransport()
        let keys = FixtureKeyProvider()
        let store = FixtureCredentialStore()
        let validator = FixtureCredentialValidator()
        let backend = OariWorkspaceW3CBackend(
            transport: transport,
            trustEvaluator: UntrustedIssuerEvaluator(),
            keyProvider: keys,
            credentialStore: store,
            credentialValidator: validator,
            profile: try .oariVcdm2Jwt(),
            now: { Date(timeIntervalSince1970: 1_800_000_000) }
        )
        let offerJSON = """
        {"credential_issuer":"https://issuer.example","credential_configuration_ids":["oari-v2"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}
        """
        let encoded = offerJSON.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let offer = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer=\(encoded)"
        )
        guard case .requireExplicitWarning = offer.trustOutcome else {
            Issue.record("Expected development warning")
            return
        }
        await #expect(throws: WorkspaceBackendError.invalidTransactionCode) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: true, transactionCode: "12ab56")
        }

        let second = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer=\(encoded)"
        )
        let issued = try await backend.issue(
            id: second.id,
            allowUntrusted: true,
            transactionCode: "123456"
        )
        #expect(issued.count == 1)
        #expect(try await store.credentials().count == 1)
        #expect(await validator.calls == 1)
        let requests = await transport.requests
        #expect(requests.contains { $0.url.path == "/token" && String(decoding: $0.body ?? Data(), as: UTF8.self).contains("tx_code=123456") })
        #expect(requests.contains { $0.url.path == "/credential" && String(decoding: $0.body ?? Data(), as: UTF8.self).contains("proofs") })
    }

    @Test("Referenced offer and cancellation are bounded")
    func referencedAndCancel() async throws {
        let backend = OariWorkspaceW3CBackend(
            transport: FixtureWorkspaceTransport(),
            trustEvaluator: TrustedIssuerEvaluator(),
            keyProvider: FixtureKeyProvider(),
            credentialStore: FixtureCredentialStore(),
            credentialValidator: FixtureCredentialValidator(),
            profile: try .oariVcdm2Jwt()
        )
        let offer = try await backend.resolveOffer(
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer"
        )
        await backend.cancel(id: offer.id)
        await #expect(throws: WorkspaceBackendError.unknownTransaction) {
            _ = try await backend.issue(id: offer.id, allowUntrusted: false, transactionCode: "123456")
        }
    }
}

private actor FixtureWorkspaceTransport: WorkspaceHTTPTransport {
    struct Request: Sendable { let url: URL; let method: String; let body: Data? }
    private(set) var requests: [Request] = []
    func send(url: URL, method: String, headers: [String: String], body: Data?) async throws -> WorkspaceHTTPResponse {
        requests.append(Request(url: url, method: method, body: body))
        let response: String
        switch url.path {
        case "/offer":
            response = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["oari-v2"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"pre-code","tx_code":{"input_mode":"numeric","length":6}}}}"#
        case "/.well-known/openid-credential-issuer":
            response = #"{"credential_endpoint":"https://issuer.example/credential","authorization_servers":["https://issuer.example"]}"#
        case "/.well-known/oauth-authorization-server":
            response = #"{"token_endpoint":"https://issuer.example/token"}"#
        case "/token":
            response = #"{"access_token":"access","c_nonce":"nonce-1"}"#
        case "/credential":
            response = #"{"credentials":[{"credential":"header.payload.signature"}]}"#
        default: throw WorkspaceBackendError.invalidResponse
        }
        return WorkspaceHTTPResponse(statusCode: 200, body: Data(response.utf8))
    }
}

private struct UntrustedIssuerEvaluator: WorkspaceIssuerTrustEvaluating {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict {
        .untrusted(reasons: [.issuerNotAccredited], evidence: [])
    }
}

private struct TrustedIssuerEvaluator: WorkspaceIssuerTrustEvaluating {
    func evaluate(issuer: String, at date: Date) async -> TrustVerdict { .trusted(evidence: []) }
}

private actor FixtureCredentialStore: EbsiCredentialStore {
    private var values: [StoredEbsiCredential] = []
    func credentials() async throws -> [StoredEbsiCredential] { values }
    func save(_ credential: StoredEbsiCredential) async throws { values.append(credential) }
    func delete(id: UUID) async throws { values.removeAll { $0.id == id } }
}

private actor FixtureCredentialValidator: WorkspaceCredentialValidating {
    private(set) var calls = 0
    func validate(
        rawCredential: Data,
        profile: EbsiCredentialProfile,
        expectedHolderDID: String,
        at date: Date
    ) async throws {
        calls += 1
        #expect(!expectedHolderDID.isEmpty)
    }
}

private actor FixtureKeyProvider: KeyProvider {
    private let key = P256.Signing.PrivateKey()
    private let id = KeyID()
    func createKey(
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
        requiresUserPresence: Bool,
        protection: KeyProtectionPolicy
    ) async throws -> KeyRecord {
        KeyRecord(
            id: id,
            purpose: purpose,
            algorithm: algorithm,
            assurance: .keychainSoftware,
            applicationTag: "fixture",
            createdAt: Date()
        )
    }
    func sign(_ request: SigningRequest) async throws -> Data {
        try key.signature(for: request.payload).rawRepresentation
    }
    func publicKey(id: KeyID) async throws -> PublicKeyMaterial {
        PublicKeyMaterial(algorithm: .es256, x963Representation: key.publicKey.x963Representation)
    }
    func deleteKey(id: KeyID) async throws {}
}
