import Foundation
import IdentityDomain
import Testing
import TrustDomain

struct EBSIEndpointRegistryTests {
    @Test("Development registry accepts multiple explicit HTTPS trust chains")
    func developmentEndpoints() throws {
        let registry = try EBSIEndpointRegistry(policy: .development, endpoints: [
            try endpoint(id: "oari", host: "ebsi.oari.io"),
            try endpoint(id: "official-candidate", host: "hub.example"),
        ])
        #expect(registry.endpoints.map(\.id) == ["oari", "official-candidate"])
        let oari = try EBSIChainEndpoint.developmentEBSIRegistries()
        #expect(oari.didRegistryURL.absoluteString == "https://ebsi.oari.io/did-registry/v5/identifiers")
        #expect(oari.trustedIssuersRegistryURL.path == "/trusted-issuers-registry/v5/issuers")
        #expect(oari.trustedSchemasRegistryURL.path == "/trusted-schemas-registry/v3/schemas")
    }

    @Test("Production registry is pinned to the exact EBSI endpoint")
    func productionApproval() throws {
        let endpoint = try endpoint(id: "official", host: "registry.example")
        #expect(throws: EBSIEndpointError.unapprovedProductionEndpoint) {
            _ = try EBSIEndpointRegistry(policy: .production, endpoints: [endpoint])
        }
        let production = try EBSIChainEndpoint.productionEBSIRegistries()
        #expect(try EBSIEndpointRegistry(
            policy: .production,
            endpoints: [production]
        ).endpoints == [production])
        #expect(production.didRegistryURL.absoluteString == "https://ebsi.oari.io/did-registry/v5/identifiers")
        #expect(production.trustedIssuersRegistryURL.absoluteString == "https://ebsi.oari.io/trusted-issuers-registry/v5/issuers")
        #expect(production.trustedSchemasRegistryURL.absoluteString == "https://ebsi.oari.io/trusted-schemas-registry/v3/schemas")
        let attacker = try self.endpoint(id: "official", host: "attacker.example")
        #expect(throws: EBSIEndpointError.unapprovedProductionEndpoint) {
            _ = try EBSIEndpointRegistry(
                policy: .production,
                endpoints: [attacker],
                approvedProductionEndpoints: ["official": attacker]
            )
        }
    }

    @Test("Registry rejects unsafe and duplicate endpoint configuration")
    func unsafeConfiguration() throws {
        #expect(throws: EBSIEndpointError.invalidEndpoint) {
            _ = try EBSIChainEndpoint(
                id: "unsafe", displayName: "Unsafe",
                didRegistryURL: URL(string: "http://registry.example/did")!,
                trustedIssuersRegistryURL: URL(string: "https://registry.example/tir")!,
                trustedSchemasRegistryURL: URL(string: "https://registry.example/tsr")!
            )
        }
        let endpoint = try endpoint(id: "duplicate", host: "registry.example")
        #expect(throws: EBSIEndpointError.duplicateEndpoint) {
            _ = try EBSIEndpointRegistry(policy: .development, endpoints: [endpoint, endpoint])
        }
        let alias = try self.endpoint(id: "alias", host: "registry.example")
        #expect(throws: EBSIEndpointError.duplicateEndpoint) {
            _ = try EBSIEndpointRegistry(policy: .development, endpoints: [endpoint, alias])
        }
        let unsafeJSON = Data("""
        {"id":" unsafe ","displayName":"Unsafe","didRegistryURL":"http://registry.example/did","trustedIssuersRegistryURL":"https://user:pass@registry.example/tir","trustedSchemasRegistryURL":"https://registry.example/tsr?query=x"}
        """.utf8)
        #expect(throws: (any Error).self) {
            _ = try JSONDecoder().decode(EBSIChainEndpoint.self, from: unsafeJSON)
        }
    }

    @Test("Resolver tries configured trust chains in order and fails closed")
    func orderedResolution() async throws {
        let did = "did:ebsi:holder"
        let result = ResolvedDID(
            document: DIDDocument(id: did, verificationMethod: [], authentication: [], assertionMethod: []),
            evidence: TrustEvidence(
                source: .ebsiRegistry, sourceIdentifier: "fixture:second", result: .valid,
                checkedAt: Date(timeIntervalSince1970: 1_700_000_000),
                expiresAt: Date(timeIntervalSince1970: 1_700_000_060),
                evidenceDigest: String(repeating: "a", count: 64)
            )
        )
        let client = try MultiEndpointEBSIRegistryClient(clients: [
            NamedEBSIRegistryClient(endpointID: "first", client: FailingRegistryClient()),
            NamedEBSIRegistryClient(endpointID: "second", client: FixedRegistryClient(result: result)),
        ])
        #expect(try await client.resolve(did: did, at: Date()) == result)
        let failing = try MultiEndpointEBSIRegistryClient(clients: [
            NamedEBSIRegistryClient(endpointID: "only", client: FailingRegistryClient()),
        ])
        await #expect(throws: EBSIEndpointError.resolutionFailed) {
            _ = try await failing.resolve(did: did, at: Date())
        }
    }

    private func endpoint(id: String, host: String) throws -> EBSIChainEndpoint {
        try EBSIChainEndpoint(
            id: id,
            displayName: id,
            didRegistryURL: URL(string: "https://\(host)/did-registry/identifiers")!,
            trustedIssuersRegistryURL: URL(string: "https://\(host)/trusted-issuers-registry/issuers")!,
            trustedSchemasRegistryURL: URL(string: "https://\(host)/trusted-schemas-registry/schemas")!
        )
    }
}

private struct FailingRegistryClient: EBSIRegistryClient {
    func resolve(did: String, at date: Date) async throws -> ResolvedDID {
        throw EBSIEndpointError.resolutionFailed
    }
}

private struct FixedRegistryClient: EBSIRegistryClient {
    let result: ResolvedDID
    func resolve(did: String, at date: Date) async throws -> ResolvedDID { result }
}
