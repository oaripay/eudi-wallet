import Foundation

public enum EBSIEnvironmentPolicy: String, Codable, Equatable, Sendable {
    case development
    case production
}

public struct EBSIChainEndpoint: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let displayName: String
    public let didRegistryURL: URL
    public let trustedIssuersRegistryURL: URL
    public let trustedSchemasRegistryURL: URL

    public init(
        id: String,
        displayName: String,
        didRegistryURL: URL,
        trustedIssuersRegistryURL: URL,
        trustedSchemasRegistryURL: URL
    ) throws {
        let id = id.trimmingCharacters(in: .whitespacesAndNewlines)
        let displayName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty, !displayName.isEmpty else { throw EBSIEndpointError.invalidEndpoint }
        self.id = id
        self.displayName = displayName
        self.didRegistryURL = try Self.validatedBaseURL(didRegistryURL)
        self.trustedIssuersRegistryURL = try Self.validatedBaseURL(trustedIssuersRegistryURL)
        self.trustedSchemasRegistryURL = try Self.validatedBaseURL(trustedSchemasRegistryURL)
    }

    private enum CodingKeys: String, CodingKey {
        case id, displayName, didRegistryURL, trustedIssuersRegistryURL, trustedSchemasRegistryURL
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            id: values.decode(String.self, forKey: .id),
            displayName: values.decode(String.self, forKey: .displayName),
            didRegistryURL: values.decode(URL.self, forKey: .didRegistryURL),
            trustedIssuersRegistryURL: values.decode(URL.self, forKey: .trustedIssuersRegistryURL),
            trustedSchemasRegistryURL: values.decode(URL.self, forKey: .trustedSchemasRegistryURL)
        )
    }

    private static func validatedBaseURL(_ url: URL) throws -> URL {
        guard (url.scheme?.lowercased() == "https" ||
            (url.scheme?.lowercased() == "http" && url.host == "127.0.0.1")), url.host != nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
            throw EBSIEndpointError.invalidEndpoint
        }
        return url
    }

    public static func developmentEBSIRegistries() throws -> EBSIChainEndpoint {
        try EBSIChainEndpoint(
            id: "oari-development",
            displayName: "EBSI Development Registries",
            didRegistryURL: URL(string: "https://ebsi.oari.io/did-registry/v5/identifiers")!,
            trustedIssuersRegistryURL: URL(string: "https://ebsi.oari.io/trusted-issuers-registry/v5/issuers")!,
            trustedSchemasRegistryURL: URL(string: "https://ebsi.oari.io/trusted-schemas-registry/v3/schemas")!
        )
    }

    /// The immutable EBSI collections used by the production wallet.
    public static func productionEBSIRegistries() throws -> EBSIChainEndpoint {
        try EBSIChainEndpoint(
            id: "oari-production",
            displayName: "EBSI Production Registries",
            didRegistryURL: URL(string: "https://ebsi.oari.io/did-registry/v5/identifiers")!,
            trustedIssuersRegistryURL: URL(string: "https://ebsi.oari.io/trusted-issuers-registry/v5/issuers")!,
            trustedSchemasRegistryURL: URL(string: "https://ebsi.oari.io/trusted-schemas-registry/v3/schemas")!
        )
    }

    public static func localAuthority() throws -> EBSIChainEndpoint {
        try EBSIChainEndpoint(
            id: "local-authority",
            displayName: "Local EBSI Authority",
            didRegistryURL: URL(string: "http://127.0.0.1:4080/openid")!,
            trustedIssuersRegistryURL: URL(string: "http://127.0.0.1:4080/openid")!,
            trustedSchemasRegistryURL: URL(string: "http://127.0.0.1:4080/openid")!
        )
    }
}

public enum EBSIEndpointError: Error, Equatable, Sendable {
    case invalidEndpoint
    case duplicateEndpoint
    case noEndpoints
    case unapprovedProductionEndpoint
    case resolutionFailed
}

public struct EBSIEndpointRegistry: Sendable {
    public let policy: EBSIEnvironmentPolicy
    public let endpoints: [EBSIChainEndpoint]

    public init(
        policy: EBSIEnvironmentPolicy,
        endpoints: [EBSIChainEndpoint],
        approvedProductionEndpoints _: [String: EBSIChainEndpoint] = [:]
    ) throws {
        guard !endpoints.isEmpty else { throw EBSIEndpointError.noEndpoints }
        guard Set(endpoints.map(\.id)).count == endpoints.count else {
            throw EBSIEndpointError.duplicateEndpoint
        }
        let endpointSignatures = endpoints.map {
            "\($0.didRegistryURL.absoluteString)|\($0.trustedIssuersRegistryURL.absoluteString)|\($0.trustedSchemasRegistryURL.absoluteString)"
        }
        guard Set(endpointSignatures).count == endpointSignatures.count else {
            throw EBSIEndpointError.duplicateEndpoint
        }
        if policy == .production {
            // Production is deliberately not configurable. In particular, a
            // caller-supplied approval map must not turn an arbitrary host into
            // a production trust anchor.
            let pinned = try EBSIChainEndpoint.productionEBSIRegistries()
            guard endpoints == [pinned] else {
                throw EBSIEndpointError.unapprovedProductionEndpoint
            }
        }
        self.policy = policy
        self.endpoints = endpoints
    }
}

public struct NamedEBSIRegistryClient: Sendable {
    public let endpointID: String
    public let client: any EBSIRegistryClient

    public init(endpointID: String, client: any EBSIRegistryClient) {
        self.endpointID = endpointID
        self.client = client
    }
}

public struct MultiEndpointEBSIRegistryClient: EBSIRegistryClient, Sendable {
    private let clients: [NamedEBSIRegistryClient]

    public init(registry: EBSIEndpointRegistry, httpClient: any BoundedHTTPSClient) throws {
        clients = try registry.endpoints.map { endpoint in
            NamedEBSIRegistryClient(
                endpointID: endpoint.id,
                client: try URLSessionEBSIRegistryClient(
                    registryBaseURL: endpoint.didRegistryURL,
                    httpClient: httpClient
                )
            )
        }
    }

    public init(clients: [NamedEBSIRegistryClient]) throws {
        guard !clients.isEmpty else { throw EBSIEndpointError.noEndpoints }
        self.clients = clients
    }

    public func resolve(did: String, at date: Date) async throws -> ResolvedDID {
        for entry in clients {
            do {
                let result = try await entry.client.resolve(did: did, at: date)
                guard result.document.id == did else { continue }
                return result
            } catch {
                continue
            }
        }
        throw EBSIEndpointError.resolutionFailed
    }
}
