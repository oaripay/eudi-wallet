import Foundation

public enum ProtocolInputRoute: Equatable, Sendable {
    case openID4VP(URL)
    case openID4VCI(URL)
    case unsupported(URL)
}

public enum ProtocolInputError: Error, Equatable, Sendable {
    case empty
    case tooLarge
    case malformedURL
    case unsupportedScheme
    case unsupportedHost
    case missingHostConfiguration
    case missingProtocolPayload
}

public struct ProtocolInputClassifier: Sendable {
    public let maximumBytes: Int
    public let allowedHosts: Set<String>

    public init(
        maximumBytes: Int = 8_192,
        allowedHosts: Set<String>
    ) {
        self.maximumBytes = maximumBytes
        self.allowedHosts = allowedHosts
    }

    public func classify(_ raw: String) throws -> ProtocolInputRoute {
        guard !raw.isEmpty else { throw ProtocolInputError.empty }
        guard raw.utf8.count <= maximumBytes else { throw ProtocolInputError.tooLarge }
        guard let url = URL(string: raw), let scheme = url.scheme?.lowercased() else {
            throw ProtocolInputError.malformedURL
        }
        guard ["https", "openid4vp", "openid-credential-offer"].contains(scheme) else {
            throw ProtocolInputError.unsupportedScheme
        }
        if scheme == "https" {
            guard !allowedHosts.isEmpty else {
                throw ProtocolInputError.missingHostConfiguration
            }
            guard let host = url.host?.lowercased(), !host.isEmpty,
                  allowedHosts.contains(host) else {
                throw ProtocolInputError.unsupportedHost
            }
        }
        guard url.query?.isEmpty == false || url.pathComponents.count > 1 else {
            throw ProtocolInputError.missingProtocolPayload
        }

        if scheme == "openid4vp" || url.queryItems?.contains(where: { $0.name == "request_uri" || $0.name == "request" }) == true {
            return .openID4VP(url)
        }
        if scheme == "openid-credential-offer" || url.queryItems?.contains(where: { $0.name == "credential_offer" || $0.name == "credential_offer_uri" }) == true {
            return .openID4VCI(url)
        }
        return .unsupported(url)
    }
}

private extension URL {
    var queryItems: [URLQueryItem]? {
        URLComponents(url: self, resolvingAgainstBaseURL: false)?.queryItems
    }
}
