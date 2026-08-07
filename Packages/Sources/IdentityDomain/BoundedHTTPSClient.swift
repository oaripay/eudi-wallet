import Foundation

public struct BoundedHTTPResponse: Equatable, Sendable {
    public let data: Data
    public let statusCode: Int
    public let finalURL: URL

    public init(data: Data, statusCode: Int, finalURL: URL) {
        self.data = data
        self.statusCode = statusCode
        self.finalURL = finalURL
    }
}

public protocol BoundedHTTPSClient: Sendable {
    func get(_ url: URL, maximumBytes: Int) async throws -> BoundedHTTPResponse
}

public struct URLSessionBoundedHTTPSClient: BoundedHTTPSClient, Sendable {
    public init() {}

    public func get(_ url: URL, maximumBytes: Int) async throws -> BoundedHTTPResponse {
        guard maximumBytes > 0,
              url.scheme?.lowercased() == "https", let host = url.host?.lowercased(),
              url.user == nil, url.password == nil,
              host != "localhost", host != "::1", !host.hasSuffix(".local"),
              !Self.isPrivateIPv4Literal(host), !Self.isReservedIPv6Literal(host) else {
            throw DIDResolutionError.registryUnavailable
        }
        let delegate = RejectRedirectDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.bytes(from: url)
        guard let http = response as? HTTPURLResponse,
              let finalURL = http.url,
              finalURL.scheme == "https",
              finalURL.host == url.host,
              (finalURL.port ?? 443) == (url.port ?? 443) else {
            throw DIDResolutionError.registryUnavailable
        }
        var data = Data()
        data.reserveCapacity(min(maximumBytes, 65_536))
        for try await byte in bytes {
            guard data.count < maximumBytes else {
                throw DIDResolutionError.registryUnavailable
            }
            data.append(byte)
        }
        return BoundedHTTPResponse(data: data, statusCode: http.statusCode, finalURL: finalURL)
    }

    private static func isPrivateIPv4Literal(_ host: String) -> Bool {
        let parts = host.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return false }
        return parts[0] == 10 || parts[0] == 127 ||
            (parts[0] == 169 && parts[1] == 254) ||
            (parts[0] == 172 && (16...31).contains(parts[1])) ||
            (parts[0] == 192 && parts[1] == 168) || parts[0] >= 224
    }

    private static func isReservedIPv6Literal(_ host: String) -> Bool {
        guard host.contains(":") else { return false }
        return host == "::" || host == "::1" || host.hasPrefix("fc") ||
            host.hasPrefix("fd") || host.hasPrefix("fe8") || host.hasPrefix("fe9") ||
            host.hasPrefix("fea") || host.hasPrefix("feb") || host.hasPrefix("ff")
    }
}

private final class RejectRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
