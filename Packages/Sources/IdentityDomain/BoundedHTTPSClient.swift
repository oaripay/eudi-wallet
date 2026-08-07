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
              url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil else {
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
