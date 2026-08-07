import Foundation

public struct CompositeDIDResolver: DIDResolver, Sendable {
    private let ebsi: any DIDResolver
    private let key = KeyDIDResolver()

    public init(ebsi: any DIDResolver) { self.ebsi = ebsi }

    public func resolve(_ did: String) async throws -> DIDDocument {
        if did.hasPrefix("did:key:") { return try await key.resolve(did) }
        if did.hasPrefix("did:ebsi:") { return try await ebsi.resolve(did) }
        throw DIDResolutionError.unsupportedMethod
    }
}
