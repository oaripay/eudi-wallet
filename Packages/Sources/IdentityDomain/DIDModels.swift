import Foundation

public struct PublicJWK: Codable, Equatable, Sendable {
    public let kty: String
    public let crv: String
    public let x: String
    public let y: String?

    public init(kty: String, crv: String, x: String, y: String? = nil) {
        self.kty = kty
        self.crv = crv
        self.x = x
        self.y = y
    }
}

public struct DIDVerificationMethod: Codable, Equatable, Sendable {
    public let id: String
    public let type: String
    public let controller: String
    public let publicKeyJwk: PublicJWK

    public init(id: String, type: String, controller: String, publicKeyJwk: PublicJWK) {
        self.id = id
        self.type = type
        self.controller = controller
        self.publicKeyJwk = publicKeyJwk
    }
}

public struct DIDDocument: Codable, Equatable, Sendable {
    public let id: String
    public let verificationMethod: [DIDVerificationMethod]
    public let authentication: [String]
    public let assertionMethod: [String]

    public init(
        id: String,
        verificationMethod: [DIDVerificationMethod],
        authentication: [String],
        assertionMethod: [String]
    ) {
        self.id = id
        self.verificationMethod = verificationMethod
        self.authentication = authentication
        self.assertionMethod = assertionMethod
    }
}

public enum DIDResolutionError: Error, Equatable, Sendable {
    case invalidDID
    case unsupportedMethod
    case unsupportedKeyType
    case malformedKey
    case notFound
    case registryUnavailable
}

public protocol DIDResolver: Sendable {
    func resolve(_ did: String) async throws -> DIDDocument
}
