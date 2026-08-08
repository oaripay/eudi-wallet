import Foundation
import WalletDomain

public struct OID4VCIClientSecurityState: Codable, Equatable, Sendable {
    public let dpopKeyID: KeyID
    public let clientAttestationKeyID: KeyID?
    public let responseEncryptionKeyID: KeyID
    public let createdAt: Date

    public init(
        dpopKeyID: KeyID,
        clientAttestationKeyID: KeyID?,
        responseEncryptionKeyID: KeyID,
        createdAt: Date = Date()
    ) {
        self.dpopKeyID = dpopKeyID
        self.clientAttestationKeyID = clientAttestationKeyID
        self.responseEncryptionKeyID = responseEncryptionKeyID
        self.createdAt = createdAt
    }
}

public struct OID4VCIDPoPClaims: Codable, Equatable, Sendable {
    public let method: String
    public let targetURI: String
    public let issuedAt: Date
    public let identifier: UUID

    public init(method: String, targetURI: String, issuedAt: Date = Date(), identifier: UUID = UUID()) {
        self.method = method
        self.targetURI = targetURI
        self.issuedAt = issuedAt
        self.identifier = identifier
    }
}

public struct OID4VCIResponseEncryptionParameters: Codable, Equatable, Sendable {
    public let algorithm: String
    public let encryption: String
    public let publicJWK: String

    public init(algorithm: String = "ECDH-ES", encryption: String = "A128CBC-HS256", publicJWK: String) {
        self.algorithm = algorithm
        self.encryption = encryption
        self.publicJWK = publicJWK
    }
}

public protocol OID4VCIClientSecurity: Sendable {
    func state(for profile: OID4VCITransportProfile) async throws -> OID4VCIClientSecurityState
    func dpopHeader(
        state: OID4VCIClientSecurityState,
        method: String,
        targetURI: URL,
        accessToken: String?
    ) async throws -> String
    func clientAttestationHeaders(
        state: OID4VCIClientSecurityState,
        audience: URL
    ) async throws -> [String: String]
    func responseEncryption(
        state: OID4VCIClientSecurityState
    ) async throws -> OID4VCIResponseEncryptionParameters
    func decryptCredentialResponse(
        state: OID4VCIClientSecurityState,
        compactJWE: Data
    ) async throws -> Data
}
