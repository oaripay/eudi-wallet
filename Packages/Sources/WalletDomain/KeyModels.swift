import Foundation

public struct KeyID: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: UUID

    public init(rawValue: UUID) {
        self.rawValue = rawValue
    }

    public init() {
        self.init(rawValue: UUID())
    }
}

public enum KeyPurpose: String, Codable, CaseIterable, Sendable {
    case walletAttestation
    case credentialBinding
    case mdocDeviceAuthentication
    case sdJWTKeyBinding
    case didAuthentication
    case didAssertion
    case ephemeralSession
}

public enum SigningAlgorithm: String, Codable, Sendable {
    case es256 = "ES256"
}

public enum KeyAssurance: String, Codable, Sendable {
    case secureEnclave
    case keychainSoftware
}

public enum KeyProtectionPolicy: String, Codable, Sendable {
    case secureEnclaveRequired
    case secureEnclavePreferred
    case keychainSoftware
}

public enum SignatureFormat: String, Codable, Sendable {
    case joseRaw
    case x962DER
}

public struct PublicKeyMaterial: Equatable, Sendable {
    public let algorithm: SigningAlgorithm
    public let x963Representation: Data

    public init(algorithm: SigningAlgorithm, x963Representation: Data) {
        self.algorithm = algorithm
        self.x963Representation = x963Representation
    }
}

public struct KeyRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: KeyID
    public let purpose: KeyPurpose
    public let algorithm: SigningAlgorithm
    public let assurance: KeyAssurance
    public let applicationTag: String
    public let createdAt: Date

    public init(
        id: KeyID = KeyID(),
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
        assurance: KeyAssurance,
        applicationTag: String,
        createdAt: Date
    ) {
        self.id = id
        self.purpose = purpose
        self.algorithm = algorithm
        self.assurance = assurance
        self.applicationTag = applicationTag
        self.createdAt = createdAt
    }
}

public struct SigningRequest: Equatable, Sendable {
    public let keyID: KeyID
    public let payload: Data
    public let userAuthenticationReason: String
    public let signatureFormat: SignatureFormat

    public init(
        keyID: KeyID,
        payload: Data,
        userAuthenticationReason: String,
        signatureFormat: SignatureFormat = .joseRaw
    ) {
        self.keyID = keyID
        self.payload = payload
        self.userAuthenticationReason = userAuthenticationReason
        self.signatureFormat = signatureFormat
    }
}
