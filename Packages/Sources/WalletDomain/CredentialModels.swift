import Foundation

public struct CredentialID: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: UUID

    public init(rawValue: UUID) {
        self.rawValue = rawValue
    }

    public init() {
        self.init(rawValue: UUID())
    }
}

public enum CredentialFormat: String, Codable, CaseIterable, Sendable {
    case jwtVC = "jwt_vc_json"
    case sdJWTVC = "dc+sd-jwt"
    case mdoc
}

public enum CryptographicValidity: String, Codable, Sendable {
    case valid
    case invalid
    case notEvaluated
}

public enum IssuerTrustState: String, Codable, Sendable {
    case trusted
    case untrusted
    case invalid
    case indeterminate
    case notEvaluated
}

public enum CredentialStatusState: String, Codable, Sendable {
    case valid
    case suspended
    case revoked
    case indeterminate
    case notEvaluated
}

public enum LegalClassification: String, Codable, Sendable {
    case eudiPID
    case eudiAttestation
    case ebsiAttestation
    case oariProvisional
    case oariCredential
    case unclassified
}

public enum IdentifierMethod: String, Codable, Sendable {
    case didKey = "did:key"
    case didEbsi = "did:ebsi"
    case jwk
    case coseKey = "cose_key"
}

public struct HolderBinding: Codable, Equatable, Sendable {
    public let method: IdentifierMethod
    public let publicIdentifier: String
    public let keyID: KeyID

    public init(method: IdentifierMethod, publicIdentifier: String, keyID: KeyID) {
        self.method = method
        self.publicIdentifier = publicIdentifier
        self.keyID = keyID
    }
}

public struct CredentialRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: CredentialID
    public let configurationID: String
    public let walletDocumentID: String?
    public let backendID: String?
    public let backendDocumentID: String?
    public let displayName: String
    public let format: CredentialFormat
    public let profileID: String
    public let issuerIdentifier: String
    public let subjectIdentifier: String?
    public let holderBinding: HolderBinding?
    public let cryptographicValidity: CryptographicValidity
    public let issuerTrust: IssuerTrustState
    public let status: CredentialStatusState
    public let legalClassification: LegalClassification
    public let issuedAt: Date?
    public let expiresAt: Date?
    public let createdAt: Date

    public init(
        id: CredentialID = CredentialID(),
        configurationID: String,
        walletDocumentID: String? = nil,
        backendID: String? = nil,
        backendDocumentID: String? = nil,
        displayName: String,
        format: CredentialFormat,
        profileID: String,
        issuerIdentifier: String,
        subjectIdentifier: String? = nil,
        holderBinding: HolderBinding? = nil,
        cryptographicValidity: CryptographicValidity = .notEvaluated,
        issuerTrust: IssuerTrustState = .notEvaluated,
        status: CredentialStatusState = .notEvaluated,
        legalClassification: LegalClassification = .unclassified,
        issuedAt: Date? = nil,
        expiresAt: Date? = nil,
        createdAt: Date
    ) {
        self.id = id
        self.configurationID = configurationID
        self.walletDocumentID = walletDocumentID
        self.backendID = backendID
        self.backendDocumentID = backendDocumentID
        self.displayName = displayName
        self.format = format
        self.profileID = profileID
        self.issuerIdentifier = issuerIdentifier
        self.subjectIdentifier = subjectIdentifier
        self.holderBinding = holderBinding
        self.cryptographicValidity = cryptographicValidity
        self.issuerTrust = issuerTrust
        self.status = status
        self.legalClassification = legalClassification
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.createdAt = createdAt
    }
}
