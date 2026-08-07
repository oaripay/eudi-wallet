import Foundation
import ProfileDomain
import WalletDomain

public enum IssuanceGrant: Equatable, Sendable {
    case authorizationCode(authorizationServer: URL)
    case preAuthorizedCode(code: String, txCodeRequired: Bool)
}

public struct CredentialOffer: Equatable, Sendable {
    public let credentialIssuer: URL
    public let configurationIDs: [String]
    public let grant: IssuanceGrant

    public init(credentialIssuer: URL, configurationIDs: [String], grant: IssuanceGrant) {
        self.credentialIssuer = credentialIssuer
        self.configurationIDs = configurationIDs
        self.grant = grant
    }
}

public struct IssuerMetadata: Equatable, Sendable {
    public let issuer: URL
    public let authorizationEndpoint: URL?
    public let tokenEndpoint: URL
    public let credentialEndpoint: URL
    public let deferredCredentialEndpoint: URL?
    public let supportedConfigurations: Set<String>

    public init(
        issuer: URL,
        authorizationEndpoint: URL?,
        tokenEndpoint: URL,
        credentialEndpoint: URL,
        deferredCredentialEndpoint: URL?,
        supportedConfigurations: Set<String>
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.credentialEndpoint = credentialEndpoint
        self.deferredCredentialEndpoint = deferredCredentialEndpoint
        self.supportedConfigurations = supportedConfigurations
    }
}

public struct IssuanceRequest: Equatable, Sendable {
    public let profileID: ProfileID
    public let configurationID: String
    public let issuer: URL
    public let grant: IssuanceGrant

    public init(profileID: ProfileID, configurationID: String, issuer: URL, grant: IssuanceGrant) {
        self.profileID = profileID
        self.configurationID = configurationID
        self.issuer = issuer
        self.grant = grant
    }
}

public enum PKCEMethod: String, Equatable, Sendable {
    case s256 = "S256"
}

public struct AuthorizationCodeContext: Equatable, Sendable {
    public let verifier: String
    public let challenge: String
    public let method: PKCEMethod
    public let state: String

    public init(verifier: String, challenge: String, method: PKCEMethod, state: String) {
        self.verifier = verifier
        self.challenge = challenge
        self.method = method
        self.state = state
    }
}

public enum IssuanceError: Error, Equatable, Sendable {
    case malformedJSON
    case missingField(String)
    case invalidURL
    case unsupportedGrant
    case issuerMismatch
    case unsupportedConfiguration
    case invalidPKCE
    case authorizationStateMismatch
}

public protocol IssuanceTransport: Sendable {
    func fetchIssuerMetadata(issuer: URL) async throws -> IssuerMetadata
    func exchangeAuthorizationCode(_ code: String, verifier: String, metadata: IssuerMetadata) async throws -> TokenResponse
    func exchangePreAuthorizedCode(_ code: String, txCode: String?, metadata: IssuerMetadata) async throws -> TokenResponse
    func requestCredential(_ request: CredentialRequest, token: TokenResponse, metadata: IssuerMetadata) async throws -> CredentialResponse
}

public struct TokenResponse: Equatable, Sendable {
    public let accessToken: String
    public let cNonce: String?
    public let expiresAt: Date

    public init(accessToken: String, cNonce: String?, expiresAt: Date) {
        self.accessToken = accessToken
        self.cNonce = cNonce
        self.expiresAt = expiresAt
    }
}

public struct CredentialRequest: Equatable, Sendable {
    public let configurationID: String
    public let proofJWT: String

    public init(configurationID: String, proofJWT: String) {
        self.configurationID = configurationID
        self.proofJWT = proofJWT
    }
}

public enum CredentialResponse: Equatable, Sendable {
    /// Metadata for a document already validated and retained by Wallet Kit.
    /// Raw credential bytes never cross into ProtocolEngine.
    case issued(metadata: CredentialRecord)
    case deferred(transactionID: String, interval: TimeInterval)
}
