import Foundation
import WalletDomain

public struct ProfileID: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }
}

public enum SpecificationStatus: String, Codable, Sendable {
    case draft
    case implementersDraft
    case final
    case recommendation
    case vendorProfile
}

public struct SpecificationVersion: Codable, Equatable, Sendable {
    public let name: String
    public let revision: String
    public let status: SpecificationStatus
    public let source: URL
    public let checkedOn: Date

    public init(
        name: String,
        revision: String,
        status: SpecificationStatus,
        source: URL,
        checkedOn: Date
    ) {
        self.name = name
        self.revision = revision
        self.status = status
        self.source = source
        self.checkedOn = checkedOn
    }
}

public enum TrustSourceKind: String, Codable, CaseIterable, Hashable, Sendable {
    case signedMetadata
    case x509
    case euTrustList
    case nationalRPRegister
    case ebsiRegistry
    case credentialStatus
}

public enum TrustPolicyMode: String, Codable, Sendable {
    case regulatedStrict
    case productionConsent = "oariProductionConsent"
    case development
}

public struct TrustFreshnessPolicy: Codable, Equatable, Sendable {
    public let maximumAge: TimeInterval
    public let maximumValidity: TimeInterval

    public init(maximumAge: TimeInterval, maximumValidity: TimeInterval) {
        self.maximumAge = maximumAge
        self.maximumValidity = maximumValidity
    }
}

public struct InteroperabilityProfile: Codable, Equatable, Identifiable, Sendable {
    public let id: ProfileID
    public let openID4VCI: SpecificationVersion
    public let openID4VP: SpecificationVersion
    public let dcql: SpecificationVersion
    public let vcdm: SpecificationVersion
    public let credentialFormats: Set<CredentialFormat>
    public let identifierMethods: Set<IdentifierMethod>
    public let signingAlgorithms: Set<SigningAlgorithm>
    public let keyProtection: KeyProtectionPolicy
    public let requiredTrustSources: Set<TrustSourceKind>
    public let trustFreshness: [TrustSourceKind: TrustFreshnessPolicy]
    public let trustPolicyMode: TrustPolicyMode
    public let permitsUntrustedOneTimeConsent: Bool
    public let eudiProfile: String?
    public let ebsiProfile: String?
    public let iGrantProfile: String?
    public let retirementRule: String

    public init(
        id: ProfileID,
        openID4VCI: SpecificationVersion,
        openID4VP: SpecificationVersion,
        dcql: SpecificationVersion,
        vcdm: SpecificationVersion,
        credentialFormats: Set<CredentialFormat>,
        identifierMethods: Set<IdentifierMethod>,
        signingAlgorithms: Set<SigningAlgorithm>,
        keyProtection: KeyProtectionPolicy,
        requiredTrustSources: Set<TrustSourceKind>,
        trustFreshness: [TrustSourceKind: TrustFreshnessPolicy],
        trustPolicyMode: TrustPolicyMode,
        permitsUntrustedOneTimeConsent: Bool,
        eudiProfile: String? = nil,
        ebsiProfile: String? = nil,
        iGrantProfile: String? = nil,
        retirementRule: String
    ) {
        self.id = id
        self.openID4VCI = openID4VCI
        self.openID4VP = openID4VP
        self.dcql = dcql
        self.vcdm = vcdm
        self.credentialFormats = credentialFormats
        self.identifierMethods = identifierMethods
        self.signingAlgorithms = signingAlgorithms
        self.keyProtection = keyProtection
        self.requiredTrustSources = requiredTrustSources
        self.trustFreshness = trustFreshness
        self.trustPolicyMode = trustPolicyMode
        self.permitsUntrustedOneTimeConsent = permitsUntrustedOneTimeConsent
        self.eudiProfile = eudiProfile
        self.ebsiProfile = ebsiProfile
        self.iGrantProfile = iGrantProfile
        self.retirementRule = retirementRule
    }
}

public struct ProfileRequest: Equatable, Sendable {
    public let id: ProfileID
    public let credentialFormat: CredentialFormat
    public let identifierMethod: IdentifierMethod
    public let signingAlgorithm: SigningAlgorithm

    public init(
        id: ProfileID,
        credentialFormat: CredentialFormat,
        identifierMethod: IdentifierMethod,
        signingAlgorithm: SigningAlgorithm
    ) {
        self.id = id
        self.credentialFormat = credentialFormat
        self.identifierMethod = identifierMethod
        self.signingAlgorithm = signingAlgorithm
    }
}
