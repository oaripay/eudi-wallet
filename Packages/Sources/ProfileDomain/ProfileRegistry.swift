import Foundation
import WalletDomain

public protocol ProfileRegistry: Sendable {
    func profile(for request: ProfileRequest) throws -> InteroperabilityProfile
}

public struct StaticProfileRegistry: ProfileRegistry, Sendable {
    private let profiles: [ProfileID: InteroperabilityProfile]

    public init(profiles: [InteroperabilityProfile]) throws {
        var indexed: [ProfileID: InteroperabilityProfile] = [:]
        for profile in profiles {
            guard indexed[profile.id] == nil else {
                throw ProfileError.duplicateProfile(profile.id)
            }
            for source in profile.requiredTrustSources {
                guard let freshness = profile.trustFreshness[source],
                      freshness.maximumAge > 0,
                      freshness.maximumValidity > 0 else {
                    throw ProfileError.invalidTrustFreshness(profile.id, source)
                }
            }
            indexed[profile.id] = profile
        }
        self.profiles = indexed
    }

    public func profile(for request: ProfileRequest) throws -> InteroperabilityProfile {
        guard let profile = profiles[request.id] else {
            throw ProfileError.unsupportedProfile(request.id)
        }
        guard profile.credentialFormats.contains(request.credentialFormat) else {
            throw ProfileError.unsupportedCredentialFormat(request.credentialFormat)
        }
        guard profile.identifierMethods.contains(request.identifierMethod) else {
            throw ProfileError.unsupportedIdentifierMethod(request.identifierMethod)
        }
        guard profile.signingAlgorithms.contains(request.signingAlgorithm) else {
            throw ProfileError.unsupportedSigningAlgorithm(request.signingAlgorithm)
        }
        return profile
    }
}

public enum ProfileError: Error, Equatable, Sendable {
    case duplicateProfile(ProfileID)
    case unsupportedProfile(ProfileID)
    case unsupportedCredentialFormat(CredentialFormat)
    case unsupportedIdentifierMethod(IdentifierMethod)
    case unsupportedSigningAlgorithm(SigningAlgorithm)
    case invalidTrustFreshness(ProfileID, TrustSourceKind)
}
