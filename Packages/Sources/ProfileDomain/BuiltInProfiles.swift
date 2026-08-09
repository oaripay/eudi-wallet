import Foundation
import WalletDomain

public enum BuiltInProfiles {
    public static let vcdm2OpenID4VCProfileID = ProfileID(rawValue: "oari-development-final-1")
    public static let iGrantDraftCompatibilityID = ProfileID(rawValue: "igrant-d13-d18-compatibility-1")

    public static func vcdm2OpenID4VCProfile(checkedOn: Date) -> InteroperabilityProfile {
        InteroperabilityProfile(
            id: vcdm2OpenID4VCProfileID,
            openID4VCI: spec(
                "OpenID for Verifiable Credential Issuance",
                "1.0",
                .final,
                "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html",
                checkedOn
            ),
            openID4VP: spec(
                "OpenID for Verifiable Presentations",
                "1.0",
                .final,
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html",
                checkedOn
            ),
            dcql: spec(
                "Digital Credentials Query Language",
                "1.0",
                .final,
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l",
                checkedOn
            ),
            vcdm: spec(
                "Verifiable Credentials Data Model",
                "2.0",
                .recommendation,
                "https://www.w3.org/TR/vc-data-model-2.0/",
                checkedOn
            ),
            credentialFormats: [.jwtVC],
            identifierMethods: [.didKey, .didEbsi],
            signingAlgorithms: [.es256],
            keyProtection: .secureEnclavePreferred,
            requiredTrustSources: [.signedMetadata, .ebsiRegistry, .credentialStatus],
            trustFreshness: [
                .signedMetadata: TrustFreshnessPolicy(maximumAge: 3_600, maximumValidity: 86_400),
                .ebsiRegistry: TrustFreshnessPolicy(maximumAge: 3_600, maximumValidity: 86_400),
                .credentialStatus: TrustFreshnessPolicy(maximumAge: 300, maximumValidity: 3_600),
            ],
            trustPolicyMode: .development,
            permitsUntrustedOneTimeConsent: true,
            ebsiProfile: "VCDM 2.0 JWT VC with EBSI trust",
            retirementRule: "Retire when the selected production EUDI/EBSI profile replaces this development profile."
        )
    }

    public static func iGrantDraftCompatibility(checkedOn: Date) -> InteroperabilityProfile {
        InteroperabilityProfile(
            id: iGrantDraftCompatibilityID,
            openID4VCI: spec(
                "OpenID for Verifiable Credential Issuance",
                "Draft 13",
                .draft,
                "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html",
                checkedOn
            ),
            openID4VP: spec(
                "OpenID for Verifiable Presentations",
                "Draft 18",
                .draft,
                "https://openid.net/specs/openid-4-verifiable-presentations-1_0-18.html",
                checkedOn
            ),
            dcql: spec(
                "iGrant/EWC presentation query profile",
                "EWC RFC002 compatibility",
                .vendorProfile,
                "https://docs.igrant.io/",
                checkedOn
            ),
            vcdm: spec(
                "Verifiable Credentials Data Model",
                "2.0",
                .recommendation,
                "https://www.w3.org/TR/vc-data-model-2.0/",
                checkedOn
            ),
            credentialFormats: [.jwtVC, .sdJWTVC, .mdoc],
            identifierMethods: [.didKey, .didEbsi, .jwk],
            signingAlgorithms: [.es256],
            keyProtection: .secureEnclavePreferred,
            requiredTrustSources: [.signedMetadata, .credentialStatus],
            trustFreshness: [
                .signedMetadata: TrustFreshnessPolicy(maximumAge: 3_600, maximumValidity: 86_400),
                .credentialStatus: TrustFreshnessPolicy(maximumAge: 300, maximumValidity: 3_600),
            ],
            trustPolicyMode: .development,
            permitsUntrustedOneTimeConsent: true,
            iGrantProfile: "Data Wallet Draft 13/Draft 18 with EWC RFC001/RFC002",
            retirementRule: "Remove after iGrant final OpenID 1.0 interoperability is verified and draft credentials are reissued."
        )
    }

    private static func spec(
        _ name: String,
        _ revision: String,
        _ status: SpecificationStatus,
        _ source: String,
        _ checkedOn: Date
    ) -> SpecificationVersion {
        SpecificationVersion(
            name: name,
            revision: revision,
            status: status,
            source: URL(string: source)!,
            checkedOn: checkedOn
        )
    }
}
