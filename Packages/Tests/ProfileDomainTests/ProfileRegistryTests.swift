import Foundation
import ProfileDomain
import Testing
import WalletDomain

struct ProfileRegistryTests {
    private let checkedOn = Date(timeIntervalSince1970: 1_754_524_800)

    @Test("Final and iGrant draft behavior stay in separate profiles")
    func draftIsolation() throws {
        let final = BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: checkedOn)
        let draft = BuiltInProfiles.iGrantDraftCompatibility(checkedOn: checkedOn)

        #expect(final.openID4VCI.status == .final)
        #expect(final.openID4VP.status == .final)
        #expect(final.iGrantProfile == nil)
        #expect(draft.openID4VCI.revision == "Draft 13")
        #expect(draft.openID4VP.revision == "Draft 18")
        #expect(draft.openID4VCI.source.absoluteString.hasSuffix("1_0-13.html"))
        #expect(draft.openID4VP.source.absoluteString.hasSuffix("1_0-18.html"))
        #expect(draft.iGrantProfile != nil)
        #expect(final.id != draft.id)
    }

    @Test("Unsupported combinations fail explicitly without fallback")
    func unsupportedCombination() throws {
        let registry = try StaticProfileRegistry(
            profiles: [BuiltInProfiles.vcdm2OpenID4VCProfile(checkedOn: checkedOn)]
        )

        #expect(throws: ProfileError.unsupportedCredentialFormat(.mdoc)) {
            try registry.profile(
                for: ProfileRequest(
                    id: BuiltInProfiles.vcdm2OpenID4VCProfileID,
                    credentialFormat: .mdoc,
                    identifierMethod: .didKey,
                    signingAlgorithm: .es256
                )
            )
        }
        #expect(throws: ProfileError.unsupportedProfile(ProfileID(rawValue: "unknown"))) {
            try registry.profile(
                for: ProfileRequest(
                    id: ProfileID(rawValue: "unknown"),
                    credentialFormat: .jwtVC,
                    identifierMethod: .didKey,
                    signingAlgorithm: .es256
                )
            )
        }
    }

    @Test("Renamed trust policy cases retain their persisted values")
    func trustPolicyRawValueCompatibility() {
        #expect(TrustPolicyMode.productionConsent.rawValue == "oariProductionConsent")
    }
}
