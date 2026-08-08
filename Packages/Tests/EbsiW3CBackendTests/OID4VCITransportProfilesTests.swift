import EbsiW3CBackend
import Foundation
import Testing

struct OID4VCITransportProfilesTests {
    @Test("Draft profiles select DPoP, anonymous authentication and encrypted response contract")
    func draftProfiles() {
        let metadata = OID4VCIAuthorizationMetadata(
            dpopSigningAlgorithms: ["ES256"],
            clientAttestationAlgorithms: ["ES256"],
            tokenEndpointAuthenticationMethods: ["attest_jwt_client_auth", "none"]
        )
        let draft13 = OID4VCITransportContract.resolve(
            selectedProfile: .draft13,
            authorizationMetadata: metadata
        )
        #expect(draft13.profile == .draft13)
        #expect(draft13.requiresDPoP)
        #expect(!draft13.requiresClientAttestation)
        #expect(draft13.requiresCredentialResponseEncryption)
        let draft18 = OID4VCITransportContract.resolve(
            selectedProfile: .draft18,
            authorizationMetadata: metadata
        )
        #expect(draft18.profile == .draft18)
        #expect(draft18.requiresDPoP)
        #expect(!draft18.requiresClientAttestation)
        #expect(draft18.requiresCredentialResponseEncryption)
        let draft17 = OID4VCITransportContract.resolve(
            selectedProfile: .draft17,
            authorizationMetadata: metadata
        )
        #expect(draft17.profile == .draft17)
        #expect(draft17.proofShape == .finalProofsJWT)
        #expect(draft17.credentialIdentifierField == .credentialIdentifier)
        #expect(draft17.requiresDPoP)
        #expect(draft17.requiresCredentialResponseEncryption)
    }

    @Test("Attestation-only draft issuer requires client attestation")
    func attestationOnlyDraft() {
        let profile = OID4VCITransportContract.resolve(
            selectedProfile: .draft13,
            authorizationMetadata: OID4VCIAuthorizationMetadata(
                dpopSigningAlgorithms: ["ES256"],
                clientAttestationAlgorithms: ["ES256"],
                tokenEndpointAuthenticationMethods: ["attest_jwt_client_auth"]
            )
        )
        #expect(profile.requiresDPoP)
        #expect(profile.requiresClientAttestation)
    }

    @Test("Unsupported required token authentication fails closed")
    func unsupportedTokenAuthentication() {
        let profile = OID4VCITransportContract.resolve(
            selectedProfile: .draft13,
            authorizationMetadata: OID4VCIAuthorizationMetadata(
                clientAttestationAlgorithms: ["ES384"],
                tokenEndpointAuthenticationMethods: ["attest_jwt_client_auth"]
            )
        )
        #expect(profile.tokenEndpointAuthentication == .unsupported)
        #expect(!profile.requiresClientAttestation)
    }

    @Test("Omitted authentication metadata is public while explicit empty metadata is unsupported")
    func omittedAndEmptyAuthenticationMetadata() {
        let omitted = OID4VCITransportContract.resolve(
            selectedProfile: .draft13,
            authorizationMetadata: OID4VCIAuthorizationMetadata()
        )
        let empty = OID4VCITransportContract.resolve(
            selectedProfile: .draft13,
            authorizationMetadata: OID4VCIAuthorizationMetadata(tokenEndpointAuthenticationMethods: [])
        )
        #expect(omitted.tokenEndpointAuthentication == .anonymous)
        #expect(omitted.requiresDPoP)
        #expect(empty.tokenEndpointAuthentication == .unsupported)
    }

    @Test("Registered draft rejects explicitly incompatible DPoP algorithms")
    func incompatibleDPoP() {
        let profile = OID4VCITransportContract.resolve(
            selectedProfile: .draft17,
            authorizationMetadata: OID4VCIAuthorizationMetadata(
                dpopSigningAlgorithms: ["ES384"],
                tokenEndpointAuthenticationMethods: ["none"]
            )
        )
        #expect(profile.requiresDPoP)
        #expect(profile.tokenEndpointAuthentication == .unsupported)
    }

    @Test("Final profile remains issuer-generic and metadata-driven")
    func finalProfile() {
        let profile = OID4VCITransportContract.resolve(
            selectedProfile: .final,
            authorizationMetadata: OID4VCIAuthorizationMetadata()
        )
        #expect(profile.profile == .final)
        #expect(profile.credentialIdentifierField == .credentialConfigurationID)
        #expect(profile.proofShape == .finalProofsJWT)
        #expect(!profile.requiresClientAttestation)
    }

    @Test("Draft routes require an explicitly configured registry")
    func explicitDraftRegistry() {
        let issuer = URL(string: "https://issuer.example/service/draft-13")!
        #expect(OID4VCITransportProfileRegistry.finalOnly.profile(for: issuer) == .final)
        #expect(OID4VCITransportProfileRegistry.developmentDraftCompatibility.profile(for: issuer) == .draft13)
        let draft17 = URL(string: "https://issuer.example/service/draft-17")!
        #expect(OID4VCITransportProfileRegistry.developmentDraftCompatibility.profile(for: draft17) == .draft17)
        let draftLookingFinal = URL(string: "https://issuer.example/draft-13/service/final")!
        #expect(OID4VCITransportProfileRegistry.developmentDraftCompatibility.profile(for: draftLookingFinal) == .final)
    }
}
