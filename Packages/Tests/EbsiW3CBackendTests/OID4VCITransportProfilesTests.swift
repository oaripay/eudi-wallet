import EbsiW3CBackend
import Foundation
import Testing

struct OID4VCITransportProfilesTests {
    @Test("Only the final profile supports deferred transaction responses")
    func finalDeferredSupport() {
        #expect(OID4VCITransportContract.final.supportsDeferredIssuance)
        #expect(OID4VCITransportContract.final.responseEnvelopes.contains(.deferredTransaction))
    }

    @Test("Production interoperability selects explicit HTTPS draft revision paths")
    func productionDraftCompatibility() throws {
        let registry = OID4VCITransportProfileRegistry.productionInteroperability
        #expect(registry.profile(for: try #require(URL(string: "https://oid4vc.igrant.io/organisation/example/service/draft-13"))) == .draft13)
        #expect(registry.profile(for: try #require(URL(string: "https://issuer.example/service/draft-17"))) == .draft17)
        #expect(registry.profile(for: try #require(URL(string: "https://credentials.example/draft-18"))) == .draft18)
        #expect(registry.profile(for: try #require(URL(string: "https://issuer.example/service/final"))) == .final)
        #expect(registry.profile(for: try #require(URL(string: "http://oid4vc.igrant.io/draft-13"))) == .final)
        #expect(registry.profile(for: try #require(URL(string: "https://oid4vc.igrant.io:444/draft-13"))) == .final)
        #expect(registry.profile(for: try #require(URL(string: "https://oid4vc.igrant.io/final?profile=draft-13"))) == .final)
    }

    @Test("Draft profiles treat advertised DPoP as optional and require encrypted responses")
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
        #expect(!draft13.requiresDPoP)
        #expect(!draft13.requiresClientAttestation)
        #expect(draft13.requiresCredentialResponseEncryption)
        #expect(!draft13.supportsDeferredIssuance)
        let draft18 = OID4VCITransportContract.resolve(
            selectedProfile: .draft18,
            authorizationMetadata: metadata
        )
        #expect(draft18.profile == .draft18)
        #expect(!draft18.requiresDPoP)
        #expect(!draft18.requiresClientAttestation)
        #expect(draft18.requiresCredentialResponseEncryption)
        #expect(!draft18.supportsDeferredIssuance)
        let draft17 = OID4VCITransportContract.resolve(
            selectedProfile: .draft17,
            authorizationMetadata: metadata
        )
        #expect(draft17.profile == .draft17)
        #expect(draft17.proofShape == .finalProofsJWT)
        #expect(draft17.credentialIdentifierField == .credentialIdentifier)
        #expect(!draft17.requiresDPoP)
        #expect(draft17.requiresCredentialResponseEncryption)
        #expect(!draft17.supportsDeferredIssuance)
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
        #expect(!profile.requiresDPoP)
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
        #expect(!omitted.requiresDPoP)
        #expect(empty.tokenEndpointAuthentication == .unsupported)
    }

    @Test("Optional DPoP algorithms do not block Bearer token authentication")
    func incompatibleDPoP() {
        let profile = OID4VCITransportContract.resolve(
            selectedProfile: .draft17,
            authorizationMetadata: OID4VCIAuthorizationMetadata(
                dpopSigningAlgorithms: ["ES384"],
                tokenEndpointAuthenticationMethods: ["none"]
            )
        )
        #expect(!profile.requiresDPoP)
        #expect(profile.tokenEndpointAuthentication == .anonymous)
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

    @Test("Native backend contracts do not advertise deferred or batch issuance")
    func unsupportedIssuanceModes() {
        for profile in [OID4VCITransportContract.draft13, .draft17, .draft18] {
            #expect(!profile.supportsDeferredIssuance)
            #expect(!profile.supportsBatchIssuance)
            #expect(!profile.responseEnvelopes.contains(.deferredTransaction))
        }
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
