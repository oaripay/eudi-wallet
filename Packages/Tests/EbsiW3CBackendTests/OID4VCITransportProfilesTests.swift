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
            issuerURL: URL(string: "https://issuer.example/service/draft-13")!,
            authorizationMetadata: metadata
        )
        #expect(draft13.profile == .draft13)
        #expect(draft13.requiresDPoP)
        #expect(!draft13.requiresClientAttestation)
        #expect(draft13.requiresCredentialResponseEncryption)
        let draft18 = OID4VCITransportContract.resolve(
            issuerURL: URL(string: "https://issuer.example/service/draft-18")!,
            authorizationMetadata: metadata
        )
        #expect(draft18.profile == .draft18)
        #expect(draft18.requiresDPoP)
        #expect(!draft18.requiresClientAttestation)
        #expect(draft18.requiresCredentialResponseEncryption)
    }

    @Test("Attestation-only draft issuer requires client attestation")
    func attestationOnlyDraft() {
        let profile = OID4VCITransportContract.resolve(
            issuerURL: URL(string: "https://issuer.example/service/draft-13")!,
            authorizationMetadata: OID4VCIAuthorizationMetadata(
                dpopSigningAlgorithms: ["ES256"],
                clientAttestationAlgorithms: ["ES256"],
                tokenEndpointAuthenticationMethods: ["attest_jwt_client_auth"]
            )
        )
        #expect(profile.requiresDPoP)
        #expect(profile.requiresClientAttestation)
    }

    @Test("Final profile remains issuer-generic and metadata-driven")
    func finalProfile() {
        let profile = OID4VCITransportContract.resolve(
            issuerURL: URL(string: "https://oid4vc.igrant.io/service/final")!,
            authorizationMetadata: OID4VCIAuthorizationMetadata()
        )
        #expect(profile.profile == .final)
        #expect(profile.credentialIdentifierField == .credentialConfigurationID)
        #expect(profile.proofShape == .finalProofsJWT)
        #expect(!profile.requiresClientAttestation)
    }
}
