import EbsiW3CBackend
import Foundation
import Testing

struct EbsiCredentialModelsTests {
    @Test("OARI VCDM2 VC JWT profile parses top-level credential and ES256")
    func oariVcdm2JWT() throws {
        let profile = try EbsiCredentialProfile.oariVcdm2Jwt()
        let token = try compactJWT(
            header: ["alg": "ES256"],
            payload: [
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "OariCarrierLicense"],
                "issuer": "did:ebsi:issuer",
                "credentialSubject": ["id": "did:key:holder"],
                "credentialSchema": ["id": "https://ebsi.oari.io/schema", "type": "FullJsonSchemaValidator2021"],
                "credentialStatus": ["type": "BitstringStatusListEntry"],
                "termsOfUse": ["type": "IssuanceCertificate"],
            ]
        )
        let credential = try EbsiCredentialInspector().inspectCompactJWT(token, profile: profile)
        #expect(credential["issuer"] == .string("did:ebsi:issuer"))
    }

    @Test("Profile rejects wrong context, algorithm and unsupported VCDM2 JWT verifier path")
    func profileMismatch() async throws {
        let profile = try EbsiCredentialProfile.oariVcdm2Jwt()
        let wrong = try compactJWT(
            header: ["alg": "RS256"],
            payload: ["@context": ["https://www.w3.org/2018/credentials/v1"], "type": ["VerifiableCredential"]]
        )
        #expect(throws: EbsiCredentialError.algorithmNotAllowed) {
            _ = try EbsiCredentialInspector().inspectCompactJWT(wrong, profile: profile)
        }
        await #expect(throws: EbsiCredentialError.unsupportedRepresentation) {
            try await SpruceCredentialVerifier().verify(
                credential: Data(wrong.utf8),
                profile: profile
            )
        }
    }

    @Test("OARI profile rejects nested V1 payload and missing schema status or terms")
    func exactOariProfile() throws {
        let profile = try EbsiCredentialProfile.oariVcdm2Jwt()
        let base: [String: Any] = [
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": ["id": "did:key:holder"],
        ]
        for payload in [
            ["vc": base],
            base,
            base.merging(["credentialSchema": ["type": "Wrong"]]) { _, new in new },
        ] {
            let token = try compactJWT(header: ["alg": "ES256"], payload: payload)
            #expect(throws: EbsiCredentialError.profileMismatch) {
                _ = try EbsiCredentialInspector().inspectCompactJWT(token, profile: profile)
            }
        }
    }

    private func compactJWT(header: Any, payload: Any) throws -> String {
        func encode(_ value: Any) throws -> String {
            try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return try "\(encode(header)).\(encode(payload)).signature"
    }
}
