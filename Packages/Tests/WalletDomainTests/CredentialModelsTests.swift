import Foundation
import Testing
@testable import WalletDomain

struct CredentialModelsTests {
    @Test("Credential state dimensions remain independent")
    func independentCredentialState() throws {
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let record = CredentialRecord(
            configurationID: "provisionalOariLPID",
            displayName: "Legal person identity",
            format: .jwtVC,
            profileID: "oari-development-v1",
            issuerIdentifier: "did:ebsi:issuer",
            cryptographicValidity: .valid,
            issuerTrust: .untrusted,
            status: .indeterminate,
            legalClassification: .oariProvisional,
            createdAt: createdAt
        )

        let decoded = try JSONDecoder().decode(
            CredentialRecord.self,
            from: JSONEncoder().encode(record)
        )

        #expect(decoded == record)
        #expect(decoded.cryptographicValidity == .valid)
        #expect(decoded.issuerTrust == .untrusted)
        #expect(decoded.status == .indeterminate)
        #expect(decoded.legalClassification == .oariProvisional)
    }

    @Test("Supported credential formats do not collapse into one representation")
    func formatsAreDistinct() {
        #expect(Set(CredentialFormat.allCases).count == 3)
        #expect(CredentialFormat.jwtVC != .sdJWTVC)
        #expect(CredentialFormat.sdJWTVC != .mdoc)
    }

    @Test("Offline display artwork round trips and legacy records remain readable")
    func displayArtworkCompatibility() throws {
        let image = CredentialDisplayImage(
            mediaType: "image/png",
            data: Data([0x89, 0x50, 0x4e, 0x47]),
            alternativeText: "Issuer mark"
        )
        let record = CredentialRecord(
            configurationID: "pid",
            displayName: "PID",
            format: .sdJWTVC,
            profileID: "test",
            issuerIdentifier: "https://issuer.example",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            display: CredentialDisplayMetadata(
                locale: "en",
                description: "Identity credential",
                backgroundColor: "#003366",
                textColor: "#ffffff",
                logo: image,
                backgroundImage: image
            )
        )
        #expect(try JSONDecoder().decode(
            CredentialRecord.self,
            from: JSONEncoder().encode(record)
        ) == record)

        var legacy = try #require(JSONSerialization.jsonObject(
            with: JSONEncoder().encode(record)
        ) as? [String: Any])
        legacy["display"] = nil
        let decodedLegacy = try JSONDecoder().decode(
            CredentialRecord.self,
            from: JSONSerialization.data(withJSONObject: legacy)
        )
        #expect(decodedLegacy.display == nil)
    }
}
