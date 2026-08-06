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
}
