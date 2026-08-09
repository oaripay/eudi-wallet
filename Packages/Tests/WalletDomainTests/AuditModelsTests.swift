import Foundation
import Testing
@testable import WalletDomain

struct AuditModelsTests {
    @Test("Audit events persist only digests and closed policy metadata")
    func auditEventIsRedactedByConstruction() throws {
        let requester = "did:example:sensitive-requester"
        let claim = "legal_person_name"
        let event = AuditEvent(
            operation: .presentation,
            outcome: .completed,
            occurredAt: Date(timeIntervalSince1970: 1_700_000_000),
            counterpartyIdentifierDigest: .sha256(requester),
            disclosedClaimDigests: [.sha256(claim)],
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        )

        let encoded = try JSONEncoder().encode(event)
        let object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let text = try #require(String(data: encoded, encoding: .utf8))

        #expect(object["disclosedClaimDigests"] != nil)
        #expect(object["claimValues"] == nil)
        #expect(object["credential"] == nil)
        #expect(object["token"] == nil)
        #expect(object["nonce"] == nil)
        #expect(!text.contains(requester))
        #expect(!text.contains(claim))
    }

    @Test("Audit digest decoding rejects raw or malformed sensitive data")
    func malformedAuditDigestIsRejected() {
        let prohibitedInputs = [
            "credential-value",
            "proof.jwt.value",
            "access-token",
            "nonce-value",
            String(repeating: "A", count: 64),
            String(repeating: "١", count: 64),
        ]

        for input in prohibitedInputs {
            let encoded = try! JSONEncoder().encode(input)
            #expect(throws: DecodingError.self) {
                try JSONDecoder().decode(AuditDigest.self, from: encoded)
            }
        }
    }

    @Test("Audit reason and policy vocabularies reject arbitrary strings")
    func arbitraryAuditMetadataIsRejected() throws {
        let rawSecret = try JSONEncoder().encode("raw-secret-value")

        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(AuditReasonCode.self, from: rawSecret)
        }
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(AuditPolicy.self, from: rawSecret)
        }
    }

    @Test("Renamed audit policy cases retain their persisted values")
    func auditPolicyRawValueCompatibility() {
        #expect(AuditPolicy.productionConsent.rawValue == "oariProductionConsent")
    }

    @Test("Every key purpose is explicit and serializable")
    func keyPurposesArePurposeBound() throws {
        let encoded = try JSONEncoder().encode(KeyPurpose.allCases)
        let decoded = try JSONDecoder().decode([KeyPurpose].self, from: encoded)

        #expect(decoded == KeyPurpose.allCases)
        #expect(decoded.count == 9)
    }
}
