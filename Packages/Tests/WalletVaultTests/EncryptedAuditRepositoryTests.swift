import Foundation
import Testing
import WalletDomain
@testable import WalletVault

struct EncryptedAuditRepositoryTests {
    @Test("Redacted audit survives restart and delete")
    func auditLifecycle() async throws {
        let fixture = try Fixture()
        let event = AuditEvent(
            operation: .presentation,
            outcome: .rejected,
            occurredAt: Date(timeIntervalSince1970: 1_700_000_000),
            counterpartyIdentifierDigest: .sha256("did:example:requester"),
            disclosedClaimDigests: [.sha256("legal_person_name")],
            policy: .regulatedStrict,
            policyVersion: AuditPolicyVersion(rawValue: 1),
            reasonCode: .trustRejected
        )
        let repository = try EncryptedAuditRepository(
            directory: fixture.auditDirectory,
            keyStore: fixture.keyStore
        )
        try await repository.append(event)
        try await repository.append(event)
        let secondEvent = AuditEvent(
            operation: .issuance,
            outcome: .completed,
            occurredAt: Date(timeIntervalSince1970: 1_700_000_100),
            policy: .regulatedStrict,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        )
        try await repository.append(secondEvent)

        let disk = try fixture.onlyFile(in: fixture.auditDirectory).readData()
        #expect(!disk.contains(Data("did:example:requester".utf8)))
        #expect(!disk.contains(Data("legal_person_name".utf8)))

        let restarted = try EncryptedAuditRepository(
            directory: fixture.auditDirectory,
            keyStore: fixture.keyStore
        )
        #expect(try await restarted.events() == [event, secondEvent])
        try await restarted.delete(id: event.id)
        #expect(try await restarted.events() == [secondEvent])
        try await restarted.deleteAll()
        #expect(try await restarted.events().isEmpty)
    }
}
