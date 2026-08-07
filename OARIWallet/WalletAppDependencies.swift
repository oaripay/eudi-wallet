import Foundation
import WalletDomain
import WalletVault

struct WalletAppDependencies: Sendable {
    let credentials: any CredentialRepository
    let audit: any AuditRepository

    static func make(configuration: AppConfiguration = .current()) -> Result<WalletAppDependencies, Error> {
#if DEBUG
        switch configuration.fixture {
        case .empty:
            return .success(fixture(credentials: [], events: []))
        case .populated:
            return .success(populatedFixture())
        case .storageFailure:
            return .failure(FixtureError.storageUnavailable)
        case .production:
            break
        }
#endif
        return Result {
            let root = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            ).appendingPathComponent("OARIWallet", isDirectory: true)
            let keyStore = KeychainVaultKeyStore(service: "io.oari.wallet.vault")
            return try WalletAppDependencies(
                credentials: EncryptedCredentialRepository(
                    directory: root.appendingPathComponent("credentials", isDirectory: true),
                    keyStore: keyStore
                ),
                audit: EncryptedAuditRepository(
                    directory: root.appendingPathComponent("audit", isDirectory: true),
                    keyStore: keyStore
                )
            )
        }
    }

#if DEBUG
    private static func fixture(
        credentials: [CredentialEnvelope],
        events: [AuditEvent]
    ) -> WalletAppDependencies {
        WalletAppDependencies(
            credentials: FixtureCredentialRepository(credentials: credentials),
            audit: FixtureAuditRepository(events: events)
        )
    }

    private static func populatedFixture() -> WalletAppDependencies {
        let date = Date(timeIntervalSince1970: 1_754_524_800)
        let record = CredentialRecord(
            configurationID: "provisionalOariLPID",
            displayName: "OARI Legal Person ID",
            format: .jwtVC,
            profileID: "oari-development-final-1",
            issuerIdentifier: "did:ebsi:fixture-issuer",
            cryptographicValidity: .valid,
            issuerTrust: .trusted,
            status: .valid,
            legalClassification: .oariProvisional,
            issuedAt: date,
            expiresAt: date.addingTimeInterval(31_536_000),
            createdAt: date
        )
        return fixture(
            credentials: [CredentialEnvelope(record: record, encodedCredential: Data())],
            events: [
                AuditEvent(
                    operation: .issuance,
                    outcome: .completed,
                    occurredAt: date,
                    credentialIDs: [record.id],
                    policy: .development,
                    policyVersion: AuditPolicyVersion(rawValue: 1)
                ),
            ]
        )
    }
#endif
}

#if DEBUG
private enum FixtureError: Error { case storageUnavailable }

private actor FixtureCredentialRepository: CredentialRepository {
    private var storage: [CredentialID: CredentialEnvelope]

    init(credentials: [CredentialEnvelope]) {
        storage = Dictionary(uniqueKeysWithValues: credentials.map { ($0.record.id, $0) })
    }

    func credentials() async throws -> [CredentialRecord] {
        storage.values.map(\.record).sorted { $0.createdAt > $1.createdAt }
    }

    func credential(id: CredentialID) async throws -> CredentialEnvelope? { storage[id] }
    func save(_ credential: CredentialEnvelope) async throws { storage[credential.record.id] = credential }
    func delete(id: CredentialID) async throws { storage[id] = nil }
}

private actor FixtureAuditRepository: AuditRepository {
    private var storage: [AuditEvent]
    init(events: [AuditEvent]) { storage = events }
    func events() async throws -> [AuditEvent] { storage }
    func append(_ event: AuditEvent) async throws { storage.append(event) }
    func deleteAll() async throws { storage = [] }
}
#endif
