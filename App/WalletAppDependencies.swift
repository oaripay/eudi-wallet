import Foundation
import EbsiW3CBackend
import EudiWalletKitAdapter
import IdentityDomain
import ProtocolEngine
import WalletDomain
import WalletVault

struct WalletAppDependencies: Sendable {
    let credentials: any CredentialMetadataRepository
    let audit: any AuditRepository
    let localAuthenticator: any LocalAuthenticator
    let eudiWallet: (any EudiWalletOperating)?
    let eudiAvailability: EudiWalletAvailability
    let ebsiWallet: (any EbsiW3COperating)?

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
            let keyStore = CachedVaultKeyStore(
                wrapping: KeychainVaultKeyStore(service: "io.oari.wallet.vault")
            )
            let metadataRepository = try EncryptedCredentialMetadataRepository(
                directory: root.appendingPathComponent("credential-metadata", isDirectory: true),
                keyStore: keyStore
            )
            let auditRepository = try EncryptedAuditRepository(
                directory: root.appendingPathComponent("audit", isDirectory: true),
                keyStore: keyStore
            )
            let eudiWallet: (any EudiWalletOperating)?
            let eudiAvailability: EudiWalletAvailability
            do {
                let eudiTrustSource = try EudiTrustAnchorSource(
                    profileID: "oari-development-eudi",
                    anchors: [DevelopmentEudiProfile.trustAnchorDER],
                    approvedSHA256Digests: [EudiTrustAnchorSource.sha256Digest(of: DevelopmentEudiProfile.trustAnchorDER)]
                )
                let eudiConfiguration = try EudiOperationalConfiguration(
                    clientID: "oari-development-wallet",
                    authorizationRedirectURI: URL(string: "https://oari.io/oauth/callback")!,
                    attestationProvider: DevelopmentEudiAttestationProvider(),
                    auditRepository: auditRepository,
                    auditPolicy: .development,
                    auditPolicyVersion: AuditPolicyVersion(rawValue: 1),
                    metadataRepository: metadataRepository,
                    recoveryStore: try EncryptedWalletOperationRecoveryStore(
                        directory: root.appendingPathComponent("operation-recovery", isDirectory: true),
                        keyStore: keyStore
                    ),
                    statusProvider: DevelopmentEudiStatusProvider(),
                    allowedIssuerOrigins: ["https://issuer.example"],
                    allowedVerifierOrigins: ["https://verifier.example"],
                    allowedApplicationRedirectOrigins: ["https://oari.io"],
                    allowUnregisteredDevelopmentCounterparties: configuration.ebsiDevelopmentEnabled
                )
                let eudiAdapter = try EudiWalletKitBaseline(
                    serviceName: "io.oari.wallet.development-eudi"
                ).makeWallet(
                    trustSource: eudiTrustSource,
                    operationalConfiguration: eudiConfiguration
                )
                eudiWallet = configuration.ebsiDevelopmentEnabled
                    ? LiveEudiWalletService(adapter: eudiAdapter)
                    : nil
                eudiAvailability = configuration.ebsiDevelopmentEnabled
                    ? .available
                    : .configurationRequired("Install an approved staging or production EUDI trust profile to enable wallet operations.")
            } catch {
                eudiWallet = nil
                eudiAvailability = .configurationRequired(
                    "EUDI Wallet Kit development profile could not be initialized: \(Self.safeDevelopmentError(error))"
                )
            }
            let ebsiWallet: (any EbsiW3COperating)?
            if configuration.ebsiDevelopmentEnabled {
                let ebsiEndpoint = try configuration.ebsiLocalAuthorityEnabled
                    ? EBSIChainEndpoint.localAuthority()
                    : EBSIChainEndpoint.oariDevelopment()
                let endpointRegistry = try EBSIEndpointRegistry(
                    policy: .development,
                    endpoints: [ebsiEndpoint]
                )
                let registryClient = try MultiEndpointEBSIRegistryClient(
                    registry: endpointRegistry,
                    httpClient: URLSessionBoundedHTTPSClient()
                )
                let ebsiStore = try EncryptedEbsiCredentialStore(
                    directory: root.appendingPathComponent("ebsi-credentials", isDirectory: true),
                    keyStore: keyStore
                )
                let workspaceTransport = URLSessionWorkspaceTransport()
                let ebsiBackend = OariWorkspaceW3CBackend(
                    transport: workspaceTransport,
                    trustEvaluator: configuration.ebsiLocalAuthorityEnabled
                        ? DevelopmentIssuerOriginTrustEvaluator(
                            trustedOrigins: [],
                            evidenceSource: "local-authority"
                        )
                        : WorkspaceTIRTrustEvaluator(
                            tirBaseURL: ebsiEndpoint.trustedIssuersRegistryURL,
                            transport: workspaceTransport
                        ),
                    keyProvider: DeviceBoundKeyProvider(applicationTagPrefix: "io.oari.wallet.ebsi.key"),
                    credentialStore: ebsiStore,
                    credentialValidator: NativeWorkspaceCredentialValidator(
                        resolver: CompositeDIDResolver(
                            ebsi: EBSIDIDResolver(client: registryClient)
                        ),
                        transport: workspaceTransport,
                        allowsDIDIssuerDelegation: true
                    ),
                    profile: try .oariVcdm2Jwt(),
                    additionalProfiles: [try .vcdm11Jwt(), try .dcSdJWTVC(), try .vcdm2SdJWT()],
                    clientSecurity: DefaultOID4VCIClientSecurity(
                        keyProvider: DeviceBoundKeyProvider(
                            applicationTagPrefix: "io.oari.wallet.oid4vci.security"
                        )
                    ),
                    transportProfileRegistry: .developmentDraftCompatibility
                )
                ebsiWallet = LiveWorkspaceEbsiWalletService(
                    backend: ebsiBackend,
                    metadata: metadataRepository,
                    audit: auditRepository
                )
            } else {
                ebsiWallet = nil
            }
            return WalletAppDependencies(
                credentials: metadataRepository,
                audit: auditRepository,
                localAuthenticator: SystemLocalAuthenticator(),
                eudiWallet: eudiWallet,
                eudiAvailability: eudiAvailability,
                ebsiWallet: ebsiWallet
            )
        }
    }

    private static func safeDevelopmentError(_ error: Error) -> String {
        switch error {
        case EudiWalletKitAdapterError.initializationFailed:
            return "Wallet Kit initialization failed"
        case EudiWalletKitAdapterError.invalidTrustAnchor:
            return "development trust anchor is invalid"
        default:
            return "Wallet Kit configuration is invalid"
        }
    }

#if DEBUG
    private static func fixture(
        credentials: [CredentialRecord],
        events: [AuditEvent]
    ) -> WalletAppDependencies {
        WalletAppDependencies(
            credentials: FixtureCredentialRepository(credentials: credentials),
            audit: FixtureAuditRepository(events: events),
            localAuthenticator: FixtureLocalAuthenticator(),
            eudiWallet: nil,
            eudiAvailability: .configurationRequired("Preview mode does not contact credential services."),
            ebsiWallet: nil
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
            credentials: [record],
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
private struct FixtureLocalAuthenticator: LocalAuthenticator {
    func authenticate(reason: String) async throws {}
}

private actor FixtureCredentialRepository: CredentialMetadataRepository {
    private var storage: [CredentialID: CredentialRecord]

    init(credentials: [CredentialRecord]) {
        storage = Dictionary(uniqueKeysWithValues: credentials.map { ($0.id, $0) })
    }

    func credentials() async throws -> [CredentialRecord] {
        storage.values.sorted { $0.createdAt > $1.createdAt }
    }

    func saveMetadata(_ credential: CredentialRecord) async throws {
        storage[credential.id] = credential
    }
    func replaceMetadata(_ credential: CredentialRecord) async throws {
        storage[credential.id] = credential
    }
    func deleteMetadata(id: CredentialID) async throws { storage[id] = nil }
}

private actor FixtureAuditRepository: AuditRepository {
    private var storage: [AuditEvent]
    init(events: [AuditEvent]) { storage = events }
    func events() async throws -> [AuditEvent] { storage }
    func append(_ event: AuditEvent) async throws { storage.append(event) }
    func deleteAll() async throws { storage = [] }
}
#endif
