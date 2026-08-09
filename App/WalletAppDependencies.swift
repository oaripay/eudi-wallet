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
    let appLockAuthenticator: any AppLockAuthenticating
    let eudiWallet: (any EudiWalletOperating)?
    let eudiAvailability: EudiWalletAvailability
    let openID4VCWallet: (any OpenID4VCOperating)?

    init(
        credentials: any CredentialMetadataRepository,
        audit: any AuditRepository,
        localAuthenticator: any LocalAuthenticator,
        appLockAuthenticator: any AppLockAuthenticating = SystemLocalAuthenticator(),
        eudiWallet: (any EudiWalletOperating)?,
        eudiAvailability: EudiWalletAvailability,
        openID4VCWallet: (any OpenID4VCOperating)?
    ) {
        self.credentials = credentials
        self.audit = audit
        self.localAuthenticator = localAuthenticator
        self.appLockAuthenticator = appLockAuthenticator
        self.eudiWallet = eudiWallet
        self.eudiAvailability = eudiAvailability
        self.openID4VCWallet = openID4VCWallet
    }

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
            let eudiWallet: (any EudiWalletOperating)? = nil
            let eudiAvailability = EudiWalletAvailability.configurationRequired(
                "Install an approved production EUDI trust profile to enable wallet operations."
            )
            let openID4VCWallet = try makeW3CWallet(
                root: root,
                keyStore: keyStore,
                metadataRepository: metadataRepository,
                auditRepository: auditRepository
            )
            return WalletAppDependencies(
                credentials: metadataRepository,
                audit: auditRepository,
                localAuthenticator: SystemLocalAuthenticator(),
                eudiWallet: eudiWallet,
                eudiAvailability: eudiAvailability,
                openID4VCWallet: openID4VCWallet
            )
        }
    }

    private static func makeW3CWallet(
        root: URL,
        keyStore: any VaultKeyStore,
        metadataRepository: any CredentialMetadataRepository,
        auditRepository: any AuditRepository
    ) throws -> any OpenID4VCOperating {
        let composition = try W3CBackendComposition.make()
        let endpointRegistry = try EBSIEndpointRegistry(
            policy: composition.environmentPolicy,
            endpoints: [composition.endpoint],
            approvedProductionEndpoints: composition.approvedProductionEndpoints
        )
        let registryClient = try MultiEndpointEBSIRegistryClient(
            registry: endpointRegistry,
            httpClient: URLSessionBoundedHTTPSClient()
        )
        let openID4VCStore = try EncryptedEbsiCredentialStore(
            directory: root.appendingPathComponent("ebsi-credentials", isDirectory: true),
            keyStore: keyStore
        )
        let transport = URLSessionOpenID4VCTransport()
        let resolver = CompositeDIDResolver(ebsi: EBSIDIDResolver(client: registryClient))
        let keyProvider = DeviceBoundKeyProvider(applicationTagPrefix: "io.oari.wallet.ebsi.key")
        let replayProtection = try EncryptedOpenID4VPReplayStore(
            directory: root.appendingPathComponent("workspace-presentation-replay", isDirectory: true),
            keyStore: keyStore
        )
        let backend = OpenID4VCW3CBackend(
            transport: transport,
            trustEvaluator: HTTPSCredentialIssuerServiceTrustEvaluator(),
            credentialSignerTrustEvaluator: EBSITIRCredentialSignerTrustEvaluator(
                tirBaseURL: composition.endpoint.trustedIssuersRegistryURL,
                transport: transport,
                resolver: resolver
            ),
            keyProvider: keyProvider,
            credentialStore: openID4VCStore,
            credentialValidator: NativeW3CCredentialValidator(
                resolver: resolver, transport: transport, allowsDIDIssuerDelegation: true
            ),
            profile: try .vcdm2JWTVC(),
            additionalProfiles: try W3CBackendComposition.additionalProfiles(),
            clientSecurity: DefaultOID4VCIClientSecurity(
                keyProvider: DeviceBoundKeyProvider(applicationTagPrefix: "io.oari.wallet.oid4vci.security")
            ),
            transportProfileRegistry: composition.transportProfileRegistry,
            holderIdentityProvider: PersistentW3CHolderIdentityProvider(
                keyProvider: keyProvider, referenceStore: KeychainW3CHolderIdentityReferenceStore()
            ),
            presentationRequestValidator: NativeOpenID4VPRequestObjectValidator(resolver: resolver),
            presentationReplayProtection: replayProtection,
            trustEnvironment: composition.environmentPolicy == .production ? .production : .development,
            authorizationClientID: W3CBackendComposition.authorizationClientID,
            authorizationRedirectURI: W3CBackendComposition.authorizationRedirectURI
        )
        return LiveOpenID4VCService(backend: backend, metadata: metadataRepository, audit: auditRepository)
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
            openID4VCWallet: nil
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
            legalClassification: .provisional,
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
