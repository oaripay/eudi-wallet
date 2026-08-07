import Foundation
import PresentationDomain
import ProfileDomain
import ProtocolEngine
import Testing
import TrustDomain
import WalletDomain

struct ExecutionCoordinatorTests {
    @Test("Presentation authenticates, signs, delivers and records redacted audit")
    func presentationExecution() async throws {
        let request = request()
        let session = PresentationSession(request: summary())
        try await prepare(session)
        let audit = MemoryAuditRepository()
        let coordinator = PresentationExecutionCoordinator(
            authenticator: AllowingAuthenticator(),
            signer: FixtureSigner(),
            delivery: FixtureDelivery(),
            auditRepository: audit,
            clock: { Date(timeIntervalSince1970: 1_754_524_800) }
        )
        try await coordinator.execute(
            session: session,
            request: request,
            authenticationReason: "Share organisation identity",
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1)
        )

        #expect(await session.state == .recorded)
        let events = try await audit.events()
        #expect(events.count == 1)
        #expect(events[0].operation == .presentation)
        #expect(events[0].disclosedClaimDigests.count == 1)
    }

    @Test("Reviewed session cannot execute a substituted request")
    func substitutedRequest() async throws {
        let session = PresentationSession(request: summary())
        try await prepare(session)
        let substituted = PresentationRequest(
            id: "request",
            clientID: "https://evil.example",
            responseURI: URL(string: "https://evil.example/callback")!,
            nonce: "1234567890123456",
            expiresAt: Date(timeIntervalSince1970: 1_754_524_860),
            state: nil,
            presentationDefinitionID: nil,
            dcqlCredentialIDs: ["pid"],
            profileID: BuiltInProfiles.oariDevelopmentFinalID
        )
        let coordinator = PresentationExecutionCoordinator(
            authenticator: AllowingAuthenticator(),
            signer: FixtureSigner(),
            delivery: FixtureDelivery(),
            auditRepository: MemoryAuditRepository()
        )
        await #expect(throws: ProtocolExecutionError.invalidDeliveryOrigin) {
            try await coordinator.execute(
                session: session,
                request: substituted,
                authenticationReason: "Share identity",
                policy: .development,
                policyVersion: AuditPolicyVersion(rawValue: 1)
            )
        }
        #expect(await session.state == .reviewApproved)
    }

    @Test("Expired reviewed request fails before authentication")
    func expiredRequest() async throws {
        let expiration = Date(timeIntervalSince1970: 1_754_524_860)
        let session = PresentationSession(request: summary(expiresAt: expiration))
        try await prepare(session)
        let audit = MemoryAuditRepository()
        let authenticator = SpyAuthenticator()
        let coordinator = PresentationExecutionCoordinator(
            authenticator: authenticator,
            signer: FixtureSigner(),
            delivery: FixtureDelivery(),
            auditRepository: audit,
            clock: { expiration }
        )
        await #expect(throws: ProtocolExecutionError.invalidDeliveryOrigin) {
            try await coordinator.execute(
                session: session,
                request: request(expiresAt: expiration),
                authenticationReason: "Share identity",
                policy: .development,
                policyVersion: AuditPolicyVersion(rawValue: 1)
            )
        }
        #expect(await session.state == .reviewApproved)
        #expect(await authenticator.callCount == 0)
        #expect(try await audit.events().isEmpty)
    }

    @Test("Authentication failure prevents signing and delivery")
    func authenticationFailure() async throws {
        let session = PresentationSession(request: summary())
        try await prepare(session)
        let coordinator = PresentationExecutionCoordinator(
            authenticator: DenyingAuthenticator(),
            signer: FixtureSigner(),
            delivery: FixtureDelivery(),
            auditRepository: MemoryAuditRepository()
        )
        await #expect(throws: FixtureError.denied) {
            try await coordinator.execute(
                session: session,
                request: request(),
                authenticationReason: "Share identity",
                policy: .development,
                policyVersion: AuditPolicyVersion(rawValue: 1)
            )
        }
        #expect(await session.state == .reviewApproved)
    }

    @Test("Wallet Kit metadata is rebound before atomic metadata save")
    func issuanceExecution() async throws {
        let credentials = MemoryCredentialRepository()
        let audit = MemoryAuditRepository()
        let profile = BuiltInProfiles.oariDevelopmentFinal(checkedOn: Date())
        let request = IssuanceRequest(
            profileID: profile.id,
            configurationID: "pid",
            issuer: URL(string: "https://issuer.example")!,
            grant: .preAuthorizedCode(code: "code", txCodeRequired: false)
        )
        let result = try await IssuanceExecutionCoordinator(
            repository: credentials,
            auditRepository: audit
        ).process(
            response: .issued(metadata: CredentialRecord(
                configurationID: request.configurationID,
                displayName: "Credential",
                format: .jwtVC,
                profileID: profile.id.rawValue,
                issuerIdentifier: request.issuer.absoluteString,
                cryptographicValidity: .valid,
                issuerTrust: .trusted,
                status: .valid,
                createdAt: Date(timeIntervalSince1970: 1_754_524_800)
            )),
            request: request,
            profile: profile,
            policy: .development,
            policyVersion: AuditPolicyVersion(rawValue: 1),
            at: Date(timeIntervalSince1970: 1_754_524_800)
        )
        guard case .stored = result else {
            Issue.record("Expected stored result")
            return
        }
        #expect(try await credentials.credentials().count == 1)
        #expect(try await audit.events().count == 1)
    }

    private func prepare(_ session: PresentationSession) async throws {
        try await session.markParsed()
        try await session.markTransportValidated()
        try await session.evaluateRequester(
            TrustDecision(effectiveVerdict: .trusted(evidence: []), action: .allow)
        )
        try await session.evaluateCandidates([CredentialID()])
        try await session.beginReview()
        try await session.approveReview()
    }

    private func request(
        expiresAt: Date = Date(timeIntervalSince1970: 2_000_000_000)
    ) -> PresentationRequest {
        PresentationRequest(
            id: "request",
            clientID: "https://verifier.example",
            responseURI: URL(string: "https://verifier.example/callback")!,
            nonce: "1234567890123456",
            expiresAt: expiresAt,
            state: nil,
            presentationDefinitionID: nil,
            dcqlCredentialIDs: ["pid"],
            profileID: BuiltInProfiles.oariDevelopmentFinalID
        )
    }

    private func summary(
        expiresAt: Date = Date(timeIntervalSince1970: 2_000_000_000)
    ) -> PresentationRequestSummary {
        PresentationRequestSummary(
            requesterName: "Verifier",
            protocolRequestID: "request",
            requesterIdentifier: "https://verifier.example",
            origin: URL(string: "https://verifier.example")!,
            purpose: "Share identity",
            requestedClaimIdentifiers: ["pid"],
            nonce: "1234567890123456",
            expiresAt: expiresAt,
            state: nil,
            profileID: BuiltInProfiles.oariDevelopmentFinalID
        )
    }
}

enum FixtureError: Error { case denied }
struct AllowingAuthenticator: LocalAuthenticator { func authenticate(reason: String) async throws {} }
struct DenyingAuthenticator: LocalAuthenticator { func authenticate(reason: String) async throws { throw FixtureError.denied } }
actor SpyAuthenticator: LocalAuthenticator {
    private(set) var callCount = 0
    func authenticate(reason: String) async throws { callCount += 1 }
}
struct FixtureSigner: PresentationSigner {
    func sign(request: PresentationRequest, credentialIDs: [CredentialID]) async throws -> SignedPresentation {
        SignedPresentation(payload: Data("signed".utf8))
    }
}
struct FixtureDelivery: PresentationDelivery {
    func deliver(_ presentation: SignedPresentation, to responseURI: URL, state: String?) async throws {}
}

actor MemoryAuditRepository: AuditRepository {
    private var stored: [AuditEvent] = []
    func events() async throws -> [AuditEvent] { stored }
    func append(_ event: AuditEvent) async throws { stored.append(event) }
    func deleteAll() async throws { stored = [] }
}

actor MemoryCredentialRepository: CredentialMetadataRepository {
    private var stored: [CredentialID: CredentialRecord] = [:]
    func credentials() async throws -> [CredentialRecord] { Array(stored.values) }
    func saveMetadata(_ credential: CredentialRecord) async throws { stored[credential.id] = credential }
    func replaceMetadata(_ credential: CredentialRecord) async throws { stored[credential.id] = credential }
    func deleteMetadata(id: CredentialID) async throws { stored[id] = nil }
}
