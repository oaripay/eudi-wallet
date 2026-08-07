import Foundation
import ProfileDomain
import WalletDomain

public protocol LocalAuthenticator: Sendable {
    func authenticate(reason: String) async throws
}

public protocol PresentationSigner: Sendable {
    func sign(
        request: PresentationRequest,
        credentialIDs: [CredentialID]
    ) async throws -> SignedPresentation
}

public struct SignedPresentation: Equatable, Sendable {
    public let payload: Data

    public init(payload: Data) {
        self.payload = payload
    }
}

public protocol PresentationDelivery: Sendable {
    func deliver(
        _ presentation: SignedPresentation,
        to responseURI: URL,
        state: String?
    ) async throws
}

public protocol WalletUnitAttestationProvider: Sendable {
    func attestation(profile: InteroperabilityProfile, at date: Date) async throws -> String
}

public enum ProtocolExecutionError: Error, Equatable, Sendable {
    case emptyAuthenticationReason
    case emptyPresentation
    case invalidDeliveryOrigin
    case invalidCredential
    case attestationUnavailable
}
