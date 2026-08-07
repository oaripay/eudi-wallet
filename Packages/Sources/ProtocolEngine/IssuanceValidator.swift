import Foundation
import CryptoKit
import ProfileDomain

public struct IssuanceValidator: Sendable {
    public init() {}

    public func validate(
        offer: CredentialOffer,
        metadata: IssuerMetadata,
        profile: InteroperabilityProfile,
        configurationID: String
    ) throws -> IssuanceRequest {
        guard metadata.issuer.isCanonicalHTTPS,
              metadata.tokenEndpoint.isCanonicalHTTPS,
              metadata.credentialEndpoint.isCanonicalHTTPS,
              metadata.authorizationEndpoint?.isCanonicalHTTPS != false,
              metadata.deferredCredentialEndpoint?.isCanonicalHTTPS != false else {
            throw IssuanceError.invalidURL
        }
        guard offer.credentialIssuer == metadata.issuer else {
            throw IssuanceError.issuerMismatch
        }
        guard offer.configurationIDs.contains(configurationID),
              metadata.supportedConfigurations.contains(configurationID) else {
            throw IssuanceError.unsupportedConfiguration
        }
        switch offer.grant {
        case let .authorizationCode(authorizationServer):
            guard let endpoint = metadata.authorizationEndpoint,
                  authorizationServer.normalizedOrigin == endpoint.normalizedOrigin else {
                throw IssuanceError.unsupportedGrant
            }
        case .preAuthorizedCode:
            break
        }
        return IssuanceRequest(
            profileID: profile.id,
            configurationID: configurationID,
            issuer: metadata.issuer,
            grant: offer.grant
        )
    }

    public func validatePKCE(verifier: String, challenge: String) throws {
        guard verifier.count >= 43, verifier.count <= 128 else {
            throw IssuanceError.invalidPKCE
        }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        guard verifier.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw IssuanceError.invalidPKCE
        }
        let digest = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        guard digest == challenge else { throw IssuanceError.invalidPKCE }
    }
}

public struct AuthorizationCodeExchangeCoordinator: Sendable {
    private let validator = IssuanceValidator()

    public init() {}

    public func exchange(
        code: String,
        returnedState: String,
        context: AuthorizationCodeContext,
        metadata: IssuerMetadata,
        transport: any IssuanceTransport
    ) async throws -> TokenResponse {
        guard !code.isEmpty, returnedState == context.state else {
            throw IssuanceError.authorizationStateMismatch
        }
        guard context.method == .s256 else { throw IssuanceError.invalidPKCE }
        try validator.validatePKCE(verifier: context.verifier, challenge: context.challenge)
        return try await transport.exchangeAuthorizationCode(
            code,
            verifier: context.verifier,
            metadata: metadata
        )
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }
}
