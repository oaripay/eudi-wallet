import Foundation

#if canImport(SpruceIDMobileSdkRs)
@preconcurrency import SpruceIDMobileSdkRs
#endif

public struct SpruceCredentialVerifier: Sendable {
    public init() {}

    public func verify(
        credential: Data,
        profile: EbsiCredentialProfile,
        contextMap: [String: String]? = nil
    ) async throws {
        guard profile.representation != .vcdm2Jwt else {
            throw EbsiCredentialError.unsupportedRepresentation
        }
        try EbsiCredentialInspector().validateEnvelope(credential, profile: profile)
        #if canImport(SpruceIDMobileSdkRs)
        let format: CredentialFormat = switch profile.representation {
        case .jwtVcJson: .jwtVcJson
        case .jwtVcJsonLd: .jwtVcJsonLd
        case .dataIntegrity: .ldpVc
        case .vcdm2SdJwt: .vcdm2SdJwt
        case .dcSdJwt: .dcSdJwt
        case .vcdm2Jwt: preconditionFailure("guarded above")
        }
        do {
            let result = try await verifyRawCredential(
                credential: RawCredential(format: format, payload: credential),
                contextMap: contextMap
            )
            try result.expectVerified()
        } catch let error as EbsiCredentialError {
            throw error
        } catch {
            throw EbsiCredentialError.verificationFailed
        }
        #else
        throw EbsiCredentialError.backendUnavailable
        #endif
    }
}
