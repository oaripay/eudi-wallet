import Foundation

public enum OID4VCITransportProfile: String, Codable, Equatable, Sendable {
    case final
    case draft13
    case draft18
}

public enum OID4VCIProofShape: String, Codable, Equatable, Sendable {
    case finalProofsJWT
    case draftProof
}

public enum OID4VCICredentialIdentifierField: String, Codable, Equatable, Sendable {
    case credentialConfigurationID
    case credentialIdentifier
}

public enum OID4VCIResponseEnvelope: String, Codable, Equatable, Sendable {
    case jsonCredential
    case jsonCredentials
    case encryptedJWT
    case deferredTransaction
}

public struct OID4VCITransportContract: Equatable, Sendable {
    public let profile: OID4VCITransportProfile
    public let proofShape: OID4VCIProofShape
    public let credentialIdentifierField: OID4VCICredentialIdentifierField
    public let responseEnvelopes: Set<OID4VCIResponseEnvelope>
    public let requiresDPoP: Bool
    public let requiresClientAttestation: Bool
    public let requiresCredentialResponseEncryption: Bool
    public let supportsDeferredIssuance: Bool
    public let supportsBatchIssuance: Bool

    public static let final = OID4VCITransportContract(
        profile: .final,
        proofShape: .finalProofsJWT,
        credentialIdentifierField: .credentialConfigurationID,
        responseEnvelopes: [.jsonCredential, .jsonCredentials, .encryptedJWT, .deferredTransaction],
        requiresDPoP: false,
        requiresClientAttestation: false,
        requiresCredentialResponseEncryption: false,
        supportsDeferredIssuance: true,
        supportsBatchIssuance: true
    )

    public static let draft13 = OID4VCITransportContract(
        profile: .draft13,
        proofShape: .draftProof,
        credentialIdentifierField: .credentialIdentifier,
        responseEnvelopes: [.encryptedJWT, .jsonCredential, .jsonCredentials, .deferredTransaction],
        requiresDPoP: true,
        requiresClientAttestation: true,
        requiresCredentialResponseEncryption: true,
        supportsDeferredIssuance: true,
        supportsBatchIssuance: true
    )

    public static let draft18 = OID4VCITransportContract(
        profile: .draft18,
        proofShape: .draftProof,
        credentialIdentifierField: .credentialIdentifier,
        responseEnvelopes: [.encryptedJWT, .jsonCredential, .jsonCredentials, .deferredTransaction],
        requiresDPoP: true,
        requiresClientAttestation: true,
        requiresCredentialResponseEncryption: true,
        supportsDeferredIssuance: true,
        supportsBatchIssuance: true
    )

    public static func resolve(
        issuerURL: URL,
        authorizationMetadata: OID4VCIAuthorizationMetadata
    ) -> OID4VCITransportContract {
        let path = issuerURL.path.lowercased()
        if path.contains("draft-13") || path.contains("draft-18") {
            let base = path.contains("draft-13") ? OID4VCITransportContract.draft13 : .draft18
            return OID4VCITransportContract(
                profile: base.profile,
                proofShape: base.proofShape,
                credentialIdentifierField: base.credentialIdentifierField,
                responseEnvelopes: base.responseEnvelopes,
                requiresDPoP: false,
                requiresClientAttestation:
                    authorizationMetadata.clientAttestationAlgorithms?.isEmpty == false &&
                    authorizationMetadata.tokenEndpointAuthenticationMethods?.contains("none") == false,
                requiresCredentialResponseEncryption: true,
                supportsDeferredIssuance: true,
                supportsBatchIssuance: true
            )
        }
        return OID4VCITransportContract(
            profile: .final,
            proofShape: .finalProofsJWT,
            credentialIdentifierField: .credentialConfigurationID,
            responseEnvelopes: [.jsonCredential, .jsonCredentials, .encryptedJWT, .deferredTransaction],
            requiresDPoP: false,
            requiresClientAttestation:
                authorizationMetadata.clientAttestationAlgorithms?.isEmpty == false &&
                authorizationMetadata.tokenEndpointAuthenticationMethods?.contains("none") == false,
            requiresCredentialResponseEncryption: false,
            supportsDeferredIssuance: true,
            supportsBatchIssuance: true
        )
    }
}

public struct OID4VCIAuthorizationMetadata: Sendable, Equatable {
    public let dpopSigningAlgorithms: [String]?
    public let clientAttestationAlgorithms: [String]?
    public let tokenEndpointAuthenticationMethods: [String]?

    public init(
        dpopSigningAlgorithms: [String]? = nil,
        clientAttestationAlgorithms: [String]? = nil,
        tokenEndpointAuthenticationMethods: [String]? = nil
    ) {
        self.dpopSigningAlgorithms = dpopSigningAlgorithms
        self.clientAttestationAlgorithms = clientAttestationAlgorithms
        self.tokenEndpointAuthenticationMethods = tokenEndpointAuthenticationMethods
    }
}
