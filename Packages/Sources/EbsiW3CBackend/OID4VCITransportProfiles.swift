import Foundation

public enum OID4VCITransportProfile: String, Codable, Equatable, Sendable {
    case final
    case draft13
    case draft17
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

public enum OID4VCITokenEndpointAuthentication: String, Codable, Equatable, Sendable {
    case anonymous
    case clientAttestation
    case unsupported
}

public struct OID4VCITransportProfileRegistry: Sendable, Equatable {
    private let terminalPathComponents: [String: OID4VCITransportProfile]
    private let requiresHTTPS: Bool

    public static let finalOnly = OID4VCITransportProfileRegistry(
        terminalPathComponents: [:], requiresHTTPS: true
    )
    public static let productionInteroperability = OID4VCITransportProfileRegistry(
        terminalPathComponents: [
            "draft-13": .draft13,
            "draft-17": .draft17,
            "draft-18": .draft18,
        ],
        requiresHTTPS: true
    )
    public static let developmentDraftCompatibility = OID4VCITransportProfileRegistry(
        terminalPathComponents: [
            "draft-13": .draft13,
            "draft-17": .draft17,
            "draft-18": .draft18,
        ],
        requiresHTTPS: false
    )

    public init(terminalPathComponents: [String: OID4VCITransportProfile]) {
        self.init(terminalPathComponents: terminalPathComponents, requiresHTTPS: false)
    }

    private init(
        terminalPathComponents: [String: OID4VCITransportProfile],
        requiresHTTPS: Bool
    ) {
        self.terminalPathComponents = terminalPathComponents
        self.requiresHTTPS = requiresHTTPS
    }

    public func profile(for issuerURL: URL) -> OID4VCITransportProfile {
        if requiresHTTPS {
            guard issuerURL.scheme?.lowercased() == "https",
                  issuerURL.host != nil,
                  issuerURL.user == nil,
                  issuerURL.password == nil,
                  issuerURL.fragment == nil,
                  issuerURL.port == nil || issuerURL.port == 443 else { return .final }
        }
        let terminalComponent = issuerURL.lastPathComponent.lowercased()
        return terminalPathComponents[terminalComponent] ?? .final
    }
}

public struct OID4VCITransportContract: Equatable, Sendable {
    public let profile: OID4VCITransportProfile
    public let proofShape: OID4VCIProofShape
    public let credentialIdentifierField: OID4VCICredentialIdentifierField
    public let responseEnvelopes: Set<OID4VCIResponseEnvelope>
    public let requiresDPoP: Bool
    public let tokenEndpointAuthentication: OID4VCITokenEndpointAuthentication
    public let requiresCredentialResponseEncryption: Bool
    public let supportsDeferredIssuance: Bool
    public let supportsBatchIssuance: Bool
    public var requiresClientAttestation: Bool { tokenEndpointAuthentication == .clientAttestation }

    public static let final = OID4VCITransportContract(
        profile: .final,
        proofShape: .finalProofsJWT,
        credentialIdentifierField: .credentialConfigurationID,
        responseEnvelopes: [.jsonCredential, .jsonCredentials],
        requiresDPoP: false,
        tokenEndpointAuthentication: .anonymous,
        requiresCredentialResponseEncryption: false,
        supportsDeferredIssuance: false,
        supportsBatchIssuance: false
    )

    public static let draft13 = OID4VCITransportContract(
        profile: .draft13,
        proofShape: .draftProof,
        credentialIdentifierField: .credentialIdentifier,
        responseEnvelopes: [.encryptedJWT],
        requiresDPoP: true,
        tokenEndpointAuthentication: .unsupported,
        requiresCredentialResponseEncryption: true,
        supportsDeferredIssuance: false,
        supportsBatchIssuance: false
    )

    public static let draft18 = OID4VCITransportContract(
        profile: .draft18,
        proofShape: .draftProof,
        credentialIdentifierField: .credentialIdentifier,
        responseEnvelopes: [.encryptedJWT],
        requiresDPoP: true,
        tokenEndpointAuthentication: .unsupported,
        requiresCredentialResponseEncryption: true,
        supportsDeferredIssuance: false,
        supportsBatchIssuance: false
    )

    public static let draft17 = OID4VCITransportContract(
        profile: .draft17,
        proofShape: .finalProofsJWT,
        credentialIdentifierField: .credentialIdentifier,
        responseEnvelopes: [.encryptedJWT],
        requiresDPoP: true,
        tokenEndpointAuthentication: .unsupported,
        requiresCredentialResponseEncryption: true,
        supportsDeferredIssuance: false,
        supportsBatchIssuance: false
    )

    public static func resolve(
        selectedProfile: OID4VCITransportProfile,
        authorizationMetadata: OID4VCIAuthorizationMetadata
    ) -> OID4VCITransportContract {
        if selectedProfile != .final {
            let base: OID4VCITransportContract = switch selectedProfile {
            case .draft13: .draft13
            case .draft17: .draft17
            case .draft18: .draft18
            case .final: .final
            }
            let authentication: OID4VCITokenEndpointAuthentication
            if authorizationMetadata.tokenEndpointAuthenticationMethods == nil {
                authentication = .anonymous
            } else if authorizationMetadata.tokenEndpointAuthenticationMethods?.contains("none") == true {
                authentication = .anonymous
            } else if authorizationMetadata.tokenEndpointAuthenticationMethods?.contains("attest_jwt_client_auth") == true &&
                        authorizationMetadata.clientAttestationAlgorithms?.contains("ES256") == true {
                authentication = .clientAttestation
            } else {
                authentication = .unsupported
            }
            return OID4VCITransportContract(
                profile: base.profile,
                proofShape: base.proofShape,
                credentialIdentifierField: base.credentialIdentifierField,
                responseEnvelopes: base.responseEnvelopes,
                requiresDPoP: false,
                tokenEndpointAuthentication: authentication,
                requiresCredentialResponseEncryption: true,
                supportsDeferredIssuance: false,
                supportsBatchIssuance: false
            )
        }
        let authentication: OID4VCITokenEndpointAuthentication
        if authorizationMetadata.tokenEndpointAuthenticationMethods == nil {
            authentication = .anonymous
        } else if authorizationMetadata.tokenEndpointAuthenticationMethods?.contains("none") == true {
            authentication = .anonymous
        } else if authorizationMetadata.tokenEndpointAuthenticationMethods?.contains("attest_jwt_client_auth") == true &&
                    authorizationMetadata.clientAttestationAlgorithms?.contains("ES256") == true {
            authentication = .clientAttestation
        } else {
            authentication = .unsupported
        }
        return OID4VCITransportContract(
            profile: .final,
            proofShape: .finalProofsJWT,
            credentialIdentifierField: .credentialConfigurationID,
            responseEnvelopes: [.jsonCredential, .jsonCredentials],
            requiresDPoP: false,
            tokenEndpointAuthentication: authentication,
            requiresCredentialResponseEncryption: false,
            supportsDeferredIssuance: false,
            supportsBatchIssuance: false
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
