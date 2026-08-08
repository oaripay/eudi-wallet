import CryptoKit
import Foundation
import JOSESwift
import WalletDomain

public actor DefaultOID4VCIClientSecurity: OID4VCIClientSecurity {
    private let keyProvider: any KeyProvider
    private var dpopKey: KeyRecord?
    private var responseKeys: [KeyID: P256.KeyAgreement.PrivateKey] = [:]

    public init(keyProvider: any KeyProvider) {
        self.keyProvider = keyProvider
    }

    public func state(for profile: OID4VCITransportProfile) async throws -> OID4VCIClientSecurityState {
        let dpop: KeyRecord
        if let existing = dpopKey {
            dpop = existing
        } else {
            dpop = try await keyProvider.createKey(
                purpose: .dpop,
                algorithm: .es256,
                requiresUserPresence: false,
                protection: .keychainSoftware
            )
            dpopKey = dpop
        }
        let responseKeyID = KeyID()
        responseKeys[responseKeyID] = P256.KeyAgreement.PrivateKey()
        return OID4VCIClientSecurityState(
            dpopKeyID: dpop.id,
            clientAttestationKeyID: nil,
            responseEncryptionKeyID: responseKeyID
        )
    }

    public func dpopHeader(
        state: OID4VCIClientSecurityState,
        method: String,
        targetURI: URL
    ) async throws -> String {
        let key = try await keyProvider.publicKey(id: state.dpopKeyID)
        var jwk = try Self.publicJWK(key.x963Representation)
        jwk["use"] = "sig"
        jwk["alg"] = "ES256"
        return try await sign(
            keyID: state.dpopKeyID,
            header: ["alg": "ES256", "typ": "dpop+jwt", "jwk": jwk],
            payload: [
                "htm": method,
                "htu": targetURI.absoluteString,
                "iat": Int(Date().timeIntervalSince1970),
                "jti": UUID().uuidString,
            ]
        )
    }

    public func clientAttestationHeaders(
        state: OID4VCIClientSecurityState,
        audience: URL
    ) async throws -> [String: String] {
        [:]
    }

    public func responseEncryption(
        state: OID4VCIClientSecurityState
    ) async throws -> OID4VCIResponseEncryptionParameters {
        guard let key = responseKeys[state.responseEncryptionKeyID] else {
            throw WorkspaceBackendError.clientSecurityUnavailable
        }
        var jwk = try Self.publicJWK(key.publicKey.x963Representation)
        jwk["alg"] = "ECDH-ES"
        jwk["enc"] = "A128CBC-HS256"
        jwk["use"] = "enc"
        let data = try JSONSerialization.data(withJSONObject: jwk, options: [.sortedKeys])
        return OID4VCIResponseEncryptionParameters(
            publicJWK: String(decoding: data, as: UTF8.self)
        )
    }

    public func decryptCredentialResponse(
        state: OID4VCIClientSecurityState,
        compactJWE: Data
    ) async throws -> Data {
        guard let key = responseKeys.removeValue(forKey: state.responseEncryptionKeyID) else {
            throw WorkspaceBackendError.clientSecurityUnavailable
        }
        let privateJWK = try Self.privateJWK(key)
        let privateData = try JSONSerialization.data(withJSONObject: privateJWK, options: [.sortedKeys])
        let ecPrivateKey = try ECPrivateKey(data: privateData)
        guard let decrypter = Decrypter(
            keyManagementAlgorithm: .ECDH_ES,
            contentEncryptionAlgorithm: .A128CBCHS256,
            decryptionKey: ecPrivateKey
        ) else {
            throw EbsiCredentialError.verificationFailed
        }
        let compact = String(decoding: compactJWE, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let jwe = try JWE(compactSerialization: compact)
        return try jwe.decrypt(using: decrypter).data()
    }

    private func sign(
        keyID: KeyID,
        header: [String: Any],
        payload: [String: Any]
    ) async throws -> String {
        let encodedHeader = try Self.base64JSON(header)
        let encodedPayload = try Self.base64JSON(payload)
        let input = Data("\(encodedHeader).\(encodedPayload)".utf8)
        let signature = try await keyProvider.sign(SigningRequest(
            keyID: keyID,
            payload: input,
            userAuthenticationReason: "Sign DPoP proof",
            signatureFormat: .joseRaw
        ))
        return "\(encodedHeader).\(encodedPayload).\(Self.base64URL(signature))"
    }

    private static func publicJWK(_ x963: Data) throws -> [String: Any] {
        guard x963.count == 65, x963.first == 0x04 else {
            throw EbsiCredentialError.malformedCredential
        }
        return [
            "kty": "EC",
            "crv": "P-256",
            "x": base64URL(x963.subdata(in: 1..<33)),
            "y": base64URL(x963.subdata(in: 33..<65)),
            "alg": "ES256",
            "use": "enc",
        ]
    }

    private static func privateJWK(_ key: P256.KeyAgreement.PrivateKey) throws -> [String: Any] {
        var result = try publicJWK(key.publicKey.x963Representation)
        result["d"] = base64URL(key.rawRepresentation)
        return result
    }

    private static func base64JSON(_ value: Any) throws -> String {
        base64URL(try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
