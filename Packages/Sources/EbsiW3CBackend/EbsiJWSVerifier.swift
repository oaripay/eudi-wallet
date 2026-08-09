import CryptoKit
import Foundation
import Security

public enum EbsiVerificationRelationship: String, Codable, Equatable, Hashable, Sendable {
    case authentication
    case assertionMethod
    case capabilityInvocation
}

public enum EbsiVerificationKey: Equatable, Sendable {
    case p256(x: Data, y: Data)
    case secp256k1(x: Data, y: Data)
    case rsa(modulus: Data, exponent: Data)
    case rsaPKCS1DER(Data)
}

public struct EbsiVerificationMethod: Equatable, Sendable {
    public let id: String
    public let controller: String
    public let key: EbsiVerificationKey
    public let relationships: Set<EbsiVerificationRelationship>

    public init(
        id: String,
        controller: String,
        key: EbsiVerificationKey,
        relationships: Set<EbsiVerificationRelationship>
    ) {
        self.id = id
        self.controller = controller
        self.key = key
        self.relationships = relationships
    }
}

public struct EbsiJWSRequirements: Equatable, Sendable {
    public let allowedAlgorithms: Set<EbsiKeyAlgorithm>
    public let requiredRelationship: EbsiVerificationRelationship
    public let expectedController: String?
    public let expectedIssuer: String?
    public let expectedAudience: String?
    public let expectedNonce: String?
    public let expectedType: String?
    public let understoodCriticalHeaders: Set<String>
    public let validationDate: Date

    public init(
        allowedAlgorithms: Set<EbsiKeyAlgorithm>,
        requiredRelationship: EbsiVerificationRelationship,
        expectedController: String? = nil,
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil,
        expectedNonce: String? = nil,
        expectedType: String? = nil,
        understoodCriticalHeaders: Set<String> = [],
        validationDate: Date = Date()
    ) {
        self.allowedAlgorithms = allowedAlgorithms
        self.requiredRelationship = requiredRelationship
        self.expectedController = expectedController
        self.expectedIssuer = expectedIssuer
        self.expectedAudience = expectedAudience
        self.expectedNonce = expectedNonce
        self.expectedType = expectedType
        self.understoodCriticalHeaders = understoodCriticalHeaders
        self.validationDate = validationDate
    }
}

public struct VerifiedEbsiJWS: Equatable, Sendable {
    public let header: [String: AnySendableJSON]
    public let payload: [String: AnySendableJSON]
    public let methodID: String
}

public struct EbsiJWSVerifier: Sendable {
    public init() {}

    public func verify(
        compactJWS: String,
        methods: [EbsiVerificationMethod],
        requirements: EbsiJWSRequirements
    ) throws -> VerifiedEbsiJWS {
        let parts = compactJWS.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = Self.decodeBase64URL(String(parts[0])),
              let payloadData = Self.decodeBase64URL(String(parts[1])),
              let signature = Self.decodeBase64URL(String(parts[2])),
              let header = try? JSONDecoder().decode([String: AnySendableJSON].self, from: headerData),
              let payload = try? JSONDecoder().decode([String: AnySendableJSON].self, from: payloadData),
              let algorithmName = header["alg"]?.string,
              let algorithm = EbsiKeyAlgorithm(rawValue: algorithmName),
              requirements.allowedAlgorithms.contains(algorithm) else {
            throw EbsiCredentialError.verificationFailed
        }
        let kid = header["kid"]?.string
        try Self.validateProtectedHeader(header, requirements: requirements)
        let hasEmbeddedKeyReference = Self.hasEmbeddedKeyReference(header)
        if kid == "None", !hasEmbeddedKeyReference {
            throw EbsiCredentialError.verificationFailed
        }
        let candidates: [EbsiVerificationMethod]
        if let kid, kid != "None" {
            let exact = methods.filter { $0.id == kid }
            candidates = exact.isEmpty && hasEmbeddedKeyReference ? methods : exact
        } else {
            candidates = methods
        }
        let eligible = candidates.filter { method in
            method.relationships.contains(requirements.requiredRelationship) &&
                (requirements.expectedController == nil || method.controller == requirements.expectedController)
        }
        guard !eligible.isEmpty else { throw EbsiCredentialError.verificationFailed }
        try Self.validateClaims(payload, requirements: requirements)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        let verified = eligible.filter { method in
            (try? Self.verifySignature(
                algorithm: algorithm,
                key: method.key,
                signature: signature,
                message: signingInput
            )) == true
        }
        guard verified.count == 1, let method = verified.first else {
            throw EbsiCredentialError.verificationFailed
        }
        return VerifiedEbsiJWS(header: header, payload: payload, methodID: method.id)
    }

    private static func hasEmbeddedKeyReference(
        _ header: [String: AnySendableJSON]
    ) -> Bool {
        if header["jwk"]?.object != nil { return true }
        if case let .array(values) = header["x5c"], !values.isEmpty,
           values.allSatisfy({ $0.string != nil }) {
            return true
        }
        return false
    }

    private static func validateProtectedHeader(
        _ header: [String: AnySendableJSON],
        requirements: EbsiJWSRequirements
    ) throws {
        if let expectedType = requirements.expectedType,
           header["typ"]?.string != expectedType {
            throw EbsiCredentialError.verificationFailed
        }
        guard let critical = header["crit"] else { return }
        guard case let .array(values) = critical, !values.isEmpty else {
            throw EbsiCredentialError.verificationFailed
        }
        let names = values.compactMap(\.string)
        let registered = Set([
            "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t",
            "x5t#S256", "typ", "cty", "crit", "b64",
        ])
        guard names.count == values.count,
              Set(names).count == names.count,
              names.allSatisfy({ header[$0] != nil }),
              Set(names).isDisjoint(with: registered),
              Set(names).isSubset(of: requirements.understoodCriticalHeaders) else {
            throw EbsiCredentialError.verificationFailed
        }
    }

    private static func validateClaims(
        _ payload: [String: AnySendableJSON],
        requirements: EbsiJWSRequirements
    ) throws {
        if let expected = requirements.expectedIssuer, payload["iss"]?.string != expected {
            throw EbsiCredentialError.verificationFailed
        }
        if let expected = requirements.expectedAudience,
           !audiences(payload["aud"]).contains(expected) {
            throw EbsiCredentialError.verificationFailed
        }
        if let expected = requirements.expectedNonce, payload["nonce"]?.string != expected {
            throw EbsiCredentialError.verificationFailed
        }
        let now = requirements.validationDate.timeIntervalSince1970
        let exp = try numericDate("exp", in: payload)
        let nbf = try numericDate("nbf", in: payload)
        let iat = try numericDate("iat", in: payload)
        if let exp, exp <= now { throw EbsiCredentialError.verificationFailed }
        if let nbf, nbf > now { throw EbsiCredentialError.verificationFailed }
        if let iat, iat > now + 60 { throw EbsiCredentialError.verificationFailed }
    }

    private static func numericDate(
        _ name: String,
        in payload: [String: AnySendableJSON]
    ) throws -> Double? {
        guard let claim = payload[name] else { return nil }
        guard let value = claim.numericValue, value.isFinite else {
            throw EbsiCredentialError.verificationFailed
        }
        return value
    }

    private static func audiences(_ value: AnySendableJSON?) -> [String] {
        switch value {
        case let .string(value): [value]
        case let .array(values): values.compactMap(\.string)
        default: []
        }
    }

    private static func verifySignature(
        algorithm: EbsiKeyAlgorithm,
        key: EbsiVerificationKey,
        signature: Data,
        message: Data
    ) throws -> Bool {
        switch (algorithm, key) {
        case let (.es256, .p256(x, y)):
            let publicKey = try P256.Signing.PublicKey(x963Representation: Data([0x04]) + x + y)
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            return publicKey.isValidSignature(signature, for: message)
        case (.es256K, .secp256k1):
            throw EbsiCredentialError.unsupportedRepresentation
        case let (.rs256, .rsa(modulus, exponent)):
            return try verifyRSA(
                keyData: rsaPKCS1(modulus: modulus, exponent: exponent),
                signature: signature,
                message: message
            )
        case let (.rs256, .rsaPKCS1DER(keyData)):
            return try verifyRSA(keyData: keyData, signature: signature, message: message)
        default:
            throw EbsiCredentialError.algorithmNotAllowed
        }
    }

    private static func verifyRSA(keyData: Data, signature: Data, message: Data) throws -> Bool {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            if let error { throw error.takeRetainedValue() }
            throw EbsiCredentialError.verificationFailed
        }
        return SecKeyVerifySignature(
            key,
            .rsaSignatureMessagePKCS1v15SHA256,
            message as CFData,
            signature as CFData,
            &error
        )
    }

    private static func rsaPKCS1(modulus: Data, exponent: Data) -> Data {
        derSequence(derInteger(modulus) + derInteger(exponent))
    }

    private static func derInteger(_ value: Data) -> Data {
        var value = Data(value.drop(while: { $0 == 0 }))
        if value.isEmpty { value = Data([0]) }
        if value.first.map({ $0 & 0x80 != 0 }) == true { value.insert(0, at: 0) }
        return Data([0x02]) + derLength(value.count) + value
    }

    private static func derSequence(_ value: Data) -> Data {
        Data([0x30]) + derLength(value.count) + value
    }

    private static func derLength(_ count: Int) -> Data {
        if count < 128 { return Data([UInt8(count)]) }
        var value = count
        var bytes: [UInt8] = []
        while value > 0 { bytes.insert(UInt8(value & 0xff), at: 0); value >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        var value = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        return Data(base64Encoded: value)
    }
}
