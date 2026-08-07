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
    public let validationDate: Date

    public init(
        allowedAlgorithms: Set<EbsiKeyAlgorithm>,
        requiredRelationship: EbsiVerificationRelationship,
        expectedController: String? = nil,
        expectedIssuer: String? = nil,
        expectedAudience: String? = nil,
        expectedNonce: String? = nil,
        validationDate: Date = Date()
    ) {
        self.allowedAlgorithms = allowedAlgorithms
        self.requiredRelationship = requiredRelationship
        self.expectedController = expectedController
        self.expectedIssuer = expectedIssuer
        self.expectedAudience = expectedAudience
        self.expectedNonce = expectedNonce
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
              requirements.allowedAlgorithms.contains(algorithm),
              let kid = header["kid"]?.string,
              let method = methods.first(where: { $0.id == kid }),
              method.relationships.contains(requirements.requiredRelationship) else {
            throw EbsiCredentialError.verificationFailed
        }
        if let expected = requirements.expectedController, method.controller != expected {
            throw EbsiCredentialError.verificationFailed
        }
        try Self.validateClaims(payload, requirements: requirements)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        guard try Self.verifySignature(
            algorithm: algorithm,
            key: method.key,
            signature: signature,
            message: signingInput
        ) else {
            throw EbsiCredentialError.verificationFailed
        }
        return VerifiedEbsiJWS(header: header, payload: payload, methodID: method.id)
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
        if let exp = payload["exp"]?.numericValue, exp <= now { throw EbsiCredentialError.verificationFailed }
        if let nbf = payload["nbf"]?.numericValue, nbf > now { throw EbsiCredentialError.verificationFailed }
        if let iat = payload["iat"]?.numericValue, iat > now + 60 { throw EbsiCredentialError.verificationFailed }
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
