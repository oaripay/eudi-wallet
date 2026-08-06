import Foundation
import LocalAuthentication
import Security
import WalletDomain

public actor DeviceBoundKeyProvider: KeyProvider {
    private let applicationTagPrefix: String
    private let clock: @Sendable () -> Date

    public init(
        applicationTagPrefix: String = "io.oari.wallet.key",
        clock: @escaping @Sendable () -> Date = Date.init
    ) {
        self.applicationTagPrefix = applicationTagPrefix
        self.clock = clock
    }

    public func createKey(
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
        requiresUserPresence: Bool,
        protection: KeyProtectionPolicy
    ) async throws -> KeyRecord {
        guard algorithm == .es256 else {
            throw WalletRepositoryError.unsupportedAlgorithm
        }

        let id = KeyID()
        let tag = applicationTag(for: id)
        let assurance: KeyAssurance

        switch protection {
        case .secureEnclaveRequired:
            try createSecKey(tag: tag, requiresUserPresence: requiresUserPresence, secureEnclave: true)
            assurance = .secureEnclave
        case .secureEnclavePreferred:
            do {
                try createSecKey(tag: tag, requiresUserPresence: requiresUserPresence, secureEnclave: true)
                assurance = .secureEnclave
            } catch {
                try createSecKey(tag: tag, requiresUserPresence: requiresUserPresence, secureEnclave: false)
                assurance = .keychainSoftware
            }
        case .keychainSoftware:
            try createSecKey(tag: tag, requiresUserPresence: requiresUserPresence, secureEnclave: false)
            assurance = .keychainSoftware
        }

        return KeyRecord(
            id: id,
            purpose: purpose,
            algorithm: algorithm,
            assurance: assurance,
            applicationTag: tag,
            createdAt: clock()
        )
    }

    public func sign(_ request: SigningRequest) async throws -> Data {
        let key = try loadPrivateKey(
            id: request.keyID,
            operationPrompt: request.userAuthenticationReason
        )
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            request.payload as CFData,
            &error
        ) as Data? else {
            throw DeviceKeyError.operationFailed(errorCode(error, fallback: errSecAuthFailed))
        }

        switch request.signatureFormat {
        case .x962DER:
            return signature
        case .joseRaw:
            return try ECDSASignatureCodec.joseRaw(fromX962DER: signature, coordinateSize: 32)
        }
    }

    public func publicKey(id: KeyID) async throws -> PublicKeyMaterial {
        let privateKey = try loadPrivateKey(id: id, operationPrompt: nil)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw DeviceKeyError.publicKeyUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let representation = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw DeviceKeyError.operationFailed(errorCode(error, fallback: errSecDecode))
        }
        return PublicKeyMaterial(algorithm: .es256, x963Representation: representation)
    }

    public func deleteKey(id: KeyID) async throws {
        let status = SecItemDelete(baseQuery(id: id) as CFDictionary)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw WalletRepositoryError.keyNotFound
            }
            throw DeviceKeyError.operationFailed(Int(status))
        }
    }

    private func createSecKey(
        tag: String,
        requiresUserPresence: Bool,
        secureEnclave: Bool
    ) throws {
        var privateAttributes: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: Data(tag.utf8),
        ]
        if secureEnclave || requiresUserPresence {
            var accessError: Unmanaged<CFError>?
            var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
            if requiresUserPresence {
                flags.insert(.userPresence)
            }
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                flags,
                &accessError
            ) else {
                throw DeviceKeyError.operationFailed(
                    errorCode(accessError, fallback: errSecParam)
                )
            }
            privateAttributes[kSecAttrAccessControl] = access
        } else {
            privateAttributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: privateAttributes,
        ]
        if secureEnclave {
            attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
        }

        var keyError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &keyError) != nil else {
            let code = errorCode(keyError, fallback: errSecUnimplemented)
            if secureEnclave {
                throw DeviceKeyError.secureEnclaveUnavailable(code)
            }
            throw DeviceKeyError.operationFailed(code)
        }
    }

    private func loadPrivateKey(id: KeyID, operationPrompt: String?) throws -> SecKey {
        var query = baseQuery(id: id)
        query[kSecReturnRef] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        if let operationPrompt, !operationPrompt.isEmpty {
            let context = LAContext()
            context.localizedReason = operationPrompt
            query[kSecUseAuthenticationContext] = context
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let key = result as! SecKey? else {
            if status == errSecItemNotFound {
                throw WalletRepositoryError.keyNotFound
            }
            throw DeviceKeyError.operationFailed(Int(status))
        }
        return key
    }

    private func baseQuery(id: KeyID) -> [CFString: Any] {
        [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: Data(applicationTag(for: id).utf8),
        ]
    }

    private func applicationTag(for id: KeyID) -> String {
        "\(applicationTagPrefix).\(id.rawValue.uuidString)"
    }

    private func errorCode(
        _ error: Unmanaged<CFError>?,
        fallback: OSStatus
    ) -> Int {
        guard let error else { return Int(fallback) }
        return CFErrorGetCode(error.takeRetainedValue())
    }
}

public enum DeviceKeyError: Error, Equatable, Sendable {
    case secureEnclaveUnavailable(Int)
    case operationFailed(Int)
    case malformedSignature
    case publicKeyUnavailable
}

enum ECDSASignatureCodec {
    static func joseRaw(fromX962DER der: Data, coordinateSize: Int) throws -> Data {
        var cursor = 0
        guard readByte(der, &cursor) == 0x30 else { throw DeviceKeyError.malformedSignature }
        let sequenceLength = try readLength(der, &cursor)
        let sequenceEnd = cursor + sequenceLength
        guard sequenceEnd == der.count else { throw DeviceKeyError.malformedSignature }
        guard readByte(der, &cursor) == 0x02 else { throw DeviceKeyError.malformedSignature }
        let r = try readInteger(
            der,
            &cursor,
            limit: sequenceEnd,
            coordinateSize: coordinateSize
        )
        guard readByte(der, &cursor) == 0x02 else { throw DeviceKeyError.malformedSignature }
        let s = try readInteger(
            der,
            &cursor,
            limit: sequenceEnd,
            coordinateSize: coordinateSize
        )
        guard cursor == sequenceEnd else { throw DeviceKeyError.malformedSignature }
        return r + s
    }

    private static func readInteger(
        _ data: Data,
        _ cursor: inout Int,
        limit: Int,
        coordinateSize: Int
    ) throws -> Data {
        let length = try readLength(data, &cursor)
        guard length > 0, cursor + length <= limit else {
            throw DeviceKeyError.malformedSignature
        }
        var integer = Data(data[cursor ..< cursor + length])
        cursor += length

        if integer.first == 0 {
            guard integer.count > 1, integer[integer.index(after: integer.startIndex)] & 0x80 != 0 else {
                throw DeviceKeyError.malformedSignature
            }
            integer.removeFirst()
        } else if let first = integer.first, first & 0x80 != 0 {
            throw DeviceKeyError.malformedSignature
        }
        guard integer.count <= coordinateSize else {
            throw DeviceKeyError.malformedSignature
        }
        return Data(repeating: 0, count: coordinateSize - integer.count) + integer
    }

    private static func readLength(_ data: Data, _ cursor: inout Int) throws -> Int {
        guard let first = readByte(data, &cursor) else { throw DeviceKeyError.malformedSignature }
        if first < 0x80 { return Int(first) }
        let byteCount = Int(first & 0x7f)
        guard byteCount > 0, byteCount <= 2 else { throw DeviceKeyError.malformedSignature }
        var length = 0
        for index in 0 ..< byteCount {
            guard let byte = readByte(data, &cursor) else { throw DeviceKeyError.malformedSignature }
            if index == 0, byte == 0 { throw DeviceKeyError.malformedSignature }
            length = (length << 8) | Int(byte)
        }
        guard length >= 0x80 else { throw DeviceKeyError.malformedSignature }
        return length
    }

    private static func readByte(_ data: Data, _ cursor: inout Int) -> UInt8? {
        guard cursor < data.count else { return nil }
        defer { cursor += 1 }
        return data[cursor]
    }
}
