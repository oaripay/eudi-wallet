import CryptoKit
import Foundation
import Security

public protocol VaultKeyStore: Sendable {
    func loadOrCreateKey() throws -> SymmetricKey
}

public struct KeychainVaultKeyStore: VaultKeyStore, Sendable {
    private let service: String
    private let account: String

    public init(service: String, account: String = "credential-vault-master-key") {
        self.service = service
        self.account = account
    }

    public func loadOrCreateKey() throws -> SymmetricKey {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let copyStatus = SecItemCopyMatching(query as CFDictionary, &result)

        if copyStatus == errSecSuccess {
            guard let data = result as? Data, data.count == 32 else {
                throw VaultError.storageFailure
            }
            return SymmetricKey(data: data)
        }
        guard copyStatus == errSecItemNotFound else {
            throw VaultError.keychain(copyStatus)
        }

        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        let addQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: keyData,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecDuplicateItem {
            return try loadOrCreateKey()
        }
        guard addStatus == errSecSuccess else {
            throw VaultError.keychain(addStatus)
        }
        return key
    }
}

public enum VaultError: Error, Equatable, Sendable {
    case keychain(OSStatus)
    case corruptCiphertext
    case storageFailure
}
