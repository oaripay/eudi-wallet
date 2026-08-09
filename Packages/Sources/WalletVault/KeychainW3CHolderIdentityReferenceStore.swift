import EbsiW3CBackend
import Foundation
import Security
import WalletDomain

public struct KeychainW3CHolderIdentityReferenceStore: W3CHolderKeyReferenceStoring, Sendable {
    private let service: String
    private let account: String

    public init(
        service: String = "io.oari.wallet.w3c-holder",
        account: String = "canonical-holder-key-id"
    ) {
        self.service = service
        self.account = account
    }

    public func loadKeyID() async throws -> KeyID? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ] as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess,
              let data = item as? Data,
              let value = String(data: data, encoding: .utf8),
              let uuid = UUID(uuidString: value) else {
            throw OpenID4VCBackendError.holderIdentityRecoveryRequired
        }
        return KeyID(rawValue: uuid)
    }

    public func saveKeyID(_ keyID: KeyID) async throws {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ] as CFDictionary
        let data = Data(keyID.rawValue.uuidString.utf8)
        let update = SecItemUpdate(query, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else {
            throw OpenID4VCBackendError.holderIdentityRecoveryRequired
        }
        let add = SecItemAdd([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
        guard add == errSecSuccess else {
            throw OpenID4VCBackendError.holderIdentityRecoveryRequired
        }
    }

    public func deleteKeyID() async throws {
        let status = SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw OpenID4VCBackendError.holderIdentityRecoveryRequired
        }
    }
}
