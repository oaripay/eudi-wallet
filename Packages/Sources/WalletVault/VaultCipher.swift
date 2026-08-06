import CryptoKit
import Foundation

struct VaultCipher: Sendable {
    let keyStore: any VaultKeyStore

    func seal(_ plaintext: Data, authenticating context: Data) throws -> Data {
        let box = try AES.GCM.seal(
            plaintext,
            using: keyStore.loadOrCreateKey(),
            authenticating: context
        )
        guard let combined = box.combined else {
            throw VaultError.storageFailure
        }
        return combined
    }

    func open(_ ciphertext: Data, authenticating context: Data) throws -> Data {
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(combined: ciphertext)
        } catch {
            throw VaultError.corruptCiphertext
        }

        let key = try keyStore.loadOrCreateKey()
        do {
            return try AES.GCM.open(
                box,
                using: key,
                authenticating: context
            )
        } catch {
            throw VaultError.corruptCiphertext
        }
    }
}
