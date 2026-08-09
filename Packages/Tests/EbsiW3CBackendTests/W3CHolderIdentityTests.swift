import CryptoKit
import EbsiW3CBackend
import Foundation
import Testing
import WalletDomain

struct W3CHolderIdentityTests {
    @Test("Canonical holder identity is created once and survives provider restart")
    func stableIdentity() async throws {
        let keys = IdentityFixtureKeyProvider()
        let references = InMemoryW3CHolderKeyReferenceStore()
        let firstProvider = PersistentW3CHolderIdentityProvider(
            keyProvider: keys,
            referenceStore: references
        )
        let first = try await firstProvider.loadOrCreateIdentity()
        let repeated = try await firstProvider.loadOrCreateIdentity()
        let restartedProvider = PersistentW3CHolderIdentityProvider(
            keyProvider: keys,
            referenceStore: references
        )
        let restarted = try await restartedProvider.loadOrCreateIdentity()

        #expect(first == repeated)
        #expect(first == restarted)
        #expect(await keys.createCount == 1)
    }

    @Test("Missing canonical private key fails instead of rotating DID")
    func missingKeyFails() async throws {
        let references = InMemoryW3CHolderKeyReferenceStore(keyID: KeyID())
        let provider = PersistentW3CHolderIdentityProvider(
            keyProvider: IdentityFixtureKeyProvider(),
            referenceStore: references
        )
        await #expect(throws: OpenID4VCBackendError.holderIdentityRecoveryRequired) {
            _ = try await provider.loadOrCreateIdentity()
        }
    }

    @Test("Reset deletes canonical key and reference")
    func resetIdentity() async throws {
        let keys = IdentityFixtureKeyProvider()
        let references = InMemoryW3CHolderKeyReferenceStore()
        let provider = PersistentW3CHolderIdentityProvider(
            keyProvider: keys,
            referenceStore: references
        )
        let identity = try await provider.loadOrCreateIdentity()
        try await provider.resetIdentity()
        #expect(try await provider.currentIdentity() == nil)
        #expect(await keys.deletedKeyIDs == [identity.keyID])
    }
}

private actor IdentityFixtureKeyProvider: KeyProvider {
    private var keys: [KeyID: P256.Signing.PrivateKey] = [:]
    private(set) var createCount = 0
    private(set) var deletedKeyIDs: [KeyID] = []

    func createKey(
        purpose: KeyPurpose,
        algorithm: SigningAlgorithm,
        requiresUserPresence: Bool,
        protection: KeyProtectionPolicy
    ) async throws -> KeyRecord {
        createCount += 1
        let id = KeyID()
        keys[id] = P256.Signing.PrivateKey()
        return KeyRecord(
            id: id,
            purpose: purpose,
            algorithm: algorithm,
            assurance: .keychainSoftware,
            applicationTag: "identity-fixture.\(id.rawValue.uuidString)",
            createdAt: Date()
        )
    }

    func sign(_ request: SigningRequest) async throws -> Data {
        guard let key = keys[request.keyID] else { throw IdentityFixtureError.keyNotFound }
        return try key.signature(for: request.payload).rawRepresentation
    }

    func publicKey(id: KeyID) async throws -> PublicKeyMaterial {
        guard let key = keys[id] else { throw IdentityFixtureError.keyNotFound }
        return PublicKeyMaterial(algorithm: .es256, x963Representation: key.publicKey.x963Representation)
    }

    func deleteKey(id: KeyID) async throws {
        keys[id] = nil
        deletedKeyIDs.append(id)
    }
}

private enum IdentityFixtureError: Error { case keyNotFound }
