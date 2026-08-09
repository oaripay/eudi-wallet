import Foundation
import IdentityDomain
import WalletDomain

public struct W3CHolderIdentity: Equatable, Sendable {
    public let keyID: KeyID
    public let did: String
    public let assertionMethod: String

    public init(keyID: KeyID, did: String, assertionMethod: String) {
        self.keyID = keyID
        self.did = did
        self.assertionMethod = assertionMethod
    }
}

public protocol W3CHolderIdentityProviding: Sendable {
    func loadOrCreateIdentity() async throws -> W3CHolderIdentity
    func currentIdentity() async throws -> W3CHolderIdentity?
    func resetIdentity() async throws
}

public protocol W3CHolderKeyReferenceStoring: Sendable {
    func loadKeyID() async throws -> KeyID?
    func saveKeyID(_ keyID: KeyID) async throws
    func deleteKeyID() async throws
}

public actor PersistentW3CHolderIdentityProvider: W3CHolderIdentityProviding {
    private let keyProvider: any KeyProvider
    private let referenceStore: any W3CHolderKeyReferenceStoring
    private var cachedIdentity: W3CHolderIdentity?

    public init(
        keyProvider: any KeyProvider,
        referenceStore: any W3CHolderKeyReferenceStoring
    ) {
        self.keyProvider = keyProvider
        self.referenceStore = referenceStore
    }

    public func loadOrCreateIdentity() async throws -> W3CHolderIdentity {
        if let cachedIdentity { return cachedIdentity }
        if let keyID = try await referenceStore.loadKeyID() {
            let identity = try await identity(for: keyID)
            cachedIdentity = identity
            return identity
        }
        let key = try await keyProvider.createKey(
            purpose: .credentialBinding,
            algorithm: .es256,
            requiresUserPresence: true,
            protection: .secureEnclavePreferred
        )
        let identity = try await identity(for: key.id)
        try await referenceStore.saveKeyID(key.id)
        cachedIdentity = identity
        return identity
    }

    public func currentIdentity() async throws -> W3CHolderIdentity? {
        if let cachedIdentity { return cachedIdentity }
        guard let keyID = try await referenceStore.loadKeyID() else { return nil }
        let identity = try await identity(for: keyID)
        cachedIdentity = identity
        return identity
    }

    public func resetIdentity() async throws {
        if let identity = try await currentIdentity() {
            try await keyProvider.deleteKey(id: identity.keyID)
        }
        try await referenceStore.deleteKeyID()
        cachedIdentity = nil
    }

    private func identity(for keyID: KeyID) async throws -> W3CHolderIdentity {
        do {
            let publicKey = try await keyProvider.publicKey(id: keyID)
            let did = try KeyDIDResolver().derive(publicKeyX963: publicKey.x963Representation)
            guard let assertionMethod = try await KeyDIDResolver().resolve(did).assertionMethod.first else {
                throw WorkspaceBackendError.holderIdentityRecoveryRequired
            }
            return W3CHolderIdentity(keyID: keyID, did: did, assertionMethod: assertionMethod)
        } catch let error as WorkspaceBackendError {
            throw error
        } catch {
            throw WorkspaceBackendError.holderIdentityRecoveryRequired
        }
    }
}

public actor InMemoryW3CHolderKeyReferenceStore: W3CHolderKeyReferenceStoring {
    private var keyID: KeyID?

    public init(keyID: KeyID? = nil) { self.keyID = keyID }
    public func loadKeyID() -> KeyID? { keyID }
    public func saveKeyID(_ keyID: KeyID) { self.keyID = keyID }
    public func deleteKeyID() { keyID = nil }
}
