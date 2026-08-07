import EudiWalletKit
import CryptoKit
import Foundation
import Security
import X509
#if canImport(EudiEtsi1196x2)
import MdocSecurity18013
#endif

public struct EudiWalletKitBaseline: Equatable, Sendable {
    public static let selectedVersion = "0.39.1"
    public static let selectedCommit = "79005ab4bf0399238c1c9ebff9ee7d8a42c521f9"

    public let serviceName: String
    public let requiresUserAuthentication: Bool

    public init(
        serviceName: String,
        requiresUserAuthentication: Bool = true
    ) throws {
        let serviceName = serviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !serviceName.isEmpty, !serviceName.contains(":") else {
            throw EudiWalletKitAdapterError.invalidServiceName
        }
        self.serviceName = serviceName
        self.requiresUserAuthentication = requiresUserAuthentication
    }

    public func walletConfiguration() -> EudiWalletConfiguration {
        EudiWalletConfiguration(
            serviceName: serviceName,
            userAuthenticationRequired: requiresUserAuthentication,
            logFileName: nil,
            bleTransferMode: .server
        )
    }

    public func presentationConfiguration() -> OpenId4VpConfiguration {
        OpenId4VpConfiguration(
            clientIdSchemes: [.x509SanDns, .x509Hash, .redirectUri],
            preferredResponseMode: .directPostJWT,
            validateRegistrationCertificate: true
        )
    }

    public func makeWallet(
        trustSource: EudiTrustAnchorSource,
        validationDate: Date = Date()
    ) throws -> EudiWalletKitAdapter {
        let trustAnchors = try trustSource.validatedAnchors(at: validationDate)
        #if canImport(EudiEtsi1196x2)
        let trustConfiguration = TrustConfiguration(
            trustSource: .staticList(
                StaticListTrustSource(rootCertificates: trustAnchors)
            ),
            fallbackTrustSource: nil,
            defaultPolicy: .enforce,
            requireSignedMetadata: true,
            statusTrustPolicy: .enforce,
            wrprcTrustPolicy: .enforce
        )
        #else
        let trustConfiguration = TrustConfiguration(
            rootIaca: [trustAnchors],
            defaultPolicy: .enforce,
            requireSignedMetadata: true,
            statusTrustPolicy: .enforce,
            wrprcTrustPolicy: .enforce
        )
        #endif
        do {
            let wallet = try EudiWallet(
                eudiWalletConfig: walletConfiguration(),
                trustConfig: trustConfiguration,
                openID4VpConfig: presentationConfiguration()
            )
            return EudiWalletKitAdapter(wallet: wallet)
        } catch {
            throw EudiWalletKitAdapterError.initializationFailed
        }
    }
}

/// A profile-bound, digest-pinned trust input populated only from an
/// authenticated trust-list/configuration boundary.
public struct EudiTrustAnchorSource: Equatable, Sendable {
    public let profileID: String
    private let anchors: [Data]
    private let approvedSHA256Digests: Set<String>

    public init(
        profileID: String,
        anchors: [Data],
        approvedSHA256Digests: Set<String>
    ) throws {
        let profileID = profileID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !profileID.isEmpty else {
            throw EudiWalletKitAdapterError.invalidTrustSource
        }
        guard !anchors.isEmpty else {
            throw EudiWalletKitAdapterError.missingTrustAnchors
        }
        guard approvedSHA256Digests.count == anchors.count,
              approvedSHA256Digests.allSatisfy(Self.isCanonicalDigest) else {
            throw EudiWalletKitAdapterError.invalidTrustSource
        }
        self.profileID = profileID
        self.anchors = anchors
        self.approvedSHA256Digests = approvedSHA256Digests
    }

    public static func sha256Digest(of anchor: Data) -> String {
        SHA256.hash(data: anchor).map { String(format: "%02x", $0) }.joined()
    }

    fileprivate func validatedAnchors(at date: Date) throws -> [Data] {
        for anchor in anchors {
            let digest = Self.sha256Digest(of: anchor)
            guard approvedSHA256Digests.contains(digest) else {
                throw EudiWalletKitAdapterError.unapprovedTrustAnchor
            }
            let certificate: Certificate
            do {
                certificate = try Certificate(derEncoded: Array(anchor))
            } catch {
                throw EudiWalletKitAdapterError.invalidTrustAnchor
            }
            guard case .isCertificateAuthority = try? certificate.extensions.basicConstraints else {
                throw EudiWalletKitAdapterError.invalidTrustAnchor
            }
            if let keyUsage = try? certificate.extensions.keyUsage,
               !keyUsage.keyCertSign {
                throw EudiWalletKitAdapterError.invalidTrustAnchor
            }
            guard certificate.notValidBefore <= date, date <= certificate.notValidAfter else {
                throw EudiWalletKitAdapterError.invalidTrustAnchor
            }
        }
        return anchors
    }

    private static func isCanonicalDigest(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }
}

public struct EudiWalletDocumentSummary: Equatable, Sendable {
    public let id: String
    public let documentType: String
    public let displayName: String?
    public let format: String
    public let status: String

    public init(
        id: String,
        documentType: String,
        displayName: String?,
        format: String,
        status: String
    ) {
        self.id = id
        self.documentType = documentType
        self.displayName = displayName
        self.format = format
        self.status = status
    }
}

public final class EudiWalletKitAdapter: @unchecked Sendable {
    private let wallet: EudiWallet

    init(wallet: EudiWallet) {
        self.wallet = wallet
    }

    public func requireOperationalRuntime() throws {
        guard !_isDebugAssertConfiguration() else {
            throw EudiWalletKitAdapterError.unsafeDebugLogging
        }
    }

    public func loadDocumentSummaries() async throws -> [EudiWalletDocumentSummary] {
        try requireOperationalRuntime()
        let documents = try await wallet.loadAllDocuments() ?? []
        return documents.map {
            EudiWalletDocumentSummary(
                id: $0.id,
                documentType: $0.docType,
                displayName: $0.displayName,
                format: $0.docDataFormat.rawValue,
                status: $0.status.rawValue
            )
        }
    }

    public func deleteAllDocuments() async throws {
        try requireOperationalRuntime()
        try await wallet.deleteAllDocuments()
    }
}

public enum EudiWalletKitAdapterError: Error, Equatable, Sendable {
    case invalidServiceName
    case missingTrustAnchors
    case invalidTrustAnchor
    case invalidTrustSource
    case unapprovedTrustAnchor
    case initializationFailed
    case unsafeDebugLogging
}
