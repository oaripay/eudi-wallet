import Foundation
import ProtocolEngine
import SwiftUI
import WalletDomain
import OariDesignSystem

@MainActor
final class WalletAppModel: ObservableObject {
    enum Tab: Hashable {
        case wallet
        case scan
        case history
        case settings
    }

    @Published private(set) var credentials: [CredentialRecord] = []
    @Published private(set) var auditEvents: [AuditEvent] = []
    @Published var theme: OariTheme = .dark
    @Published var scanInput = ""
    @Published private(set) var scanResult: ScanResult = .idle
    @Published private(set) var loadingState: LoadingState = .idle
    @Published private(set) var isPrivacyCoverVisible = false
    @Published var selectedTab: Tab = .wallet
    private let allowedHosts: Set<String>

    init(allowedHosts: Set<String> = ["wallet.dev.oari.io"]) {
        self.allowedHosts = allowedHosts
    }

    enum LoadingState: Equatable {
        case idle
        case loading
        case loaded
        case failed(String)
    }

    enum ScanResult: Equatable {
        case idle
        case presentation
        case issuance
        case unsupported
        case rejected(String)
    }

    var credentialCountDescription: String {
        switch credentials.count {
        case 0: "No credentials"
        case 1: "1 credential"
        default: "\(credentials.count) credentials"
        }
    }

    func load(
        credentials repository: any CredentialRepository,
        audit auditRepository: any AuditRepository
    ) async throws {
        credentials = try await repository.credentials()
        auditEvents = try await auditRepository.events().sorted { $0.occurredAt > $1.occurredAt }
    }

    func load(_ dependencies: Result<WalletAppDependencies, Error>) async {
        loadingState = .loading
        do {
            let dependencies = try dependencies.get()
            try await load(credentials: dependencies.credentials, audit: dependencies.audit)
            loadingState = .loaded
        } catch {
            loadingState = .failed("Protected wallet storage is unavailable. No credential data was displayed.")
        }
    }

    func classifyScan() {
        do {
            switch try ProtocolInputClassifier(allowedHosts: allowedHosts).classify(scanInput) {
            case .openID4VP: scanResult = .presentation
            case .openID4VCI: scanResult = .issuance
            case .unsupported: scanResult = .unsupported
            }
        } catch {
            scanResult = .rejected("The code is malformed or is not from an approved host.")
        }
    }

    func handleIncomingURL(_ url: URL) {
        handleScannedCode(url.absoluteString)
    }

    func handleScannedCode(_ code: String) {
        scanInput = code
        classifyScan()
        selectedTab = .scan
    }

    func setPrivacyCoverVisible(_ visible: Bool) {
        isPrivacyCoverVisible = visible
    }
}
