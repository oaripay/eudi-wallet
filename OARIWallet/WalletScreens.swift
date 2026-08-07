import OariDesignSystem
import SwiftUI
import WalletDomain

struct WalletVaultView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: OariSpacing.x5) {
                    Text("HOLDER WALLET")
                        .font(OariTypography.label)
                        .tracking(2)
                        .foregroundStyle(OariColor.textSecondary(scheme))
                    Text(model.credentialCountDescription)
                        .font(OariTypography.title)
                        .accessibilityIdentifier("wallet.credential-count")
                    if case let .failed(message) = model.loadingState {
                        OariCard {
                            OariStatusBadge("Wallet storage unavailable", kind: .invalid)
                            Text(message)
                                .font(OariTypography.body)
                                .foregroundStyle(OariColor.textSecondary(scheme))
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityIdentifier("wallet.storage-error")
                    }
                    if model.credentials.isEmpty {
                        OariCard {
                            Label("Wallet setup required", systemImage: "lock.shield")
                                .font(OariTypography.heading)
                            Text("No credentials are stored. Scan an approved credential offer to begin.")
                                .font(OariTypography.body)
                                .foregroundStyle(OariColor.textSecondary(scheme))
                        }
                        .accessibilityElement(children: .combine)
                    } else {
                        ForEach(model.credentials) { credential in
                            CredentialTile(credential: credential)
                        }
                    }
                }
                .padding(OariSpacing.x5)
            }
            .background(OariColor.background(scheme))
            .navigationTitle("Wallet")
        }
    }
}

private struct CredentialTile: View {
    @Environment(\.colorScheme) private var scheme
    let credential: CredentialRecord

    var body: some View {
        OariCard {
            VStack(alignment: .leading, spacing: OariSpacing.x3) {
                OariStatusBadge(statusLabel, kind: statusKind)
                Text(credential.displayName).font(OariTypography.heading)
                Text(credential.issuerIdentifier)
                    .font(OariTypography.technical)
                    .foregroundStyle(OariColor.textSecondary(scheme))
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(credential.displayName), \(statusLabel)")
        .accessibilityIdentifier("wallet.credential.\(credential.configurationID)")
    }

    private var statusLabel: String {
        switch credential.issuerTrust {
        case .trusted: "Trusted issuer"
        case .untrusted: "Issuer not verified"
        case .invalid: "Invalid issuer"
        case .indeterminate: "Issuer status unavailable"
        case .notEvaluated: "Issuer not evaluated"
        }
    }

    private var statusKind: OariStatusKind {
        switch credential.issuerTrust {
        case .trusted: .trusted
        case .untrusted, .notEvaluated: .warning
        case .invalid: .invalid
        case .indeterminate: .indeterminate
        }
    }
}

struct WalletScannerView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    @State private var isCameraPresented = false

    var body: some View {
        NavigationStack {
            VStack(spacing: OariSpacing.x5) {
                OariCard {
                    VStack(alignment: .leading, spacing: OariSpacing.x4) {
                        Label("Scan or paste a wallet code", systemImage: "qrcode.viewfinder")
                            .font(OariTypography.heading)
                        TextField("Approved HTTPS or wallet URL", text: $model.scanInput, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .padding(OariSpacing.x4)
                            .background(OariColor.surfaceInset(scheme))
                            .clipShape(RoundedRectangle(cornerRadius: OariRadius.medium))
                            .accessibilityLabel("Wallet code")
                            .accessibilityIdentifier("scanner.input")
                        Button("Review code") {
                            model.classifyScan()
                        }
                        .buttonStyle(OariPrimaryButtonStyle())
                        .disabled(model.scanInput.isEmpty)
                        .accessibilityIdentifier("scanner.review")
                        Button {
                            isCameraPresented = true
                        } label: {
                            Label("Scan with camera", systemImage: "camera.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .accessibilityIdentifier("scanner.camera")
                    }
                }
                ScanResultView(result: model.scanResult, input: model.scanInput)
                Spacer()
            }
            .padding(OariSpacing.x5)
            .background(OariColor.background(scheme))
            .navigationTitle("Scan")
            .sheet(isPresented: $isCameraPresented) {
                CameraQRScannerSheet(onCode: model.handleScannedCode)
            }
        }
    }
}

private struct ScanResultView: View {
    let result: WalletAppModel.ScanResult
    let input: String

    var body: some View {
        switch result {
        case .idle: EmptyView()
        case .presentation:
            NavigationLink {
                WalletRequestReviewView(kind: .presentation, source: input)
            } label: {
                OariStatusBadge("Review presentation request", kind: .warning)
            }
            .accessibilityIdentifier("scanner.result.presentation")
        case .issuance:
            NavigationLink {
                WalletRequestReviewView(kind: .issuance, source: input)
            } label: {
                OariStatusBadge("Review credential offer", kind: .warning)
            }
            .accessibilityIdentifier("scanner.result.issuance")
        case .unsupported:
            OariStatusBadge("Unsupported wallet request", kind: .indeterminate)
                .accessibilityIdentifier("scanner.result.unsupported")
        case let .rejected(reason):
            OariStatusBadge(reason, kind: .invalid)
                .accessibilityIdentifier("scanner.result.rejected")
        }
    }
}

private enum WalletRequestReviewKind {
    case presentation
    case issuance

    var title: String {
        self == .presentation ? "Presentation request" : "Credential offer"
    }
}

private struct WalletRequestReviewView: View {
    @Environment(\.colorScheme) private var scheme
    let kind: WalletRequestReviewKind
    let source: String

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: OariSpacing.x5) {
                OariStatusBadge("Not verified", kind: .warning)
                    .accessibilityIdentifier("review.not-verified")
                Text(kind.title)
                    .font(OariTypography.title)
                    .accessibilityIdentifier("review.screen")
                OariCard {
                    VStack(alignment: .leading, spacing: OariSpacing.x3) {
                        Label("Review required", systemImage: "exclamationmark.triangle.fill")
                            .font(OariTypography.heading)
                        Text("The code was classified, but requester identity, trust evidence and requested claims have not been verified. No wallet action has been performed.")
                            .font(OariTypography.body)
                        Text(source)
                            .font(OariTypography.technical)
                            .foregroundStyle(OariColor.textSecondary(scheme))
                            .lineLimit(4)
                    }
                }
                Text("Return to Scan to cancel. A continue action is shown only after protocol and trust validation.")
                    .font(OariTypography.body)
                    .foregroundStyle(OariColor.textSecondary(scheme))
            }
            .padding(OariSpacing.x5)
        }
        .background(OariColor.background(scheme))
        .navigationTitle("Review")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct WalletHistoryView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel

    var body: some View {
        NavigationStack {
            List(model.auditEvents) { event in
                VStack(alignment: .leading, spacing: OariSpacing.x2) {
                    Text(event.operation.rawValue.capitalized).font(OariTypography.action)
                    Text(event.outcome.rawValue.capitalized)
                    Text(event.occurredAt, style: .date)
                        .font(OariTypography.technical)
                        .foregroundStyle(OariColor.textSecondary(scheme))
                }
                .accessibilityElement(children: .combine)
            }
            .accessibilityIdentifier("history.list")
            .overlay {
                if model.auditEvents.isEmpty {
                    ContentUnavailableView("No activity", systemImage: "clock", description: Text("Completed wallet actions appear here without credential values."))
                        .accessibilityIdentifier("history.empty")
                }
            }
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme))
            .navigationTitle("History")
        }
    }
}

struct WalletSettingsView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel

    var body: some View {
        NavigationStack {
            Form {
                Section("Appearance") {
                    Picker("Theme", selection: $model.theme) {
                        ForEach(OariTheme.allCases) { theme in
                            Text(theme.rawValue.capitalized).tag(theme)
                        }
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("settings.theme")
                }
                Section("Security") {
                    Label("Private keys stay on this device", systemImage: "lock.shield")
                    Label("Credentials are excluded from backup", systemImage: "externaldrive.badge.xmark")
                    Label("Development build, not certified", systemImage: "exclamationmark.triangle")
                        .accessibilityIdentifier("settings.certification")
                }
            }
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme))
            .navigationTitle("Settings")
        }
    }
}
