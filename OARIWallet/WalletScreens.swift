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
                            Button { model.selectCredential(credential) } label: {
                                CredentialTile(credential: credential)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .padding(OariSpacing.x5)
            }
            .background(OariColor.background(scheme))
            .navigationTitle("Wallet")
        }
        .sheet(item: $model.selectedCredential) { credential in
            CredentialDetailView(model: model, credential: credential)
                .presentationDetents([.medium, .large])
        }
    }
}

private struct CredentialDetailView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    let credential: CredentialRecord
    @State private var confirmsDeletion = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: OariSpacing.x5) {
                    Text(credential.displayName).font(OariTypography.title)
                    OariCard {
                        detail("Issuer", credential.issuerIdentifier)
                        detail("Format", credential.format.rawValue)
                        detail("Document state", model.documentStatus(for: credential) ?? "Unavailable")
                        detail("Credential status", credential.status.rawValue)
                        detail("Issuer trust", credential.issuerTrust.rawValue)
                        detail("Legal profile", credential.legalClassification.rawValue)
                        if let issuedAt = credential.issuedAt { detail("Issued", issuedAt.formatted()) }
                        if let expiresAt = credential.expiresAt { detail("Expires", expiresAt.formatted()) }
                    }
                    if model.documentStatus(for: credential) == "deferred" {
                        Button("Check deferred issuance") {
                            Task { await model.retrySelectedDeferredCredential() }
                        }
                        .buttonStyle(OariPrimaryButtonStyle())
                        .disabled(model.credentialActionIsWorking || !model.isEudiOperational)
                    }
                    Button("Remove credential", role: .destructive) { confirmsDeletion = true }
                        .frame(maxWidth: .infinity)
                        .disabled(model.credentialActionIsWorking || !model.isEudiOperational)
                    if !model.isEudiOperational {
                        Label("Install an approved EUDI profile to manage this credential.", systemImage: "lock.shield")
                            .font(.caption)
                            .foregroundStyle(OariColor.textSecondary(scheme))
                            .accessibilityIdentifier("credential.operationsUnavailable")
                    }
                    actionStatus
                }
                .padding(OariSpacing.x5)
            }
            .background(OariColor.background(scheme).ignoresSafeArea())
            .navigationTitle("Credential details")
            .navigationBarTitleDisplayMode(.inline)
        }
        .confirmationDialog(
            "Remove this credential from Wallet Kit and OARI metadata?",
            isPresented: $confirmsDeletion,
            titleVisibility: .visible
        ) {
            Button("Remove credential", role: .destructive) {
                Task { await model.deleteSelectedCredential() }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private func detail(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: OariSpacing.x1) {
            Text(label).font(.caption).foregroundStyle(OariColor.textSecondary(scheme))
            Text(value).font(OariTypography.body).textSelection(.enabled)
        }
        .padding(.vertical, OariSpacing.x1)
    }

    @ViewBuilder
    private var actionStatus: some View {
        switch model.credentialActionState {
        case .idle: EmptyView()
        case let .working(message): ProgressView(message)
        case let .completed(message):
            Label(message, systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            Button("Done") { model.acknowledgeCredentialAction() }
                .buttonStyle(OariPrimaryButtonStyle())
        case let .failed(message):
            Label(message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Button("Dismiss") { model.dismissCredentialAction() }
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
                            if model.isEudiOperational {
                                Task { await model.reviewScannedRequest() }
                            } else {
                                model.classifyScan()
                            }
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
                if case let .configurationRequired(message) = model.eudiFlow {
                    OariCard {
                        VStack(alignment: .leading, spacing: OariSpacing.x3) {
                            Label("Wallet setup required", systemImage: "wrench.and.screwdriver.fill")
                                .font(OariTypography.heading)
                            Text(message).foregroundStyle(OariColor.textSecondary(scheme))
                            Text("Credential operations remain disabled until an approved trust and attestation profile is installed.")
                                .font(.caption)
                                .foregroundStyle(OariColor.textSecondary(scheme))
                        }
                    }
                    .accessibilityIdentifier("scanner.configurationRequired")
                }
                if model.hasRecoverablePendingIssuance {
                    OariCard {
                        VStack(alignment: .leading, spacing: OariSpacing.x3) {
                            Label("Pending credential", systemImage: "hourglass.circle.fill")
                                .font(OariTypography.heading)
                            Text("Identity verification is still required before the issuer can finish this credential.")
                                .foregroundStyle(OariColor.textSecondary(scheme))
                            Button("Continue pending credential") {
                                model.returnToPendingIssuance()
                            }
                            .buttonStyle(OariPrimaryButtonStyle())
                        }
                    }
                    .accessibilityIdentifier("scanner.pendingCredential")
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
                Section("EUDI profile") {
                    switch model.eudiAvailability {
                    case .available:
                        Label("Approved EUDI profile installed", systemImage: "checkmark.shield.fill")
                            .foregroundStyle(.green)
                    case let .configurationRequired(message):
                        Label("Profile installation required", systemImage: "exclamationmark.shield.fill")
                            .foregroundStyle(.orange)
                        Text(message).font(.caption).foregroundStyle(.secondary)
                    }
                    LabeledContent("Callback domain", value: "oari.io")
                    LabeledContent("Wallet backend", value: "EUDI Wallet Kit 0.39.1")
                }
            }
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme))
            .navigationTitle("Settings")
        }
    }
}

struct WalletOnboardingView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: OariSpacing.x6) {
                    Image(systemName: "wallet.pass.fill")
                        .font(.system(size: 56)).foregroundStyle(OariColor.action)
                    Text("Your EUDI wallet").font(OariTypography.title)
                    Text("OARI uses the EUDI Wallet Kit for PID, SD-JWT, mdoc, issuance, presentation and device-bound keys.")
                        .font(OariTypography.body)
                    onboardingRow("You approve every disclosure", icon: "checkmark.shield")
                    onboardingRow("Private keys stay under Wallet Kit secure storage", icon: "key.fill")
                    onboardingRow("Only approved issuer and verifier profiles can connect", icon: "network.badge.shield.half.filled")
                    OariCard {
                        VStack(alignment: .leading, spacing: OariSpacing.x3) {
                            Label("Environment setup", systemImage: "wrench.and.screwdriver.fill")
                                .font(OariTypography.heading)
                            switch model.eudiAvailability {
                            case .available:
                                Text("An approved EUDI profile is installed.")
                            case let .configurationRequired(message):
                                Text(message)
                                Text("Credential operations remain disabled until deployment installs trust anchors, issuer/verifier origins and an attestation provider.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    Button("Continue to wallet") { model.completeOnboarding() }
                        .buttonStyle(OariPrimaryButtonStyle())
                        .accessibilityIdentifier("onboarding.continue")
                }
                .padding(OariSpacing.x6)
            }
            .background(OariColor.background(scheme).ignoresSafeArea())
        }
    }

    private func onboardingRow(_ text: String, icon: String) -> some View {
        Label(text, systemImage: icon).font(OariTypography.body)
    }
}
