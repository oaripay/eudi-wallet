import OariDesignSystem
import SwiftUI
import WalletDomain

struct WalletVaultView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    @State private var searchText = ""
    @State private var filter: CredentialFilter = .all

    private enum CredentialFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case valid = "Valid"
        case pending = "Pending"
        case warnings = "Warnings"
        var id: String { rawValue }
    }

    var body: some View {
        NavigationStack {
            List {
                if case let .failed(message) = model.loadingState {
                    Section {
                        Label("Wallet services unavailable", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                        Text(message).font(.caption).foregroundStyle(.secondary)
                    }
                    .accessibilityIdentifier("wallet.storage-error")
                }
                if model.credentials.isEmpty {
                    ContentUnavailableView(
                        "Your wallet is empty",
                        systemImage: "wallet.pass",
                        description: Text("Scan a credential offer to add your first credential.")
                    )
                    .listRowBackground(Color.clear)
                } else {
                    Section {
                        ForEach(filteredCredentials) { credential in
                            Button { model.selectCredential(credential) } label: {
                                CredentialListRow(credential: credential)
                            }
                            .buttonStyle(.plain)
                        }
                    } header: {
                        HStack {
                            Text("Credentials")
                            Spacer()
                            Text("\(filteredCredentials.count)").foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .searchable(text: $searchText, prompt: "Search credentials")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Picker("Filter", selection: $filter) {
                            ForEach(CredentialFilter.allCases) { Text($0.rawValue).tag($0) }
                        }
                    } label: { Image(systemName: "line.3.horizontal.decrease.circle") }
                    .accessibilityLabel("Filter credentials")
                }
            }
            .navigationTitle("Wallet")
        }
        .sheet(item: $model.selectedCredential) { credential in
            CredentialDetailView(model: model, credential: credential)
                .presentationDetents([.medium, .large])
        }
    }

    private var filteredCredentials: [CredentialRecord] {
        model.credentials.filter { credential in
            let matchesSearch = searchText.isEmpty || [credential.displayName, credential.issuerIdentifier, credential.profileID, credential.format.rawValue]
                .contains { $0.localizedCaseInsensitiveContains(searchText) }
            let matchesFilter: Bool
            switch filter {
            case .all: matchesFilter = true
            case .valid: matchesFilter = credential.status == .valid
            case .pending: matchesFilter = model.documentStatus(for: credential) == "pending" || model.documentStatus(for: credential) == "deferred"
            case .warnings: matchesFilter = credential.issuerTrust != .trusted || credential.status == .indeterminate
            }
            return matchesSearch && matchesFilter
        }
    }
}

private struct CredentialListRow: View {
    let credential: CredentialRecord
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: credential.format == .mdoc ? "person.text.rectangle.fill" : "doc.text.fill")
                .font(.title3).foregroundStyle(.tint)
                .frame(width: 38, height: 38)
                .background(Color.accentColor.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 3) {
                Text(credential.displayName).font(.body.weight(.semibold)).lineLimit(1)
                Text(credential.issuerIdentifier).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 6)
            VStack(alignment: .trailing, spacing: 3) {
                Text(statusText).font(.caption.weight(.medium)).foregroundStyle(statusColor)
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 5)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(credential.displayName), \(statusText)")
        .accessibilityIdentifier("wallet.credential.row.\(credential.configurationID)")
    }

    private var statusText: String {
        switch credential.issuerTrust {
        case .trusted: credential.status == .valid ? "Valid" : credential.status.rawValue
        case .untrusted: "Development warning"
        default: credential.status.rawValue
        }
    }

    private var statusColor: Color {
        switch credential.issuerTrust {
        case .trusted: .green
        case .untrusted: .orange
        default: .secondary
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
            List {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(credential.displayName).font(.title3.weight(.semibold))
                        Text(credential.issuerIdentifier)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        HStack(spacing: 6) {
                            OariBackendBadge(credential.backendID == "oari-workspace-w3c" ? "Workspace W3C" : "EUDI Wallet Kit")
                            OariStatusBadge(credential.format.rawValue, kind: .indeterminate)
                        }
                    }
                    .padding(.vertical, 4)
                }
                Section("Status") {
                    detailRow("Current status", model.documentStatus(for: credential) ?? "Unavailable")
                    detailRow("Credential status", credential.status.rawValue)
                    detailRow("Issuer trust", credential.issuerTrust.rawValue)
                    if let issuedAt = credential.issuedAt { detailRow("Issued", issuedAt.formatted(date: .abbreviated, time: .omitted)) }
                    if let expiresAt = credential.expiresAt { detailRow("Expires", expiresAt.formatted(date: .abbreviated, time: .omitted)) }
                }
                Section("Credential") {
                    detailRow("Format", credential.format.rawValue)
                    detailRow("Profile", credential.profileID)
                    detailRow("Legal profile", credential.legalClassification.rawValue)
                    NavigationLink("Technical details") {
                        technicalDetails
                    }
                }
                if !credential.displayClaims.isEmpty {
                    Section("Claims") {
                        ForEach(credential.displayClaims) { claim in
                            LabeledContent(claim.label, value: claim.value)
                        }
                    }
                }
                Section("Actions") {
                    if model.documentStatus(for: credential) == "deferred" {
                        Button {
                            Task { await model.retrySelectedDeferredCredential() }
                        } label: {
                            Label("Check deferred issuance", systemImage: "arrow.clockwise")
                        }
                        .disabled(model.credentialActionIsWorking || !model.isEudiOperational)
                    }
                    Button("Remove credential", role: .destructive) { confirmsDeletion = true }
                        .disabled(model.credentialActionIsWorking || !model.isEudiOperational)
                    if !model.isEudiOperational {
                        Label("Install an approved EUDI profile to manage this credential.", systemImage: "lock.shield")
                            .font(.caption)
                            .foregroundStyle(OariColor.textSecondary(scheme))
                            .accessibilityIdentifier("credential.operationsUnavailable")
                    }
                }
                if model.credentialActionState != .idle {
                    Section { actionStatus }
                }
            }
            .listStyle(.insetGrouped)
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

    private func detailRow(_ label: String, _ value: String) -> some View {
        LabeledContent(label) { Text(value).foregroundStyle(.secondary).multilineTextAlignment(.trailing) }
    }

    private var technicalDetails: some View {
        List {
            Section("Identifiers") {
                detailRow("Issuer", credential.issuerIdentifier)
                detailRow("Backend document", credential.backendDocumentID ?? credential.walletDocumentID ?? "Unavailable")
                detailRow("Wallet document", credential.walletDocumentID ?? "Unavailable")
            }
            Section("Processing") {
                detailRow("Backend", credential.backendID ?? "EUDI Wallet Kit")
                detailRow("Configuration", credential.configurationID)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Technical details")
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
    @FocusState private var inputFocused: Bool

    var body: some View {
        NavigationStack {
            OariScreen {
                OariCard {
                    VStack(alignment: .leading, spacing: OariSpacing.x4) {
                        Label("Scan or paste a wallet code", systemImage: "qrcode.viewfinder")
                            .font(OariTypography.heading)
                        TextField("Credential offer or presentation URL", text: $model.scanInput, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .padding(OariSpacing.x4)
                            .background(OariColor.surfaceInset(scheme))
                            .clipShape(RoundedRectangle(cornerRadius: OariRadius.medium))
                            .accessibilityLabel("Wallet code")
                            .accessibilityIdentifier("scanner.input")
                            .focused($inputFocused)
                            .submitLabel(.done)
                            .onSubmit { inputFocused = false }
                        Button("Redeem") {
                            inputFocused = false
                            Task { await model.redeemScannedRequest() }
                        }
                        .buttonStyle(OariPrimaryButtonStyle())
                        .disabled(model.scanInput.isEmpty)
                        .accessibilityIdentifier("scanner.redeem")
                        Button {
                            isCameraPresented = true
                        } label: {
                            Label("Scan QR code", systemImage: "qrcode.viewfinder")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(OariSecondaryButtonStyle())
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
            }
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { inputFocused = false }
                }
            }
            .navigationTitle("Scan")
            .fullScreenCover(isPresented: $isCameraPresented) {
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
        OariScreen {
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
                Text("Return to Scan to cancel. A continue action appears only after protocol validation.")
                    .font(OariTypography.body)
                    .foregroundStyle(OariColor.textSecondary(scheme))
        }
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
            OariScreen {
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
        }
    }

    private func onboardingRow(_ text: String, icon: String) -> some View {
        Label(text, systemImage: icon).font(OariTypography.body)
    }
}
