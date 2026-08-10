import OariDesignSystem
import EudiWalletKitAdapter
import SwiftUI
import UIKit
import WalletDomain

private extension CredentialStatusState {
    var displayText: String {
        switch self {
        case .valid: "Valid"
        case .suspended: "Suspended"
        case .revoked: "Revoked"
        case .indeterminate: "Status unavailable"
        case .notProvided: "No status mechanism provided"
        case .notEvaluated: "Status not checked"
        }
    }
}

private extension CredentialRecord {
    var cardStatusText: String {
        switch status {
        case .revoked: return "Revoked"
        case .suspended: return "Suspended"
        case .indeterminate: return "Status unavailable"
        case .valid, .notProvided, .notEvaluated: break
        }
        switch issuerTrust {
        case .trusted: return "Trusted issuer"
        case .untrusted: return "Issuer warning"
        case .invalid: return "Invalid issuer"
        case .indeterminate: return "Issuer status unavailable"
        case .notEvaluated: return "Issuer not evaluated"
        }
    }
}

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
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme).ignoresSafeArea())
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
    @Environment(\.colorScheme) private var scheme
    let credential: CredentialRecord
    var body: some View {
        ZStack {
            OariColor.safeColor(credential.display?.backgroundColor, fallback: OariColor.surface(scheme))
            if let image = credential.display?.backgroundImage {
                LocalCredentialImage(image: image, contentMode: .fill)
                    .opacity(0.72)
                LinearGradient(
                    colors: [.black.opacity(0.08), .black.opacity(0.48)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            }
            HStack(spacing: 12) {
                credentialLogo(size: 42)
                VStack(alignment: .leading, spacing: 3) {
                    Text(credential.displayName).font(.body.weight(.semibold)).lineLimit(1)
                    Text(credential.issuerIdentifier).font(.caption).opacity(0.78).lineLimit(1)
                }
                Spacer(minLength: 6)
                VStack(alignment: .trailing, spacing: 4) {
                    if credential.issuerTrust == .untrusted {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.orange)
                            .accessibilityLabel("Development warning")
                    } else {
                        Label(statusText, systemImage: statusIcon)
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 5)
                            .background(.ultraThinMaterial, in: Capsule())
                    }
                    Image(systemName: "chevron.right").font(.caption.weight(.semibold)).opacity(0.7)
                }
                .frame(maxHeight: .infinity, alignment: .topTrailing)
            }
            .padding(12)
        }
        .foregroundStyle(cardTextColor)
        .clipShape(RoundedRectangle(cornerRadius: OariRadius.large, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: OariRadius.large, style: .continuous)
                .stroke(.white.opacity(scheme == .dark ? 0.12 : 0.22))
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(credential.displayName), \(statusText)")
        .accessibilityIdentifier("wallet.credential.row.\(credential.configurationID)")
    }

    @ViewBuilder
    private func credentialLogo(size: CGFloat) -> some View {
        if let logo = credential.display?.logo {
            LocalCredentialImage(image: logo, contentMode: .fit)
                .padding(7)
                .frame(width: size, height: size)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                .accessibilityLabel(logo.alternativeText ?? "Credential logo")
        } else {
            Image(systemName: credential.format == .mdoc ? "person.text.rectangle.fill" : "doc.text.fill")
                .font(.title3)
                .frame(width: size, height: size)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                .accessibilityHidden(true)
        }
    }

    private var cardTextColor: Color {
        OariColor.safeColor(
            credential.display?.textColor,
            fallback: credential.display?.backgroundImage == nil ? OariColor.textPrimary(scheme) : .white
        )
    }

    private var statusText: String {
        credential.cardStatusText
    }

    private var statusIcon: String {
        switch credential.issuerTrust {
        case .trusted: "checkmark.shield.fill"
        case .untrusted: "exclamationmark.triangle.fill"
        case .invalid: "xmark.octagon.fill"
        default: "questionmark.diamond.fill"
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
                    CredentialHeroCard(credential: credential)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }
                Section("Status") {
                    detailRow("Current status", model.documentStatus(for: credential) ?? "Unavailable")
                    detailRow("Credential status", credential.status.displayText)
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
                        .disabled(model.credentialActionIsWorking || !model.canDeleteCredential(credential))
                    if !model.canDeleteCredential(credential) {
                        Label(deletionUnavailableMessage, systemImage: "lock.shield")
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
        .alert("Remove credential?", isPresented: $confirmsDeletion) {
            Button("Remove credential", role: .destructive) {
                Task { await model.deleteSelectedCredential() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(deletionConfirmationMessage)
        }
    }

    private var deletionConfirmationMessage: String {
        if W3CBackendComposition.ownsCredential(backendID: credential.backendID) {
            return "This removes the credential from encrypted W3C storage and Oari Wallet. Face ID or your device passcode will be required."
        }
        return "This removes the credential from Wallet Kit and Oari Wallet. Face ID or your device passcode will be required."
    }

    private var deletionUnavailableMessage: String {
        W3CBackendComposition.ownsCredential(backendID: credential.backendID)
            ? "The encrypted W3C credential reference is unavailable."
            : "Install an approved EUDI profile to manage this credential."
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

private struct CredentialHeroCard: View {
    @Environment(\.colorScheme) private var scheme
    let credential: CredentialRecord

    var body: some View {
        VStack(alignment: .leading, spacing: OariSpacing.x3) {
            HStack(alignment: .top) {
                logo
                Spacer()
                Label(statusLabel, systemImage: statusIcon)
                    .font(.caption.weight(.bold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(.ultraThinMaterial, in: Capsule())
            }
            Spacer(minLength: 20)
            Text(credential.displayName)
                .font(.title2.weight(.bold))
                .lineLimit(3)
                .minimumScaleFactor(0.82)
                .fixedSize(horizontal: false, vertical: true)
                .layoutPriority(1)
            Text(issuerLabel)
                .font(.caption)
                .opacity(0.82)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                OariBackendBadge(W3CBackendComposition.ownsCredential(backendID: credential.backendID) ? "W3C Verifiable Credential" : "EUDI Wallet Kit")
                Text(credential.format.rawValue)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(.ultraThinMaterial, in: Capsule())
            }
        }
        .padding(OariSpacing.x5)
        .foregroundStyle(textColor)
        .frame(maxWidth: .infinity, minHeight: 260, alignment: .bottomLeading)
        .background { artworkBackground }
        .clipShape(RoundedRectangle(cornerRadius: OariRadius.extraLarge, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: OariRadius.extraLarge, style: .continuous)
                .stroke(.white.opacity(scheme == .dark ? 0.12 : 0.25))
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(credential.displayName), issued by \(credential.issuerIdentifier), \(statusLabel)")
    }

    @ViewBuilder private var artworkBackground: some View {
        ZStack {
            OariColor.safeColor(
                credential.display?.backgroundColor,
                fallback: OariColor.action.opacity(0.13)
            )
            if let background = credential.display?.backgroundImage {
                GeometryReader { geometry in
                    LocalCredentialImage(image: background, contentMode: .fill)
                        .frame(width: geometry.size.width, height: geometry.size.height)
                        .clipped()
                }
                LinearGradient(
                    colors: [.black.opacity(0.02), .black.opacity(0.62)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            }
        }
    }

    @ViewBuilder private var logo: some View {
        if let image = credential.display?.logo {
            LocalCredentialImage(image: image, contentMode: .fit)
                .padding(9)
                .frame(width: 58, height: 58)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                .accessibilityLabel(image.alternativeText ?? "Credential logo")
        } else {
            Image(systemName: credential.format == .mdoc ? "person.text.rectangle.fill" : "doc.text.fill")
                .font(.title2)
                .frame(width: 58, height: 58)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                .accessibilityHidden(true)
        }
    }

    private var textColor: Color {
        OariColor.safeColor(
            credential.display?.textColor,
            fallback: credential.display?.backgroundImage == nil ? OariColor.textPrimary(scheme) : .white
        )
    }

    private var issuerLabel: String {
        if let url = URL(string: credential.issuerIdentifier), let host = url.host {
            return host
        }
        guard credential.issuerIdentifier.count > 52 else { return credential.issuerIdentifier }
        return "\(credential.issuerIdentifier.prefix(36))...\(credential.issuerIdentifier.suffix(10))"
    }

    private var statusLabel: String {
        credential.cardStatusText
    }

    private var statusIcon: String {
        switch credential.issuerTrust {
        case .trusted: "checkmark.shield.fill"
        case .untrusted: "exclamationmark.triangle.fill"
        case .invalid: "xmark.octagon.fill"
        default: "questionmark.diamond.fill"
        }
    }
}

private struct LocalCredentialImage: View {
    let image: CredentialDisplayImage
    let contentMode: ContentMode

    var body: some View {
        if let uiImage = UIImage(data: image.data) {
            Image(uiImage: uiImage)
                .resizable()
                .aspectRatio(contentMode: contentMode)
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
                            .keyboardType(.URL)
                            .padding(OariSpacing.x4)
                            .background(OariColor.surfaceInset(scheme))
                            .clipShape(RoundedRectangle(cornerRadius: OariRadius.medium))
                            .accessibilityLabel("Wallet code")
                            .accessibilityIdentifier("scanner.input")
                            .focused($inputFocused)
                            .onSubmit { inputFocused = false }
                        Button("Redeem") {
                            inputFocused = false
                            Task { await model.reviewScannedRequest() }
                        }
                        .buttonStyle(OariPrimaryButtonStyle())
                        .disabled(model.scanInput.isEmpty)
                        .accessibilityIdentifier("scanner.redeem")
                        Button {
                            inputFocused = false
                            isCameraPresented = true
                        } label: {
                            Label("Scan QR code", systemImage: "qrcode.viewfinder")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(OariSecondaryButtonStyle())
                        .accessibilityIdentifier("scanner.camera")
                    }
                }
                .onTapGesture { inputFocused = false }
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
                ScanResultView(result: model.scanResult)
            }
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("Scan")
            .fullScreenCover(isPresented: $isCameraPresented) {
                CameraQRScannerSheet(onCode: model.handleScannedCode)
            }
        }
    }
}

private struct ScanResultView: View {
    let result: WalletAppModel.ScanResult

    var body: some View {
        switch result {
        case .idle: EmptyView()
        case .presentation:
            detectedRequest("Presentation request detected", icon: "person.badge.shield.checkmark")
                .accessibilityIdentifier("scanner.result.presentation")
        case .issuance:
            detectedRequest("Credential offer detected", icon: "person.text.rectangle")
                .accessibilityIdentifier("scanner.result.issuance")
        case .unsupported:
            OariStatusBadge("Unsupported wallet request", kind: .indeterminate)
                .accessibilityIdentifier("scanner.result.unsupported")
        case let .rejected(reason):
            OariStatusBadge(reason, kind: .invalid)
                .accessibilityIdentifier("scanner.result.rejected")
        }
    }

    private func detectedRequest(_ title: String, icon: String) -> some View {
        Label(title, systemImage: icon)
            .font(OariTypography.label)
            .foregroundStyle(OariColor.action)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, OariSpacing.x3)
            .padding(.vertical, OariSpacing.x2)
            .background(OariColor.action.opacity(0.08), in: RoundedRectangle(cornerRadius: OariRadius.medium))
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
                if model.isAuditHistoryLoading {
                    ProgressView("Loading activity…")
                } else if model.auditEvents.isEmpty {
                    ContentUnavailableView("No activity", systemImage: "clock", description: Text("Completed wallet actions appear here without credential values."))
                        .accessibilityIdentifier("history.empty")
                }
            }
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme))
            .navigationTitle("History")
        }
        .task { await model.loadAuditHistoryIfNeeded() }
    }
}

struct WalletSettingsView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    private let sourceURL = URL(string: "https://github.com/oaripay/eudi-wallet")!

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
                    Toggle("App Lock", isOn: Binding(
                        get: { model.isAppLockEnabled },
                        set: { value in Task { await model.configureAppLock(enabled: value) } }
                    ))
                    .disabled(model.appLockState == .authenticating)
                    .accessibilityIdentifier("settings.app-lock")
                    LabeledContent("Authentication", value: model.appLockAuthenticationName)
                    if model.isAppLockEnabled {
                        Text("Required when the wallet returns from the background. Device passcode remains available as a fallback.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    LabeledContent("Private keys", value: "On this device")
                    LabeledContent("Credential backup", value: "Excluded")
                }
                Section("Wallet environments") {
                    NavigationLink {
                        EudiReferenceDemoSettingsView(availability: model.eudiAvailability)
                    } label: {
                        WalletEnvironmentRow(
                            title: "EUDI Reference Demo",
                            subtitle: "Official reference services",
                            icon: "person.text.rectangle",
                            status: model.eudiAvailability.isAvailable ? "Interop" : "Unavailable",
                            statusColor: model.eudiAvailability.isAvailable ? .orange : .red
                        )
                    }
                    .accessibilityIdentifier("settings.eudi")

                    NavigationLink {
                        EbsiOpenID4VCSettingsView()
                    } label: {
                        WalletEnvironmentRow(
                            title: "EBSI / OpenID4VC",
                            subtitle: "W3C credential backend",
                            icon: "network.badge.shield.half.filled",
                            status: "Interop",
                            statusColor: .orange
                        )
                    }
                    .accessibilityIdentifier("settings.ebsi")
                    Text("Interoperability environments, not certified")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("settings.certification")
                }
                Section("About") {
                    LabeledContent("Oari Wallet", value: appVersion)
                        .accessibilityIdentifier("settings.version")
                    Link(destination: sourceURL) {
                        Label("Open Source", systemImage: "chevron.left.forwardslash.chevron.right")
                    }
                    .accessibilityIdentifier("settings.opensource")
                }
            }
            .scrollContentBackground(.hidden)
            .background(OariColor.background(scheme))
            .navigationTitle("Settings")
        }
    }

    private var appVersion: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "-"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "-"
        return "\(version) (\(build))"
    }
}

private extension EudiWalletAvailability {
    var isAvailable: Bool {
        if case .available = self { return true }
        return false
    }
}

private struct WalletEnvironmentRow: View {
    let title: String
    let subtitle: String
    let icon: String
    let status: String
    let statusColor: Color

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(OariColor.action)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Text(status)
                .font(.caption.weight(.semibold))
                .foregroundStyle(statusColor)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(statusColor.opacity(0.12), in: Capsule())
        }
    }
}

private struct EudiReferenceDemoSettingsView: View {
    @Environment(\.colorScheme) private var scheme
    let availability: EudiWalletAvailability

    var body: some View {
        Form {
            Section {
                OariCard {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Interoperability environment").font(.headline)
                            Text("Uses official EUDI reference services and development trust infrastructure. It is not a production identity environment.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }
            Section("Status") {
                LabeledContent("Environment", value: "Reference Demo")
                LabeledContent("Wallet Kit", value: EudiWalletKitBaseline.selectedVersion)
                LabeledContent("Trust policy", value: "Warning")
                LabeledContent("Signed metadata", value: "Required")
                LabeledContent("Unregistered parties", value: "Allowed")
                LabeledContent("Availability", value: availability.isAvailable ? "Available" : "Unavailable")
            }
            Section("Services") {
                TechnicalValueRow("Issuer", value: "issuer.eudiw.dev")
                TechnicalValueRow("Backend issuer", value: "issuer-backend.eudiw.dev")
                TechnicalValueRow("Wallet Provider", value: EudiReferenceDemoConfiguration.walletProviderURL.host ?? "-")
                TechnicalValueRow("Verifier", value: EudiReferenceDemoConfiguration.verifierURL.host ?? "-")
            }
            Section("Protocol") {
                TechnicalValueRow("Client ID", value: EudiReferenceDemoConfiguration.clientID)
                TechnicalValueRow("Callback", value: EudiReferenceDemoConfiguration.redirectURI.absoluteString)
                LabeledContent("PAR", value: "Required")
                LabeledContent("DPoP", value: "Required")
            }
        }
        .scrollContentBackground(.hidden)
        .background(OariColor.background(scheme))
        .navigationTitle("EUDI Reference Demo")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct EbsiOpenID4VCSettingsView: View {
    @Environment(\.colorScheme) private var scheme
    private let composition = try? W3CBackendComposition.make()

    var body: some View {
        Form {
            Section {
                OariCard {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Standards interoperability").font(.headline)
                            Text("Uses pinned EBSI registries with cryptographic verification and explicit warnings when signer accreditation is unavailable.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: "network.badge.shield.half.filled").foregroundStyle(OariColor.action)
                    }
                }
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            }
            Section("Status") {
                LabeledContent("Environment", value: composition?.environmentPolicy == .production ? "Production registries" : "Unavailable")
                LabeledContent("Unknown signer", value: "Warning")
                LabeledContent("Signature checks", value: "Required")
                LabeledContent("Transport", value: W3CBackendComposition.issuanceProfiles)
            }
            Section("Registries") {
                TechnicalValueRow("DID Registry", value: composition?.endpoint.didRegistryURL.absoluteString ?? "Unavailable")
                TechnicalValueRow("Trusted Issuers", value: composition?.endpoint.trustedIssuersRegistryURL.absoluteString ?? "Unavailable")
                TechnicalValueRow("Trusted Schemas", value: composition?.endpoint.trustedSchemasRegistryURL.absoluteString ?? "Unavailable")
            }
            Section("OpenID4VC") {
                TechnicalValueRow("Client ID", value: W3CBackendComposition.authorizationClientID)
                TechnicalValueRow("Callback", value: W3CBackendComposition.authorizationRedirectURI.absoluteString)
                LabeledContent("Credentials", value: W3CBackendComposition.credentialModels)
                LabeledContent("Presentation", value: W3CBackendComposition.presentationProfile)
            }
        }
        .scrollContentBackground(.hidden)
        .background(OariColor.background(scheme))
        .navigationTitle("EBSI / OpenID4VC")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct TechnicalValueRow: View {
    let label: String
    let value: String

    init(_ label: String, value: String) {
        self.label = label
        self.value = value
    }

    var body: some View {
        LabeledContent(label) {
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
        }
        .contextMenu { Button("Copy") { UIPasteboard.general.string = value } }
    }
}

struct WalletOnboardingView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel

    var body: some View {
        NavigationStack {
            OariScreen {
                VStack(spacing: OariSpacing.x4) {
                    Image("OariMark")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 92, height: 92)
                        .accessibilityHidden(true)

                    VStack(spacing: OariSpacing.x2) {
                        Text("Oari Digital Credentials Wallet")
                            .font(OariTypography.title)
                            .multilineTextAlignment(.center)
                        Text("Store and share digital credentials with clear consent every time.")
                            .font(OariTypography.body)
                            .foregroundStyle(OariColor.textSecondary(scheme))
                            .multilineTextAlignment(.center)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, OariSpacing.x3)

                OariCard {
                    VStack(alignment: .leading, spacing: OariSpacing.x4) {
                        onboardingRow("You approve every share", icon: "checkmark.shield.fill")
                        onboardingRow("Private keys stay on this device", icon: "key.fill")
                        onboardingRow("Trusted connections are checked", icon: "network.badge.shield.half.filled")
                    }
                }

                if case let .configurationRequired(message) = model.eudiAvailability {
                    OariCard {
                        HStack(alignment: .top, spacing: OariSpacing.x3) {
                            Image(systemName: "wrench.and.screwdriver.fill")
                                .foregroundStyle(.orange)
                            VStack(alignment: .leading, spacing: OariSpacing.x2) {
                                Text("Wallet profile required")
                                    .font(OariTypography.heading)
                                Text(message)
                                    .font(.caption)
                                    .foregroundStyle(OariColor.textSecondary(scheme))
                            }
                        }
                    }
                }

                OariCard {
                    VStack(alignment: .leading, spacing: OariSpacing.x4) {
                        HStack(spacing: OariSpacing.x3) {
                            Image(systemName: model.appLockAuthenticationIcon)
                                .font(.title2)
                                .foregroundStyle(OariColor.action)
                                .frame(width: 36)
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Protect your wallet")
                                    .font(OariTypography.heading)
                                Text("Unlock with \(model.appLockAuthenticationName), with device passcode fallback.")
                                    .font(.caption)
                                    .foregroundStyle(OariColor.textSecondary(scheme))
                            }
                        }

                        if let error = model.appLockSetupError {
                            Text(error)
                                .font(.caption)
                                .foregroundStyle(.red)
                        }

                        if model.hasCompletedAppLockSetup {
                            Button("Continue to wallet") { model.completeOnboarding() }
                                .buttonStyle(OariPrimaryButtonStyle())
                                .accessibilityIdentifier("onboarding.continue")
                        } else {
                            Button("Continue with \(model.appLockAuthenticationName)") {
                                Task {
                                    await model.configureAppLock(enabled: true)
                                    if model.isAppLockEnabled { model.completeOnboarding() }
                                }
                            }
                            .buttonStyle(OariPrimaryButtonStyle())
                            .disabled(
                                model.appLockAuthenticationKind == .unavailable ||
                                    model.appLockState == .authenticating
                            )
                            .accessibilityIdentifier("onboarding.app-lock.enable")

                            Button("Continue without App Lock") {
                                model.declineAppLockSetup()
                                model.completeOnboarding()
                            }
                            .frame(maxWidth: .infinity)
                            .buttonStyle(.plain)
                            .disabled(model.appLockState == .authenticating)
                            .accessibilityIdentifier("onboarding.app-lock.skip")
                        }
                    }
                }
            }
            .navigationBarHidden(true)
        }
    }

    private func onboardingRow(_ text: String, icon: String) -> some View {
        Label {
            Text(text).font(OariTypography.body)
        } icon: {
            Image(systemName: icon)
                .foregroundStyle(OariColor.action)
                .frame(width: 24)
        }
    }
}

struct WalletAppLockSetupView: View {
    @Environment(\.colorScheme) private var scheme
    @ObservedObject var model: WalletAppModel
    let allowsDismissal: Bool

    var body: some View {
        VStack(spacing: OariSpacing.x4) {
            Image(systemName: model.appLockAuthenticationIcon)
                .font(.system(size: 42, weight: .medium))
                .foregroundStyle(OariColor.action)
            Text("Protect Oari Wallet")
                .font(OariTypography.heading)
            Text("Use \(model.appLockAuthenticationName) whenever you open the wallet. Your device passcode remains available as a secure fallback.")
                .multilineTextAlignment(.center)
                .foregroundStyle(OariColor.textSecondary(scheme))
            if let error = model.appLockSetupError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }
            if model.hasCompletedAppLockSetup {
                Label(
                    model.isAppLockEnabled ? "App Lock is enabled" : "App Lock setup skipped",
                    systemImage: model.isAppLockEnabled ? "checkmark.shield.fill" : "shield.slash"
                )
                .foregroundStyle(model.isAppLockEnabled ? .green : .secondary)
            } else {
                Button("Set Up \(model.appLockAuthenticationName)") {
                    Task { await model.configureAppLock(enabled: true) }
                }
                .buttonStyle(OariPrimaryButtonStyle())
                .disabled(model.appLockAuthenticationKind == .unavailable || model.appLockState == .authenticating)

                Button("Not Now") { model.declineAppLockSetup() }
                    .buttonStyle(.plain)
                    .disabled(model.appLockState == .authenticating)
            }
        }
        .padding(OariSpacing.x5)
        .frame(maxWidth: .infinity)
        .background(OariColor.background(scheme))
        .accessibilityElement(children: .contain)
    }
}
