import OariDesignSystem
import SwiftUI

struct EudiFlowView: View {
    @ObservedObject var model: WalletAppModel
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: OariSpacing.x5) {
                    content
                }
                .padding(OariSpacing.x5)
            }
            .background(OariColor.background(scheme).ignoresSafeArea())
            .navigationTitle("Wallet request")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.eudiFlow {
        case let .working(message):
            VStack(spacing: OariSpacing.x4) {
                ProgressView()
                Text(message).font(OariTypography.heading).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, minHeight: 220)

        case let .issuanceReview(offer):
            Label("Credential offer", systemImage: "person.text.rectangle")
                .font(OariTypography.heading)
            Text(offer.issuerName).foregroundStyle(OariColor.textSecondary(scheme))
            ForEach(offer.documents, id: \.configurationID) { document in
                Toggle(isOn: Binding(
                    get: { model.selectedIssuanceConfigurationIDs.contains(document.configurationID) },
                    set: { selected in
                        if selected { model.selectedIssuanceConfigurationIDs.insert(document.configurationID) }
                        else { model.selectedIssuanceConfigurationIDs.remove(document.configurationID) }
                    }
                )) {
                    VStack(alignment: .leading) {
                        Text(document.displayName).font(.headline)
                        Text(document.documentType).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if offer.transactionCode != nil {
                SecureField("Transaction code", text: $model.transactionCode)
                    .textContentType(.oneTimeCode)
                    .keyboardType(offer.transactionCode?.inputMode == "numeric" ? .numberPad : .asciiCapable)
                    .textFieldStyle(.roundedBorder)
            }
            primaryButton("Add to wallet", icon: "plus.circle.fill") {
                await model.acceptIssuance()
            }

        case let .ebsiIssuanceReview(interaction):
            Label("EBSI development credential", systemImage: "network.badge.shield.half.filled")
                .font(OariTypography.heading)
            Text(interaction.displayName ?? interaction.counterpartyIdentifier)
                .foregroundStyle(OariColor.textSecondary(scheme))
            ForEach(interaction.configurationIDs, id: \.self) { Text($0).font(.caption) }
            if interaction.transactionCodeRequired {
                SecureField("Transaction code", text: $model.ebsiTransactionCode)
                    .textContentType(.oneTimeCode)
                    .keyboardType(.numberPad)
                    .textFieldStyle(.roundedBorder)
            }
            primaryButton("Issue and store credential", icon: "plus.circle.fill") {
                await model.issueReviewedEbsiCredential()
            }
            Button("Cancel") { Task { await model.cancelEbsiTrustWarning() } }
                .frame(maxWidth: .infinity)

        case let .ebsiPresentationRequired(challenge):
            Label("Present your PID", systemImage: "person.badge.shield.checkmark")
                .font(OariTypography.heading)
            Text("The issuer requires an OpenID4VP presentation before it can issue this W3C credential.")
            Text("DCQL request: \(challenge.dcqlQuery.keys.sorted().joined(separator: ", "))")
                .font(.caption).foregroundStyle(.secondary)
            primaryButton("Review PID claims", icon: "person.text.rectangle") {
                await model.startEudiPresentationForEbsi(challenge)
            }

        case let .presentationConsent(request):
            Label("Share identity information", systemImage: "person.badge.shield.checkmark")
                .font(OariTypography.heading)
            Text(request.verifierLegalName ?? request.verifierName ?? "Unknown verifier")
                .font(.headline)
            if request.verifierCertificateValid == false {
                Label("Verifier certificate was not validated", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            ForEach(request.claims, id: \.id) { claim in
                Toggle(isOn: Binding(
                    get: { model.selectedClaimIDs.contains(claim.id) },
                    set: { selected in
                        guard !claim.required || selected else { return }
                        if selected { model.selectedClaimIDs.insert(claim.id) }
                        else { model.selectedClaimIDs.remove(claim.id) }
                    }
                )) {
                    VStack(alignment: .leading) {
                        Text(claim.claimPath.last ?? "Claim")
                        Text(claim.displayValue ?? "Value hidden").font(.caption).foregroundStyle(.secondary)
                        if claim.required { Text("Required").font(.caption2).foregroundStyle(.secondary) }
                    }
                }
                .disabled(claim.required)
            }
            primaryButton("Approve and continue", icon: "checkmark.shield.fill") {
                await model.submitPresentation(accepted: true)
            }
            Button("Decline") { Task { await model.submitPresentation(accepted: false) } }
                .frame(maxWidth: .infinity)

        case let .pending(pending):
            Label("Identity verification required", systemImage: "hourglass.circle")
                .font(OariTypography.heading)
            Text(pending.document.displayName ?? pending.document.documentType).font(.headline)
            Text("The issuer needs a PID presentation before issuing this credential. You will review every requested claim before anything is shared.")
                .foregroundStyle(OariColor.textSecondary(scheme))
            primaryButton("Review PID request", icon: "person.badge.shield.checkmark") {
                await model.continuePendingIssuance()
            }

        case let .completed(message):
            Label("Completed", systemImage: "checkmark.circle.fill")
                .font(OariTypography.heading).foregroundStyle(.green)
            Text(message)
            Button("Done") { model.dismissEudiFlow() }
                .buttonStyle(OariPrimaryButtonStyle())

        case let .failed(message):
            Label("Request stopped", systemImage: "xmark.shield.fill")
                .font(OariTypography.heading).foregroundStyle(.red)
            Text(message)
            Text("No unapproved data was shared.").font(.caption).foregroundStyle(.secondary)
            if model.hasRecoverablePendingIssuance {
                Button("Return to pending credential") { model.returnToPendingIssuance() }
                    .buttonStyle(OariPrimaryButtonStyle())
            }
            Button("Close") { model.dismissEudiFlow() }
                .frame(maxWidth: .infinity)

        case .idle, .configurationRequired:
            EmptyView()
        }
    }

    private func primaryButton(
        _ title: String,
        icon: String,
        action: @escaping @MainActor () async -> Void
    ) -> some View {
        Button {
            Task { await action() }
        } label: {
            Label(title, systemImage: icon).frame(maxWidth: .infinity)
        }
        .buttonStyle(OariPrimaryButtonStyle())
    }
}
