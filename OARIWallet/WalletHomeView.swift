import SwiftUI
import WalletDomain

struct WalletHomeModel: Equatable, Sendable {
    let title: String
    let status: String
    let detail: String

    static let initial = WalletHomeModel(
        title: "OARI Wallet",
        status: "Wallet setup required",
        detail: "No credentials are stored. Issuance and presentation remain disabled until a supported profile is configured."
    )

    static func credentialCountDescription(_ credentials: [CredentialRecord]) -> String {
        switch credentials.count {
        case 0: "No credentials"
        case 1: "1 credential"
        default: "\(credentials.count) credentials"
        }
    }
}

struct WalletHomeView: View {
    let model: WalletHomeModel

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                Text("HOLDER WALLET")
                    .font(.caption.weight(.heavy))
                    .tracking(2)
                    .foregroundStyle(.secondary)

                Text(model.title)
                    .font(.largeTitle.bold())
                    .tracking(-0.8)

                VStack(alignment: .leading, spacing: 12) {
                    Label(model.status, systemImage: "lock.shield")
                        .font(.headline.weight(.heavy))
                    Text(model.detail)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(20)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20))
                .accessibilityElement(children: .combine)

                Spacer()
            }
            .padding(24)
            .navigationTitle("Wallet")
        }
        .preferredColorScheme(.dark)
    }
}

#Preview {
    WalletHomeView(model: .initial)
}
