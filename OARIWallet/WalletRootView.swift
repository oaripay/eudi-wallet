import OariDesignSystem
import SwiftUI

struct WalletRootView: View {
    @ObservedObject var model: WalletAppModel

    var body: some View {
        TabView(selection: $model.selectedTab) {
            WalletVaultView(model: model)
                .tag(WalletAppModel.Tab.wallet)
                .tabItem {
                    Label("Wallet", systemImage: "wallet.pass")
                        .accessibilityIdentifier("tab.wallet")
                }
            WalletScannerView(model: model)
                .tag(WalletAppModel.Tab.scan)
                .tabItem {
                    Label("Scan", systemImage: "qrcode.viewfinder")
                        .accessibilityIdentifier("tab.scan")
                }
            WalletHistoryView(model: model)
                .tag(WalletAppModel.Tab.history)
                .tabItem {
                    Label("History", systemImage: "clock.arrow.circlepath")
                        .accessibilityIdentifier("tab.history")
                }
            WalletSettingsView(model: model)
                .tag(WalletAppModel.Tab.settings)
                .tabItem {
                    Label("Settings", systemImage: "gearshape")
                        .accessibilityIdentifier("tab.settings")
                }
        }
        .tint(OariColor.action)
        .overlay {
            if model.isPrivacyCoverVisible {
                WalletPrivacyCover()
                    .accessibilityIdentifier("privacy.cover")
            }
        }
        .sheet(isPresented: Binding(
            get: {
                switch model.eudiFlow {
                case .issuanceReview, .presentationConsent, .pending, .completed, .failed, .working:
                    true
                case .idle, .configurationRequired:
                    false
                }
            },
            set: { if !$0 { model.dismissEudiFlow() } }
        )) {
            EudiFlowView(model: model)
                .presentationDetents([.medium, .large])
                .interactiveDismissDisabled(model.preventsInteractiveFlowDismissal)
        }
    }
}

private struct WalletPrivacyCover: View {
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        ZStack {
            OariColor.background(scheme).ignoresSafeArea()
            VStack(spacing: OariSpacing.x4) {
                Image(systemName: "lock.shield.fill")
                    .font(.largeTitle)
                Text("OARI Wallet locked")
                    .font(OariTypography.heading)
            }
            .foregroundStyle(OariColor.textPrimary(scheme))
            .accessibilityElement(children: .combine)
        }
    }
}
