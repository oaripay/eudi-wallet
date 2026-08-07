import OariDesignSystem
import SwiftUI

struct WalletRootView: View {
    @ObservedObject var model: WalletAppModel

    var body: some View {
        TabView {
            WalletVaultView(model: model)
                .tabItem { Label("Wallet", systemImage: "wallet.pass") }
            WalletScannerView(model: model)
                .tabItem { Label("Scan", systemImage: "qrcode.viewfinder") }
            WalletHistoryView(model: model)
                .tabItem { Label("History", systemImage: "clock.arrow.circlepath") }
            WalletSettingsView(model: model)
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
        .tint(OariColor.action)
    }
}
