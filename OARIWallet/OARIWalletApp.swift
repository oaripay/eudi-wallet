import SwiftUI

@main
struct OARIWalletApp: App {
    var body: some Scene {
        WindowGroup {
            WalletHomeView(model: .initial)
        }
    }
}
