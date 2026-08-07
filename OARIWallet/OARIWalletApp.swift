import SwiftUI

@main
struct OARIWalletApp: App {
    @StateObject private var model = WalletAppModel()
    private let dependencies = WalletAppDependencies.make()

    var body: some Scene {
        WindowGroup {
            WalletRootView(model: model)
                .preferredColorScheme(model.theme.colorScheme)
                .task {
                    await model.load(dependencies)
                }
        }
    }
}
