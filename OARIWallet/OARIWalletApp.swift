import SwiftUI

@main
struct OARIWalletApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model: WalletAppModel
    private let configuration: AppConfiguration
    private let dependencies: Result<WalletAppDependencies, Error>

    init() {
        let configuration = AppConfiguration.current()
        self.configuration = configuration
        dependencies = WalletAppDependencies.make(configuration: configuration)
        _model = StateObject(
            wrappedValue: WalletAppModel(
                allowedHosts: configuration.allowedHosts,
                showsOnboarding: !UserDefaults.standard.bool(forKey: "oari.onboarding.completed")
            )
        )
    }

    var body: some Scene {
        WindowGroup {
            WalletRootView(model: model)
                .preferredColorScheme(model.theme.colorScheme)
                .task {
                    await model.load(dependencies)
                    if let incomingURL = configuration.incomingURL {
                        model.handleIncomingURL(incomingURL)
                    }
                }
                .onOpenURL(perform: model.handleIncomingURL)
                .onChange(of: scenePhase) { _, phase in
                    model.setPrivacyCoverVisible(phase != .active)
                }
                .transaction { transaction in
                    if configuration.disablesAnimations {
                        transaction.disablesAnimations = true
                    }
                }
        }
    }
}
