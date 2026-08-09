import SwiftUI
import OariDesignSystem

@main
struct OariWalletApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model: WalletAppModel
    private let configuration: AppConfiguration

    init() {
        let configuration = AppConfiguration.current()
        self.configuration = configuration
        _model = StateObject(
            wrappedValue: WalletAppModel(
                allowedHosts: configuration.allowedHosts,
                showsOnboarding: configuration.fixture == .production &&
                    !UserDefaults.standard.bool(forKey: "oari.onboarding.completed")
            )
        )
    }

    var body: some Scene {
        WindowGroup {
            ZStack {
                if showsStartupSplash {
                    WalletStartupSplash()
                        .task { await bootstrapWallet() }
                        .transition(.opacity)
                        .zIndex(10)
                } else {
                    WalletRootView(model: model)
                }
            }
            .preferredColorScheme(model.theme.colorScheme)
            .onOpenURL(perform: model.handleIncomingURL)
            .overlay {
                if scenePhase != .active || model.isAppLockBlocking {
                    WalletPrivacyShield(
                        model: model,
                        isSpinning: scenePhase != .active || model.appLockState == .authenticating
                    )
                        .transition(.identity)
                        .zIndex(100)
                }
            }
            .sheet(isPresented: $model.showsAppLockSetup) {
                WalletAppLockSetupView(model: model, allowsDismissal: false)
                    .interactiveDismissDisabled()
                    .presentationDetents([.medium])
            }
            .onChange(of: scenePhase) { _, phase in
                Task { await model.handleScenePhase(appLifecyclePhase(phase)) }
            }
            .transaction { transaction in
                if configuration.disablesAnimations { transaction.disablesAnimations = true }
            }
            .animation(.easeOut(duration: 0.28), value: showsStartupSplash)
        }
    }

    private var showsStartupSplash: Bool {
        switch model.loadingState {
        case .idle, .loading: true
        case .loaded, .failed: false
        }
    }

    private func bootstrapWallet() async {
        await Task.yield()
        let bootstrap = await Task.detached(priority: .userInitiated) {
            switch WalletAppDependencies.make(configuration: configuration) {
            case let .success(dependencies): WalletBootstrapResult.success(dependencies)
            case let .failure(error): WalletBootstrapResult.failure(WalletBootstrapError(message: String(describing: error)))
            }
        }.value
        let dependencies: Result<WalletAppDependencies, Error> = switch bootstrap {
        case let .success(value): .success(value)
        case let .failure(error): .failure(error)
        }
        await model.handleScenePhase(appLifecyclePhase(scenePhase))
        await model.load(dependencies)
        if let incomingURL = configuration.incomingURL { model.handleIncomingURL(incomingURL) }
    }

    private func appLifecyclePhase(_ phase: ScenePhase) -> WalletAppModel.AppLifecyclePhase {
        switch phase {
        case .active: .active
        case .inactive: .inactive
        case .background: .background
        @unknown default: .inactive
        }
    }
}

private enum WalletBootstrapResult: Sendable {
    case success(WalletAppDependencies)
    case failure(WalletBootstrapError)
}

private struct WalletBootstrapError: LocalizedError, Sendable {
    let message: String
    var errorDescription: String? { message }
}

private struct WalletStartupSplash: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var rotation: Double = 0

    var body: some View {
        ZStack {
            Color("LaunchBackground").ignoresSafeArea()
            Image("OariMark")
                .resizable()
                .scaledToFit()
                .frame(width: 180, height: 180)
                .rotationEffect(.degrees(rotation))
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Oari Wallet is preparing your secure wallet")
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.linear(duration: 2).repeatForever(autoreverses: false)) { rotation = 360 }
        }
    }
}
