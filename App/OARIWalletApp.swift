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
                WalletRootView(model: model)
                if showsStartupSplash {
                    WalletStartupSplash()
                        .transition(.opacity)
                        .zIndex(10)
                }
            }
                .preferredColorScheme(model.theme.colorScheme)
                .task {
                    // Let SwiftUI display the branded startup view before Wallet Kit setup begins.
                    await Task.yield()
                    let bootstrap = await Task.detached(priority: .userInitiated) {
                        switch WalletAppDependencies.make(configuration: configuration) {
                        case let .success(dependencies):
                            WalletBootstrapResult.success(dependencies)
                        case let .failure(error):
                            WalletBootstrapResult.failure(
                                WalletBootstrapError(message: String(describing: error))
                            )
                        }
                    }.value
                    let dependencies: Result<WalletAppDependencies, Error> = switch bootstrap {
                    case let .success(value): .success(value)
                    case let .failure(error): .failure(error)
                    }
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
                .animation(.easeOut(duration: 0.28), value: showsStartupSplash)
        }
    }

    private var showsStartupSplash: Bool {
        switch model.loadingState {
        case .idle, .loading: true
        case .loaded, .failed: false
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
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var breathes = false

    var body: some View {
        ZStack {
            OariColor.background(scheme).ignoresSafeArea()
            Circle()
                .fill(OariColor.action.opacity(scheme == .dark ? 0.12 : 0.08))
                .frame(width: 320, height: 320)
                .blur(radius: 70)

            VStack(spacing: OariSpacing.x5) {
                Spacer()
                Image("OariMark")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 156, height: 156)
                    .scaleEffect(reduceMotion ? 1 : (breathes ? 1.035 : 0.97))
                    .shadow(color: OariColor.action.opacity(0.2), radius: 28)

                VStack(spacing: OariSpacing.x2) {
                    Text("OARI")
                        .font(.system(size: 34, weight: .black, design: .rounded))
                        .tracking(5)
                    Text("Wallet")
                        .font(.headline.weight(.medium))
                        .foregroundStyle(OariColor.textSecondary(scheme))
                }

                ProgressView()
                    .tint(OariColor.action)
                    .controlSize(.regular)
                    .accessibilityLabel("Preparing wallet")

                Spacer()
                Label("Keys stay on this device", systemImage: "lock.shield.fill")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(OariColor.textSecondary(scheme))
                    .padding(.bottom, OariSpacing.x7)
            }
            .foregroundStyle(OariColor.textPrimary(scheme))
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Oari Wallet is preparing your secure wallet")
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.easeInOut(duration: 1.6).repeatForever(autoreverses: true)) {
                breathes = true
            }
        }
    }
}
