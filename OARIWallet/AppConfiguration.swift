import Foundation

struct AppConfiguration: Sendable {
    enum Fixture: String, Sendable {
        case production
        case empty
        case populated
        case storageFailure = "storage-failure"
    }

    let allowedHosts: Set<String>
    let fixture: Fixture
    let incomingURL: URL?
    let disablesAnimations: Bool
    let ebsiDevelopmentEnabled: Bool
    let ebsiLocalAuthorityEnabled: Bool

    static func current(
        arguments: [String] = ProcessInfo.processInfo.arguments
    ) -> AppConfiguration {
#if DEBUG
        let fixture = value(after: "--fixture", in: arguments)
            .flatMap(Fixture.init(rawValue:)) ?? .production
        let incomingURL = value(after: "--incoming-url", in: arguments).flatMap(URL.init(string:))
        let fixtureHosts: Set<String> = fixture == .production
            ? []
            : ["verifier.example", "issuer.example"]
#else
        let fixture = Fixture.production
        let incomingURL: URL? = nil
        let fixtureHosts: Set<String> = []
#endif
        // This build is the dedicated EUDI/EBSI interoperability wallet. Keep the
        // open development profile on by default so testers do not need to maintain
        // issuer/verifier trust lists for every development counterparty.
        let ebsiDevelopmentEnabled = !arguments.contains("--disable-ebsi-development")
        return AppConfiguration(
            allowedHosts: Set(["wallet.dev.oari.io"]).union(fixtureHosts),
            fixture: fixture,
            incomingURL: incomingURL,
            disablesAnimations: arguments.contains("--disable-animations"),
            ebsiDevelopmentEnabled: ebsiDevelopmentEnabled,
            ebsiLocalAuthorityEnabled: arguments.contains("--enable-local-ebsi-authority") ||
                ProcessInfo.processInfo.environment["OARI_EBSI_LOCAL_AUTHORITY"] == "1"
        )
    }

    private static func value(after key: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: key) else { return nil }
        let valueIndex = arguments.index(after: index)
        return valueIndex < arguments.endIndex ? arguments[valueIndex] : nil
    }
}
