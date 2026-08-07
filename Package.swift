// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "OARIWalletModules",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "WalletDomain", targets: ["WalletDomain"]),
        .library(name: "WalletVault", targets: ["WalletVault"]),
        .library(name: "ProfileDomain", targets: ["ProfileDomain"]),
        .library(name: "TrustDomain", targets: ["TrustDomain"]),
        .library(name: "PresentationDomain", targets: ["PresentationDomain"]),
        .library(name: "ProtocolEngine", targets: ["ProtocolEngine"]),
        .library(name: "OariDesignSystem", targets: ["OariDesignSystem"]),
    ],
    targets: [
        .target(
            name: "WalletDomain",
            path: "Packages/Sources/WalletDomain"
        ),
        .target(
            name: "WalletVault",
            dependencies: ["WalletDomain"],
            path: "Packages/Sources/WalletVault"
        ),
        .target(
            name: "ProfileDomain",
            dependencies: ["WalletDomain"],
            path: "Packages/Sources/ProfileDomain"
        ),
        .target(
            name: "TrustDomain",
            dependencies: ["ProfileDomain"],
            path: "Packages/Sources/TrustDomain"
        ),
        .target(
            name: "PresentationDomain",
            dependencies: ["ProfileDomain", "TrustDomain", "WalletDomain"],
            path: "Packages/Sources/PresentationDomain"
        ),
        .target(
            name: "ProtocolEngine",
            dependencies: ["PresentationDomain", "ProfileDomain", "TrustDomain", "WalletDomain"],
            path: "Packages/Sources/ProtocolEngine"
        ),
        .target(
            name: "OariDesignSystem",
            path: "Packages/Sources/OariDesignSystem"
        ),
        .testTarget(
            name: "WalletDomainTests",
            dependencies: ["WalletDomain"],
            path: "Packages/Tests/WalletDomainTests"
        ),
        .testTarget(
            name: "WalletVaultTests",
            dependencies: ["WalletDomain", "WalletVault"],
            path: "Packages/Tests/WalletVaultTests"
        ),
        .testTarget(
            name: "ProfileDomainTests",
            dependencies: ["ProfileDomain"],
            path: "Packages/Tests/ProfileDomainTests"
        ),
        .testTarget(
            name: "TrustDomainTests",
            dependencies: ["ProfileDomain", "TrustDomain"],
            path: "Packages/Tests/TrustDomainTests"
        ),
        .testTarget(
            name: "PresentationDomainTests",
            dependencies: ["PresentationDomain", "ProfileDomain", "TrustDomain"],
            path: "Packages/Tests/PresentationDomainTests"
        ),
        .testTarget(
            name: "ProtocolEngineTests",
            dependencies: ["ProtocolEngine", "PresentationDomain", "ProfileDomain", "TrustDomain", "WalletDomain"],
            path: "Packages/Tests/ProtocolEngineTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
