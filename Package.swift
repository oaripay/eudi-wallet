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
    ],
    swiftLanguageModes: [.v6]
)
