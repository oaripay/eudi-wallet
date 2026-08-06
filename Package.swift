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
    ],
    swiftLanguageModes: [.v6]
)
