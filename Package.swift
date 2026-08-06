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
    ],
    targets: [
        .target(
            name: "WalletDomain",
            path: "Packages/Sources/WalletDomain"
        ),
        .testTarget(
            name: "WalletDomainTests",
            dependencies: ["WalletDomain"],
            path: "Packages/Tests/WalletDomainTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
