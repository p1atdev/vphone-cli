// swift-tools-version:6.0

import PackageDescription

let package = Package(
    name: "vphone-cli",
    platforms: [
        .macOS(.v15)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.1"),
        .package(url: "https://github.com/mhdhejazi/Dynamic", from: "1.2.0"),
        .package(url: "https://github.com/p1atdev/Image4.git", from: "1.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "vphone-cli",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Dynamic", package: "Dynamic"),
                .product(name: "Image4", package: "Image4"),
            ],
            path: "sources/vphone-cli",
            linkerSettings: [
                .linkedFramework("Virtualization"),
                .linkedFramework("AppKit"),
            ]
        )
    ]
)
