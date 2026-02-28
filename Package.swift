// swift-tools-version:5.10

import PackageDescription

let package = Package(
    name: "vphone-cli",
    platforms: [
        .macOS(.v14)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.1"),
        .package(url: "https://github.com/p1atdev/Image4.git", from: "1.0.0"),
    ],
    targets: [
        // ObjC module: wraps private Virtualization.framework APIs
        .target(
            name: "VPhoneObjC",
            path: "sources/vphone-objc",
            publicHeadersPath: "include",
            linkerSettings: [
                .linkedFramework("Virtualization")
            ]
        ),
        // Swift executable
        .executableTarget(
            name: "vphone-cli",
            dependencies: [
                "VPhoneObjC",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Image4", package: "Image4"),
            ],
            path: "sources/vphone-cli",
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"])
            ],
            linkerSettings: [
                .linkedFramework("Virtualization"),
                .linkedFramework("AppKit"),
            ]
        ),
    ]
)
