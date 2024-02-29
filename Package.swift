// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "WultraSSLPinning",
    platforms: [
        .iOS(.v12),
        .tvOS(.v12)
    ],
    products: [
        .library(
            name: "WultraSSLPinning",
            targets: ["WultraSSLPinning"]),
    ],
    dependencies: [
        .package(url: "https://github.com/wultra/powerauth-mobile-sdk-spm.git", .upToNextMinor(from: "1.8.0"))
    ],
    targets: [
        .target(
            name: "WultraSSLPinning",
            dependencies: [
                .product(name: "PowerAuth2", package: "powerauth-mobile-sdk-spm"),
                .product(name: "PowerAuthCore", package: "powerauth-mobile-sdk-spm")
            ]
        )
    ]
)
