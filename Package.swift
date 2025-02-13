// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "WultraSSLPinning",
    platforms: [
        .iOS(.v13),
        .tvOS(.v13)
    ],
    products: [
        .library(
            name: "WultraSSLPinning",
            targets: ["WultraSSLPinning"]),
    ],
    targets: [
        .target(
            name: "WultraSSLPinning"
        )
    ]
)
