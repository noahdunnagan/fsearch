// swift-tools-version: 6.0
import PackageDescription
import Foundation

let package = Package(
    name: "FSearch",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "FSearch",
            targets: ["FSearch"]
        ),
    ],
    targets: [
        .systemLibrary(
            name: "CFSearch",
            path: "Sources/CFSearch"
        ),
        .target(
            name: "FSearch",
            dependencies: ["CFSearch"],
            path: "Sources/FSearch",
            linkerSettings: [
                .unsafeFlags([
                    "-Xlinker", "-force_load",
                    "-Xlinker", "\(Context.packageDirectory)/target/release/libfsearch.a",
                ]),
            ]
        ),
        .testTarget(
            name: "FSearchTests",
            dependencies: ["FSearch"],
            path: "Tests/FSearchTests",
            linkerSettings: [
                .unsafeFlags([
                    "-Xlinker", "-force_load",
                    "-Xlinker", "\(Context.packageDirectory)/target/release/libfsearch.a",
                ]),
            ]
        ),
    ]
)
