// swift-tools-version: 6.0
// SPDX-License-Identifier: GPL-3.0-or-later

import PackageDescription

let package = Package(
    name: "ObscuraCrypto",
    platforms: [
        .macOS(.v13),
        .iOS(.v17),
    ],
    products: [
        .library(name: "ObscuraCrypto", targets: ["ObscuraCrypto"]),
        .executable(name: "obscura", targets: ["ObscuraCLI"]),
    ],
    targets: [
        // No dependencies beyond Apple's CryptoKit, CommonCrypto and Security,
        // so everything that touches a key is in this repository.
        .target(name: "ObscuraCrypto"),
        .executableTarget(
            name: "ObscuraCLI",
            dependencies: ["ObscuraCrypto"]
        ),
        .testTarget(
            name: "ObscuraCryptoTests",
            dependencies: ["ObscuraCrypto"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
