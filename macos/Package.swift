// swift-tools-version: 6.0

import Foundation
import PackageDescription

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let package = Package(
  name: "Fido2VC",
  platforms: [.macOS(.v14)],
  products: [.executable(name: "Fido2VC", targets: ["Fido2VC"])],
  targets: [
    .systemLibrary(name: "Backend"),
    .executableTarget(
      name: "Fido2VC", dependencies: ["Backend"],
      linkerSettings: [
        .unsafeFlags(["-L", root.appendingPathComponent("target/release").path]),
        .linkedFramework("IOKit"), .linkedFramework("CoreFoundation"),
        .linkedFramework("Security"), .linkedLibrary("c++"),
      ]),
    .testTarget(name: "Fido2VCTests", dependencies: ["Fido2VC"]),
  ],
  swiftLanguageModes: [.v6]
)
