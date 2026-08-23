// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OverMeshBar",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "OverMeshBar",
            path: "Sources/OverMeshBar"
        )
    ]
)
