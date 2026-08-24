import SwiftUI

@main
struct OverMeshApp: App {
    @StateObject private var app = AppState()

    var body: some Scene {
        MenuBarExtra {
            MenuContentView()
                .environmentObject(app)
        } label: {
            Image(systemName: app.isUp ? "network" : "network.slash")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(app)
        }
    }
}
