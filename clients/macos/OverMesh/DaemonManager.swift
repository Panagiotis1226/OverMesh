import Foundation
import ServiceManagement

// Installs and manages the bundled overmeshd as a launchd daemon via
// SMAppService: the user clicks once, approves the background item in
// System Settings, and the daemon runs as root from inside the app
// bundle — no Terminal, no separate install.
//
// macOS requires apps registering *daemons* to live in /Applications.
@MainActor
final class DaemonManager: ObservableObject {
    static let plistName = "com.overmesh.overmeshd.plist"
    private let service = SMAppService.daemon(plistName: DaemonManager.plistName)

    @Published var status: SMAppService.Status = .notRegistered
    @Published var lastError: String?

    var inApplications: Bool {
        Bundle.main.bundlePath.hasPrefix("/Applications/")
    }

    var statusLabel: String {
        switch status {
        case .enabled: return "installed"
        case .requiresApproval: return "waiting for approval in System Settings"
        case .notRegistered: return "not installed"
        case .notFound: return "not installed"
        @unknown default: return "unknown"
        }
    }

    func refresh() {
        status = service.status
    }

    func install() {
        lastError = nil
        do {
            try service.register()
        } catch {
            // Registration commonly "fails" into requiresApproval —
            // that's the expected System Settings consent flow.
            if service.status != .requiresApproval {
                lastError = error.localizedDescription
            }
        }
        refresh()
        if status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
        }
    }

    func uninstall() async {
        lastError = nil
        do {
            try await service.unregister()
        } catch {
            lastError = error.localizedDescription
        }
        refresh()
    }
}
