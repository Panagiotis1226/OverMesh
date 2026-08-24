import AppKit
import Foundation
import SwiftUI

// The app's live view of the daemon: polls status/transfers/inbox and
// exposes the actions the UI needs. All daemon calls go through the
// unix control socket (run overmeshd with `-socket-group admin`).
@MainActor
final class AppState: ObservableObject {
    @AppStorage("socketPath") var socketPath = "/var/run/overmesh.sock"

    @Published var status: MeshStatus?
    @Published var transfers: [Transfer] = []
    @Published var inbox: InboxResponse?
    @Published var daemonReachable = false
    @Published var busy = false // a connect/disconnect is in flight
    @Published var lastError: String?

    let profiles = ProfileStore()
    private var timer: Timer?

    var client: ControlClient { ControlClient(socketPath: socketPath) }

    var isUp: Bool { status?.running ?? false }
    var peers: [Peer] { status?.peers ?? [] }
    var activeTransfers: [Transfer] { transfers.filter { $0.state == "sending" } }

    init() {
        startPolling()
    }

    func startPolling() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        Task { await refresh() }
    }

    func refresh() async {
        do {
            status = try await client.get("/status", as: MeshStatus.self)
            daemonReachable = true
        } catch {
            daemonReachable = false
            status = nil
            return
        }
        transfers = (try? await client.get("/transfers", as: TransfersResponse.self).transfers) ?? transfers
        inbox = (try? await client.get("/inbox", as: InboxResponse.self)) ?? inbox
    }

    // MARK: actions

    /// Connect to a profile's server. Any current session is torn down
    /// first — this is also how switching servers works.
    func connect(_ profile: Profile) async {
        guard !profile.server.isEmpty else {
            lastError = "profile \(profile.name) has no server address"
            return
        }
        busy = true
        lastError = nil
        defer { busy = false }
        _ = try? await client.post("/down") // fine if already down
        var body: [String: Any] = [
            "server": profile.server,
            "advertise_routes": profile.routesList,
            "exit_node": "",
            "tls": profile.useTLS,
        ]
        if !profile.setupKey.isEmpty { body["key"] = profile.setupKey }
        do {
            _ = try await client.post("/up", body: body)
            profiles.activeID = profile.id
        } catch {
            lastError = error.localizedDescription
        }
        await refresh()
    }

    func disconnect() async {
        busy = true
        defer { busy = false }
        do {
            _ = try await client.post("/down")
        } catch {
            lastError = error.localizedDescription
        }
        await refresh()
    }

    /// Re-apply the active profile (e.g. after editing its routes).
    func reapplyActive() async {
        if let p = profiles.active, isUp {
            await connect(p)
        }
    }

    func setExitNode(_ name: String?) async {
        do {
            _ = try await client.post("/exitnode", body: ["name": name ?? ""])
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        await refresh()
    }

    func sendFile(_ url: URL, to peer: Peer) async {
        do {
            _ = try await client.post("/drop", body: ["file": url.path, "peer": peer.hostname],
                                      as: DropResponse.self)
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
        await refresh()
    }

    func openInboxFolder() {
        if let dir = inbox?.dir ?? status?.overdropDir, !dir.isEmpty {
            NSWorkspace.shared.open(URL(fileURLWithPath: dir))
        }
    }
}
