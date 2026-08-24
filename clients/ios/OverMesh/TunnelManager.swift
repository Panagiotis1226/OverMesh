import Foundation
import NetworkExtension

struct PeerStatus: Decodable, Identifiable {
    var id: String { hostname }
    let hostname: String
    let ipv4: String
    let path: String
    let online: Bool
}

private struct CoreStatus: Decodable {
    let running: Bool?
    let hostname: String?
    let network: String?
    let ipv4: String?
    let relay: String?
    let peers: [PeerStatus]?
}

// Owns the NETunnelProviderManager: saves the configuration, toggles
// the tunnel, and polls StatusJSON from the extension while connected.
@MainActor
final class TunnelManager: ObservableObject {
    static let providerBundleID = "com.overmesh.OverMesh.PacketTunnel"

    @Published var vpnStatus: NEVPNStatus = .invalid
    @Published var selfIPv4 = ""
    @Published var networkName = ""
    @Published var relayURL = ""
    @Published var peers: [PeerStatus] = []
    @Published var lastError = ""

    private var manager: NETunnelProviderManager?
    private var pollTask: Task<Void, Never>?

    init() {
        NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            guard let session = note.object as? NETunnelProviderSession else { return }
            Task { @MainActor in self?.statusChanged(session.status) }
        }
        Task { await reload() }
    }

    func reload() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first
            statusChanged(manager?.connection.status ?? .invalid)
        } catch {
            lastError = error.localizedDescription
        }
    }

    func connect(server: String, setupKey: String, hostname: String, tls: Bool) async {
        lastError = ""
        do {
            let mgr = manager ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleID
            proto.serverAddress = server
            proto.providerConfiguration = [
                "server": server,
                "setupKey": setupKey,
                "hostname": hostname,
                "tls": tls,
            ]
            mgr.protocolConfiguration = proto
            mgr.localizedDescription = "OverMesh"
            mgr.isEnabled = true
            try await mgr.saveToPreferences()
            // A freshly saved manager must be reloaded before starting.
            try await mgr.loadFromPreferences()
            manager = mgr
            try mgr.connection.startVPNTunnel()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    private func statusChanged(_ status: NEVPNStatus) {
        vpnStatus = status
        pollTask?.cancel()
        if status == .connected {
            pollTask = Task { [weak self] in
                while !Task.isCancelled {
                    await self?.pollStatus()
                    try? await Task.sleep(for: .seconds(3))
                }
            }
        } else {
            selfIPv4 = ""; relayURL = ""; peers = []
        }
    }

    private func pollStatus() async {
        guard let session = manager?.connection as? NETunnelProviderSession,
              session.status == .connected else { return }
        do {
            try session.sendProviderMessage("status".data(using: .utf8)!) { [weak self] data in
                guard let data,
                      let st = try? JSONDecoder().decode(CoreStatus.self, from: data)
                else { return }
                Task { @MainActor in
                    self?.selfIPv4 = st.ipv4 ?? ""
                    self?.networkName = st.network ?? ""
                    self?.relayURL = st.relay ?? ""
                    self?.peers = st.peers ?? []
                }
            }
        } catch {
            // transient while the extension spins up; next poll retries
        }
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .connected: return "Connected"
        case .connecting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        case .reasserting: return "Reconnecting…"
        case .disconnected: return "Disconnected"
        default: return "Not configured"
        }
    }
}
