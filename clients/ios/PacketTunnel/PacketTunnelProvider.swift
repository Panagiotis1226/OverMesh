import NetworkExtension
import UIKit
import Mobilecore

// The packet-tunnel side of OverMesh on iOS. The heavy lifting —
// WireGuard, holepunching, relay fallback, ACL filter, mesh DNS,
// OverDrop — all lives in Mobilecore (Go). This class only:
//   1. hands the utun file descriptor to the core, and
//   2. programs NEPacketTunnelNetworkSettings from the core's
//      OnNetMap callback, then confirms with networkSettingsApplied().
class PacketTunnelProvider: NEPacketTunnelProvider, MobilecoreEventsProtocol {
    private var core: MobilecoreCore?
    private var startCompletion: ((Error?) -> Void)?
    private var serverHost = "127.0.0.1"

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let conf = proto.providerConfiguration,
              let server = conf["server"] as? String, !server.isEmpty else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        serverHost = server.split(separator: ":").first.map(String.init) ?? server

        guard let fd = tunnelFileDescriptor() else {
            NSLog("overmesh: no utun file descriptor")
            completionHandler(NEVPNError(.connectionFailed))
            return
        }

        let stateDir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("overmesh", isDirectory: true).path
        var err: NSError?
        guard let core = MobilecoreNewCore(stateDir, &err) else {
            completionHandler(err ?? NEVPNError(.connectionFailed))
            return
        }
        self.core = core

        var cfg: [String: Any] = [
            "server": server,
            "hostname": conf["hostname"] as? String ?? UIDevice.current.name,
        ]
        if let key = conf["setupKey"] as? String, !key.isEmpty { cfg["setup_key"] = key }
        if let tls = conf["tls"] as? Bool, tls { cfg["tls"] = true }
        let cfgJSON = String(data: try! JSONSerialization.data(withJSONObject: cfg),
                             encoding: .utf8)!

        // completionHandler fires from onNetMap once settings are live.
        startCompletion = completionHandler
        do {
            try core.start(cfgJSON, tunFD: fd, ev: self)
        } catch {
            self.core = nil
            startCompletion = nil
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        core?.stop()
        core = nil
        completionHandler()
    }

    // The app polls status over the provider-message channel.
    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler else { return }
        if String(data: messageData, encoding: .utf8) == "status", let core {
            completionHandler(core.statusJSON().data(using: .utf8))
        } else {
            completionHandler(nil)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        core?.setForeground(false)
        completionHandler()
    }

    override func wake() {
        core?.setForeground(true)
    }

    // MARK: MobilecoreEventsProtocol

    func onState(_ state: String?) {
        NSLog("overmesh: state=%@", state ?? "")
    }

    func onNetMap(_ netmapJSON: String?) {
        guard let data = netmapJSON?.data(using: .utf8),
              let s = try? JSONDecoder().decode(NetmapSettings.self, from: data) else {
            NSLog("overmesh: bad netmap settings json")
            return
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverHost)

        let v4 = NEIPv4Settings(addresses: [s.ipv4],
                                subnetMasks: [Self.mask(fromPrefix: s.ipv4Prefix)])
        v4.includedRoutes = s.routes.filter { !$0.contains(":") }.map { r in
            let parts = r.split(separator: "/")
            return NEIPv4Route(destinationAddress: String(parts[0]),
                               subnetMask: Self.mask(fromPrefix: Int(parts[1]) ?? 32))
        }
        settings.ipv4Settings = v4

        let v6 = NEIPv6Settings(addresses: [s.ipv6],
                                networkPrefixLengths: [NSNumber(value: s.ipv6Prefix)])
        v6.includedRoutes = s.routes.filter { $0.contains(":") }.map { r in
            let parts = r.split(separator: "/")
            return NEIPv6Route(destinationAddress: String(parts[0]),
                               networkPrefixLength: NSNumber(value: Int(parts[1]) ?? 128))
        }
        settings.ipv6Settings = v6

        let dns = NEDNSSettings(servers: [s.dnsServer])
        dns.matchDomains = [""] // default resolver: bare names like `ps-iPhone` work
        dns.searchDomains = [s.dnsDomain]
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: s.mtu)

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if error == nil {
                self.core?.networkSettingsApplied()
            } else {
                NSLog("overmesh: setTunnelNetworkSettings: %@",
                      error!.localizedDescription)
            }
            if let done = self.startCompletion {
                self.startCompletion = nil
                done(error)
            }
        }
    }

    // MARK: helpers

    private struct NetmapSettings: Decodable {
        let ipv4: String
        let ipv4Prefix: Int
        let ipv6: String
        let ipv6Prefix: Int
        let routes: [String]
        let dnsServer: String
        let dnsDomain: String
        let mtu: Int
        enum CodingKeys: String, CodingKey {
            case ipv4, ipv6, routes, mtu
            case ipv4Prefix = "ipv4_prefix"
            case ipv6Prefix = "ipv6_prefix"
            case dnsServer = "dns_server"
            case dnsDomain = "dns_domain"
        }
    }

    private static func mask(fromPrefix p: Int) -> String {
        let bits: UInt32 = p == 0 ? 0 : ~UInt32(0) << (32 - UInt32(p))
        return "\(bits >> 24 & 255).\(bits >> 16 & 255).\(bits >> 8 & 255).\(bits & 255)"
    }

    // NEPacketTunnelFlow keeps the utun fd private; recover it the way
    // WireGuard/Tailscale do — the KVC fast path, then a descriptor
    // scan for the utun control socket.
    private func tunnelFileDescriptor() -> Int? {
        if let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32 {
            return Int(fd)
        }
        var buf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        for fd: Int32 in 0...1024 {
            var len = socklen_t(buf.count)
            if getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */,
                          &buf, &len) == 0,
               String(cString: buf).hasPrefix("utun") {
                return Int(fd)
            }
        }
        return nil
    }
}
