// OverMeshBar — a minimal macOS menu bar companion for overmeshd.
//
// v0 design: a thin UI over the `overmesh` CLI (found on PATH or in
// /usr/local/bin). It shows connection state and peers, copies overlay
// IPs, picks an exit node, and sends files with OverDrop. It refreshes
// every few seconds.
//
// Requirements on the Mac:
//   - overmeshd running with a group-accessible control socket:
//       sudo overmeshd -socket-group admin &
//   - the logged-in user is in the 'admin' group (default on macOS)
//   - overmesh + overmeshd binaries in /usr/local/bin (or PATH)
//
// Build: swift build -c release  (produces .build/release/OverMeshBar)

import AppKit
import Foundation

// MARK: - CLI bridge

struct PeerInfo: Decodable {
    var hostname: String
    var ipv4: String
    var online: Bool
    var path: String?
    var offers_exit: Bool?
}

struct MeshStatus: Decodable {
    var running: Bool
    var hostname: String?
    var network: String?
    var ipv4: String?
    var conn: String?
    var exit_node: String?
    var exit_node_active: Bool?
    var overdrop_dir: String?
    var peers: [PeerInfo]?
}

enum CLI {
    static var binary: String {
        for p in ["/usr/local/bin/overmesh", "/opt/homebrew/bin/overmesh"] {
            if FileManager.default.isExecutableFile(atPath: p) { return p }
        }
        return "overmesh" // hope for PATH
    }

    @discardableResult
    static func run(_ args: [String]) -> (out: String, code: Int32) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = [binary] + args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return ("\(error)", -1) }
        p.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (String(data: data, encoding: .utf8) ?? "", p.terminationStatus)
    }

    static func status() -> MeshStatus? {
        let r = run(["status", "-json"])
        guard r.code == 0, let data = r.out.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(MeshStatus.self, from: data)
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private var timer: Timer?
    private var status: MeshStatus?

    func applicationDidFinishLaunching(_ note: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "◌"
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.refresh()
        }
        rebuildMenu()
    }

    private func refresh() {
        DispatchQueue.global(qos: .utility).async {
            let st = CLI.status()
            DispatchQueue.main.async {
                self.status = st
                self.item.button?.title = (st?.running == true && st?.conn == "connected") ? "●" : "◌"
                self.rebuildMenu()
            }
        }
    }

    private func rebuildMenu() {
        let menu = NSMenu()

        if let st = status, st.running {
            let head = NSMenuItem(
                title: "\(st.hostname ?? "?") @ \(st.network ?? "?") — \(st.conn ?? "?")",
                action: nil, keyEquivalent: "")
            head.isEnabled = false
            menu.addItem(head)
            if let ip = st.ipv4 {
                let ipItem = NSMenuItem(title: "Copy my IP (\(ip))",
                                        action: #selector(copyText(_:)), keyEquivalent: "")
                ipItem.representedObject = ip
                ipItem.target = self
                menu.addItem(ipItem)
            }
            menu.addItem(.separator())

            // Peers: copy IP + send file.
            let peers = st.peers ?? []
            if peers.isEmpty {
                menu.addItem(withTitle: "No peers yet", action: nil, keyEquivalent: "")
            }
            for p in peers {
                let sub = NSMenu()
                let copy = NSMenuItem(title: "Copy IP \(p.ipv4)",
                                      action: #selector(copyText(_:)), keyEquivalent: "")
                copy.representedObject = p.ipv4
                copy.target = self
                sub.addItem(copy)
                let send = NSMenuItem(title: "Send file…",
                                      action: #selector(sendFile(_:)), keyEquivalent: "")
                send.representedObject = p.hostname
                send.target = self
                send.isEnabled = p.online
                sub.addItem(send)

                let head = NSMenuItem(
                    title: "\(p.online ? "🟢" : "⚪️") \(p.hostname)  \(p.path ?? "")",
                    action: nil, keyEquivalent: "")
                menu.addItem(head)
                menu.setSubmenu(sub, for: head)
            }
            menu.addItem(.separator())

            // Exit node picker.
            let exits = peers.filter { $0.offers_exit == true }
            if !exits.isEmpty || st.exit_node?.isEmpty == false {
                let exitMenu = NSMenu()
                let none = NSMenuItem(title: "None", action: #selector(pickExit(_:)), keyEquivalent: "")
                none.representedObject = ""
                none.target = self
                none.state = (st.exit_node ?? "").isEmpty ? .on : .off
                exitMenu.addItem(none)
                for e in exits {
                    let it = NSMenuItem(title: e.hostname, action: #selector(pickExit(_:)), keyEquivalent: "")
                    it.representedObject = e.hostname
                    it.target = self
                    it.state = (st.exit_node == e.hostname) ? .on : .off
                    exitMenu.addItem(it)
                }
                let exitHead = NSMenuItem(title: "Exit node", action: nil, keyEquivalent: "")
                menu.addItem(exitHead)
                menu.setSubmenu(exitMenu, for: exitHead)
            }
            if let dir = st.overdrop_dir, !dir.isEmpty {
                let inbox = NSMenuItem(title: "Open OverDrop inbox",
                                       action: #selector(openInbox(_:)), keyEquivalent: "")
                inbox.representedObject = dir
                inbox.target = self
                menu.addItem(inbox)
            }
            menu.addItem(.separator())
            menu.addItem(withTitle: "Disconnect", action: #selector(goDown), keyEquivalent: "")
                .target = self
        } else {
            menu.addItem(withTitle: "Not connected", action: nil, keyEquivalent: "")
            let hint = NSMenuItem(
                title: "Run: sudo overmeshd -socket-group admin & overmesh up …",
                action: nil, keyEquivalent: "")
            hint.isEnabled = false
            menu.addItem(hint)
        }

        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit OverMeshBar",
                     action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.menu = menu
    }

    @objc private func copyText(_ sender: NSMenuItem) {
        guard let s = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }

    @objc private func pickExit(_ sender: NSMenuItem) {
        guard let name = sender.representedObject as? String else { return }
        DispatchQueue.global().async {
            _ = CLI.run(["exit-node", name.isEmpty ? "off" : name])
            self.refresh()
        }
    }

    @objc private func openInbox(_ sender: NSMenuItem) {
        guard let dir = sender.representedObject as? String else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: dir))
    }

    @objc private func goDown() {
        DispatchQueue.global().async {
            _ = CLI.run(["down"])
            self.refresh()
        }
    }

    @objc private func sendFile(_ sender: NSMenuItem) {
        guard let peer = sender.representedObject as? String else { return }
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Send a file to \(peer) with OverDrop"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        DispatchQueue.global().async {
            let r = CLI.run(["drop", url.path, peer])
            DispatchQueue.main.async {
                let alert = NSAlert()
                if r.code == 0 {
                    alert.messageText = "Sent \(url.lastPathComponent) to \(peer)"
                } else {
                    alert.messageText = "Send failed"
                    alert.informativeText = r.out
                }
                alert.runModal()
            }
        }
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory) // menu bar only, no Dock icon
let delegate = AppDelegate()
app.delegate = delegate
app.run()
