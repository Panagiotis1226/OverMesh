import SwiftUI
import AppKit
import ServiceManagement
import UniformTypeIdentifiers

struct MenuContentView: View {
    @EnvironmentObject var app: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            Divider()
            if !app.daemonReachable {
                daemonHelp
            } else {
                selfInfo
                if app.isUp {
                    Divider()
                    devices
                }
                if app.isUp {
                    Divider()
                    exitNodeRow
                    routesRow
                }
                if !app.transfers.isEmpty || (app.inbox?.files.isEmpty == false) {
                    Divider()
                    overdropSection
                }
            }
            if let err = app.lastError {
                Divider()
                Text(err)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(4)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            Divider()
            footer
        }
        .padding(12)
        .frame(width: 340)
    }

    // MARK: header — profile switcher + connect toggle

    private var header: some View {
        HStack {
            Circle()
                .fill(app.isUp ? (app.status?.conn == "connected" ? .green : .orange) : .gray)
                .frame(width: 10, height: 10)
            if app.profiles.profiles.isEmpty {
                Text("No servers configured").font(.headline)
            } else {
                Menu {
                    ForEach(app.profiles.profiles) { p in
                        Button {
                            Task { await app.connect(p) }
                        } label: {
                            if p.id == app.profiles.activeID {
                                Label(p.name, systemImage: "checkmark")
                            } else {
                                Text(p.name)
                            }
                        }
                    }
                } label: {
                    Text(app.profiles.active?.name ?? "Choose server")
                        .font(.headline)
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
            Spacer()
            if app.busy {
                ProgressView().controlSize(.small)
            } else if app.isUp {
                Button("Disconnect") { Task { await app.disconnect() } }
            } else if let p = app.profiles.active {
                Button("Connect") { Task { await app.connect(p) } }
                    .disabled(p.server.isEmpty)
            }
        }
    }

    private var daemonHelp: some View {
        DaemonSetupView(svc: app.daemonSvc)
    }

    private var selfInfo: some View {
        Group {
            if let st = app.status, st.running {
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(st.hostname ?? "—").bold()
                        Text("@ \(st.network ?? "?")").foregroundStyle(.secondary)
                        Spacer()
                        Text(st.conn ?? "").font(.caption).foregroundStyle(.secondary)
                    }
                    if let ip = st.ipv4 {
                        CopyableText(label: ip, copyValue: ip)
                            .font(.system(.caption, design: .monospaced))
                    }
                    if let domain = st.domain {
                        Text("DNS: peers reachable as bare names (.\(domain))")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
            } else {
                Text("Not connected").foregroundStyle(.secondary)
            }
        }
    }

    // MARK: devices

    private var devices: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Devices").font(.caption).foregroundStyle(.secondary)
            if app.peers.isEmpty {
                Text("No other devices yet. Join one with a setup key from the web UI and it appears here — each row gets a \(Image(systemName: "paperplane")) button (or drag a file onto it) to send with OverDrop.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(app.peers) { peer in
                    PeerRow(peer: peer)
                }
            }
        }
    }

    // MARK: exit node

    private var exitNodeRow: some View {
        HStack {
            Text("Exit node").font(.caption).foregroundStyle(.secondary)
            Spacer()
            Menu {
                Button {
                    Task { await app.setExitNode(nil) }
                } label: {
                    if app.status?.exitNode?.isEmpty != false {
                        Label("None", systemImage: "checkmark")
                    } else {
                        Text("None")
                    }
                }
                ForEach(app.peers.filter { $0.offersExit == true }) { p in
                    Button {
                        Task { await app.setExitNode(p.hostname) }
                    } label: {
                        if app.status?.exitNode == p.hostname {
                            Label(p.hostname, systemImage: "checkmark")
                        } else {
                            Text(p.hostname)
                        }
                    }
                }
            } label: {
                HStack(spacing: 4) {
                    Text(app.status?.exitNode?.isEmpty == false ? (app.status?.exitNode ?? "") : "None")
                    if app.status?.exitNodeActive == true {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                    }
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }

    // MARK: subnet routes summary

    private var routesRow: some View {
        Group {
            if let adv = app.status?.advertisedRoutes, !adv.isEmpty {
                let approved = Set(app.status?.approvedRoutes ?? [])
                VStack(alignment: .leading, spacing: 2) {
                    Text("Offering routes").font(.caption).foregroundStyle(.secondary)
                    ForEach(adv, id: \.self) { r in
                        HStack {
                            Text(r).font(.system(.caption, design: .monospaced))
                            Spacer()
                            if approved.contains(r) {
                                Text("approved").font(.caption2).foregroundStyle(.green)
                            } else {
                                Text("awaiting approval").font(.caption2).foregroundStyle(.orange)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: OverDrop

    private var overdropSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(app.activeTransfers) { t in
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(t.fileName) → \(t.peer)").font(.caption)
                    ProgressView(value: t.fraction)
                    Text("\(humanBytes(t.sent)) / \(humanBytes(t.total))")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            if let inbox = app.inbox, !inbox.files.isEmpty {
                HStack {
                    Text("Inbox: \(inbox.files.count) file\(inbox.files.count == 1 ? "" : "s")")
                        .font(.caption)
                    Spacer()
                    Button("Open Folder") { app.openInboxFolder() }
                        .font(.caption)
                }
                ForEach(inbox.files.prefix(3)) { f in
                    HStack {
                        Text(f.name).font(.caption2).lineLimit(1)
                        Spacer()
                        Text("from \(f.from) · \(humanBytes(f.size))\(f.partial ? " · partial" : "")")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var footer: some View {
        HStack {
            SettingsLink { Text("Settings…") }
            Spacer()
            Button("Quit") { NSApp.terminate(nil) }
        }
        .font(.callout)
    }
}

// First-run setup: installs the bundled overmeshd as a launchd daemon
// through SMAppService — one click plus one approval in System
// Settings; no Terminal.
struct DaemonSetupView: View {
    @ObservedObject var svc: DaemonManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("OverMesh service is not running", systemImage: "exclamationmark.triangle")
                .font(.callout)
            if !svc.inApplications {
                Text("Move OverMesh.app into /Applications first — macOS only allows background services from there — then reopen it.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                switch svc.status {
                case .enabled:
                    Text("Service installed — starting up… (a few seconds on first run)")
                        .font(.caption).foregroundStyle(.secondary)
                case .requiresApproval:
                    Text("Approve OverMesh under Login Items & Extensions → Allow in Background.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Open System Settings") {
                        SMAppService.openSystemSettingsLoginItems()
                    }
                default:
                    Text("Install the bundled overmeshd as a background service (runs as root; you'll approve it once in System Settings).")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Install OverMesh Service") { svc.install() }
                        .buttonStyle(.borderedProminent)
                }
            }
            if let err = svc.lastError {
                Text(err).font(.caption).foregroundStyle(.red)
            }
        }
        .onAppear { svc.refresh() }
    }
}

// One device in the list: status dot, name, path badge, copyable IP,
// a send-file button, and drag-and-drop as a target.
struct PeerRow: View {
    @EnvironmentObject var app: AppState
    let peer: Peer
    @State private var dropHover = false

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(peer.online ? .green : .gray)
                .frame(width: 7, height: 7)
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 4) {
                    Text(peer.hostname).font(.callout)
                    if peer.offersExit == true {
                        Text("exit").font(.caption2)
                            .padding(.horizontal, 4).background(.blue.opacity(0.2))
                            .clipShape(Capsule())
                    }
                    if let routes = peer.routes, !routes.isEmpty {
                        Text("router").font(.caption2)
                            .padding(.horizontal, 4).background(.purple.opacity(0.2))
                            .clipShape(Capsule())
                    }
                }
                CopyableText(label: peer.ipv4, copyValue: peer.ipv4)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(pathLabel)
                .font(.caption2)
                .foregroundStyle(peer.path == "direct" || peer.path == "lan" ? .green : .secondary)
            if peer.online {
                Button {
                    pickAndSend()
                } label: {
                    Image(systemName: "paperplane")
                }
                .buttonStyle(.borderless)
                .help("Send a file to \(peer.hostname) (OverDrop)")
            }
        }
        .padding(4)
        .background(dropHover ? Color.accentColor.opacity(0.15) : .clear)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .onDrop(of: [UTType.fileURL], isTargeted: $dropHover) { providers in
            guard peer.online else { return false }
            for provider in providers {
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    if let url {
                        Task { @MainActor in await app.sendFile(url, to: peer) }
                    }
                }
            }
            return true
        }
    }

    private var pathLabel: String {
        var label = peer.path
        if let rtt = peer.rttMs, rtt > 0, peer.path == "direct" || peer.path == "lan" {
            label += " · \(rtt) ms"
        }
        return label
    }

    private func pickAndSend() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Send a file to \(peer.hostname) with OverDrop"
        if panel.runModal() == .OK, let url = panel.url {
            Task { await app.sendFile(url, to: peer) }
        }
    }
}

struct CopyableText: View {
    let label: String
    let copyValue: String
    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(copyValue, forType: .string)
            copied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { copied = false }
        } label: {
            HStack(spacing: 3) {
                Text(label)
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .imageScale(.small)
            }
        }
        .buttonStyle(.plain)
        .help("Copy")
    }
}
