import SwiftUI

// Settings window: server profiles (the multi-server switcher's data)
// and the daemon socket path.
struct SettingsView: View {
    @EnvironmentObject var app: AppState
    @State private var selection: UUID?

    var body: some View {
        HSplitView {
            profileList
                .frame(minWidth: 170, maxWidth: 220)
            editor
                .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(width: 620, height: 420)
        .onAppear { selection = app.profiles.activeID ?? app.profiles.profiles.first?.id }
    }

    private var profileList: some View {
        VStack(alignment: .leading, spacing: 0) {
            List(selection: $selection) {
                ForEach(app.profiles.profiles) { p in
                    HStack {
                        Text(p.name)
                        if p.id == app.profiles.activeID {
                            Spacer()
                            Image(systemName: "circle.fill")
                                .foregroundStyle(.green).imageScale(.small)
                        }
                    }
                    .tag(p.id)
                }
            }
            Divider()
            HStack(spacing: 12) {
                Button {
                    let p = Profile()
                    app.profiles.upsert(p)
                    selection = p.id
                } label: { Image(systemName: "plus") }
                Button {
                    if let sel = selection { app.profiles.remove(sel) }
                    selection = app.profiles.profiles.first?.id
                } label: { Image(systemName: "minus") }
                    .disabled(selection == nil)
                Spacer()
            }
            .buttonStyle(.borderless)
            .padding(6)
        }
    }

    @ViewBuilder
    private var editor: some View {
        if let sel = selection,
           let idx = app.profiles.profiles.firstIndex(where: { $0.id == sel }) {
            ProfileEditor(profile: Binding(
                get: { app.profiles.profiles[idx] },
                set: { app.profiles.upsert($0) }
            ))
        } else {
            VStack(spacing: 8) {
                Text("Add a server profile to get started.")
                    .foregroundStyle(.secondary)
                advanced
            }
            .padding()
        }
    }

    private var advanced: some View {
        Form {
            TextField("Daemon socket", text: app.$socketPath)
                .font(.system(.body, design: .monospaced))
        }
    }
}

struct ProfileEditor: View {
    @EnvironmentObject var app: AppState
    @Binding var profile: Profile

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $profile.name)
                TextField("Server (host:41641)", text: $profile.server)
                    .font(.system(.body, design: .monospaced))
                SecureField("Setup key (sk-…, first join only)", text: $profile.setupKey)
                Toggle("Connect over TLS", isOn: $profile.useTLS)
            }
            Section("Subnet routing") {
                TextField("Advertise routes (comma-separated CIDRs)",
                          text: $profile.advertiseRoutes,
                          prompt: Text("192.168.1.0/24, 10.0.0.0/8"))
                    .font(.system(.body, design: .monospaced))
                Toggle("Offer this Mac as an exit node", isOn: $profile.advertiseExitNode)
                Text("Routes and exit-node offers need one-click admin approval in the web UI before they carry traffic.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section {
                HStack {
                    Button(app.profiles.activeID == profile.id && app.isUp
                           ? "Reconnect with these settings" : "Connect") {
                        Task { await app.connect(profile) }
                    }
                    .disabled(profile.server.isEmpty || app.busy)
                    if app.busy { ProgressView().controlSize(.small) }
                    Spacer()
                }
                TextField("Daemon socket", text: app.$socketPath)
                    .font(.system(.caption, design: .monospaced))
                HStack {
                    Text("Background service: \(app.daemonSvc.statusLabel)")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Uninstall Service") {
                        Task { await app.daemonSvc.uninstall() }
                    }
                    .font(.caption)
                }
            }
        }
        .formStyle(.grouped)
        .padding()
        .onAppear { app.daemonSvc.refresh() }
    }
}
