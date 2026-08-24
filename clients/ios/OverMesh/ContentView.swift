import SwiftUI
import NetworkExtension

struct ContentView: View {
    @StateObject private var tunnel = TunnelManager()
    @AppStorage("server") private var server = ""
    @AppStorage("hostname") private var hostname = UIDevice.current.name
        .replacingOccurrences(of: " ", with: "-")
    @AppStorage("tls") private var tls = true
    // The setup key is one-shot enrollment material; keep it out of
    // @AppStorage (UserDefaults) and let the user paste it when joining.
    @State private var setupKey = ""

    private var isUp: Bool {
        tunnel.vpnStatus == .connected || tunnel.vpnStatus == .connecting
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Coordination server") {
                    TextField("host:41641", text: $server)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    TextField("Setup key (sk-…, first join only)", text: $setupKey)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Device name", text: $hostname)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Toggle("TLS", isOn: $tls)
                }

                Section {
                    Button(isUp ? "Disconnect" : "Connect") {
                        if isUp {
                            tunnel.disconnect()
                        } else {
                            Task {
                                await tunnel.connect(server: server, setupKey: setupKey,
                                                     hostname: hostname, tls: tls)
                            }
                        }
                    }
                    .disabled(server.isEmpty && !isUp)
                    LabeledContent("Status", value: tunnel.vpnStatus.label)
                    if !tunnel.selfIPv4.isEmpty {
                        LabeledContent("Overlay IP", value: tunnel.selfIPv4)
                    }
                    if !tunnel.networkName.isEmpty {
                        LabeledContent("Network", value: tunnel.networkName)
                    }
                    if !tunnel.lastError.isEmpty {
                        Text(tunnel.lastError).foregroundStyle(.red).font(.footnote)
                    }
                }

                if !tunnel.peers.isEmpty {
                    Section("Peers") {
                        ForEach(tunnel.peers) { peer in
                            HStack {
                                Circle()
                                    .fill(peer.online ? .green : .gray)
                                    .frame(width: 8, height: 8)
                                VStack(alignment: .leading) {
                                    Text(peer.hostname)
                                    Text(peer.ipv4).font(.footnote)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(peer.path).font(.footnote)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("OverMesh")
        }
    }
}
