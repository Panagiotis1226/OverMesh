import Foundation

// A saved OverMesh server. Switching profiles is `down` + `up` on the
// daemon — the device keeps one identity (machine key) across servers,
// so a setup key is only needed the first time it joins each server.
struct Profile: Codable, Identifiable, Equatable {
    var id = UUID()
    var name: String = "New server"
    var server: String = "" // host:41641
    var setupKey: String = "" // sk-…; used on first join, then ignorable
    var useTLS: Bool = false
    var advertiseRoutes: String = "" // comma-separated CIDRs
    var advertiseExitNode: Bool = false

    var routesList: [String] {
        var routes = advertiseRoutes
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        if advertiseExitNode {
            routes.append(contentsOf: ["0.0.0.0/0", "::/0"])
        }
        return routes
    }
}

final class ProfileStore: ObservableObject {
    @Published var profiles: [Profile] {
        didSet { save() }
    }
    @Published var activeID: UUID? {
        didSet { UserDefaults.standard.set(activeID?.uuidString, forKey: "activeProfileID") }
    }

    var active: Profile? {
        profiles.first { $0.id == activeID }
    }

    init() {
        if let data = UserDefaults.standard.data(forKey: "profiles"),
           let list = try? JSONDecoder().decode([Profile].self, from: data) {
            profiles = list
        } else {
            profiles = []
        }
        if let s = UserDefaults.standard.string(forKey: "activeProfileID") {
            activeID = UUID(uuidString: s)
        }
        if activeID == nil { activeID = profiles.first?.id }
    }

    private func save() {
        if let data = try? JSONEncoder().encode(profiles) {
            UserDefaults.standard.set(data, forKey: "profiles")
        }
    }

    func upsert(_ p: Profile) {
        if let i = profiles.firstIndex(where: { $0.id == p.id }) {
            profiles[i] = p
        } else {
            profiles.append(p)
        }
        if activeID == nil { activeID = p.id }
    }

    func remove(_ id: UUID) {
        profiles.removeAll { $0.id == id }
        if activeID == id { activeID = profiles.first?.id }
    }
}
