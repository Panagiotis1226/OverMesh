import Foundation

// JSON shapes of overmeshd's control API (internal/daemon).

struct Peer: Decodable, Identifiable {
    var id: String { hostname }
    let hostname: String
    let ipv4: String
    let ipv6: String?
    let online: Bool
    let path: String // direct | lan | relay | connecting | none
    let rttMs: Int64?
    let routes: [String]?
    let offersExit: Bool?

    enum CodingKeys: String, CodingKey {
        case hostname, ipv4, ipv6, online, path, routes
        case rttMs = "rtt_ms"
        case offersExit = "offers_exit"
    }
}

struct MeshStatus: Decodable {
    let running: Bool
    let server: String?
    let network: String?
    let hostname: String?
    let ipv4: String?
    let ipv6: String?
    let conn: String? // connected | reconnecting
    let relay: String?
    let domain: String?
    let advertisedRoutes: [String]?
    let approvedRoutes: [String]?
    let exitNode: String?
    let exitNodeActive: Bool?
    let overdropDir: String?
    let peers: [Peer]?

    enum CodingKeys: String, CodingKey {
        case running, server, network, hostname, ipv4, ipv6, conn, relay, domain, peers
        case advertisedRoutes = "advertised_routes"
        case approvedRoutes = "approved_routes"
        case exitNode = "exit_node"
        case exitNodeActive = "exit_node_active"
        case overdropDir = "overdrop_dir"
    }
}

struct Transfer: Decodable, Identifiable {
    let id: Int64
    let file: String
    let peer: String
    let sent: Int64
    let total: Int64
    let state: String // sending | done | error
    let error: String?

    var fileName: String { (file as NSString).lastPathComponent }
    var fraction: Double { total > 0 ? Double(sent) / Double(total) : 0 }
}

struct TransfersResponse: Decodable { let transfers: [Transfer] }

struct InboxFile: Decodable, Identifiable {
    var id: String { path }
    let from: String
    let name: String
    let size: Int64
    let partial: Bool
    let modTime: Int64
    let path: String

    enum CodingKeys: String, CodingKey {
        case from, name, size, partial, path
        case modTime = "mod_time"
    }
}

struct InboxResponse: Decodable {
    let dir: String
    let files: [InboxFile]
}

struct DropResponse: Decodable { let id: Int64 }

func humanBytes(_ n: Int64) -> String {
    let f = ByteCountFormatter()
    f.countStyle = .file
    return f.string(fromByteCount: n)
}
