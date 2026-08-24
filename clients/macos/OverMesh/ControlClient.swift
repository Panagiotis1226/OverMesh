import Foundation
import Network

// Minimal HTTP/1.1 client over overmeshd's unix control socket.
// URLSession can't dial unix sockets, so this speaks just enough HTTP
// itself: one connection per request, "Connection: close", read to EOF.
struct ControlClient {
    var socketPath: String

    enum ControlError: LocalizedError {
        case daemon(String)     // the daemon answered with an error body
        case unreachable(String)
        case badResponse

        var errorDescription: String? {
            switch self {
            case .daemon(let m): return m
            case .unreachable(let m): return "overmeshd unreachable: \(m)"
            case .badResponse: return "malformed response from overmeshd"
            }
        }
    }

    func get<T: Decodable>(_ path: String, as type: T.Type) async throws -> T {
        try JSONDecoder().decode(T.self, from: try await request("GET", path, body: nil))
    }

    func post<T: Decodable>(_ path: String, body: [String: Any], as type: T.Type) async throws -> T {
        let data = try JSONSerialization.data(withJSONObject: body)
        return try JSONDecoder().decode(T.self, from: try await request("POST", path, body: data))
    }

    @discardableResult
    func post(_ path: String, body: [String: Any] = [:]) async throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: body)
        return try await request("POST", path, body: data)
    }

    private func request(_ method: String, _ path: String, body: Data?) async throws -> Data {
        let conn = NWConnection(to: .unix(path: socketPath), using: .tcp)

        var head = "\(method) \(path) HTTP/1.1\r\nHost: overmeshd\r\nConnection: close\r\n"
        if let body {
            head += "Content-Type: application/json\r\nContent-Length: \(body.count)\r\n"
            head += "\r\n"
            var payload = Data(head.utf8)
            payload.append(body)
            return try await roundTrip(conn, payload)
        }
        head += "\r\n"
        return try await roundTrip(conn, Data(head.utf8))
    }

    private func roundTrip(_ conn: NWConnection, _ payload: Data) async throws -> Data {
        defer { conn.cancel() }
        try await start(conn)
        try await send(conn, payload)
        let raw = try await receiveAll(conn)
        return try parseResponse(raw)
    }

    private func start(_ conn: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            let done = Locked(false)
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if done.take() { c.resume() }
                case .failed(let err), .waiting(let err):
                    if done.take() { c.resume(throwing: ControlError.unreachable(err.localizedDescription)) }
                default:
                    break
                }
            }
            conn.start(queue: .global())
        }
    }

    private func send(_ conn: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { err in
                if let err { c.resume(throwing: ControlError.unreachable(err.localizedDescription)) }
                else { c.resume() }
            })
        }
    }

    private func receiveAll(_ conn: NWConnection) async throws -> Data {
        var out = Data()
        while true {
            let (chunk, complete): (Data?, Bool) = try await withCheckedThrowingContinuation { c in
                conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, complete, err in
                    if let err { c.resume(throwing: ControlError.unreachable(err.localizedDescription)) }
                    else { c.resume(returning: (data, complete)) }
                }
            }
            if let chunk { out.append(chunk) }
            if complete { return out }
        }
    }

    private func parseResponse(_ raw: Data) throws -> Data {
        guard let sep = raw.range(of: Data("\r\n\r\n".utf8)) else { throw ControlError.badResponse }
        let headText = String(decoding: raw[..<sep.lowerBound], as: UTF8.self)
        let body = raw[sep.upperBound...]
        guard let statusLine = headText.split(separator: "\r\n").first,
              statusLine.hasPrefix("HTTP/1."),
              let code = Int(statusLine.split(separator: " ").dropFirst().first ?? "") else {
            throw ControlError.badResponse
        }
        if code >= 400 {
            struct ErrBody: Decodable { let error: String }
            if let e = try? JSONDecoder().decode(ErrBody.self, from: Data(body)) {
                throw ControlError.daemon(e.error)
            }
            throw ControlError.daemon("HTTP \(code)")
        }
        return Data(body)
    }
}

// Tiny once-guard so a state handler resumes its continuation exactly once.
private final class Locked: @unchecked Sendable {
    private var flag: Bool
    private let lock = NSLock()
    init(_ v: Bool) { flag = v }
    /// Returns true only on the first call.
    func take() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if flag { return false }
        flag = true
        return true
    }
}
