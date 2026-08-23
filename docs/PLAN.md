# OverMesh — Build Plan

**OverMesh** is a fully self-hostable overlay mesh VPN in the Tailscale / NetBird class: a WireGuard data plane, a self-hosted control plane, NAT holepunching, an embedded DERP-style relay with guaranteed TCP/TLS fallback, a Taildrop-style file drop ("OverDrop"), overlay DNS, Web-UI-managed ACLs, and exit nodes tuned for maximum throughput.

Guiding decisions:

- **Reuse proven open-source libraries** (wireguard-go, gVisor netstack, pion) rather than reinventing protocols.
- **Local auth first** (pre-auth setup keys + local admin accounts); OIDC SSO arrives in a later phase.
- **Web admin UI built alongside the control plane from the start** — it grows a little every phase, and everything an admin does (including ACLs) is doable in the UI, never via config files.
- **Platforms:** Linux servers/desktops + macOS first; Windows, iOS, Android in later phases.
- **Connectivity guarantee:** if NAT traversal fails, traffic always falls back to the relay's TCP/TLS connection on port 443 — two nodes that can both reach a relay can always talk.

---

## Tech stack (chosen for speed, connectivity, and low device footprint)

| Concern | Choice | Why |
|---|---|---|
| Language (server + daemon) | **Go** | wireguard-go, wgctrl, gVisor netstack, pion are all Go; single static binaries; gomobile for iOS/Android later; same language everywhere = one codebase for the hard networking logic |
| Data plane (Linux) | **Kernel WireGuard via `wgctrl-go` (netlink)**, fallback wireguard-go | Kernel module is the fastest path (no user↔kernel copies) — critical for exit-node throughput |
| Data plane (macOS) | **wireguard-go on utun** | No kernel extension needed; Apple-sanctioned path |
| Data plane (fallback/mobile later) | **wireguard-go + gVisor netstack** | Userspace TCP/IP stack; also enables running without TUN (containers, userspace-only mode) |
| NAT traversal | **pion/stun for discovery + pion/ice for holepunch signaling** | Battle-tested (NetBird uses pion); revisit later with a leaner Tailscale-disco-style path prober as an optimization, not a prerequisite |
| Relay | **Custom DERP-style relay ("OMR"), embedded in the server binary and standalone** | Small framed protocol over TLS :443 (HTTP upgrade), packets addressed by WireGuard public key. ~1–2k LOC; DERP's design is public and simple. Works through the worst firewalls because it looks like HTTPS |
| Control channel | **gRPC (protobuf) with a server→client netmap stream** | Typed schema shared by daemon, CLI, and mobile later; streams give instant netmap pushes |
| Admin API | **REST (JSON) generated alongside gRPC** (grpc-gateway or ConnectRPC) | Web UI and third-party scripting without protobuf tooling |
| Server storage | **SQLite (modernc.org/sqlite, pure Go) default; Postgres optional** | Zero-dependency self-hosting; Postgres for bigger installs |
| Web UI | **React + TypeScript + Vite + Tailwind, embedded via `go:embed`** | Single-binary self-hosting including the UI |
| Overlay DNS | **miekg/dns** in the daemon (MagicDNS-style local resolver) | Proven Go DNS library |
| Overlay IPs | **IPv4 default 100.96.0.0/11 (upper half of CGNAT space — deliberately NOT Tailscale's full 100.64.0.0/10) + a distinct IPv6 ULA prefix (e.g. fdab:3f19::/48) per network; both configurable per network in the Web UI** | CGNAT space still avoids colliding with home/office LANs, but the default range differs from Tailscale's so OverMesh and Tailscale can coexist on one machine without address clashes |
| macOS menu bar app | **SwiftUI wrapper talking to the Go daemon over local gRPC/unix socket** | Native feel, tiny; daemon stays the single source of truth |
| Windows (later) | **WireGuardNT kernel driver + Go daemon + tray app** | WireGuardNT is the fastest Windows data plane |
| iOS/Android (later) | **gomobile-built core (netstack mode) + NetworkExtension / VpnService shells** | Reuses the entire Go engine; this is exactly how Tailscale/NetBird ship mobile |

Licensing: all dependencies are MIT/BSD/Apache-2; OverMesh's own license (BSD-3 vs AGPL) to be decided before public release.

## Repository layout (monorepo)

```
overmesh/
├── cmd/
│   ├── overmesh-server/     # control plane + embedded relay + embedded web UI
│   ├── overmeshd/           # node daemon (Linux/macOS)
│   ├── overmesh/            # user CLI (talks to overmeshd via unix socket)
│   └── overmesh-relay/      # standalone relay (same code the server embeds)
├── internal/
│   ├── coord/               # netmap engine, device registry, gRPC services
│   ├── ipam/                # overlay address allocation
│   ├── auth/                # setup keys, node keys, sessions (OIDC later)
│   ├── relay/               # OMR relay protocol: server + client
│   ├── magicsock/           # the "smart socket": direct/relay path selection, STUN, ICE, roaming
│   ├── wgengine/            # kernel-WG (wgctrl) and userspace-WG (wireguard-go) drivers
│   ├── netmap/              # network map types + diffing
│   ├── policy/              # ACL compilation into per-node packet filters
│   ├── dns/                 # overlay DNS resolver
│   ├── drop/                # OverDrop file transfer
│   └── netstack/            # gVisor userspace networking mode
├── proto/                   # protobuf: coordination, relay frames, local daemon API
├── webui/                   # React + TS + Vite, embedded by the server build
├── clients/macos/           # SwiftUI menu bar app (Phase 6)
└── test/lab/                # netns/docker NAT-simulation lab, iperf harness
```

---

## Phases

Each phase is small, independently testable, and ends with a concrete **exit test** so troubleshooting stays local to what just changed.

### Phase 0 — Foundations & walking skeleton (~1 week)

- Monorepo scaffolding, Go workspace, protobuf toolchain, CI (lint, test, cross-compile linux/amd64+arm64, darwin/arm64).
- Protobuf v1 of the coordination protocol: `RegisterNode`, `StreamNetMap`, key types (node key = WG public key + separate machine identity key).
- `test/lab/`: docker-compose + Linux network-namespace lab that can simulate NAT types (full-cone, port-restricted, symmetric) — built FIRST so every later phase has a reproducible network testbed.
- **Exit test:** all binaries build on CI for Linux + macOS; lab spins up and namespaces can/can't reach each other as configured.

### Phase 1 — Control plane core + static mesh (Linux + macOS daemons)

- Server: SQLite schema (users, networks, nodes, setup keys), node registration via one-time/reusable **setup keys**, IPAM (default 100.96.0.0/11 + OverMesh ULA v6 prefix, overridable per network), netmap computation, gRPC netmap stream.
- Daemon: registers, receives netmap, programs WireGuard — **kernel WG via wgctrl on Linux, wireguard-go/utun on macOS** — with *direct, known endpoints only* (same LAN / public IPs). Persistent node identity on disk.
- CLI: `overmesh up --server https://… --key sk-…`, `status`, `ping`.
- Web UI v0 (embedded): login (local admin), device list with online status, create/revoke setup keys, delete device.
- **Exit test:** two lab nodes on the same subnet + one Mac register and ping each other over overlay IPs; device list shows all three live.

### Phase 2 — NAT holepunching

- `magicsock` v1: STUN discovery of public endpoint (pion/stun), candidate exchange through a server-relayed signaling channel, **pion/ice** holepunch, WG endpoint switched to the winning candidate pair; persistent keepalives; **endpoint roaming** (Wi-Fi→hotspot mid-session re-punches without dropping the tunnel).
- Server hosts 1+ STUN listeners so self-hosters need nothing external (configurable extra STUN servers).
- **Exit test:** lab matrix — cone↔cone punches direct (including endpoint roaming recovery); any pairing involving a symmetric NAT fails *cleanly* into a "no path" state (netfilter cone NATs are port-restricted, and port-restricted↔symmetric is not holepunchable — honest relay territory for Phase 3); `overmesh status` shows `direct <ip:port> (rtt)` vs `connecting` vs `none`.

### Phase 3 — Embedded DERP-style relay (OMR) + fail-open connectivity

- OMR protocol: TLS (+ HTTP/1.1 upgrade on :443), client authenticates by proving node key; frames = `(dst_pubkey, wg_payload)`; server pipes frames between connected clients. Embedded in `overmesh-server` **and** standalone `overmesh-relay` for multi-region; relays are dumb/stateless — they never see plaintext (payloads are WG-encrypted).
- Client logic (the trick that makes connectivity feel instant): **connect via relay immediately, then race holepunching in the background and transparently upgrade to direct**. **Guaranteed fallback: whenever NAT holepunching/traversal fails or a direct path dies, traffic automatically falls back to the DERP-style relay's TCP/TLS connection — a peer pair is never left unreachable just because UDP can't get through** (worst case: both sides symmetric NAT or UDP blocked entirely → relay carries the tunnel over TCP 443). Relay map + latency-based home-relay selection distributed in the netmap.
- Signaling from Phase 2 moves onto relay frames (works even when the coordination server is briefly unreachable).
- **Exit test:** symmetric↔symmetric lab pair gets connectivity via relay in <2s; cone↔cone starts on relay and upgrades to direct within seconds; killing the direct path fails over to relay without dropping an SSH session.

### Phase 4 — Overlay DNS + ACL policy engine

- MagicDNS-style: daemon runs a local resolver on the overlay, serves `<node>.<network>.mesh` (configurable base domain), forwards everything else; OS DNS configured per platform (resolved/resolv.conf on Linux, scoped resolvers on macOS).
- ACLs: **managed entirely in the Web UI — no config files.** Policy lives as structured rows in the database (rules: src users/groups/tags → dst nodes/tags + ports/protocols), edited through a visual rule builder (dropdown pickers for users/groups/tags/nodes, port fields, allow/deny toggles, drag-to-reorder). Rules compile into per-node packet filters distributed via netmap and **enforced on the receiving node** (Tailscale model); default policy = allow-all inside a network. An import/export (JSON) button exists for backup/automation, but it is never the editing interface.
- Web UI: visual ACL builder with inline validation + dry-run tester ("can A reach B:22?" answered live before saving), groups/tags management page, DNS settings page.
- **Exit test:** `ssh nodename` works by name on both platforms; a deny rule blocks port 22 between two tagged nodes while ping stays allowed.

### Phase 5 — Exit nodes, subnet routers, and the throughput pass

- **Exit node:** node advertises `0.0.0.0/0, ::/0`; admin approves in UI; clients select it (`overmesh up --exit-node=…`); exit node does IP forwarding + nftables masquerade; client-side kill-switch-safe routing (policy routing on Linux, route scoping on macOS).
- **Subnet router:** advertise arbitrary routes (e.g. `10.0.0.0/24`) for non-mesh LAN devices; same approval flow.
- **Throughput pass (this is where "most throughput possible" is earned):**
  - Linux exit nodes: kernel WireGuard always preferred; detect module availability and say so in `overmesh status`.
  - Userspace path: enable **UDP GSO/GRO + TUN vnet_hdr offloads** in wireguard-go (this is what took Tailscale from ~2 to ~10 Gbps userspace).
  - MTU: default 1280, **per-path PMTU probing** to run 1420 where possible; avoid relay double-overhead accounting bugs.
  - Relay throughput: buffer tuning (SO_RCVBUF/SNDBUF), per-client send queues with drop policy so one slow client can't stall the relay.
  - Publish an `iperf3` benchmark harness in `test/lab/` + CI perf job with regression thresholds (direct, relayed, exit-node NAT'd).
- **Exit test:** browser traffic egresses via exit node (IP check); iperf3 through a kernel-WG Linux exit node reaches near-line-rate on the lab hosts; baseline numbers recorded in the repo.

### Phase 6 — OverDrop (Taildrop-style file transfer) + macOS menu bar app

- OverDrop: each daemon exposes an HTTP/2 service **bound only to the overlay IP**; peer identity = WG source (cryptographically bound); send: stream with resume (offset requests); receive: staged inbox dir + accept flow; ACL-gated (`overdrop` capability in policy). CLI: `overmesh drop <file> <node>`.
- macOS menu bar app (SwiftUI): connect/disconnect, node list with copy-IP, exit-node picker, OverDrop drag-and-drop onto a peer; talks to `overmeshd` over local unix-socket gRPC.
- Packaging: Homebrew tap (macOS), deb/rpm + systemd unit (Linux), `overmesh-server` docker image + compose example.
- **Exit test:** drag a 2 GB file Mac→Linux over a relayed path; interrupt mid-transfer and resume; ACL can block drops between two nodes.

### Phase 7 — user accounts, roles, key rotation, audit log

(Rescoped by decision: **no OIDC/SSO for now** — local accounts only;
SSO may return as a future phase.)

- Local accounts (username + bcrypt password): admins create users in the web UI, plus an optional **open-signup toggle**; legacy single-admin installs migrate to user `admin` automatically.
- Roles: admin = everything; **member = own devices only** — setup keys carry an owner, devices enroll under the key's owner, and ACLs/route approvals/user management are admin-only (403).
- **Node key rotation:** `overmesh rotate-key` swaps the WireGuard key live (device first, then re-register; peers re-handshake off the netmap push).
- Audit log: append-only trail (logins, user/key/device events, ACL + route changes, rotations) with a read-only web UI card.
- **Exit test:** member sees only their own device and is 403'd elsewhere; signup 404s until toggled on; rotation keeps connectivity (proven by ping recovery); audit contains the expected trail.

### Phase 8 — Windows client

- Daemon as a Windows service using the **WireGuardNT** kernel driver (fastest Windows data plane) via wireguard-go's driver bindings; Wintun fallback.
- Tray app (WinUI or lightweight Go tray) mirroring the macOS feature set; MSI installer.
- **Exit test:** Windows laptop behind NAT reaches Linux nodes direct, uses exit node, receives an OverDrop file.

### Phase 9 — iOS + Android

- Core engine compiled with **gomobile**; data plane = wireguard-go + **gVisor netstack** where TUN semantics differ; iOS **NetworkExtension (NEPacketTunnelProvider)** — mind the ~50 MB extension memory cap: netmap trimming, lazy allocations, no web-UI assets in the client; Android **VpnService** + Kotlin UI.
- Battery discipline: push-based netmap (no polling), adaptive keepalives, idle relay connection coalescing.
- **Exit test:** iPhone on LTE ↔ home Linux node direct or via relay; exit node works on both mobile OSes; app survives background/foreground cycles.

### Phase 10 — Hardening & 1.0

- Prometheus metrics + `/healthz` on server and relay; structured logs; `overmesh netcheck` (NAT type, relay latencies, port 443 reachability) and `overmesh bugreport`.
- Control-plane HA notes (Postgres mode + stateless server replicas behind LB; relays already horizontally scalable), backup/restore docs, threat-model doc, external security review of auth + relay code paths, versioned protocol compatibility policy (old clients keep working one minor version back).
- **Exit test:** kill -9 the server → existing tunnels keep passing traffic (data plane independent of control plane); server restore-from-backup drill; upgrade drill N-1 client vs N server.

---

## Performance principles (applied throughout, verified in Phase 5's harness)

1. Kernel WireGuard on Linux wherever possible — exit nodes and subnet routers especially.
2. Userspace fallback must run with UDP GSO/GRO + TUN offloads enabled, not naive per-packet I/O.
3. Direct paths always preferred; relay is a bootstrap and a fallback, and path upgrade is automatic and transparent.
4. PMTU-aware: biggest safe MTU per path instead of a blanket 1280.
5. Mobile/laptop footprint: event-driven netmap streams, adaptive keepalives, no polling loops.
