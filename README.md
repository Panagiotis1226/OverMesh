# OverMesh

A fully self-hostable **WireGuard-based overlay mesh VPN** — control plane included — in the Tailscale / NetBird class.

> Status: **Phase 10 in progress — hardening & operations**. The relay now has its **own listener (:41643)** so the web UI can stay local-only (`-http 127.0.0.1:8080`); Prometheus `/metrics` on server and relay; `overmesh netcheck` and `overmesh bugreport`; ops docs ([`docs/OPERATIONS.md`](docs/OPERATIONS.md), [`docs/SECURITY.md`](docs/SECURITY.md)); exit-tested: tunnels keep passing traffic through a `kill -9` of the control plane, and a backup/restore drill reconnects every node without re-enrolling. Phase 9 shipped the **iOS client** (gomobile core over the packet-tunnel fd, CI-proven on Linux; builds with Xcode 27). See [`docs/PLAN.md`](docs/PLAN.md).

## Quickstart (LAN)

```sh
# On the server machine:
./overmesh-server -admin-password 'choose-one'
# open http://<server>:8080, sign in, create a setup key

# On each device (Linux or macOS, as root):
sudo ./overmeshd &
sudo ./overmesh up -server <server>:41641 -key sk-...
sudo ./overmesh status
sudo ./overmesh ping <other-device>
```

For the internet: add `-tls-cert/-tls-key` (or a TLS reverse proxy),
and keep the web UI private with `-http 127.0.0.1:8080` — nodes never
need it.

### Ports

| Port | Proto | What | Open it? |
|---|---|---|---|
| 41641 | TCP | gRPC coordination (server) | **yes** — every node connects here |
| 3478 | UDP | STUN (server) | **yes** for direct paths (relay still works without) |
| 41643 | TCP | OMR relay, guaranteed fallback (server) | **yes** |
| 8080 | TCP | web UI + API + metrics (server) | no — keep local/VPN-only |
| 41642 | UDP | WireGuard on every node | no — outbound holepunching suffices |
| 41645, 53 | TCP/UDP | OverDrop + mesh DNS on every node | never — they bind the overlay IP only |

Details, private-UI setups, monitoring, backup/restore:
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) · threat model:
[`docs/SECURITY.md`](docs/SECURITY.md).

## What it will do

- **WireGuard data plane** — kernel WireGuard on Linux for maximum throughput, wireguard-go/utun on macOS, WireGuardNT on Windows (later), gVisor netstack on mobile (later).
- **Self-hosted control plane** — single static Go binary with an embedded web admin UI and SQLite storage (Postgres optional). No external services required.
- **NAT holepunching** — STUN discovery + ICE holepunch, endpoint roaming, direct connections whenever the network allows.
- **Embedded DERP-style relay** — TLS on :443, embedded in the server and deployable standalone. If holepunching fails or a direct path dies, traffic **always falls back to the relay's TCP/TLS connection** — two nodes that can reach a relay can always talk. Direct-path upgrade happens automatically in the background.
- **OverDrop** — Taildrop-style peer-to-peer file transfer: `overmesh drop <file> <peer>`, resumable, relay-capable, ACL-gated; files land in a per-sender inbox (`overmesh inbox`).
- **Exit nodes & subnet routers** — devices offer routes (`-advertise-routes`, `-advertise-exit-node`), admins approve them with one click in the web UI, and clients opt in with `overmesh exit-node <name>`. Kernel WireGuard recommended for dedicated exit nodes; `-mtu 1420` on known-good underlays; iperf3 bench harness included.
- **Overlay DNS** — MagicDNS-style `<node>.<network>.mesh` names.
- **Web-UI-first administration** — devices, setup keys, and **ACLs managed entirely through a visual rule builder in the web UI**, never through config files.
- **Distinct addressing** — defaults to `100.96.0.0/11` + an OverMesh-specific IPv6 ULA prefix (not Tailscale's exact ranges), so both can coexist on one machine; configurable per network.

## Architecture at a glance

```
                    ┌──────────────────────────────────┐
                    │        overmesh-server           │
                    │  control plane · web UI · STUN   │
                    │      · embedded OMR relay        │
                    └───────┬──────────────┬───────────┘
              netmap stream │              │ netmap stream
               (gRPC/TLS)   │              │
                    ┌───────┴────┐   ┌─────┴──────┐
                    │ overmeshd  │   │ overmeshd  │
                    │  node A    │   │  node B    │
                    └─────┬──────┘   └─────┬──────┘
                          │   WireGuard    │
                          ├───direct UDP───┤   ← holepunched when possible
                          └──relay (TCP)───┘   ← guaranteed fallback via OMR
```

## Planned stack

Go (server, daemon, CLI, relay) · wireguard-go + wgctrl · pion/stun + pion/ice · gVisor netstack · gRPC/protobuf · SQLite (Postgres optional) · React + TypeScript web UI embedded via `go:embed` · SwiftUI menu bar app on macOS.

## Roadmap

| Phase | Deliverable |
|---|---|
| 0 | Foundations: monorepo, protobuf schema, CI, NAT-simulation test lab |
| 1 | Control plane + setup keys + web UI v0; Linux/macOS daemons; static mesh |
| 2 | NAT holepunching (STUN/ICE) + endpoint roaming |
| 3 | Embedded DERP-style relay + guaranteed TCP fallback + direct upgrade |
| 4 | Overlay DNS + visual ACL builder in the web UI |
| 5 | Exit nodes, subnet routers, web-UI route approval, MTU tuning, bench harness |
| 6 | OverDrop file transfer + packaging (deb/rpm/docker/brew) + macOS menu bar scaffold |
| 7 | User accounts (login/signup) + roles, node key rotation, audit log |
| 8 | Windows client (service + Wintun + installer script) |
| 9 | iOS client (gomobile core + packet tunnel); Android deferred to a later phase |
| 10 | Hardening, metrics, HA, security review → 1.0 |

Full details, exit tests per phase, and design rationale: [`docs/PLAN.md`](docs/PLAN.md).

## Development

```sh
make build       # all four binaries into ./bin (needs Go 1.26+)
make test        # unit tests with the race detector
make tools proto # regenerate gRPC/protobuf code after editing proto/
sudo test/lab/lab.sh up && sudo test/lab/lab.sh verify   # NAT lab (Linux)
```

The iOS app (gomobile core + packet tunnel) builds on a Mac — see
[`clients/ios/README.md`](clients/ios/README.md).

Prebuilt binaries for linux/darwin × amd64/arm64 are attached to every CI
run — GitHub → Actions → pick the latest run → Artifacts. The NAT lab is
documented in [`test/lab/README.md`](test/lab/README.md).
