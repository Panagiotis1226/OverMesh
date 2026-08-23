# OverMesh

A fully self-hostable **WireGuard-based overlay mesh VPN** — control plane included — in the Tailscale / NetBird class.

> Status: **Phase 1 complete** — working mesh on a LAN: self-hosted control plane (SQLite + gRPC netmap streaming + embedded web UI), setup-key enrollment, WireGuard programmed automatically (kernel on Linux, wireguard-go/utun on macOS), overlay pings between real nodes. NAT traversal (Phase 2) and the relay (Phase 3) are next. See [`docs/PLAN.md`](docs/PLAN.md).

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

Phase 1 speaks to the control plane in the clear — use it on trusted
networks; TLS + internet exposure arrive with Phase 2.

## What it will do

- **WireGuard data plane** — kernel WireGuard on Linux for maximum throughput, wireguard-go/utun on macOS, WireGuardNT on Windows (later), gVisor netstack on mobile (later).
- **Self-hosted control plane** — single static Go binary with an embedded web admin UI and SQLite storage (Postgres optional). No external services required.
- **NAT holepunching** — STUN discovery + ICE holepunch, endpoint roaming, direct connections whenever the network allows.
- **Embedded DERP-style relay** — TLS on :443, embedded in the server and deployable standalone. If holepunching fails or a direct path dies, traffic **always falls back to the relay's TCP/TLS connection** — two nodes that can reach a relay can always talk. Direct-path upgrade happens automatically in the background.
- **OverDrop** — Taildrop-style peer-to-peer file transfer over the mesh, with resume.
- **Exit nodes & subnet routers** — with a dedicated throughput pass (kernel WG, UDP GSO/GRO offloads, PMTU probing) to make exit-node speed a first-class feature.
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
| 5 | Exit nodes, subnet routers, throughput pass (kernel WG, GSO/GRO, PMTU) |
| 6 | OverDrop file transfer + macOS menu bar app + packaging |
| 7 | OIDC SSO, roles, key rotation, audit log |
| 8 | Windows client (WireGuardNT) |
| 9 | iOS + Android (gomobile + netstack) |
| 10 | Hardening, metrics, HA, security review → 1.0 |

Full details, exit tests per phase, and design rationale: [`docs/PLAN.md`](docs/PLAN.md).

## Development

```sh
make build       # all four binaries into ./bin (needs Go 1.25+)
make test        # unit tests with the race detector
make tools proto # regenerate gRPC/protobuf code after editing proto/
sudo test/lab/lab.sh up && sudo test/lab/lab.sh verify   # NAT lab (Linux)
```

Prebuilt binaries for linux/darwin × amd64/arm64 are attached to every CI
run — GitHub → Actions → pick the latest run → Artifacts. The NAT lab is
documented in [`test/lab/README.md`](test/lab/README.md).
