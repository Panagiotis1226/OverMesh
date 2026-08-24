# Operating OverMesh

Practical notes for self-hosters: firewall ports, keeping the web UI
private, monitoring, backup/restore, HA, and upgrades.

## Ports

Only three things on the **server host** need to be reachable by nodes;
everything else can stay closed or local.

| Port | Proto | What | Where | Must be open? |
|---|---|---|---|---|
| 41641 | TCP | gRPC coordination (registration, netmap stream, signaling) | server | **Yes** — every node connects here |
| 3478 | UDP | STUN (NAT endpoint discovery) | server | **Yes** for direct paths; without it everything still works via relay |
| 41643 | TCP | OMR relay (guaranteed fallback path; HTTP upgrade at `/relay`) | server | **Yes** — this is the connectivity guarantee |
| 8080 | TCP | Web UI + admin API + `/metrics` | server | **No** — keep it private (see below) |
| 41642 | UDP | WireGuard + ICE on every node | each node | **No** — outbound holepunching handles it; opening it inbound on a public-IP node improves direct-path odds |
| 41645 | TCP | OverDrop receiver | each node | Never — binds the overlay IP only, unreachable from the internet |
| 53 | UDP/TCP | mesh DNS | each node | Never — binds the overlay IP only |

Extra relays (`overmesh-relay`) listen on `-listen` (default `:3443`);
open that TCP port wherever you run one. For the strictest client
networks, run the relay on **443 with TLS** (`-relay-listen :443
-tls-cert ... -tls-key ...`, or a standalone relay behind a TLS proxy):
it then looks like ordinary HTTPS.

## Keeping the web UI private

The relay has its own listener precisely so the UI never needs public
exposure. Options, combinable:

- **Bind local only**: `-http 127.0.0.1:8080` — then administer via SSH
  port-forward (`ssh -L 8080:127.0.0.1:8080 server`) …
- **… or over the mesh itself**: bind `-http <server's overlay IP>:8080`
  once the server host is also a node, and the UI is reachable only from
  inside the VPN.
- Docker: publish as `127.0.0.1:8080:8080`.

The gRPC port (41641) must stay reachable, but it only speaks the node
protocol (setup-key/machine-key authenticated) — no admin surface.

## Monitoring

- `GET /healthz` on the web-UI listener, the relay listener, and the
  standalone relay.
- `GET /metrics` (Prometheus text) on the web-UI listener: registered
  nodes, online nodes, netmap pushes, relay clients / frames / bytes /
  drops. The standalone relay serves its own `/metrics`.
- On any node: `overmesh netcheck` (control plane, STUN, relay
  reachability + latencies) and `overmesh bugreport` (paste-ready
  diagnostics, secret-free).

## Backup & restore

All control-plane state is one SQLite database:
`<state-dir>/server.db` (default `overmesh-server-data/`, packages use
`/var/lib/overmesh-server`).

- **Backup**: stop the server and copy the file, or use
  `sqlite3 server.db ".backup backup.db"` live. Nightly cron of the
  `.backup` variant is plenty.
- **Restore**: place the file in the state dir and start the server.
  Nodes reconnect and re-stream netmaps automatically; nothing
  node-side needs re-enrolling (identities live on the nodes).
- **What's in it**: node registrations, users (bcrypt hashes), setup
  keys, ACLs, routes, audit log. Treat backups as sensitive.

The **data plane survives control-plane loss**: established WireGuard
tunnels (direct and relayed via other relays) keep passing traffic
while the server is down — verified by the Phase 10 exit test. New
joins, netmap changes, and the embedded relay are unavailable until
it returns.

## High availability notes

- The server is a single writer over SQLite: HA today means fast
  restart (systemd `Restart=on-failure`) + backups, which the
  data-plane independence above makes tolerable.
- Relays are stateless — run several (`overmesh-relay`) in different
  regions and list them with `-relay-extra`; nodes race and pick the
  fastest, and any one of them keeps the mesh connected.
- A Postgres storage backend + stateless server replicas behind a load
  balancer is the intended 1.x path; the store is already isolated
  behind one interface.

## Upgrades

- Compatibility policy: a node one minor version behind the server
  keeps working (netmaps are additive; unknown fields are ignored).
  Upgrade the server first, then nodes at leisure.
- Nodes: upgrade the package and restart `overmeshd` — tunnels
  re-establish in seconds; peers ride the relay in the meantime.
