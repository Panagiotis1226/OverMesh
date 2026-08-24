# OverMesh security model

What protects what, what the parts can and cannot see, and the trust
boundaries a self-hoster should understand. (Pre-1.0; an external
review of the auth and relay paths is planned before a public release.)

## Keys and identities

| Key | Lives | Purpose |
|---|---|---|
| Machine key (Curve25519) | node state dir, 0600 | permanent device identity; authenticates every control-plane call after enrollment |
| Node key (Curve25519) | node state dir, 0600 | WireGuard key; rotatable live (`overmesh rotate-key`); also authenticates to relays |
| Setup key (`sk-…`) | server DB; shown once in UI | enrollment bearer token; single-use or reusable, expiring, owner-bound |
| User passwords | server DB | bcrypt-hashed; sessions via HttpOnly cookies |

Private keys never leave the node. The server learns public keys only.

## Transport security

- **Peer traffic**: WireGuard end-to-end (Noise IK, ChaCha20-Poly1305)
  on every path — direct or relayed. This is the core guarantee.
- **Relay**: forwards *already-encrypted* WireGuard frames between
  authenticated clients. A relay (even a hostile one) sees only
  ciphertext, sizes, timing, and the two node public keys — it cannot
  read, forge, or replay tunnel traffic (WG handles replay). Client
  auth is a nacl/box challenge proving possession of the node private
  key. TLS on the relay adds outer privacy (hides even the OMR
  protocol) and firewall traversal, not confidentiality of payloads.
- **Control plane**: gRPC, optionally TLS (`-tls-cert/-tls-key` or a
  terminating proxy — recommended on the internet). Netmaps contain
  topology (names, IPs, endpoints, public keys), not traffic.
- **Web UI/API**: session cookies over the private listener; see
  docs/OPERATIONS.md for keeping it off the internet entirely.

## Enforcement points

- **ACLs** compile server-side to per-node packet filters enforced in
  the node's data path (both directions wrap the TUN device) — not
  just at the UI. A peer that ignores its netmap still can't bypass
  your node's own inbound filter.
- **OverDrop** binds only the overlay IP and derives sender identity
  from the WireGuard-cryptokey-bound source address; ACLs (tcp/41645)
  gate it.
- **RBAC**: members manage only their own devices/keys; ACLs, routes,
  users, and the audit log are admin-only, enforced server-side.
- **Audit log** is append-only in the DB.

## Threat notes

- **Compromised server**: can add nodes, change ACLs/netmaps (it is
  the control plane) — but cannot decrypt peer traffic, past or
  future, since it never holds private keys. Protect it like an SSO/CA
  box; keep the UI private; use TLS; back up the DB securely.
- **Compromised relay**: metadata only (who talks to whom, when, how
  much). Run your own; add TLS.
- **Stolen setup key**: can enroll a device under the key's owner
  until it expires or is revoked — treat like a join token, prefer
  single-use keys, revoke in the UI.
- **Stolen node state dir**: full device impersonation until the
  device is deleted in the UI (which cuts it off at the next netmap)
  — same blast radius as any VPN client credential.
- **DoS**: the relay drops frames toward stalled clients rather than
  buffering unboundedly; gRPC keepalive policing caps ping abuse.

## Reporting

Pre-1.0: open a private GitHub security advisory on the repository.
