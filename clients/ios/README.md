# OverMesh for iOS

A SwiftUI app plus an `NEPacketTunnelProvider` extension. All mesh
logic — WireGuard, NAT holepunching, the guaranteed relay fallback,
ACL packet filter, mesh DNS (`ps-iPhone` bare names), OverDrop
receiving — lives in `mobilecore` (Go), bound into
`Mobilecore.xcframework` with gomobile. The Swift layer is thin: it
hands the utun file descriptor to the core and programs
`NEPacketTunnelNetworkSettings` from the core's `OnNetMap` callback.

The exact same core is exercised in CI on Linux over a real TUN fd
(`test/integration/phase9.sh`), so everything below the Swift glue is
continuously tested.

## Requirements

- macOS with Xcode 26+ (tested with Xcode 27 beta 5) and a **paid**
  Apple Developer Program membership: the
  `packet-tunnel-provider` entitlement is not granted to free personal
  teams, and Network Extensions don't run in the simulator — running
  on a real device requires the paid account. Without one you can
  still compile everything (and the same core is fully exercised by
  CI's Linux TUN-fd test).
- Go 1.26+ (`brew install go` or https://go.dev/dl)
- XcodeGen (`brew install xcodegen`)

## Build

```sh
# 1. From the repo root: bind the Go core into an xcframework
clients/ios/build-ios.sh

# 2. Generate the Xcode project
cd clients/ios
xcodegen generate

# 3. Open, sign, run
open OverMesh.xcodeproj
```

In Xcode: select the OverMesh scheme, set your team on both the
**OverMesh** and **PacketTunnel** targets (Signing & Capabilities —
both need the Network Extensions capability, which the generated
entitlements already request), pick your iPhone, and Run.

## First join

1. On the phone, enter your coordination server (`host:41641`), a
   setup key from the web UI (Setup Keys → New key), and a device
   name (e.g. `ps-iPhone`).
2. Tap Connect and accept the iOS VPN permission prompt.
3. The device appears in the web UI; other nodes can reach it by
   bare name (`ping ps-iPhone`) and send it files
   (`overmesh drop photo.jpg ps-iPhone`). Received files land in the
   extension's `Application Support/overmesh/overdrop/<sender>/`
   container.

The setup key is only needed once — the device keeps its identity in
the extension container and reconnects with it.

## Notes

- TLS: leave the toggle on when your server has `-tls-cert/-tls-key`
  or sits behind a TLS proxy; switch it off for a plain-text lab
  server.
- Battery: the core is push-based (no netmap polling); on
  `sleep`/`wake` the provider tells the core to widen WireGuard
  keepalives via `SetForeground`.
- Exit nodes and subnet-route *advertising* are desktop features for
  now; the phone consumes approved subnet routes automatically.
