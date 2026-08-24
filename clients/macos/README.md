# OverMesh for macOS

A SwiftUI **menu bar app** with the daemon **built in** — install the
app, click once, and the Mac is a mesh node:

- **Server profiles** — save several OverMesh servers (address, setup
  key, TLS, routes) and switch between them from the menu bar; the
  device keeps one identity, so a setup key is only needed the first
  time it joins each server.
- **Devices** — live peer list with online state, connection path
  (direct / lan / relay) and RTT, copyable overlay IPs, exit/router
  badges.
- **OverDrop** — send a file to any online device (paperplane button or
  drag & drop onto the device row), watch progress live, browse the
  inbox.
- **Exit node** — pick any peer that offers exit; traffic routes
  through it (half-default routes on the tunnel, with automatic
  loop-protection host routes for the daemon's own connections).
- **Subnet routing** — advertise LAN routes per profile, with live
  approved/awaiting-approval status.

## Install (no build needed)

1. GitHub → Actions → latest green run → artifact
   **overmesh-macos-app** → unzip.
2. Move `OverMesh.app` into **/Applications** (required: macOS only
   allows apps there to register background services).
3. The build is unsigned (no Apple Developer certificate), so macOS
   quarantines it. Clear that once:

   ```sh
   xattr -dr com.apple.quarantine /Applications/OverMesh.app
   ```

   (`spctl -a` will still say "rejected" — that's Gatekeeper's verdict
   on any non-notarized app and is only enforced while the quarantine
   flag is present. Notarization arrives with an Apple Developer ID.)

4. Open the app → click **Install OverMesh Service** → approve it in
   System Settings (Login Items & Extensions → Allow in Background).
   That registers the bundled `overmeshd` as a root launch daemon —
   no Terminal, no separate install.
5. Menu bar icon → **Settings…** → add a profile (server `host:41641`
   + setup key from the web UI) → **Connect**.

From then on it works like Tailscale: the icon is your on/off switch,
devices and file drops are one click away, and profiles switch servers.

## Build from source (alternative)

Requirements: macOS 14+, Xcode 15+ (tested with Xcode 27), Go 1.26+,
XcodeGen (`brew install xcodegen`).

```sh
cd clients/macos
xcodegen generate
open OverMesh.xcodeproj   # sign with your Apple ID, Run
```

A run-script build phase compiles `overmeshd` + `overmesh` (universal
arm64+amd64) into the app bundle, and the LaunchDaemon plist ships in
`Contents/Library/LaunchDaemons/`.

## Notes

- The `overmesh` CLI ships inside the bundle as `overmesh-cli` (the
  name `overmesh` would collide with the app's own `OverMesh` binary
  on macOS's case-insensitive filesystem). For terminal use:

  ```sh
  sudo ln -s /Applications/OverMesh.app/Contents/MacOS/overmesh-cli /usr/local/bin/overmesh
  ```

- The service logs to `/var/log/overmeshd.log`.
- Uninstall: Settings… → Uninstall Service (or delete the app after
  uninstalling; the daemon state lives in `/var/lib/overmesh` and the
  overlay identity survives reinstalls).
- If you previously ran `overmeshd` manually or via another launchd
  job, stop that one first — two daemons can't share the control
  socket.
