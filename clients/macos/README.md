# OverMesh for macOS

A SwiftUI **menu bar app** over the local `overmeshd` daemon:

- **Server profiles** — save several OverMesh servers (address, setup
  key, TLS, routes) and switch between them from the menu bar; the
  device keeps one identity, so a setup key is only needed the first
  time it joins each server.
- **Devices** — live peer list with online state, connection path
  (direct / lan / relay) and RTT, copyable overlay IPs, and exit/router
  badges.
- **OverDrop** — send a file to any online device (paperplane button or
  drag & drop onto the device row), watch progress live, and browse the
  inbox of received files.
- **Exit node** — pick any peer that offers exit (note: exit-node
  *consumption* is currently implemented in the Linux daemon; the
  picker surfaces the daemon's answer on other platforms).
- **Subnet routing** — advertise LAN routes (or offer this Mac as an
  exit node) per profile, with live approved/awaiting-approval status.

The app is a thin UI: all networking lives in `overmeshd`, reached over
its unix control socket.

## Requirements

- macOS 14+, Xcode 15+ (tested with Xcode 27), XcodeGen
  (`brew install xcodegen`)
- `overmeshd` installed and running with a group-accessible socket:

  ```sh
  sudo overmeshd -socket-group admin
  ```

  (`admin` is the default group of macOS administrator accounts;
  members of the group get full control of the daemon.)

## Build

```sh
cd clients/macos
xcodegen generate
open OverMesh.xcodeproj   # select the OverMesh scheme, sign, Run
```

or from the command line:

```sh
xcodebuild -project OverMesh.xcodeproj -scheme OverMesh -configuration Release build
```

## First use

1. Click the OverMesh icon in the menu bar → **Settings…** → add a
   profile: name, `server:41641`, setup key from the web UI, TLS if
   your server has it.
2. **Connect**. The menu shows your overlay IP, the device list, and
   OverDrop.
3. Add more profiles to switch servers from the menu-bar header at any
   time (switching disconnects from the current server first).
