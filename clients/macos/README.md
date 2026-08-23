# OverMeshBar (macOS menu bar app)

A minimal menu bar companion for `overmeshd`: connection state at a
glance, peer list with copy-IP, exit-node picker, "Send file…" via
OverDrop, and one-click access to the OverDrop inbox.

**Status: experimental.** It builds with Swift 5.9+ on macOS 13+, but
it is not compiled in CI (CI has no macOS/Xcode toolchain for it yet),
so treat it as a scaffold that tracks the CLI.

## Setup

1. Put `overmeshd` and `overmesh` in `/usr/local/bin` (CI darwin
   artifacts or a source build).
2. Run the daemon with a group-accessible control socket, so the app
   (running as your user) can drive it without sudo:

   ```sh
   sudo overmeshd -socket-group admin &
   sudo overmesh up -server <server>:41641 -key sk-...
   ```

   Your account must be in the `admin` group (macOS default for the
   first user). Anyone in that group can control the mesh — that is
   the tradeoff for a sudo-less UI.

3. Build and run the app:

   ```sh
   cd clients/macos/OverMeshBar
   swift build -c release
   .build/release/OverMeshBar &
   ```

The v0 app shells out to the `overmesh` CLI rather than speaking the
control socket directly — one code path for humans and UI. A proper
signed .app bundle with drag-and-drop lands with the packaging polish.
