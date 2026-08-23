# OverMesh on Windows

The daemon runs as a Windows **service** on the userspace WireGuard
data plane (Wintun adapter — the same driver Tailscale and the
official WireGuard client use). Everything the CLI does on
Linux/macOS works here too: join, status, ping by bare hostname*,
OverDrop send/receive, key rotation.

Not yet on Windows (same phased story as macOS): *being* a subnet
router or exit node, and *using* an exit node. Consuming peers'
approved subnet routes works.

## Install

1. GitHub → Actions → latest green run → Artifacts →
   `overmesh_windows_amd64` (unzip somewhere).
2. Copy `clients/windows/install.ps1` next to the unzipped
   `overmeshd.exe`/`overmesh.exe` (the CI artifact includes it).
3. Elevated PowerShell:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\install.ps1
   overmesh up -server <your-server>:41641 -key sk-...
   overmesh status
   ```

The service starts automatically at boot and resumes the session.
Uninstall with `uninstall.ps1`.

\* Bare hostnames use the mesh suffix on the adapter plus the global
DNS suffix search list (restored on down). If a corporate policy
manages that registry value, use FQDNs (`node.default.mesh`) —
they always work.

## Notes

- `overmeshd.exe -service install|uninstall|start|stop` manages the
  service directly; run the daemon in a console with just
  `overmeshd.exe` for troubleshooting.
- State (keys, enrollment, OverDrop inbox) lives in
  `%ProgramData%\OverMesh`.
- The control socket is an AF_UNIX socket in the same folder
  (Windows 10 1803+).
- MSI packaging is future work; the CI zip + install.ps1 is the
  supported path today.
