# Packaging

Everything needed to deploy OverMesh outside a dev checkout.

| Path | What |
|---|---|
| `systemd/overmeshd.service` | Node daemon unit (installed by the deb/rpm) |
| `systemd/overmesh-server.service` | Control-plane unit (installed by the server deb/rpm) |
| `docker/Dockerfile.server` | Control-plane container image |
| `docker/docker-compose.yml` | One-command self-hosted control plane |
| `nfpm/*.yaml` | deb/rpm definitions — CI attaches built packages to every run |
| `homebrew/overmesh.rb` | Formula template for a Homebrew tap (macOS) |

## Quick recipes

**Server via Docker (recommended for the control plane):**

```sh
cd packaging/docker
printf 'ADMIN_PASSWORD=choose-one\nPUBLIC_HOST=vpn.example.com\n' > .env
docker compose up -d
```

**Node via deb/rpm:** download `overmesh_<ver>_linux_<arch>.deb` (or
`.rpm`) from the CI run's artifacts, then:

```sh
sudo dpkg -i overmesh_*.deb        # or: sudo rpm -i overmesh-*.rpm
sudo systemctl enable --now overmeshd
sudo overmesh up -server <server>:41641 -key sk-...
```

**macOS:** the Homebrew formula is a template until releases are
tagged; until then use the CI `overmesh_darwin_*` artifacts directly
(`sudo ./overmeshd &`, `sudo ./overmesh up ...`).
