# PassWall2 OpenWrt Docker Sandbox (`passwall2-dev`)

Fast `x86_64` OpenWrt 24.10.1 + LuCI development and integration testing container with `NET_RAW` and `NET_ADMIN` capabilities for running `sni-spoof-rs`.

## Quick Start

From the repository root:

```bash
docker compose -f docker/compose.yml up -d --build
./docker/dev-install.sh
```

Open `http://localhost:8080` in your browser and sign in with:
- Username: `root`
- Password: `root`

Navigate to **Services -> PassWall 2 -> SNI Spoofer**.

## Syncing Local Changes

After editing any file under `luci-app-passwall2/`, re-sync in ~1 second without rebuilding the container:

```bash
./docker/dev-install.sh
```

## Testing Binaries Inside the Container

Because this container runs on `x86_64` Linux:
- Use `sni-spoof-rs-linux-amd64-musl` (via **GitHub Release** download or **Local Upload**) to start the daemon and inspect live logs in `passwall2-dev`.
- Select `sni-spoof-rs-google-wifi-armv7-musl` to verify cross-architecture ELF inspection (`ELF armv7`, `arch_match = false`) and safe install checks before deploying to a router.

## Useful Commands

```bash
docker exec -it passwall2-dev sh
docker exec passwall2-dev logread
docker exec passwall2-dev /etc/init.d/passwall2_sni_spoofer status
docker compose -f docker/compose.yml down
```
