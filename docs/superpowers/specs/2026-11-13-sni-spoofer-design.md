# Design Spec: SNI Spoofer Integration, `status.htm` Update, and Docker Dev Sandbox

**Date:** 2026-11-13  
**Package:** `luci-app-passwall2` (`openwrt-passwall2`)  
**Target Companion Binary:** `sni-spoof-rs` from [`mohamadtsn/sni-spoofing-rust`](https://github.com/mohamadtsn/sni-spoofing-rust) (default router target `sni-spoof-rs-google-wifi-armv7-musl`)

---

## 1. Goals and Scope

Add a dedicated **SNI Spoofer** section to `luci-app-passwall2` that operates as an independent background service within PassWall2, incorporates the user's status view updates from `temp/status.htm`, and provides a fast `x86_64` OpenWrt + LuCI Docker test environment in the repository.

### In Scope
1. Independent `SNI Spoofer` service (`/etc/init.d/passwall2_sni_spoofer` + `/usr/share/passwall2/sni_spoofer.sh`), UCI schema in `/etc/config/passwall2`, and migration defaults in `uci-defaults`.
2. Binary installation via **both** local chunked file upload and direct download from GitHub Releases (`mohamadtsn/sni-spoofing-rust`), defaulting to `sni-spoof-rs-google-wifi-armv7-musl` with selectable architecture builds (`sni-spoof-rs-linux-amd64-musl`, `sni-spoof-rs-linux-arm64`), ELF header/arch inspection, atomic replacement, and `sysupgrade.conf` persistence.
3. Full configuration parity with `sni-spoof-rs/src/config.rs` (global settings + dynamic `listeners[]`) with live preview of the generated `config.json`.
4. LuCI dashboard (`template` view) styled to adapt cleanly to active light/dark LuCI themes (`bootstrap` and `argon`), offering service control (Start, Stop, Restart, Boot Auto-Start), live status/binary telemetry, interactive config editor, and real-time log viewer (`RUST_LOG`, `NO_COLOR=1`, copytruncate cap at 512 KiB).
5. Merge `temp/status.htm` into `luci-app-passwall2/luasrc/view/passwall2/global/status.htm` while restoring line 11's Pure CSS license URL comment back to `github.com`.
6. Repository-level `docker/` environment (`openwrt/rootfs` x86_64 + `uhttpd` + `LuCI` + `rpcd` + `NET_RAW`/`NET_ADMIN`) with an instant repo-sync installer script (`docker/dev-install.sh`).

### Explicitly Out of Scope
- Embedding `sni-spoof-rs` into PassWall2's core `app.sh` / firewall / proxy start-stop lifecycle.
- Interactive `sni-spoof-rs scan` UI job orchestration inside LuCI.
- Persian (`.po`) translation additions (English UI strings only, with `dir="ltr"` on technical fields such as IPs, paths, hashes, JSON, and logs).

---

## 2. File Inventory & Unit Boundaries

### Package Files (`luci-app-passwall2/`)
| Path | Action | Responsibility |
| --- | --- | --- |
| `luasrc/passwall2/sni_spoofer.lua` | Create | Single source of truth for UCI config read/write, strict field & conflict validation, `config.json` generation, ELF header parsing, binary checksum/metadata, GitHub release fetching, chunked upload assembly, sysupgrade registration, and daemon status/log queries. |
| `luasrc/controller/passwall2.lua` | Modify | Register `SNI Spoofer` menu entry (priority `94`) and HTTP/JSON RPC endpoints with `test_post_security()` checks on mutations. |
| `luasrc/view/passwall2/sni_spoofer/index.htm` | Create | Main LuCI view template rendering the 5-card dashboard and loading dedicated CSS/JS assets. |
| `htdocs/luci-static/resources/view/passwall2/sni_spoofer.css` | Create | Theme-adaptive Light/Dark CSS tokens, responsive 12-column -> single-column layout, 44px touch targets, accessible focus styles, and console styling. |
| `htdocs/luci-static/resources/view/passwall2/sni_spoofer.js` | Create | Client-side state controller: status polling, Start/Stop/Restart actions, chunked base64 upload, GitHub release check + download progress polling, listener builder with UTF-8 byte counter and live JSON preview, and interactive log console. |
| `root/etc/init.d/passwall2_sni_spoofer` | Create | OpenWrt `rc.common` (`START=99`) service entrypoint managing boot autostart (`boot()`) and delegating `start`, `stop`, `restart`, `status` to `sni_spoofer.sh`. |
| `root/usr/share/passwall2/sni_spoofer.sh` | Create | Shell daemon runner: calls `sni_spoofer.lua` to validate & emit `/tmp/etc/passwall2/sni_spoofer/config.json`, enforces `RUST_LOG` + `NO_COLOR=1`, starts/stops PID-tracked daemon cleanly, and caps `/tmp/log/passwall2_sni_spoofer.log` via copytruncate. |
| `root/usr/share/passwall2/0_default_config` | Modify | Append default `global_sni_spoofer` section and one disabled example `sni_spoofer_listener`. |
| `root/etc/uci-defaults/luci-app-passwall2` | Modify | Idempotently create `global_sni_spoofer` when upgrading existing `/etc/config/passwall2` installs and register default `bin_path` in `/etc/sysupgrade.conf`. |
| `luasrc/view/passwall2/global/status.htm` | Modify | Apply `temp/status.htm` updates (IRAN `my.gov.ir`, Instagram, SVGs, accessibility fixes) and fix line 11 license URL comment (`github.com`). |

### Repository Docker Files (`docker/`)
Placed at repo root (`docker/`) so OpenWrt `luci-app-passwall2/Makefile` (`luci.mk`) packaging remains untouched:
- `docker/Dockerfile`
- `docker/compose.yml`
- `docker/entrypoint.sh`
- `docker/dev-install.sh`
- `docker/README.md` (concise usage instructions, commands to start, install/update code, and test)

---

## 3. Data Model & Configuration Contract

### 3.1 UCI Schema (`/etc/config/passwall2`)
Global daemon section (`config global_sni_spoofer 'global_sni_spoofer'`):
- `enabled`: `'0'` | `'1'` (controls boot autostart; manual Start/Restart from UI works regardless, with clear boot-sync switch)
- `bin_path`: string, default `'/usr/bin/sni-spoof-rs'`
- `rust_log`: `'error'` | `'warn'` | `'info'` | `'debug'` | `'trace'`, default `'warn'`
- `idle_timeout`: optional positive integer seconds (`''` -> `null` / omitted in JSON)
- `buffer_size`: integer KiB (`>= 1`), default `'8'`
- `graceful_shutdown_sec`: integer seconds (`>= 0`), default `'0'`
- `github_asset`: string, default `'sni-spoof-rs-google-wifi-armv7-musl'`
- `bin_version`: cached tag string recorded when downloaded from GitHub (empty for manual upload)
- `bin_sha256`: cached lowercase SHA-256 hex digest of the installed binary

Listener sections (`config sni_spoofer_listener`):
- `enabled`: `'0'` | `'1'`, default `'1'`
- `remarks`: optional human label string
- `listen`: `SocketAddr` (`IP:Port`), default `'127.0.0.1:40443'`
- `connect`: `SocketAddr` (`IP:Port` strictly IPv4/IPv6 + port, no hostnames per `sni-spoof-rs/src/config.rs`)
- `fake_sni`: hostname/string, default `'security.vercel.com'` (1 to 219 UTF-8 bytes)
- `conn_timeout_sec`: integer (`>= 1`), default `'5'`
- `handshake_timeout_sec`: integer (`>= 1`), default `'2'`
- `keepalive_time_sec`: integer (`>= 1`), default `'11'`
- `keepalive_interval_sec`: integer (`>= 1`), default `'2'`

Because `/etc/config/passwall2` is already listed in `Makefile` `conffiles` and `controller/passwall2.lua` `backup_files`, SNI Spoofer config automatically participates in PassWall2 backups, restores, and OpenWrt sysupgrades.

### 3.2 Generated JSON & Validation Invariants (`sni_spoofer.lua`)
Matches [`sni-spoof-rs/src/config.rs`](file:///home/mohamadtsn/projects/rust/sni-spoofing-rust/src/config.rs):
- Generated path: `/tmp/etc/passwall2/sni_spoofer/config.json`.
- Only `enabled == '1'` listeners are emitted into JSON `listeners[]`. (UI allows saving disabled draft listeners; daemon start requires at least 1 enabled listener.)
- Validation rules enforced both in JS (inline feedback) and Lua (authoritative pre-save and pre-start):
  - `bin_path` must be an absolute path without shell metacharacters, not pointing to a directory.
  - `buffer_size >= 1`, `graceful_shutdown_sec >= 0`, `idle_timeout` either empty or integer `>= 1`.
  - Every enabled listener must have:
    - Valid `listen` and `connect` parsed as IPv4 `a.b.c.d:port` or bracketed IPv6 `[addr]:port` with `1 <= port <= 65535`.
    - `not connects_to_listener(listen, connect)`: rejects identical IP:Port and rejects `connect` targeting loopback (`127.0.0.1` / `::1`) when `listen` binds wildcard (`0.0.0.0` / `::`) on the same port, matching `config.rs`.
    - No two enabled listeners bind the exact same `listen` IP:Port.
    - `fake_sni` non-empty and `#fake_sni <= 219` UTF-8 bytes.
    - Timing fields positive integers `>= 1`.

---

## 4. Background Service, Binary Lifecycle & Live Logging

### 4.1 Service Lifecycle (`passwall2_sni_spoofer` + `sni_spoofer.sh`)
- PID file: `/var/run/passwall2_sni_spoofer.pid`.
- Lock file: `/var/lock/passwall2_sni_spoofer.lock`.
- Log file: `/tmp/log/passwall2_sni_spoofer.log`.
- `boot()` in `/etc/init.d/passwall2_sni_spoofer` checks `uci -q get passwall2.global_sni_spoofer.enabled` and only starts if `'1'`.
- `start` runs `/usr/share/passwall2/sni_spoofer.sh start`:
  1. Guards against duplicate running PID using `/proc/<pid>/cmdline` check against configured `bin_path`.
  2. Verifies `bin_path` exists, is regular file, has `\x7fELF` header, and is executable (`chmod +x` if needed).
  3. Invokes Lua generator to validate UCI config and emit `/tmp/etc/passwall2/sni_spoofer/config.json`. On validation error, appends timestamped error to log and exits non-zero.
  4. Caps log size before start if `> 524288` bytes via `copytruncate` (retaining last ~256 KiB in the same inode).
  5. Exports `RUST_LOG=<rust_log>` and `NO_COLOR=1` (preventing ANSI escape codes from polluting plain text log output since `tracing_subscriber::fmt()` defaults to ANSI enabled), then starts `"$bin_path" "$config_file" >> "$log_file" 2>&1 &` (or via `start-stop-daemon` when available) and writes PID.
  6. Briefly checks after ~300 ms that the child did not immediately crash on startup (e.g., missing capability / port already in use / wrong ELF arch); if it exited immediately, cleans PID file and reports tail log error.
- `stop`: sends `SIGTERM`, waits up to `max(2, graceful_shutdown_sec + 1)` seconds, falls back to `SIGKILL` if still alive, cleans PID file.
- `restart`: executes `stop` then `start`.
- Log bounding on read: `sni_spoofer.lua` checks log file size on poll and performs in-place `copytruncate` if `> 524288` bytes so long-running `debug`/`trace` sessions cannot exhaust router `/tmp` tmpfs without breaking open `O_APPEND` descriptors.

### 4.2 Binary Inspection & Installation (Local Upload + GitHub Release)
- **Pure Lua ELF Inspection:** Reads first 20 bytes + `uname -m` without external `file`/`readelf`:
  - Checks `\x7fELF` magic (`0x7f 45 4c 46`).
  - Reads `e_machine` respecting `EI_DATA` endianness: maps `0x28` -> `armv7/arm`, `0xB7` -> `aarch64`, `0x3E` -> `x86_64`, `0x08` -> `mips`, `0xF3` -> `riscv64`.
  - Computes `arch_match` against `uname -m` so UI displays an explicit compatibility badge (`Compatible` vs `Cross-arch binary: ELF armv7 on x86_64 host`) without blocking saving a router binary on a test host.
  - Note on `sni-spoof-rs` CLI (`src/main.rs`): `sni-spoof-rs` only recognizes `scan`, `-h`/`--help`, or `[CONFIG]` (passing `--version` treats it as a config file path and fails). Therefore executability verification on matching architectures uses `<bin> --help` (`exit 0`, checking `stderr`/`stdout` contains `sni-spoof-rs`), NEVER `--version`.
- **Chunked Upload (`sni_spoofer_upload`):**
  - Frontend slices file into 192 KiB chunks, Base64-encodes each chunk, sends `{ upload_id, bin_path, filename, chunk_index, total_chunks, chunk }`.
  - Backend validates `upload_id` pattern (`^[%w_-]+$`), appends decoded bytes to `/tmp/sni_spoof_upload.<upload_id>`, checks final chunk for `\x7fELF` magic + destination free space (`api.get_free_space`), stops running service if active (`was_running` flag), moves atomically (`mv -f`), `chmod 0755`, computes SHA-256, updates `global_sni_spoofer`, registers path in `/etc/sysupgrade.conf`, and restarts service if `was_running` and host arch matches.
- **Direct GitHub Download (`sni_spoofer_release_info` + `sni_spoofer_download`):**
  - Queries `https://api.github.com/repos/mohamadtsn/sni-spoofing-rust/releases/latest` (prefixing `@global_app[0].gh_proxy_url` if set, following PassWall2 convention).
  - Extracts `tag_name`, `published_at`, and downloadable assets prioritizing `sni-spoof-rs-google-wifi-armv7-musl`, `sni-spoof-rs-linux-amd64-musl`, and `sni-spoof-rs-linux-arm64`.
  - If GitHub API returns rate-limit/error, UI still allows direct `releases/latest/download/<selected_asset>` fallback URL download.
  - Download executes in background or tracked temp path (`/tmp/sni_spoof_dl.<task_id>`) using `curl`, allowing frontend polling of `progress` (downloaded bytes vs expected asset size), followed by optional SHA-256 verification (against GitHub asset `digest` when present), `\x7fELF` validation, free space check, atomic install, and metadata persistence.

---

## 5. LuCI Controller & Frontend Architecture

### 5.1 Controller Endpoints (`luci-app-passwall2/luasrc/controller/passwall2.lua`)
Menu entry added under `admin -> services -> passwall2`:
`entry({"admin", "services", appname, "sni_spoofer"}, template(appname .. "/sni_spoofer/index"), _("SNI Spoofer"), 94).leaf = true`

API endpoints (mutations require `POST` + `luci.dispatcher.test_post_security()`):
- `sni_spoofer_status` (`GET`): live process status (`running`, `pid`, `uptime_sec`, `enabled`), `host_arch`, binary inspection object, UCI global/listeners snapshot, live `config.json` preview + validation warnings, `log_bytes`.
- `sni_spoofer_control` (`POST`): `action` in `{ start, stop, restart, set_boot }` -> executes control command and returns fresh status + error string if action fails.
- `sni_spoofer_save` (`POST`): accepts JSON payload `{ global: {...}, listeners: [...], restart: bool }` -> validates cleanly, updates UCI atomically, optionally restarts service, returns updated status + validation errors if any.
- `sni_spoofer_upload` (`POST`): chunked binary upload handler.
- `sni_spoofer_release_info` (`GET`): fetches latest release info from `mohamadtsn/sni-spoofing-rust`.
- `sni_spoofer_download` (`POST`): `task=start` / `task=progress` async binary fetch & install.
- `sni_spoofer_log` (`GET`/`POST`): `GET` returns recent log lines + size/truncated flag; `POST action=clear` truncates `/tmp/log/passwall2_sni_spoofer.log`.

### 5.2 Visual Design & UI Structure (`index.htm` + `sni_spoofer.css` + `sni_spoofer.js`)
Design direction: **Theme-Adaptive OpenWrt Control Plane** (Direction A approved by user):
- Uses CSS custom properties (`--ss-bg`, `--ss-surface`, `--ss-surface-muted`, `--ss-border`, `--ss-text`, `--ss-muted`, `--ss-accent`, `--ss-ok`, `--ss-warn`, `--ss-err`) tuned cleanly for both Light and Dark LuCI themes (`@media (prefers-color-scheme: dark)` plus `[data-theme="dark"]` / dark background detection for `argon`), verified >= 4.5:1 text contrast and >= 3:1 UI component contrast.
- Responsive single-page 5-card architecture with explicit **Empty / Loading / Error / Ready** states (`antislop` R-27) and zero dead controls or fabricated metrics (`antislop` R-17, R-26, R-36):
  1. **Service Status & Control Header:** Status badge (`Running` / `Stopped` / `Binary Missing`), real `PID` & `Uptime` (hidden/dash when stopped), Boot Autostart switch, **Start / Stop / Restart** action buttons with busy spinner/disabled guard.
  2. **Binary Manager Card:** Current binary telemetry (installed path, size, short SHA-256, release tag if downloaded, detected ELF arch vs host arch). Tabbed installer (`GitHub Release` default `sni-spoof-rs-google-wifi-armv7-musl` + `Local Upload` drag/file input) with live percentage progress bar and actionable retry/error banner.
  3. **Global Daemon Config Card:** `bin_path`, `rust_log`, `buffer_size` (KiB), `idle_timeout` (optional sec), `graceful_shutdown_sec` (sec).
  4. **Listeners Manager Card:** Add / Enable-Disable / Duplicate / Remove listener cards. Each card shows `Remarks`, `Listen (IP:Port)`, `Connect (IP:Port)`, `Fake SNI` with **live UTF-8 byte counter (`N / 219 B`)**, and an accessible `<details>` disclosure for advanced timing (`conn_timeout_sec`, `handshake_timeout_sec`, `keepalive_time_sec`, `keepalive_interval_sec`). Includes a collapsible `Generated config.json Preview` `<details>` block and sticky/clear **Save** and **Save & Restart** buttons with unsaved-changes state.
  5. **Live Log Console Card:** `XHR.poll` every 2.5s when active, Pause/Resume polling button, Log level filter (`All`, `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`), Auto-scroll toggle, Copy button, Clear button, and explicit empty/error states.
- All technical inputs, file paths, hashes, JSON previews, and logs carry `dir="ltr"`. Interactive controls meet 44x44px touch target sizing on narrow viewports and visible keyboard `:focus-visible` outlines.

---

## 6. `status.htm` Integration

Replace `luci-app-passwall2/luasrc/view/passwall2/global/status.htm` with the user-modified `temp/status.htm`, preserving all functional, SVG (`IRAN` checking `my.gov.ir`, `Instagram` checking `instagram.com`, `Google`), `width`/`height`/`alt`, and keyboard accessibility (`role="button"`, `tabindex="0"`, `onkeydown`, `.check:focus-visible`) changes, while restoring line 11's MIT license comment URL from `https://www.instagram.com//pure-css/pure/...` back to `https://github.com/pure-css/pure/blob/master/LICENSE.md`.

---

## 7. Docker Test Environment (`docker/`)

- **`docker/Dockerfile`:** Based on `openwrt/rootfs` (`x86-64`, OpenWrt 24.10 `opkg` or verified tag), pre-installs OpenWrt runtime & LuCI dependencies from [`luci-app-passwall2/Makefile`](../../luci-app-passwall2/Makefile) (`uhttpd`, `rpcd`, `luci-base`, `luci-compat`, `luci-lua-runtime`, `luci-theme-bootstrap`, `coreutils`, `coreutils-base64`, `coreutils-nohup`, `coreutils-timeout`, `curl`, `ca-bundle`, `ip-full`, `libuci-lua`, `lua`, `luci-lib-jsonc`, `lyaml`, `resolveip`, `jsonfilter`, `unzip`), and initializes a test `root` password (`root` by default, overrideable) for LuCI login.
- **`docker/entrypoint.sh`:** Prepares `/tmp`, `/var/run`, `/var/lock`, runs `/etc/uci-defaults/*` once/idempotently, starts `ubusd`, `rpcd`, and `uhttpd` in foreground, and leaves UCI + `init.d` ready.
- **`docker/compose.yml`:** Exposes `8080:80`, adds capabilities `NET_RAW` and `NET_ADMIN` (required by `sni-spoof-rs`'s `AF_PACKET` raw socket + BPF filter), and mounts the repo read-only or uses `dev-install.sh` cleanly.
- **`docker/dev-install.sh`:** Syncs `luci-app-passwall2/{luasrc,root,htdocs}` directly into the running container, sets executable bits (`init.d/*`, `usr/share/passwall2/*.sh`), runs `uci-defaults`, clears `/tmp/luci-*` caches, reloads `rpcd`, and prints the ready `http://localhost:8080` URL.

---

## 8. Verification Plan

1. **Static & Syntax Verification:** `luac -p` across all `.lua` files, `sh -n` across `.sh` and `init.d` scripts, CSS/JS syntax checks, and `antislop-human/contrast-check.py` on every Light/Dark palette pair.
2. **Container Integration Verification (`docker/`):**
   - Build image, boot container, run `docker/dev-install.sh`, verify LuCI responds HTTP 200 on `http://localhost:8080`.
   - Verify updated `global/status.htm` renders with fixed line 11 comment and IRAN/Google/Instagram status checks.
   - Verify `sni_spoofer` validation rejects `fake_sni > 219` UTF-8 bytes, invalid/hostname `connect` values, and `listen == connect` conflicts.
   - Test direct GitHub download of `sni-spoof-rs-google-wifi-armv7-musl` (verifying ELF armv7 detection + mismatch notice on `x86_64` container) AND test `sni-spoof-rs-linux-amd64-musl` download + local chunked upload.
   - Start daemon with a test listener inside container (`CAP_NET_RAW`), verify PID running status, live `config.json` generation, `NO_COLOR=1` + `RUST_LOG` live logs polling/clearing, Restart, and clean Stop.
