# SNI Spoofer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an independent **SNI Spoofer** service section (binary upload + GitHub download, full JSON config editor, start/stop/restart controls, live status and logs) to `luci-app-passwall2`, merge `temp/status.htm` cleanly into `global/status.htm`, and add an `x86_64` OpenWrt + LuCI Docker dev/test sandbox in `docker/`.

**Architecture:** A single shared Lua module (`luci.passwall2.sni_spoofer`) owns UCI persistence, validation, JSON emission matching `sni-spoof-rs/src/config.rs`, pure-Lua ELF header inspection, chunked upload assembly, GitHub release downloads, and log truncation. An independent `rc.common` service (`/etc/init.d/passwall2_sni_spoofer` + `/usr/share/passwall2/sni_spoofer.sh`) manages the daemon lifecycle and log cap, while a dedicated LuCI `template` view (`sni_spoofer/index.htm` + `sni_spoofer.css` + `sni_spoofer.js`) renders a theme-adaptive Light/Dark control-plane dashboard backed by CSRF-protected controller RPCs. Building the Docker sandbox early enables real OpenWrt Lua/UCI/uhttpd/BusyBox testing at every step.

**Tech Stack:** OpenWrt Lua 5.1 + LuCI (`nixio`, `luci.jsonc`, `luci.dispatcher`, `uci`), POSIX/BusyBox `/bin/sh` (`rc.common`), Vanilla ES6 JavaScript + CSS Custom Properties, Docker (`openwrt/rootfs` x86-64, `uhttpd`, `rpcd`), Node.js v24 (JS syntax + logic tests), Python `contrast-check.py` (`antislop-human`).

**Spec:** [`docs/superpowers/specs/2026-11-13-sni-spoofer-design.md`](../specs/2026-11-13-sni-spoofer-design.md)

## Global Constraints

- Independent daemon lifecycle: never couple `passwall2_sni_spoofer` start/stop to `/usr/share/passwall2/app.sh`.
- English UI copy only (wrap labels/strings with PassWall2 `<%:...%>` / `i18n.translate(...)`, omit `po/fa/passwall2.po` additions for now); force `dir="ltr"` on technical inputs, hashes, paths, JSON previews, and log streams.
- Config parity with `~/projects/rust/sni-spoofing-rust/src/config.rs`: `listeners` non-empty when running; `listen` and `connect` strictly `SocketAddr` (`IPv4:port` or `[IPv6]:port`, no hostnames); `fake_sni` `1..=219` UTF-8 bytes; no `connects_to_listener` wildcard/loopback conflict; `buffer_size >= 1`; `graceful_shutdown_sec >= 0`; `idle_timeout` optional `>= 1`; positive listener timeouts (`>= 1`).
- Binary CLI contract from `src/main.rs`: never invoke `<bin> --version` (treated as `config.json` path and exits 1); verify binary via `\x7fELF` header and same-arch `<bin> --help`.
- Logging contract from `src/main.rs`: export `RUST_LOG=<level>` and `NO_COLOR=1` so `tracing_subscriber` writes clean uncolored lines to `/tmp/log/passwall2_sni_spoofer.log`, capped at `524288` bytes via in-place `copytruncate`.
- Antislop & Accessibility: Light + Dark WCAG AA contrast (`>= 4.5:1` text, `>= 3:1` UI components), explicit Empty/Loading/Error states, 44px touch targets on narrow screens, `:focus-visible` keyboard rings, zero decorative em dashes (`—`) or fake telemetry.
- Shell commands run prefixed with `rtk` where applicable; `docker/` lives at repo root so `luci-app-passwall2/Makefile` (`luci.mk`) stays clean.
- Commit discipline (`atomic-commit`): Implementer tasks MUST NOT run raw `git commit`. Complete implementation, run all linters/tests, and verify diffs task-by-task against the plan's file list. After Task 9 E2E + whole-branch review pass, invoke `~/.gemini/config/skills/atomic-commit/SKILL.md` to inspect changes, group files cohesively by feature/layer (excluding untracked `temp/`), draft Conventional Commit messages (<= 72 chars summary, bulleted body, no attribution trailers, no em dashes), and request explicit user approval (Step 4) before executing `git commit`.

## Review Focus

1. **Cross-arch ELF uploaded or downloaded into `x86_64` Docker sandbox (`sni-spoof-rs-google-wifi-armv7-musl`):** Must install to `bin_path`, report `ELF armv7` + `arch_match = false` without running cross-arch `--help` (avoid `Exec format error` abort), and surface clear diagnostic error if Start fails. (Pinned in Task 4 & Task 5)
2. **UTF-8 multibyte `fake_sni` byte-limit & IPv6/wildcard conflict rules:** Must count UTF-8 bytes (`<= 219`, not Unicode char count), validate bracketed IPv6 `[addr]:port`, and block `0.0.0.0:P -> 127.0.0.1:P` and `[::]:P -> [::1]:P` in both Lua and JS. (Pinned in Task 4 & Task 8)
3. **HTML/404/truncated response masquerading as binary on upload or GitHub download:** Must verify `\x7fELF` magic, free destination space, and GitHub asset SHA-256 (`digest`) before stopping any running daemon or moving over `bin_path`. (Pinned in Task 4)
4. **Live log copytruncate inode preservation (`524288` B cap):** Must trim logs into the existing file descriptor without `mv` unlinking the running daemon's `O_APPEND` target, while stripping any stray ANSI sequences. (Pinned in Task 4 & Task 5)
5. **`status.htm` comment accuracy & CSRF protection on controller mutations:** Must restore line 11 MIT license comment to `github.com` in `global/status.htm`, and verify mutating endpoints enforce `luci.dispatcher.test_post_security()`. (Pinned in Task 1 & Task 6)

---

### Task 1: Merge `temp/status.htm` into `global/status.htm`

**Files:**
- Modify: `luci-app-passwall2/luasrc/view/passwall2/global/status.htm:1-203`
- Reference: `temp/status.htm:1-203`

**Interfaces:**
- Produces: updated LuCI view template preserving all `temp/status.htm` IRAN (`my.gov.ir`) / Google / Instagram status cards, SVGs, `width`/`height`/`alt`, `.check:focus-visible`, and keyboard `role="button"` handlers, with line 11 Pure CSS license comment restored to `https://github.com/pure-css/pure/blob/master/LICENSE.md`.

- [ ] **Step 1: Verify exact difference between `temp/status.htm` and `global/status.htm`**

Run: `rtk diff -u luci-app-passwall2/luasrc/view/passwall2/global/status.htm temp/status.htm`
Expected: confirms line 11 comment difference (`github.com` vs `www.instagram.com`), focus-visible CSS, `IRAN`/`Instagram` cards, SVG icons, `width="48" height="48" alt=""`, `role="button"`, `tabindex="0"`, `onkeydown`.

- [ ] **Step 2: Apply `temp/status.htm` to `luci-app-passwall2/luasrc/view/passwall2/global/status.htm` and restore line 11**

Copy `temp/status.htm` contents over `luci-app-passwall2/luasrc/view/passwall2/global/status.htm` and replace line 11 `https://www.instagram.com//pure-css/pure/blob/master/LICENSE.md` with `https://github.com/pure-css/pure/blob/master/LICENSE.md`. Leave `temp/` untouched on disk.

- [ ] **Step 3: Verify result with diff checks**

Run:
```bash
rtk diff -u temp/status.htm luci-app-passwall2/luasrc/view/passwall2/global/status.htm
rtk grep "github.com/pure-css" luci-app-passwall2/luasrc/view/passwall2/global/status.htm
rtk grep -E "my\.gov\.ir|instagram\.com|focus-visible" luci-app-passwall2/luasrc/view/passwall2/global/status.htm
```
Expected: ONLY line 11 differs against `temp/status.htm`; `github.com/pure-css/pure/blob/master/LICENSE.md` and `my.gov.ir`, `instagram.com`, `focus-visible` all match.

- [ ] **Step 4: Handoff diff for task review (defer commit to `atomic-commit` gate)**

Run `rtk git diff luci-app-passwall2/luasrc/view/passwall2/global/status.htm` to verify clean diff (`temp/` untouched), ready for Task 1 review and final `atomic-commit` grouping.

---

### Task 2: OpenWrt + LuCI Docker Dev/Test Sandbox (`docker/`)

**Files:**
- Create: `docker/Dockerfile`
- Create: `docker/entrypoint.sh`
- Create: `docker/compose.yml`
- Create: `docker/dev-install.sh`
- Create: `docker/README.md`

**Interfaces:**
- Produces: running Docker container `passwall2-dev` (`openwrt/rootfs` x86_64 with OpenWrt 24.10 `opkg` feeds) serving LuCI on `http://localhost:8080`, capabilities `NET_RAW` + `NET_ADMIN`, password `root`, and `./docker/dev-install.sh` to sync `luci-app-passwall2/` + test harness files in seconds.

- [ ] **Step 1: Verify available OpenWrt x86_64 Docker base tag and runtime dependencies**

Check `openwrt/rootfs:x86-64-24.10.0` (or `openwrt/rootfs:x86_64-24.10` / `openwrtorg/rootfs:x86-64-openwrt-24.10`) pullability and inspect `/etc/opkg/distfeeds.conf` inside a quick container test so the `Dockerfile` uses an exact verified OpenWrt tag and installable package set matching [`luci-app-passwall2/Makefile`](../../luci-app-passwall2/Makefile#L26-L29) (`uhttpd`, `rpcd`, `luci-base`, `luci-compat`, `luci-lua-runtime`, `luci-theme-bootstrap`, `coreutils`, `coreutils-base64`, `coreutils-nohup`, `coreutils-timeout`, `curl`, `ca-bundle`, `ip-full`, `libuci-lua`, `lua`, `luci-lib-jsonc`, `lyaml`, `resolveip`, `jsonfilter`, `unzip`, `shadow-passwd` or busybox `passwd`). Note: third-party PassWall-feed binaries (`geoview`, `tcping`, `v2ray-geoip`, `v2ray-geosite`, `xray-core`) may not exist in official OpenWrt feeds; install base OpenWrt packages cleanly in `Dockerfile` and stub/verify PassWall2 UI startup safely.

- [ ] **Step 2: Author `docker/Dockerfile`, `docker/entrypoint.sh`, `docker/compose.yml`, `docker/dev-install.sh`, and `docker/README.md`**

Requirements for each unit:
- `docker/Dockerfile`: sets `mkdir -p /var/lock /var/run /tmp`, updates `opkg`, installs verified OpenWrt LuCI + PassWall2 runtime packages, sets `root` password to `root` cleanly for LuCI login, enables `uhttpd` HTTP on `0.0.0.0:80` (disabling HTTPS redirect for local `http://localhost:8080`), copies `docker/entrypoint.sh`, exposes port `80`.
- `docker/entrypoint.sh`: idempotently prepares `/tmp/log`, `/tmp/etc`, `/var/lock`, `/var/run`, ensures `/etc/uci-defaults/*` run cleanly once if present, runs `/etc/init.d/passwall2_sni_spoofer boot` if enabled, starts `/sbin/ubusd` (background), `/sbin/rpcd` (background), and `/usr/sbin/uhttpd -f -h /www -r OpenWrt -x /cgi-bin -u /ubus -t 60 -T 30 -k 20 -A 1 -n 3 -N 100 -R -p 0.0.0.0:80` cleanly in foreground with signal trapping.
- `docker/compose.yml`: service `openwrt` (`container_name: passwall2-dev`), `build: .`, ports `8080:80`, `cap_add: [NET_RAW, NET_ADMIN]`, `restart: unless-stopped`.
- `docker/dev-install.sh`: syncs `luci-app-passwall2/luasrc/*` -> `/usr/lib/lua/luci/`, `luci-app-passwall2/root/*` -> `/`, `luci-app-passwall2/htdocs/*` -> `/www/` into running `passwall2-dev` via `docker cp` / `tar -cf - | docker exec -i passwall2-dev tar -xf - -C ...`, sets executable bits on `/etc/init.d/passwall2*` and `/usr/share/passwall2/*.sh`, executes `/etc/uci-defaults/luci-app-passwall2` if needed, clears `/tmp/luci-*`, reloads `rpcd`.
- `docker/README.md`: crisp quick-start instructions (`docker compose -f docker/compose.yml up -d --build`, `./docker/dev-install.sh`, `http://localhost:8080`, login `root` / `root`, testing `sni-spoof-rs-linux-amd64-musl` vs `armv7` upload/download check).

- [ ] **Step 3: Build image, boot container, sync package, and run live smoke test**

Run:
```bash
rtk proxy docker compose -f docker/compose.yml up -d --build
./docker/dev-install.sh
curl -fsS -o /dev/null -w "%{http_code}\n" http://localhost:8080/cgi-bin/luci
rtk proxy docker exec passwall2-dev sh -c 'lua -v && which uci jsonfilter curl sha256sum start-stop-daemon'
```
Expected: HTTP `200` (or `403`/login HTML `200`) from LuCI on `localhost:8080`, `lua` + `uci` + `jsonfilter` + `curl` + `sha256sum` present inside `passwall2-dev`, and `status.htm` rendered in LuCI.

- [ ] **Step 4: Handoff files for task review (defer commit to `atomic-commit` gate)**

Run `rtk git status --short docker/` to verify all 5 `docker/` files exist cleanly and `luci-app-passwall2/` was not altered by container setup.

---

### Task 3: UCI Default Config & `uci-defaults` Migration

**Files:**
- Modify: `luci-app-passwall2/root/usr/share/passwall2/0_default_config:210-228`
- Modify: `luci-app-passwall2/root/etc/uci-defaults/luci-app-passwall2:1-43`
- Test: `tests/sh/test_uci_defaults.sh` (executed inside `passwall2-dev`)

**Interfaces:**
- Produces:
  - UCI named section `passwall2.global_sni_spoofer` (type `global_sni_spoofer`): `enabled='0'`, `bin_path='/usr/bin/sni-spoof-rs'`, `rust_log='warn'`, `buffer_size='8'`, `graceful_shutdown_sec='0'`, `github_asset='sni-spoof-rs-google-wifi-armv7-musl'`.
  - Default disabled example `sni_spoofer_listener`: `enabled='0'`, `remarks='Example Cloudflare'`, `listen='127.0.0.1:40443'`, `connect='172.67.139.236:443'`, `fake_sni='security.vercel.com'`, `conn_timeout_sec='5'`, `handshake_timeout_sec='2'`, `keepalive_time_sec='11'`, `keepalive_interval_sec='2'`.
  - `/etc/sysupgrade.conf` includes `/usr/bin/sni-spoof-rs` without duplicate entries across repeated `uci-defaults` runs.

- [ ] **Step 1: Write failing UCI migration & defaults test `tests/sh/test_uci_defaults.sh`**

Test cases inside `passwall2-dev`:
1. Copy `0_default_config` into temporary UCI config dir, verify `uci -c "$TMP_UCI" get passwall2.global_sni_spoofer.bin_path` equals `/usr/bin/sni-spoof-rs`, `rust_log` == `warn`, `github_asset` == `sni-spoof-rs-google-wifi-armv7-musl`.
2. Remove `global_sni_spoofer` from a mock `/etc/config/passwall2`, run `uci-defaults` migration snippet twice with temp `/etc/sysupgrade.conf`, verify `global_sni_spoofer` is recreated with defaults and `/etc/sysupgrade.conf` has exactly 1 matching `/usr/bin/sni-spoof-rs` line.

- [ ] **Step 2: Run test inside container to verify failure before implementation**

Run: `rtk proxy docker exec passwall2-dev sh -s < tests/sh/test_uci_defaults.sh`
Expected: FAIL (`uci: Entry not found` for `global_sni_spoofer`).

- [ ] **Step 3: Update `0_default_config` and `uci-defaults/luci-app-passwall2`**

- Append `config global_sni_spoofer 'global_sni_spoofer'` and `config sni_spoofer_listener` to `luci-app-passwall2/root/usr/share/passwall2/0_default_config`.
- Update `luci-app-passwall2/root/etc/uci-defaults/luci-app-passwall2` to idempotently initialize `passwall2.global_sni_spoofer` when upgrading older configs, `chmod 0755 /etc/init.d/passwall2_sni_spoofer 2>/dev/null || true`, and append the configured `bin_path` (fallback `/usr/bin/sni-spoof-rs`) to `/etc/sysupgrade.conf` if not already present.

- [ ] **Step 4: Sync to Docker & run `tests/sh/test_uci_defaults.sh`**

Run: `./docker/dev-install.sh && rtk proxy docker exec passwall2-dev sh -s < tests/sh/test_uci_defaults.sh`
Expected: PASS on all assertions.

- [ ] **Step 5: Handoff diff for task review (defer commit to `atomic-commit` gate)**

Run `rtk git diff luci-app-passwall2/root/` to inspect UCI defaults and migration changes before moving to Task 4.

---

### Task 4: Core `luci.passwall2.sni_spoofer` Lua Module (TDD in OpenWrt Runtime)

**Files:**
- Create: `luci-app-passwall2/luasrc/passwall2/sni_spoofer.lua`
- Test: `tests/lua/test_sni_spoofer.lua`

**Interfaces:**
- Consumes: `luci.passwall2.api` (`uci`, `uci_get_c`, `uci_set_c`, `uci_save_c`, `get_api_json`, `verify_sha256`, `curl_direct`, `curl_auto`, `get_free_space`, `get_file_space`, `get_final_dir`, `exec`, `fs`, `sys`, `util`, `jsonc`, `i18n`, `CACHE_PATH`, `TMP_PATH`), UCI `passwall2` schema from Task 3.
- Produces (`luci.passwall2.sni_spoofer`):
  - `GITHUB_REPO = "mohamadtsn/sni-spoofing-rust"`
  - `DEFAULT_BIN_PATH = "/usr/bin/sni-spoof-rs"`
  - `LOG_FILE = "/tmp/log/passwall2_sni_spoofer.log"`
  - `PID_FILE = "/var/run/passwall2_sni_spoofer.pid"`
  - `RUNTIME_DIR = "/tmp/etc/passwall2/sni_spoofer"`
  - `CONFIG_JSON_PATH = "/tmp/etc/passwall2/sni_spoofer/config.json"`
  - `parse_socket_addr(val)` -> `ip, port, is_ipv6` or `nil, err`
  - `connects_to_listener(listen_addr, connect_addr)` -> `boolean`
  - `validate_payload(payload)` -> `ok, normalized, field_errors`
  - `build_runtime_config(cfg)` -> `table_for_json`
  - `write_runtime_config(target_path)` -> `ok, err, json_str`
  - `get_config()` -> `{ global = {...}, listeners = {...} }`
  - `save_config(payload)` -> `{ ok = bool, errors = table, config = table }`
  - `parse_elf_header(bytes)` -> `{ valid = bool, bits = 32|64, arch = string, endian = string }`
  - `inspect_binary(path, stored_meta)` -> `{ exists, executable, path, size_bytes, sha256, elf, host_arch, arch_match, help_ok, version_tag, error }`
  - `register_sysupgrade_path(path)` -> `boolean`
  - `install_verified_binary(tmp_file, target_path, meta)` -> `{ code = 0|1, error = string, binary = table }`
  - `handle_upload_chunk(params)` -> `{ status = "success"|"error", message = string, binary = table }`
  - `fetch_latest_release()` -> `{ code = 0|1, tag_name, published_at, html_url, assets = [...], error }`
  - `start_download(params)` / `get_download_progress(task_id)`
  - `cap_log_file(path, max_bytes, keep_bytes)` -> `truncated_bool` (using same-inode copytruncate!)
  - `strip_ansi(str)` -> clean string
  - `get_log(limit)` / `clear_log()`
  - `get_pid_status(bin_path)` -> `{ running = bool, pid = number|nil, uptime_sec = number|nil }`
  - `get_status()` -> full status payload combining `get_pid_status`, `inspect_binary`, `get_config`, JSON preview + validation status, `log_bytes`.

- [ ] **Step 1: Write failing unit & integration test suite `tests/lua/test_sni_spoofer.lua`**

Assertions covering every Review Focus item + happy paths inside `passwall2-dev`:
1. `parse_socket_addr` accepts `"127.0.0.1:40443"`, `"[::1]:40443"`, rejects `"example.com:443"`, `"127.0.0.1"`, `"127.0.0.1:0"`, `"127.0.0.1:70000"`.
2. `connects_to_listener` returns `true` for identical `127.0.0.1:40443` / `127.0.0.1:40443`, `0.0.0.0:40443` / `127.0.0.1:40443`, `[::]:40443` / `[::1]:40443`, and `false` for `127.0.0.1:40443` / `172.67.139.236:443`.
3. `validate_payload` rejects `fake_sni` of 220 ASCII bytes AND rejects 110 two-byte UTF-8 characters (`220` UTF-8 bytes) while accepting 219 UTF-8 bytes; rejects duplicate enabled `listen` addresses; accepts disabled listener drafts if config has >= 1 enabled when flagged for start, and `build_runtime_config` omits `idle_timeout` when blank and includes only `enabled == "1"` listeners.
4. `parse_elf_header` parses synthetic ARMv7 ELF (`\x7fELF\x01\x01...` machine `0x2800` LE -> `armv7`), x86_64 ELF (`\x7fELF\x02\x01...` machine `0x3E00` LE -> `x86_64`), and rejects `"<html>404</html>"`. `inspect_binary` detects cross-arch (`armv7` on `x86_64`) with `arch_match = false` and does NOT error out on cross-arch `--help`.
5. `install_verified_binary` rejects non-ELF temp files while keeping an existing valid binary untouched; succeeds on valid ELF with `0755` permissions and single-entry `/etc/sysupgrade.conf` registration.
6. `cap_log_file` trims a `> max_bytes` temp log file while preserving the **exact file inode** (`stat -c %i` before == after!) and stripping ANSI escapes via `strip_ansi`.
7. `handle_upload_chunk` reassembles multi-chunk base64 synthetic ELF binary cleanly and rejects missing/invalid `upload_id` traversal.

- [ ] **Step 2: Run Lua test in Docker to verify failure**

Run: `rtk proxy docker exec passwall2-dev sh -c 'mkdir -p /tmp/tests && cat > /tmp/tests/test_sni_spoofer.lua && lua /tmp/tests/test_sni_spoofer.lua' < tests/lua/test_sni_spoofer.lua`
Expected: FAIL (`module 'luci.passwall2.sni_spoofer' not found`).

- [ ] **Step 3: Implement `luci-app-passwall2/luasrc/passwall2/sni_spoofer.lua`**

Implement modular, focused functions with shallow nesting, reusing `luci.passwall2.api` helpers (`get_api_json`, `verify_sha256`, `curl_direct`, `curl_auto`, `get_free_space`, `get_file_space`, `get_final_dir`, `exec`, `fs`, `sys`, `util`, `jsonc`) and executing binary permission via `api.exec("/bin/chmod", {"0755", path})` (`nixio` octal precision). Keep `download` state in `/tmp/etc/passwall2/sni_spoofer/dl_<id>.json` so async curl background downloads report live progress (`downloaded` / `total` / `percent`) and finalize cleanly with SHA-256 verification when GitHub `digest` is present.

- [ ] **Step 4: Sync to Docker and run `tests/lua/test_sni_spoofer.lua`**

Run:
```bash
./docker/dev-install.sh
rtk proxy docker exec passwall2-dev luac -p /usr/lib/lua/luci/passwall2/sni_spoofer.lua
rtk proxy docker exec -i passwall2-dev lua - < tests/lua/test_sni_spoofer.lua
```
Expected: PASS on all 7 test groups with zero syntax errors.

- [ ] **Step 5: Handoff files for task review (defer commit to `atomic-commit` gate)**

Run `rtk git status --short luci-app-passwall2/luasrc/passwall2/sni_spoofer.lua tests/lua/test_sni_spoofer.lua` and verify `luac -p` + tests remain green.

---

### Task 5: Background Service (`/etc/init.d/passwall2_sni_spoofer` + `sni_spoofer.sh`)

**Files:**
- Create: `luci-app-passwall2/root/etc/init.d/passwall2_sni_spoofer`
- Create: `luci-app-passwall2/root/usr/share/passwall2/sni_spoofer.sh`
- Test: `tests/sh/test_sni_spoofer_service.sh`

**Interfaces:**
- Consumes: `luci.passwall2.sni_spoofer` (`write_runtime_config`, `cap_log_file`, `inspect_binary`, `get_pid_status`).
- Produces: OpenWrt service commands `/etc/init.d/passwall2_sni_spoofer {boot,start,stop,restart,status,enable,disable}` writing PID `/var/run/passwall2_sni_spoofer.pid`, config `/tmp/etc/passwall2/sni_spoofer/config.json`, uncolored logs (`RUST_LOG=<level>`, `NO_COLOR=1`) to `/tmp/log/passwall2_sni_spoofer.log`.

- [ ] **Step 1: Write failing service lifecycle test `tests/sh/test_sni_spoofer_service.sh`**

Test cases run inside `passwall2-dev` (using `NET_RAW` capability + temporary mock/real binary + isolated cleanup):
1. Verify `sh -n` passes on `/etc/init.d/passwall2_sni_spoofer` and `/usr/share/passwall2/sni_spoofer.sh`.
2. With missing binary (`bin_path=/tmp/nonexistent-sni`), `/etc/init.d/passwall2_sni_spoofer start` exits non-zero and writes descriptive error into `/tmp/log/passwall2_sni_spoofer.log`.
3. With `enabled='0'`, `/etc/init.d/passwall2_sni_spoofer boot` does NOT start the daemon.
4. With a valid executable test binary (both a tiny shell mock verifying `RUST_LOG` + `NO_COLOR=1` + `SIGTERM` graceful exit AND downloading/running real `sni-spoof-rs-linux-amd64-musl` if online in container), `start` creates valid JSON `/tmp/etc/passwall2/sni_spoofer/config.json`, writes live PID to `/var/run/passwall2_sni_spoofer.pid`, `status` returns 0 (`running`), `restart` yields a new live PID, and `stop` cleanly terminates process within `graceful_shutdown_sec` and removes PID file.

- [ ] **Step 2: Run test inside container to verify failure**

Run: `rtk proxy docker exec -i passwall2-dev sh < tests/sh/test_sni_spoofer_service.sh`
Expected: FAIL (`/etc/init.d/passwall2_sni_spoofer: not found`).

- [ ] **Step 3: Implement `passwall2_sni_spoofer` and `sni_spoofer.sh`**

- `/etc/init.d/passwall2_sni_spoofer` (`START=99`, `STOP=10`, `/etc/rc.common`): defines `boot()`, `start()`, `stop()`, `restart()`, `status()` (plus `extra_command "status" "Show SNI Spoofer service status"`). `boot()` exits 0 immediately unless `uci -q get passwall2.global_sni_spoofer.enabled` is `'1'`.
- `/usr/share/passwall2/sni_spoofer.sh`: acquires mkdir lock (`/var/lock/passwall2_sni_spoofer.lock.d` or flock cleanly), delegates pre-flight validation + `config.json` generation to Lua (`sni_spoofer.write_runtime_config`), caps log before launch (`cap_log_file`), starts daemon in background via `start-stop-daemon` (or `/bin/sh -c` PID tracking with `exec env RUST_LOG=... NO_COLOR=1`), polls ~300 ms to catch immediate crash (recording tail in error), handles `stop` (`SIGTERM`, polling up to `max(2, graceful_shutdown_sec + 1)` seconds, `SIGKILL` fallback, remove PID).

- [ ] **Step 4: Sync to Docker (`chmod +x`) & run `tests/sh/test_sni_spoofer_service.sh`**

Run: `./docker/dev-install.sh && rtk proxy docker exec -i passwall2-dev sh < tests/sh/test_sni_spoofer_service.sh`
Expected: PASS on all assertions.

- [ ] **Step 5: Handoff files for task review (defer commit to `atomic-commit` gate)**

Run `rtk git status --short luci-app-passwall2/root/etc/init.d/passwall2_sni_spoofer luci-app-passwall2/root/usr/share/passwall2/sni_spoofer.sh tests/sh/test_sni_spoofer_service.sh` and confirm `0755` permissions on init/shell scripts.

---

### Task 6: LuCI Controller Routes & CSRF-Guarded RPCs

**Files:**
- Modify: `luci-app-passwall2/luasrc/controller/passwall2.lua:39-48,120-125,1075-1082`
- Test: `tests/sh/test_controller_rpc.sh`

**Interfaces:**
- Consumes: `luci.passwall2.sni_spoofer` (all methods from Task 4) + `/etc/init.d/passwall2_sni_spoofer` (from Task 5).
- Produces HTTP routes under `/cgi-bin/luci/admin/services/passwall2/`:
  - `sni_spoofer` -> `template(appname .. "/sni_spoofer/index")`, menu label `_("SNI Spoofer")`, order `94`
  - `sni_spoofer_status` (GET)
  - `sni_spoofer_control` (POST, `test_post_security()`)
  - `sni_spoofer_save` (POST, `test_post_security()`)
  - `sni_spoofer_upload` (POST, `test_post_security()`)
  - `sni_spoofer_release_info` (GET)
  - `sni_spoofer_download` (POST, `test_post_security()`)
  - `sni_spoofer_log` (GET returns tail; POST `action=clear` enforces `test_post_security()`)

- [ ] **Step 1: Write failing HTTP RPC & CSRF test `tests/sh/test_controller_rpc.sh`**

Test script authenticating against `http://localhost:8080/cgi-bin/luci` (`root`/`root`), extracting cookie + CSRF token:
1. Request `GET .../sni_spoofer_control?action=start` -> MUST reject (HTTP 403 / non-execution without POST + token).
2. Request `GET .../sni_spoofer_status` -> JSON `{ code = 1, data = { running, host_arch, binary, config, json_preview, log_bytes } }`.
3. Request `POST .../sni_spoofer_save` with invalid `fake_sni` (220 bytes) -> returns JSON `{ code = 0 }` + field errors without overwriting valid UCI; then valid save -> persists & returns updated snapshot.
4. Request `POST .../sni_spoofer_log` with `action=clear` + valid token -> truncates log file.

- [ ] **Step 2: Run test against Docker to verify failure**

Run: `bash tests/sh/test_controller_rpc.sh`
Expected: FAIL (`404 Not Found` for `/sni_spoofer_status`).

- [ ] **Step 3: Wire routes and handler functions in `luci-app-passwall2/luasrc/controller/passwall2.lua`**

Add menu route at line ~43 (order `94`, between `Load Balancing` `93` and `App Update` `95`) and register the 7 RPC calls; implement concise controller handlers delegating cleanly to `require "luci.passwall2.sni_spoofer"`, guarding every mutation with `if not luci.dispatcher.test_post_security() then return end`, parsing JSON body cleanly (`http.content()` or `formvalue("payload")`). Note: create a minimal placeholder `luci-app-passwall2/luasrc/view/passwall2/sni_spoofer/index.htm` ONLY if needed for route resolution or verify `sni_spoofer_status` immediately; better yet, add minimal valid template stub `<%+header%><h2>SNI Spoofer</h2><%+footer%>` so `GET /sni_spoofer` also returns 200 right away before Task 8 replaces it!

- [ ] **Step 4: Sync to Docker and run `tests/sh/test_controller_rpc.sh`**

Run: `./docker/dev-install.sh && rtk proxy docker exec passwall2-dev luac -p /usr/lib/lua/luci/controller/passwall2.lua && bash tests/sh/test_controller_rpc.sh`
Expected: PASS on all CSRF + JSON save/status/log assertions.

- [ ] **Step 5: Handoff diff for task review (defer commit to `atomic-commit` gate)**

Run `rtk git diff luci-app-passwall2/luasrc/controller/passwall2.lua` and `rtk git status --short tests/sh/test_controller_rpc.sh` to verify clean RPC changes before Task 7.

---

### Task 7: Design Tokens, Theme-Adaptive CSS & WCAG AA Contrast Audit

**Files:**
- Create: `luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.css`
- Test: `tests/verify_contrast.sh`

**Interfaces:**
- Produces: scoped `.sni-spoofer-page` stylesheet supporting Light & Dark LuCI themes (`@media (prefers-color-scheme: dark)` + `[data-theme="dark"]` / `body.dark` / `:root[data-dark="true"]`), responsive grid breakpoints (`<= 900px`), `44px` minimum interactive controls on coarse/mobile viewports, `:focus-visible` keyboard outlines, `.ss-ltr` direction helper, `.ss-console` terminal palette, zero decorative pulse or em dashes.

- [ ] **Step 1: Consult `ui-ux-pro-max`, `impeccable`, and `antislop` contrast rules**

Read `~/.gemini/config/skills/impeccable/reference/new-work.md` & `craft-floor.md` (and query `ui-ux-pro-max/scripts/search.py` for clean control-plane dashboard palette & typography guidance) to define the exact Light & Dark palette tokens with clean contrast headroom.

- [ ] **Step 2: Author `tests/verify_contrast.sh` calling `contrast-check.py`**

Write `tests/verify_contrast.sh` to parse `--ss-*` hex custom properties directly from Light (`:root` / `.sni-spoofer-page`) and Dark (`prefers-color-scheme: dark` / `[data-theme="dark"]`) blocks of `luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.css` and run `python3 /home/mohamadtsn/.gemini/config/skills/antislop-human/contrast-check.py` on every pair (`--ss-text` on `--ss-bg`, `--ss-text` on `--ss-surface`, `--ss-muted` on `--ss-surface`, `--ss-accent-fg` on `--ss-accent`, status pill fg/bg pairs, and console log badge fg/bg pairs), asserting PASS (`>= 4.5:1` text / `>= 3.0:1` UI borders & icons). Run it first before creating `sni_spoofer.css` so missing file fails as expected.

- [ ] **Step 3: Run `tests/verify_contrast.sh` and refine tokens if any pair fails, then implement `sni_spoofer.css`**

Write `luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.css` using only verified Light & Dark token values. Re-run `tests/verify_contrast.sh` to confirm every token pair inside `sni_spoofer.css` passes WCAG AA!

- [ ] **Step 4: Handoff stylesheet for task review (defer commit to `atomic-commit` gate)**

Run `rtk git status --short luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.css tests/verify_contrast.sh` and confirm `tests/verify_contrast.sh` passes cleanly.

---

### Task 8: Dashboard View & Interactive JS Controller (`index.htm` + `sni_spoofer.js`)

**Files:**
- Modify: `luci-app-passwall2/luasrc/view/passwall2/sni_spoofer/index.htm`
- Create: `luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.js`
- Test: `tests/js/test_sni_spoofer_ui.mjs`

**Interfaces:**
- Consumes: Task 6 RPC endpoints URLs (`status`, `control`, `save`, `upload`, `release_info`, `download`, `log`, CSRF `token`) passed via data/config object from `index.htm`, plus Task 7 classes in `sni_spoofer.css`.
- Produces: classic `<script src="...">`-compatible UMD module (`window.PasswallSniSpoofer` in browser + `module.exports` when required from Node.js via `createRequire`) exporting pure UI helpers (`utf8ByteLength`, `parseSocketAddr`, `hasListenerConflict`, `validateConfigForm`, `buildJsonPreview`, `splitIntoChunks`, `parseLogLine`) alongside DOM initialization when `#sni-spoofer-app` is present.

- [ ] **Step 1: Write failing JS unit tests `tests/js/test_sni_spoofer_ui.mjs`**

Test pure JS helpers loaded via `createRequire(import.meta.url)('../../luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.js')` with `node:assert/strict`:
1. `utf8ByteLength("سلام")` == `8` (whereas `.length` is `4`); `validateConfigForm` rejects 220-byte ASCII and 110-char 2-byte UTF-8 `fake_sni`, accepts 219-byte `fake_sni`.
2. `parseSocketAddr` accepts IPv4 and `[::1]:40443`; rejects hostnames (`cf.example.com:443`) and out-of-range ports.
3. `hasListenerConflict` catches `0.0.0.0:40443` + `127.0.0.1:40443`, `[::]:40443` + `[::1]:40443`, and duplicate `listen` endpoints across enabled listeners.
4. `buildJsonPreview` emits exact `sni-spoof-rs/src/config.rs` schema, omits `idle_timeout` when empty, excludes disabled listeners.
5. `splitIntoChunks` splits binary `Uint8Array` cleanly at `196608` bytes (multiple of 3) with exact Base64 round-trip and chunk count.
6. `parseLogLine` classifies `ERROR` / `WARN` / `INFO` / `DEBUG` / `TRACE` cleanly without injecting raw HTML (XSS-safe text nodes).

- [ ] **Step 2: Run test to verify failure**

Run: `node tests/js/test_sni_spoofer_ui.mjs`
Expected: FAIL (`Cannot find module .../sni_spoofer.js` or missing exports).

- [ ] **Step 3: Implement `luci-app-passwall2/luasrc/view/passwall2/sni_spoofer/index.htm` and `sni_spoofer.js`**

Build all 5 accessible cards cleanly with `index.htm` markup + `sni_spoofer.js`:
1. **Header & Service Control Strip:** Status pill (`Running` / `Stopped` / `Binary Missing`), real `PID` & `Uptime` (dash when stopped), Boot Auto-Start toggle, Start / Stop / Restart buttons with busy/loading disabled states.
2. **Binary Manager Card:** Installed telemetry (`path`, human size, short SHA-256, release tag, ELF arch badge + compatibility status vs host arch); Accessible tabs switching cleanly between **GitHub Release** (asset selector defaulting to `sni-spoof-rs-google-wifi-armv7-musl`, plus `sni-spoof-rs-linux-amd64-musl` and `sni-spoof-rs-linux-arm64`, Check Release button + Download & Install button + progress bar + error/retry banner) and **Local Upload** (file picker dropzone + chunked progress bar).
3. **Global Settings Card:** `bin_path` (`dir="ltr"`), `rust_log`, `buffer_size` (KiB), `idle_timeout` (optional sec), `graceful_shutdown_sec` (sec).
4. **Listeners Manager Card:** Dynamic Add / Duplicate / Enable-Disable / Remove listener cards; inline UTF-8 byte counter `N / 219 B`; inline validation messages; collapsible `<details>` for `conn_timeout_sec`, `handshake_timeout_sec`, `keepalive_time_sec`, `keepalive_interval_sec`; collapsible `Generated config.json Preview` `<details>`; sticky/clean **Save** & **Save & Restart** buttons with unsaved changes warning (`aria-live="polite"`).
5. **Live Log Console Card:** `XHR.poll` every 2.5s when enabled, Pause/Resume toggle, Level filter (`All`/`ERROR`/`WARN`/`INFO`/`DEBUG`/`TRACE`), Auto-scroll toggle, Copy button, Clear Log button, and explicit Empty (`No log entries yet`), Loading, and Error states.

- [ ] **Step 4: Run JS syntax & unit tests**

Run: `node --check luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.js && node tests/js/test_sni_spoofer_ui.mjs`
Expected: PASS on syntax check and all 6 unit test groups.

- [ ] **Step 5: Handoff UI files for task review (defer commit to `atomic-commit` gate)**

Run `rtk git status --short luci-app-passwall2/luasrc/view/passwall2/sni_spoofer/index.htm luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.js tests/js/test_sni_spoofer_ui.mjs` and confirm syntax + JS tests remain green.

---

### Task 9: End-to-End Docker Verification & Cleanup Audit

**Files:**
- Verify: all files modified/created across Tasks 1-8
- Test: `tests/e2e/test_docker_e2e.sh`

- [ ] **Step 1: Sync latest code cleanly into `passwall2-dev` and verify static checks**

Run: `./docker/dev-install.sh`, `luac -p` across all Lua files inside `passwall2-dev`, `sh -n` across all shell/init scripts, `node --check`, and `tests/verify_contrast.sh`.

- [ ] **Step 2: Run full end-to-end verification in Docker container `tests/e2e/test_docker_e2e.sh`**

Verify against live `http://localhost:8080`:
1. `global/status` page renders updated `IRAN` (`my.gov.ir`), `Google`, `Instagram` markup with fixed `github.com/pure-css` line 11 comment.
2. `SNI Spoofer` menu link and page render HTTP `200` with CSS/JS assets returning HTTP `200`.
3. `sni_spoofer_release_info` fetches live GitHub release info for `mohamadtsn/sni-spoofing-rust` including `sni-spoof-rs-google-wifi-armv7-musl` and `sni-spoof-rs-linux-amd64-musl` (and gracefully handles rate limit fallback if offline).
4. Download `sni-spoof-rs-google-wifi-armv7-musl` via RPC -> verifies `\x7fELF`, reports `armv7` + `arch_match = false` on `x86_64` container without crashing installer.
5. Download/upload `sni-spoof-rs-linux-amd64-musl` (also test chunked upload flow!) -> verifies `arch_match = true`, `help_ok = true`.
6. Save listener (`127.0.0.1:40443 -> 104.18.4.130:443`, `fake_sni = security.vercel.com`, `rust_log = debug`) -> Start service -> assert running PID, live `config.json`, uncolored `RUST_LOG` entries appearing in `sni_spoofer_log` -> Restart -> assert PID changed -> Stop -> Clear log -> assert clean state.
7. Optional visual verification in browser via `browser` subagent if available (`http://localhost:8080`, Light + Dark viewport + mobile responsive check).

- [ ] **Step 3: Audit Antislop Delivery Gate & Whole-Branch Review**

Run `rtk git status`, confirm all static checks and E2E tests pass 100%, run final whole-branch code review (`../requesting-code-review/code-reviewer.md`) and Antislop Delivery Gate audit, confirm zero unintended modifications (`temp/` untouched), and ensure zero unresolved defects remain.

- [ ] **Step 4: Atomic Commit Workflow (`atomic-commit` skill)**

Invoke `~/.gemini/config/skills/atomic-commit/SKILL.md`:
1. Inspect `rtk git status --porcelain`, `rtk git log --oneline -10`, `rtk git diff --stat` (excluding untracked `temp/` and scratch files).
2. Re-run final linters (`luac -p`, `sh -n`, `node --check`, `tests/verify_contrast.sh`).
3. Group changes into logical atomic commits (e.g., `status.htm` update, `docker/` sandbox, backend core `uci + lua + init.d + controller + backend tests`, frontend dashboard `css + js + index.htm + ui/e2e tests`, plus plan doc if tracked) with concise Conventional Commit messages (<= 72 chars summary, bulleted body, no attribution trailers, no em dashes).
4. Present each staged file list and proposed commit message to the user for explicit approval (Step 4 gate) BEFORE executing `git commit`.
5. Run `rtk git log -1 --stat` per approved group and final `rtk git status` to verify clean completion.
