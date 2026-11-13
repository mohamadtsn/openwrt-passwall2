#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${PASSWALL2_URL:-http://localhost:8080/cgi-bin/luci}"
API_BASE="${BASE_URL}/admin/services/passwall2"
STATIC_BASE="${PASSWALL2_STATIC_URL:-http://localhost:8080/luci-static}"
CONTAINER="${PASSWALL2_CONTAINER:-passwall2-dev}"

COOKIE_JAR="$(mktemp /tmp/pw2_e2e_cookie.XXXXXX)"
TMP_DIR="$(mktemp -d /tmp/pw2_e2e.XXXXXX)"
UCI_BAK="/tmp/pw2_e2e_uci_bak.$$"
SYSUPGRADE_BAK="/tmp/pw2_e2e_sysup_bak.$$"
HAD_BIN=0

docker exec "$CONTAINER" sh -c "
	cp -f /etc/config/passwall2 '$UCI_BAK'
	if [ -f /etc/sysupgrade.conf ]; then
		cp -f /etc/sysupgrade.conf '$SYSUPGRADE_BAK'
	else
		rm -f '$SYSUPGRADE_BAK'
	fi
"
if docker exec "$CONTAINER" test -f /usr/bin/sni-spoof-rs; then
	HAD_BIN=1
	docker exec "$CONTAINER" cp -f /usr/bin/sni-spoof-rs "/tmp/pw2_e2e_bin_bak.$$"
fi

cleanup() {
	docker exec "$CONTAINER" sh -c "
		/etc/init.d/passwall2_sni_spoofer stop >/dev/null 2>&1 || true
		[ -f '$UCI_BAK' ] && cp -f '$UCI_BAK' /etc/config/passwall2 && rm -f '$UCI_BAK'
		if [ -f '$SYSUPGRADE_BAK' ]; then
			cp -f '$SYSUPGRADE_BAK' /etc/sysupgrade.conf
			rm -f '$SYSUPGRADE_BAK'
		else
			rm -f /etc/sysupgrade.conf
		fi
		if [ '$HAD_BIN' = '1' ] && [ -f '/tmp/pw2_e2e_bin_bak.$$' ]; then
			mv -f '/tmp/pw2_e2e_bin_bak.$$' /usr/bin/sni-spoof-rs
		else
			rm -f /usr/bin/sni-spoof-rs
		fi
		rm -f /tmp/log/passwall2_sni_spoofer.log
		rm -rf /tmp/pw2_sni_dl_* /tmp/pw2_sni_ul_* /tmp/etc/passwall2/sni_spoofer/dl_*
		uci revert passwall2 >/dev/null 2>&1 || true
	" >/dev/null 2>&1 || true
	rm -rf "$TMP_DIR" "$COOKIE_JAR"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $1" >&2
	exit 1
}

# Authenticate and obtain session cookie + CSRF token
curl -fsS -L -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
	-d "luci_username=root&luci_password=root" \
	"${API_BASE}" -o "$TMP_DIR/status_home.html"

TOKEN="$(python3 -c '
import re, sys
html = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()
m = re.search(r"\"token\"\s*:\s*\"([a-fA-F0-9]+)\"", html)
print(m.group(1) if m else "")
' "$TMP_DIR/status_home.html")"
[ -n "$TOKEN" ] || fail "Failed to extract CSRF token from LuCI status page"

# 1. Verify merged global/status page & restored Pure CSS license comment
curl -fsS -b "$COOKIE_JAR" "${API_BASE}" -o "$TMP_DIR/global_status.html"
python3 -c '
import sys
html = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()
for needle in ("my.gov.ir", "Google", "Instagram", "https://github.com/pure-css/pure/blob/master/LICENSE.md"):
    assert needle in html, f"missing {needle!r} in global status page"
assert "github.com/pure-css-notfound" not in html
' "$TMP_DIR/global_status.html"
echo "E2E [1/6]: global status page & Pure CSS comment OK"

# 2. Verify SNI Spoofer template HTTP 200 and CSS/JS assets HTTP 200
PAGE_CODE="$(curl -sS -b "$COOKIE_JAR" -o "$TMP_DIR/sni_page.html" -w "%{http_code}" "${API_BASE}/sni_spoofer")"
[ "$PAGE_CODE" = "200" ] || fail "GET /sni_spoofer returned HTTP $PAGE_CODE"

python3 -c '
import json, re, sys
html = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()
assert "id=\"sni-spoofer-app\"" in html, "missing sni-spoofer-app root"
assert "sni_spoofer.css" in html, "missing sni_spoofer.css link"
assert "sni_spoofer.js" in html, "missing sni_spoofer.js script"
m = re.search(r"<script[^>]*id=\"sni-spoofer-boot\"[^>]*>(.*?)</script>", html, re.S)
assert m, "missing sni-spoofer-boot JSON"
boot = json.loads(m.group(1))
assert boot.get("token"), "boot JSON missing CSRF token"
for key in ("status", "control", "save", "upload", "release_info", "download", "log"):
    assert boot.get("urls", {}).get(key), f"missing boot url {key}"
' "$TMP_DIR/sni_page.html"

CSS_CODE="$(curl -sS -o "$TMP_DIR/view.css" -w "%{http_code}" "${STATIC_BASE}/resources/view/passwall2/sni_spoofer.css?v=1")"
[ "$CSS_CODE" = "200" ] && [ -s "$TMP_DIR/view.css" ] || fail "CSS asset HTTP=$CSS_CODE"
JS_CODE="$(curl -sS -o "$TMP_DIR/view.js" -w "%{http_code}" "${STATIC_BASE}/resources/view/passwall2/sni_spoofer.js?v=1")"
[ "$JS_CODE" = "200" ] && [ -s "$TMP_DIR/view.js" ] || fail "JS asset HTTP=$JS_CODE"
echo "E2E [2/6]: sni_spoofer page + CSS + JS assets HTTP 200 OK"

# 3. Release info check (handles live GitHub or fallback gracefully)
curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_release_info" -o "$TMP_DIR/release.json"
python3 -c '
import json, sys
res = json.load(open(sys.argv[1]))
data = res["data"]
names = {a["name"] for a in data.get("assets", [])}
for req in (
    "sni-spoof-rs-google-wifi-armv7-musl",
    "sni-spoof-rs-linux-amd64-musl",
    "sni-spoof-rs-linux-arm64",
):
    assert req in names, f"missing asset {req} in release_info: {names}"
code = res.get("code")
tag = data.get("tag_name", "fallback")
print(f"E2E [3/6]: release_info code={code} tag={tag}")
' "$TMP_DIR/release.json"

download_via_rpc() {
	local asset="$1"
	local out_json="$2"
	local start_json="$TMP_DIR/dl_start_${asset}.json"
	local dl_url=""
	local digest=""
	local size="0"
	dl_url="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["data"]
for a in d.get("assets", []):
    if a["name"] == sys.argv[2]:
        print(a.get("browser_download_url", ""))
        break
' "$TMP_DIR/release.json" "$asset")"
	digest="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["data"]
for a in d.get("assets", []):
    if a["name"] == sys.argv[2]:
        print(a.get("digest", ""))
        break
' "$TMP_DIR/release.json" "$asset")"
	size="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["data"]
for a in d.get("assets", []):
    if a["name"] == sys.argv[2]:
        print(a.get("size", 0))
        break
' "$TMP_DIR/release.json" "$asset")"

	curl -fsS -b "$COOKIE_JAR" \
		--data-urlencode "token=$TOKEN" \
		--data-urlencode "task=start" \
		--data-urlencode "asset=$asset" \
		--data-urlencode "download_url=$dl_url" \
		--data-urlencode "expected_digest=$digest" \
		--data-urlencode "total_bytes=$size" \
		--data-urlencode "bin_path=/usr/bin/sni-spoof-rs" \
		"${API_BASE}/sni_spoofer_download" -o "$start_json"

	local task_id
	task_id="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["code"]==1, d; print(d["data"]["task_id"])' "$start_json")"

	local attempt=0
	while [ "$attempt" -lt 90 ]; do
		curl -fsS -b "$COOKIE_JAR" \
			--data-urlencode "token=$TOKEN" \
			--data-urlencode "task=progress" \
			--data-urlencode "task_id=$task_id" \
			"${API_BASE}/sni_spoofer_download" -o "$out_json"
		local state
		state="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("data",{}).get("status",""))' "$out_json")"
		if [ "$state" = "done" ]; then
			return 0
		elif [ "$state" = "error" ]; then
			return 2
		fi
		attempt=$((attempt + 1))
		sleep 1
	done
	return 3
}

# 4. Download ARMv7 Google WiFi binary -> verify ELF armv7 + arch_match=false + clean start block
if download_via_rpc "sni-spoof-rs-google-wifi-armv7-musl" "$TMP_DIR/dl_arm_done.json"; then
	curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_status" -o "$TMP_DIR/status_arm.json"
	python3 -c '
import json, sys
b = json.load(open(sys.argv[1]))["data"]["binary"]
assert b["exists"] is True and b["executable"] is True, b
assert b["elf"]["valid"] is True and "arm" in b["elf"]["arch"], b["elf"]
assert b["arch_match"] is False, f"expected cross-arch false on x86_64: {b}"
' "$TMP_DIR/status_arm.json"

	# Attempting start with cross-arch binary must fail cleanly (code=0, descriptive message)
	curl -fsS -b "$COOKIE_JAR" \
		--data-urlencode "token=$TOKEN" \
		--data-urlencode "action=start" \
		"${API_BASE}/sni_spoofer_control" -o "$TMP_DIR/ctrl_arm_start.json"
	python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))
assert r.get("code") == 0, f"expected clean block starting armv7 binary on x86_64: {r}"
' "$TMP_DIR/ctrl_arm_start.json"
	echo "E2E [4/6]: ARMv7 GitHub download + ELF cross-arch safeguard OK"
else
	fail "Failed downloading armv7 release asset: $(cat "$TMP_DIR/dl_arm_done.json")"
fi

# 5. Download amd64 binary via RPC, then also test chunked Base64 upload RPC round-trip
if download_via_rpc "sni-spoof-rs-linux-amd64-musl" "$TMP_DIR/dl_amd64_done.json"; then
	curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_status" -o "$TMP_DIR/status_amd64_dl.json"
	DL_SHA="$(python3 -c '
import json, sys
b = json.load(open(sys.argv[1]))["data"]["binary"]
assert b["exists"] is True and b["executable"] is True, b
assert b["elf"]["valid"] is True and b["arch_match"] is True, b
assert b["help_ok"] is True, b
print(b["sha256"])
' "$TMP_DIR/status_amd64_dl.json")"

	# Pull binary out of container & re-upload via multi-chunk Base64 HTTP POSTs
	docker exec "$CONTAINER" cat /usr/bin/sni-spoof-rs > "$TMP_DIR/amd64_bin"
	docker exec "$CONTAINER" rm -f /usr/bin/sni-spoof-rs

	python3 - "$TMP_DIR/amd64_bin" "$TMP_DIR/chunks.json" <<'PY'
import base64, json, math, sys
data = open(sys.argv[1], "rb").read()
chunk_sz = 24576
total = math.ceil(len(data) / chunk_sz)
chunks = []
for i in range(total):
    part = data[i * chunk_sz : (i + 1) * chunk_sz]
    chunks.append(base64.b64encode(part).decode("ascii"))
json.dump(chunks, open(sys.argv[2], "w"))
PY

	TOTAL_CHUNKS="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$TMP_DIR/chunks.json")"
	UPLOAD_ID="e2e_ul_$$"
	for idx in $(seq 0 $((TOTAL_CHUNKS - 1))); do
		python3 - "$TMP_DIR/chunks.json" "$idx" "$TOTAL_CHUNKS" "$UPLOAD_ID" "$TOKEN" "$TMP_DIR/ul_body_${idx}.txt" <<'PY'
import json, sys, urllib.parse
chunk = json.load(open(sys.argv[1]))[int(sys.argv[2])]
body = urllib.parse.urlencode({
    "token": sys.argv[5],
    "upload_id": sys.argv[4],
    "chunk_index": sys.argv[2],
    "total_chunks": sys.argv[3],
    "chunk": chunk,
    "bin_path": "/usr/bin/sni-spoof-rs",
    "filename": "sni-spoof-rs-linux-amd64-musl",
})
open(sys.argv[6], "w", encoding="ascii").write(body)
PY
		curl -fsS -b "$COOKIE_JAR" \
			-H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" \
			--data-binary "@$TMP_DIR/ul_body_${idx}.txt" \
			"${API_BASE}/sni_spoofer_upload" -o "$TMP_DIR/ul_chunk_${idx}.json"
	done

	python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))
assert r.get("code") == 1, r
assert r["data"]["status"] == "success", r
assert r["data"]["binary"]["sha256"] == sys.argv[2], (r, sys.argv[2])
' "$TMP_DIR/ul_chunk_$((TOTAL_CHUNKS - 1)).json" "$DL_SHA"

	# Verify sysupgrade.conf single entry (no duplicates)
	SYSUP_CNT="$(docker exec "$CONTAINER" grep -cx "/usr/bin/sni-spoof-rs" /etc/sysupgrade.conf)"
	[ "$SYSUP_CNT" = "1" ] || fail "expected single sysupgrade entry, got $SYSUP_CNT"
	echo "E2E [5/6]: amd64 GitHub download + $TOTAL_CHUNKS-chunk upload + sysupgrade OK"
else
	fail "Failed downloading amd64 release asset: $(cat "$TMP_DIR/dl_amd64_done.json")"
fi

# 6. Save config -> Start -> Live config.json & uncolored logs -> Restart -> Stop -> Clear log
SAVE_PAYLOAD="$(python3 -c '
import json
print(json.dumps({
    "global": {
        "enabled": "1",
        "bin_path": "/usr/bin/sni-spoof-rs",
        "rust_log": "debug",
        "idle_timeout": "",
        "buffer_size": "8",
        "graceful_shutdown_sec": "1",
        "github_asset": "sni-spoof-rs-linux-amd64-musl"
    },
    "listeners": [{
        "enabled": "1",
        "remarks": "E2E Listener",
        "listen": "127.0.0.1:40443",
        "connect": "104.18.4.130:443",
        "fake_sni": "security.vercel.com",
        "conn_timeout_sec": "5",
        "handshake_timeout_sec": "2",
        "keepalive_time_sec": "11",
        "keepalive_interval_sec": "2"
    }]
}))')"

curl -fsS -b "$COOKIE_JAR" \
	--data-urlencode "token=$TOKEN" \
	--data-urlencode "payload=$SAVE_PAYLOAD" \
	"${API_BASE}/sni_spoofer_save" -o "$TMP_DIR/save_ok.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["code"]==1, d' "$TMP_DIR/save_ok.json"

curl -fsS -b "$COOKIE_JAR" --data-urlencode "token=$TOKEN" --data-urlencode "action=start" \
	"${API_BASE}/sni_spoofer_control" -o "$TMP_DIR/start.json"
sleep 1
curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_status" -o "$TMP_DIR/running1.json"

PID1="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["data"]
assert d["running"] is True and isinstance(d["pid"], int) and d["pid"] > 0, d
print(d["pid"])
' "$TMP_DIR/running1.json")"

docker exec "$CONTAINER" cat /tmp/etc/passwall2/sni_spoofer/config.json > "$TMP_DIR/live_config.json"
python3 -c '
import json, sys
cfg = json.load(open(sys.argv[1]))
assert "idle_timeout" not in cfg, cfg
assert cfg["buffer_size"] == 8, cfg
assert cfg["graceful_shutdown_sec"] == 1, cfg
assert len(cfg["listeners"]) == 1, cfg
assert cfg["listeners"][0]["fake_sni"] == "security.vercel.com", cfg
' "$TMP_DIR/live_config.json"

curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_log?limit=300" -o "$TMP_DIR/logs.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["data"]
lines = d.get("lines", [])
assert len(lines) > 0, f"expected live logs after start, got {d}"
joined = "\n".join(lines)
assert "\x1b[" not in joined, f"unexpected ANSI color codes in logs: {joined!r}"
' "$TMP_DIR/logs.json"

curl -fsS -b "$COOKIE_JAR" --data-urlencode "token=$TOKEN" --data-urlencode "action=restart" \
	"${API_BASE}/sni_spoofer_control" -o "$TMP_DIR/restart.json"
sleep 1
curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_status" -o "$TMP_DIR/running2.json"
PID2="$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["data"]
assert d["running"] is True and d["pid"] > 0, d
print(d["pid"])
' "$TMP_DIR/running2.json")"
[ "$PID1" != "$PID2" ] || fail "Expected new PID after restart ($PID1 == $PID2)"

curl -fsS -b "$COOKIE_JAR" --data-urlencode "token=$TOKEN" --data-urlencode "action=stop" \
	"${API_BASE}/sni_spoofer_control" -o "$TMP_DIR/stop.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["data"]
assert d["running"] is False and d.get("pid") is None, d
' "$TMP_DIR/stop.json"

curl -fsS -b "$COOKIE_JAR" --data-urlencode "token=$TOKEN" --data-urlencode "action=clear" \
	"${API_BASE}/sni_spoofer_log" -o "$TMP_DIR/clear.json"
curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_log?limit=300" -o "$TMP_DIR/logs_cleared.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))["data"]
assert d["total_bytes"] == 0 and d["lines"] == [], d
' "$TMP_DIR/logs_cleared.json"

echo "E2E [6/6]: save -> start (PID=$PID1) -> config.json + NO_COLOR logs -> restart (PID=$PID2) -> stop -> clear OK"
echo "PASS: test_docker_e2e.sh (all 6 scenarios)"
