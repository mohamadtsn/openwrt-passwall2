#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${PASSWALL2_URL:-http://localhost:8080/cgi-bin/luci}"
COOKIE_JAR="$(mktemp /tmp/pw2_rpc_cookie.XXXXXX)"
TMP_DIR="$(mktemp -d /tmp/pw2_rpc_test.XXXXXX)"
PASSWALL_BAK="/tmp/pw2_rpc_uci_bak.$$"

docker exec passwall2-dev cp -f /etc/config/passwall2 "$PASSWALL_BAK"

cleanup() {
	docker exec passwall2-dev sh -c "
		[ -f '$PASSWALL_BAK' ] && cp -f '$PASSWALL_BAK' /etc/config/passwall2 && rm -f '$PASSWALL_BAK'
		uci revert passwall2 >/dev/null 2>&1 || true
	" >/dev/null 2>&1 || true
	rm -rf "$TMP_DIR" "$COOKIE_JAR"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $1" >&2
	exit 1
}

# Authenticate and extract CSRF token from LuCI HTML
curl -fsS -L -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
	-d "luci_username=root&luci_password=root" \
	"${BASE_URL}/admin/services/passwall2" \
	-o "$TMP_DIR/login.html"

TOKEN="$(python3 -c '
import re, sys
html = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()
m = re.search(r"\"token\"\s*:\s*\"([a-fA-F0-9]+)\"", html)
print(m.group(1) if m else "")
' "$TMP_DIR/login.html")"

[ -n "$TOKEN" ] || fail "Failed to extract LuCI CSRF token after login"

API_BASE="${BASE_URL}/admin/services/passwall2"

# 0. Menu page HTTP 200
PAGE_HTTP="$(curl -sS -b "$COOKIE_JAR" -o "$TMP_DIR/page.html" -w "%{http_code}" "${API_BASE}/sni_spoofer")"
[ "$PAGE_HTTP" = "200" ] || fail "GET /sni_spoofer expected 200, got ${PAGE_HTTP}"

# 1. GET control must be rejected (405 Method Not Allowed) & invalid CSRF token rejected (403)
CTRL_GET_HTTP="$(curl -sS -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "${API_BASE}/sni_spoofer_control?action=start")"
[ "$CTRL_GET_HTTP" = "403" ] || [ "$CTRL_GET_HTTP" = "405" ] || fail "GET control must reject with 403/405, got ${CTRL_GET_HTTP}"

CTRL_BAD_HTTP="$(curl -sS -b "$COOKIE_JAR" -d "token=invalid_token&action=start" -o /dev/null -w "%{http_code}" "${API_BASE}/sni_spoofer_control")"
[ "$CTRL_BAD_HTTP" = "403" ] || fail "POST control with bad token expected 403, got ${CTRL_BAD_HTTP}"

# 2. GET sni_spoofer_status
STATUS_HTTP="$(curl -sS -b "$COOKIE_JAR" -o "$TMP_DIR/status.json" -w "%{http_code}" "${API_BASE}/sni_spoofer_status")"
[ "$STATUS_HTTP" = "200" ] || fail "GET /sni_spoofer_status expected 200, got ${STATUS_HTTP}"

python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("code") == 1, f"expected code=1, got {d}"
data = d["data"]
for k in ("running", "host_arch", "binary", "config", "json_preview", "log_bytes"):
    assert k in data, f"missing status key {k}"
assert data["host_arch"] != "", "empty host_arch"
assert data["config"]["global"]["bin_path"], "missing bin_path"
' "$TMP_DIR/status.json"

# 3. POST sni_spoofer_save (invalid 220-byte fake_sni must return code=0 without overwriting valid config)
ORIG_RUST_LOG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["data"]["config"]["global"]["rust_log"])' "$TMP_DIR/status.json")"
BAD_PAYLOAD="$(python3 -c '
import json
print(json.dumps({
    "global": {
        "enabled": "0",
        "bin_path": "/usr/bin/sni-spoof-rs",
        "rust_log": "trace",
        "idle_timeout": "",
        "buffer_size": "8",
        "graceful_shutdown_sec": "0",
        "github_asset": "sni-spoof-rs-google-wifi-armv7-musl"
    },
    "listeners": [{
        "enabled": "1",
        "remarks": "TooLong",
        "listen": "127.0.0.1:42443",
        "connect": "172.67.139.236:443",
        "fake_sni": "a" * 220,
        "conn_timeout_sec": "5",
        "handshake_timeout_sec": "2",
        "keepalive_time_sec": "11",
        "keepalive_interval_sec": "2"
    }]
}))')"

SAVE_BAD_HTTP="$(curl -sS -b "$COOKIE_JAR" \
	--data-urlencode "token=$TOKEN" \
	--data-urlencode "payload=$BAD_PAYLOAD" \
	-o "$TMP_DIR/save_bad.json" -w "%{http_code}" \
	"${API_BASE}/sni_spoofer_save")"
[ "$SAVE_BAD_HTTP" = "200" ] || fail "POST invalid save expected HTTP 200 JSON error, got ${SAVE_BAD_HTTP}"

python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("code") == 0, f"expected code=0 on invalid fake_sni, got {d}"
errs = d.get("data", {}).get("errors", {})
assert any("fake_sni" in k for k in errs), f"missing fake_sni field error: {errs}"
' "$TMP_DIR/save_bad.json"

# Verify UCI wasn't overwritten by invalid save
curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_status" -o "$TMP_DIR/status_after_bad.json"
AFTER_BAD_LOG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["data"]["config"]["global"]["rust_log"])' "$TMP_DIR/status_after_bad.json")"
[ "$AFTER_BAD_LOG" = "$ORIG_RUST_LOG" ] || fail "Invalid save overwrote UCI rust_log ($AFTER_BAD_LOG != $ORIG_RUST_LOG)"

# Valid save persists and returns updated snapshot
GOOD_PAYLOAD="$(python3 -c '
import json
print(json.dumps({
    "global": {
        "enabled": "0",
        "bin_path": "/usr/bin/sni-spoof-rs",
        "rust_log": "info",
        "idle_timeout": "",
        "buffer_size": "8",
        "graceful_shutdown_sec": "0",
        "github_asset": "sni-spoof-rs-google-wifi-armv7-musl"
    },
    "listeners": [{
        "enabled": "1",
        "remarks": "Cloudflare",
        "listen": "127.0.0.1:42443",
        "connect": "172.67.139.236:443",
        "fake_sni": "security.vercel.com",
        "conn_timeout_sec": "5",
        "handshake_timeout_sec": "2",
        "keepalive_time_sec": "11",
        "keepalive_interval_sec": "2"
    }]
}))')"

curl -fsS -b "$COOKIE_JAR" \
	--data-urlencode "token=$TOKEN" \
	--data-urlencode "payload=$GOOD_PAYLOAD" \
	"${API_BASE}/sni_spoofer_save" -o "$TMP_DIR/save_good.json"

python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("code") == 1, f"expected code=1 on valid save, got {d}"
assert d["data"]["config"]["global"]["rust_log"] == "info"
assert len(d["data"]["config"]["listeners"]) == 1
' "$TMP_DIR/save_good.json"

# 4. Log tail + CSRF-protected clear
docker exec passwall2-dev sh -c 'printf "2026-11-13 INFO controller test entry\n" > /tmp/log/passwall2_sni_spoofer.log'
curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_log" -o "$TMP_DIR/log_read.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("code") == 1
assert any("controller test entry" in l for l in d["data"]["lines"]), d
' "$TMP_DIR/log_read.json"

curl -fsS -b "$COOKIE_JAR" \
	--data-urlencode "token=$TOKEN" \
	--data-urlencode "action=clear" \
	"${API_BASE}/sni_spoofer_log" -o "$TMP_DIR/log_clear.json"

curl -fsS -b "$COOKIE_JAR" "${API_BASE}/sni_spoofer_log" -o "$TMP_DIR/log_after.json"
python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("code") == 1
assert d["data"]["total_bytes"] == 0 and d["data"]["lines"] == [], d
' "$TMP_DIR/log_after.json"

echo "PASS: test_controller_rpc.sh (CSRF + status + save + log)"
