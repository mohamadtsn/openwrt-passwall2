#!/bin/sh
set -eu

PASSWALL_BAK="$(mktemp /tmp/passwall2_uci_bak.XXXXXX)"
cp -f /etc/config/passwall2 "$PASSWALL_BAK"
TEST_BIN="/tmp/test_sni_spoof_rs_amd64"

cleanup() {
	[ -x /etc/init.d/passwall2_sni_spoofer ] && /etc/init.d/passwall2_sni_spoofer stop >/dev/null 2>&1 || true
	cp -f "$PASSWALL_BAK" /etc/config/passwall2
	uci revert passwall2 >/dev/null 2>&1 || true
	rm -f "$PASSWALL_BAK" /tmp/etc/passwall2/sni_spoofer/config.json /var/run/passwall2_sni_spoofer.pid
}
trap cleanup EXIT

fail() {
	echo "FAIL: $1" >&2
	exit 1
}

[ -x /etc/init.d/passwall2_sni_spoofer ] || fail "/etc/init.d/passwall2_sni_spoofer not found or not executable"
[ -x /usr/share/passwall2/sni_spoofer.sh ] || fail "/usr/share/passwall2/sni_spoofer.sh not found or not executable"

sh -n /etc/init.d/passwall2_sni_spoofer
sh -n /usr/share/passwall2/sni_spoofer.sh

# 1. Boot does not start when disabled
uci set passwall2.global_sni_spoofer.enabled='0'
uci set passwall2.global_sni_spoofer.bin_path='/tmp/nonexistent-sni'
uci commit passwall2
/etc/init.d/passwall2_sni_spoofer boot
if /etc/init.d/passwall2_sni_spoofer status >/dev/null 2>&1; then
	fail "boot started service while enabled=0"
fi

# 2. Missing binary start fails with descriptive log entry
: > /tmp/log/passwall2_sni_spoofer.log
if /etc/init.d/passwall2_sni_spoofer start >/dev/null 2>&1; then
	fail "start should fail when bin_path is missing"
fi
grep -qiE "binary|exist|found|not executable" /tmp/log/passwall2_sni_spoofer.log || fail "missing binary error not logged"

# 3. Real x86_64 musl daemon lifecycle test
if [ ! -x "$TEST_BIN" ]; then
	curl -fsSL "https://github.com/mohamadtsn/sni-spoofing-rust/releases/latest/download/sni-spoof-rs-linux-amd64-musl" -o "$TEST_BIN"
	chmod 0755 "$TEST_BIN"
fi

# Configure clean enabled listener
while uci -q delete passwall2.@sni_spoofer_listener[0]; do :; done
sid="$(uci add passwall2 sni_spoofer_listener)"
uci set "passwall2.${sid}.enabled=1"
uci set "passwall2.${sid}.remarks=DockerTest"
uci set "passwall2.${sid}.listen=127.0.0.1:41443"
uci set "passwall2.${sid}.connect=172.67.139.236:443"
uci set "passwall2.${sid}.fake_sni=security.vercel.com"
uci set "passwall2.${sid}.conn_timeout_sec=5"
uci set "passwall2.${sid}.handshake_timeout_sec=2"
uci set "passwall2.${sid}.keepalive_time_sec=11"
uci set "passwall2.${sid}.keepalive_interval_sec=2"

uci set passwall2.global_sni_spoofer.enabled='0'
uci set passwall2.global_sni_spoofer.bin_path="$TEST_BIN"
uci set passwall2.global_sni_spoofer.rust_log='debug'
uci set passwall2.global_sni_spoofer.buffer_size='8'
uci set passwall2.global_sni_spoofer.graceful_shutdown_sec='0'
uci delete passwall2.global_sni_spoofer.idle_timeout >/dev/null 2>&1 || true
uci commit passwall2

: > /tmp/log/passwall2_sni_spoofer.log
/etc/init.d/passwall2_sni_spoofer start || fail "start failed with real x86_64 binary"

[ -f /tmp/etc/passwall2/sni_spoofer/config.json ] || fail "config.json missing"
[ "$(jsonfilter -i /tmp/etc/passwall2/sni_spoofer/config.json -e '@.listeners[0].fake_sni')" = "security.vercel.com" ] || fail "config.json fake_sni mismatch"

[ -f /var/run/passwall2_sni_spoofer.pid ] || fail "PID file missing after start"
PID1="$(cat /var/run/passwall2_sni_spoofer.pid)"
kill -0 "$PID1" 2>/dev/null || fail "PID1 is not alive"
/etc/init.d/passwall2_sni_spoofer status >/dev/null 2>&1 || fail "status failed while running"

tr '\0' '\n' < "/proc/$PID1/environ" | grep -qx "NO_COLOR=1" || fail "NO_COLOR=1 missing in daemon env"
tr '\0' '\n' < "/proc/$PID1/environ" | grep -qx "RUST_LOG=debug" || fail "RUST_LOG=debug missing in daemon env"

# Verify no ANSI ESC sequences leaked into log
if grep -q "$(printf '\033')" /tmp/log/passwall2_sni_spoofer.log; then
	fail "ANSI escape found in log despite NO_COLOR=1"
fi

/etc/init.d/passwall2_sni_spoofer restart || fail "restart failed"
PID2="$(cat /var/run/passwall2_sni_spoofer.pid)"
[ "$PID2" != "$PID1" ] || fail "restart did not produce new PID"
kill -0 "$PID2" 2>/dev/null || fail "PID2 not alive after restart"

timeout 10 /usr/share/passwall2/sni_spoofer.sh restart || fail "direct sni_spoofer.sh restart deadlocked or failed"
PID3="$(cat /var/run/passwall2_sni_spoofer.pid)"
[ "$PID3" != "$PID2" ] || fail "direct sni_spoofer.sh restart did not produce new PID"
kill -0 "$PID3" 2>/dev/null || fail "PID3 not alive after direct restart"

/etc/init.d/passwall2_sni_spoofer stop || fail "stop failed"
[ ! -f /var/run/passwall2_sni_spoofer.pid ] || fail "PID file remained after stop"
if kill -0 "$PID3" 2>/dev/null; then
	fail "daemon still running after stop"
fi
if /etc/init.d/passwall2_sni_spoofer status >/dev/null 2>&1; then
	fail "status returned 0 after stop"
fi

echo "PASS: test_sni_spoofer_service.sh (all assertions)"
