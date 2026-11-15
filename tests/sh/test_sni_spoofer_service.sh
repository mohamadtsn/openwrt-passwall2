#!/bin/sh
set -eu

PASSWALL_BAK="$(mktemp /tmp/passwall2_uci_bak.XXXXXX)"
cp -f /etc/config/passwall2 "$PASSWALL_BAK"
TEST_BIN="/tmp/test_sni_spoof_rs_amd64"

cleanup() {
	[ -x /etc/init.d/passwall2_sni_spoofer ] && /etc/init.d/passwall2_sni_spoofer stop >/dev/null 2>&1 || true
	cp -f "$PASSWALL_BAK" /etc/config/passwall2
	uci revert passwall2 >/dev/null 2>&1 || true
	rm -f "$PASSWALL_BAK" /tmp/etc/passwall2_sni_spoofer/config.json /tmp/etc/passwall2_sni_spoofer/manual_stop /tmp/etc/passwall2_sni_spoofer/iface_state /var/run/passwall2_sni_spoofer.pid /var/run/passwall2_sni_spoofer_boot.pid
}
trap cleanup EXIT

fail() {
	echo "FAIL: $1" >&2
	exit 1
}

[ -x /etc/init.d/passwall2_sni_spoofer ] || fail "/etc/init.d/passwall2_sni_spoofer not found or not executable"
[ -x /usr/share/passwall2/sni_spoofer.sh ] || fail "/usr/share/passwall2/sni_spoofer.sh not found or not executable"
[ -f /etc/hotplug.d/iface/99-passwall2-sni-spoofer ] || fail "/etc/hotplug.d/iface/99-passwall2-sni-spoofer not found"

sh -n /etc/init.d/passwall2_sni_spoofer
sh -n /usr/share/passwall2/sni_spoofer.sh
sh -n /etc/hotplug.d/iface/99-passwall2-sni-spoofer

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

[ -f /tmp/etc/passwall2_sni_spoofer/config.json ] || fail "config.json missing"
[ "$(jsonfilter -i /tmp/etc/passwall2_sni_spoofer/config.json -e '@.listeners[0].fake_sni')" = "security.vercel.com" ] || fail "config.json fake_sni mismatch"

[ -f /var/run/passwall2_sni_spoofer.pid ] || fail "PID file missing after start"
PID1="$(cat /var/run/passwall2_sni_spoofer.pid)"
kill -0 "$PID1" 2>/dev/null || fail "PID1 is not alive"
/etc/init.d/passwall2_sni_spoofer status >/dev/null 2>&1 || fail "status failed while running"

# Verify app.sh stop process-kill regex and TMP_PATH wipe cannot hit running spoofer
KILL_FILTER="$(grep 'pgrep -af "${CONFIG}/"' /usr/share/passwall2/app.sh || true)"
[ -n "$KILL_FILTER" ] || fail "expected pgrep line in app.sh"
if CONFIG=passwall2 sh -c 'busybox pgrep -af "${1}/" | awk '\''! /app\.sh|subscribe\.lua|rule_update\.lua|tasks\.sh|server_app\.lua|sni_spoofer|sni-spoof-rs|ujail/{print $1}'\''' sh passwall2 | grep -qx "$PID1"; then
	fail "app.sh pgrep kill filter matched SNI Spoofer PID $PID1"
fi
mkdir -p /tmp/etc/passwall2
rm -rf /tmp/etc/passwall2
[ -f /tmp/etc/passwall2_sni_spoofer/config.json ] || fail "config.json removed when /tmp/etc/passwall2 cleaned"
kill -0 "$PID1" 2>/dev/null || fail "PID1 died after /tmp/etc/passwall2 cleanup"

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
[ -f /tmp/etc/passwall2_sni_spoofer/manual_stop ] || fail "manual_stop flag missing after stop"

# 4. Boot with enabled=1 starts service, and manual_stop blocks hotplug resurrection
uci set passwall2.global_sni_spoofer.enabled='1'
uci commit passwall2

DEF_DEV="$(ip route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); break } exit }' || true)"
if [ -n "$DEF_DEV" ]; then
	ACTION=ifup DEVICE="$DEF_DEV" sh /etc/hotplug.d/iface/99-passwall2-sni-spoofer
	sleep 1
	if /etc/init.d/passwall2_sni_spoofer status >/dev/null 2>&1; then
		fail "hotplug started daemon despite manual_stop"
	fi
fi

/etc/init.d/passwall2_sni_spoofer boot || fail "boot failed when enabled=1"
[ ! -f /tmp/etc/passwall2_sni_spoofer/manual_stop ] || fail "manual_stop remained after boot"
/etc/init.d/passwall2_sni_spoofer status >/dev/null 2>&1 || fail "boot did not start service while enabled=1"
PID_BOOT="$(cat /var/run/passwall2_sni_spoofer.pid)"
kill -0 "$PID_BOOT" 2>/dev/null || fail "boot PID is not alive"

# Simulated ifup when daemon is not running and not manually stopped starts it via hotplug
if [ -n "$DEF_DEV" ]; then
	/etc/init.d/passwall2_sni_spoofer stop || fail "stop before hotplug test failed"
	rm -f /tmp/etc/passwall2_sni_spoofer/manual_stop
	ACTION=ifup DEVICE="$DEF_DEV" sh /etc/hotplug.d/iface/99-passwall2-sni-spoofer
	WAIT_OK=0
	for _w in $(seq 1 15); do
		if /etc/init.d/passwall2_sni_spoofer status >/dev/null 2>&1; then
			WAIT_OK=1
			break
		fi
		sleep 0.2 2>/dev/null || sleep 1
	done
	[ "$WAIT_OK" = "1" ] || fail "hotplug did not start service on ifup of $DEF_DEV"
	PID_HP1="$(cat /var/run/passwall2_sni_spoofer.pid)"

	# Hotplug helper checks: matching device is detected and unchanged route does not bounce daemon
	/usr/share/passwall2/sni_spoofer.sh _uses_device "$DEF_DEV" || fail "_uses_device failed for $DEF_DEV"
	if /usr/share/passwall2/sni_spoofer.sh _routes_changed; then
		fail "_routes_changed returned true when route signature was unchanged"
	fi
	ACTION=ifup DEVICE="$DEF_DEV" sh /etc/hotplug.d/iface/99-passwall2-sni-spoofer
	sleep 1
	[ "$(cat /var/run/passwall2_sni_spoofer.pid)" = "$PID_HP1" ] || fail "redundant ifup bounced daemon unexpectedly"

	# ifdown clears iface_state, and subsequent ifup restarts daemon so AF_PACKET rebinds cleanly
	ACTION=ifdown DEVICE="$DEF_DEV" sh /etc/hotplug.d/iface/99-passwall2-sni-spoofer
	[ ! -f /tmp/etc/passwall2_sni_spoofer/iface_state ] || fail "ifdown did not clear iface_state for $DEF_DEV"
	ACTION=ifup DEVICE="$DEF_DEV" sh /etc/hotplug.d/iface/99-passwall2-sni-spoofer
	REBOUND_OK=0
	for _w in $(seq 1 20); do
		PID_HP2="$(cat /var/run/passwall2_sni_spoofer.pid 2>/dev/null || true)"
		if [ -n "$PID_HP2" ] && [ "$PID_HP2" != "$PID_HP1" ] && kill -0 "$PID_HP2" 2>/dev/null; then
			REBOUND_OK=1
			break
		fi
		sleep 0.2 2>/dev/null || sleep 1
	done
	[ "$REBOUND_OK" = "1" ] || fail "ifup after ifdown did not restart daemon to rebind AF_PACKET"

	/etc/init.d/passwall2_sni_spoofer stop >/dev/null 2>&1 || true
fi

echo "PASS: test_sni_spoofer_service.sh (all assertions)"
