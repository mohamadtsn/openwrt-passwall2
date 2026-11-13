#!/bin/sh
set -eu

TMP_DIR="$(mktemp -d /tmp/test_uci_defaults.XXXXXX)"
cleanup() {
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $1" >&2
	exit 1
}

assert_eq() {
	actual="$1"
	expected="$2"
	msg="$3"
	if [ "$actual" != "$expected" ]; then
		fail "$msg (expected '$expected', got '$actual')"
	fi
}

TMP_UCI="$TMP_DIR/uci"
mkdir -p "$TMP_UCI"
cp /usr/share/passwall2/0_default_config "$TMP_UCI/passwall2"

assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.global_sni_spoofer.enabled || true)" "0" "default enabled"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.global_sni_spoofer.bin_path || true)" "/usr/bin/sni-spoof-rs" "default bin_path"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.global_sni_spoofer.rust_log || true)" "warn" "default rust_log"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.global_sni_spoofer.buffer_size || true)" "8" "default buffer_size"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.global_sni_spoofer.graceful_shutdown_sec || true)" "0" "default graceful_shutdown_sec"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.global_sni_spoofer.github_asset || true)" "sni-spoof-rs-google-wifi-armv7-musl" "default github_asset"

assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].enabled || true)" "0" "listener enabled"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].remarks || true)" "Example Cloudflare" "listener remarks"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].listen || true)" "127.0.0.1:40443" "listener listen"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].connect || true)" "172.67.139.236:443" "listener connect"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].fake_sni || true)" "security.vercel.com" "listener fake_sni"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].conn_timeout_sec || true)" "5" "listener conn_timeout_sec"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].handshake_timeout_sec || true)" "2" "listener handshake_timeout_sec"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].keepalive_time_sec || true)" "11" "listener keepalive_time_sec"
assert_eq "$(uci -c "$TMP_UCI" -q get passwall2.@sni_spoofer_listener[0].keepalive_interval_sec || true)" "2" "listener keepalive_interval_sec"

# Migration test: legacy config without global_sni_spoofer
TMP_MIG="$TMP_DIR/mig"
mkdir -p "$TMP_MIG"
cat > "$TMP_MIG/passwall2" <<'EOF'
config global 'global'
	option enabled '0'
EOF
touch "$TMP_DIR/sysupgrade.conf"

PASSWALL2_UCI_DIR="$TMP_MIG" PASSWALL2_SYSUPGRADE_CONF="$TMP_DIR/sysupgrade.conf" PASSWALL2_SKIP_SYSTEM_UCI=1 sh /etc/uci-defaults/luci-app-passwall2
PASSWALL2_UCI_DIR="$TMP_MIG" PASSWALL2_SYSUPGRADE_CONF="$TMP_DIR/sysupgrade.conf" PASSWALL2_SKIP_SYSTEM_UCI=1 sh /etc/uci-defaults/luci-app-passwall2

assert_eq "$(uci -c "$TMP_MIG" -q get passwall2.global_sni_spoofer || true)" "global_sni_spoofer" "migrated section exists"
assert_eq "$(uci -c "$TMP_MIG" -q get passwall2.global_sni_spoofer.bin_path || true)" "/usr/bin/sni-spoof-rs" "migrated bin_path"
assert_eq "$(uci -c "$TMP_MIG" -q get passwall2.global_sni_spoofer.github_asset || true)" "sni-spoof-rs-google-wifi-armv7-musl" "migrated github_asset"

COUNT="$(grep -c -F -x '/usr/bin/sni-spoof-rs' "$TMP_DIR/sysupgrade.conf" || true)"
assert_eq "$COUNT" "1" "sysupgrade.conf contains exactly 1 matching bin_path line"

echo "PASS: test_uci_defaults.sh (all assertions)"
