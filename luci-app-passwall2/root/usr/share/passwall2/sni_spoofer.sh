#!/bin/sh
set -eu

LOG_FILE="/tmp/log/passwall2_sni_spoofer.log"
PID_FILE="/var/run/passwall2_sni_spoofer.pid"
BOOT_PID_FILE="/var/run/passwall2_sni_spoofer_boot.pid"
RUNTIME_DIR="/tmp/etc/passwall2_sni_spoofer"
CONFIG_JSON="$RUNTIME_DIR/config.json"
MANUAL_STOP_FILE="$RUNTIME_DIR/manual_stop"
IFACE_STATE_FILE="$RUNTIME_DIR/iface_state"
LOCK_DIR="/var/lock/passwall2_sni_spoofer.lock.d"

mkdir -p /tmp/log /var/run /var/lock "$RUNTIME_DIR"

log_line() {
	printf '%s [sni-spoofer] %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'now')" "$1" >>"$LOG_FILE"
}

release_lock() {
	local holder
	holder="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
	if [ -z "$holder" ] || [ "$holder" = "$$" ]; then
		rm -rf "$LOCK_DIR"
	fi
}

sleep_short() {
	if command -v usleep >/dev/null 2>&1; then
		usleep 200000
	else
		lua -e 'require("nixio").nanosleep(0, 200000000)' 2>/dev/null || sleep 1
	fi
}

acquire_lock() {
	local holder
	holder="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
	if [ -n "$holder" ] && [ "$holder" = "$$" ]; then
		return 0
	fi

	local attempts=0
	while ! mkdir "$LOCK_DIR" 2>/dev/null; do
		holder="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
		if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
			rm -rf "$LOCK_DIR"
			continue
		fi
		attempts=$((attempts + 1))
		if [ "$attempts" -ge 50 ]; then
			echo "Timed out waiting for sni_spoofer lock" >&2
			return 1
		fi
		sleep_short
	done
	printf '%s\n' "$$" >"$LOCK_DIR/pid"
	trap 'release_lock' EXIT INT TERM
}

uci_get_opt() {
	uci -q get "passwall2.global_sni_spoofer.$1" 2>/dev/null || true
}

read_pid_alive() {
	[ -f "$PID_FILE" ] || return 1
	local pid
	pid="$(cat "$PID_FILE" 2>/dev/null || true)"
	case "$pid" in
		''|*[!0-9]*) return 1 ;;
	esac
	[ -d "/proc/$pid" ] || return 1
	kill -0 "$pid" 2>/dev/null || return 1
	local bin_path base
	bin_path="$(uci_get_opt bin_path)"
	[ -z "$bin_path" ] && bin_path="/usr/bin/sni-spoof-rs"
	base="$(basename "$bin_path")"
	if [ -r "/proc/$pid/cmdline" ] && ! tr '\0' ' ' <"/proc/$pid/cmdline" | grep -qF "$base"; then
		return 1
	fi
	printf '%s\n' "$pid"
}

stop_boot_wait() {
	[ -f "$BOOT_PID_FILE" ] || return 0
	local bpid
	bpid="$(cat "$BOOT_PID_FILE" 2>/dev/null || true)"
	case "$bpid" in
		''|*[!0-9]*) ;;
		*)
			if [ "$bpid" != "$$" ] && [ -r "/proc/$bpid/cmdline" ] && tr '\0' ' ' <"/proc/$bpid/cmdline" 2>/dev/null | grep -qF "sni_spoofer.sh"; then
				kill -TERM "$bpid" 2>/dev/null || true
			fi
			;;
	esac
	rm -f "$BOOT_PID_FILE"
}

list_upstream_ips() {
	[ -s "$CONFIG_JSON" ] || return 0
	SNI_CFG_JSON="$CONFIG_JSON" lua -e '
		local jsonc = require "luci.jsonc"
		local ss = require "luci.passwall2.sni_spoofer"
		local f = io.open(os.getenv("SNI_CFG_JSON"), "rb")
		if not f then return end
		local cfg = jsonc.parse(f:read("*a") or "")
		f:close()
		local seen = {}
		for _, l in ipairs(type(cfg) == "table" and cfg.listeners or {}) do
			local ip = ss.parse_socket_addr(l.connect or "")
			if ip and not seen[ip] then
				seen[ip] = true
				print(ip)
			end
		end
	' 2>/dev/null || true
}

resolve_route_for_ip() {
	local ip="$1"
	local out
	case "$ip" in
		*:*) out="$(ip -6 route get "$ip" 2>/dev/null || true)" ;;
		*) out="$(ip -4 route get "$ip" 2>/dev/null || ip route get "$ip" 2>/dev/null || true)" ;;
	esac
	[ -n "$out" ] || return 1
	printf '%s\n' "$out" | awk '{
		d=""; s="";
		for (i = 1; i <= NF; i++) {
			if ($i == "dev" && i < NF) d = $(i + 1);
			if ($i == "src" && i < NF) s = $(i + 1);
		}
		if (d != "" || s != "") {
			print d "|" s;
			exit 0;
		}
		exit 1;
	}'
}

compute_route_signature() {
	command -v ip >/dev/null 2>&1 || return 0
	local ips ip resolved
	ips="$(list_upstream_ips)"
	[ -n "$ips" ] || return 0
	for ip in $ips; do
		if resolved="$(resolve_route_for_ip "$ip")"; then
			printf '%s|%s\n' "$ip" "$resolved"
		else
			printf '%s|unroutable|\n' "$ip"
		fi
	done | sort -u
}

check_upstreams_routable() {
	command -v ip >/dev/null 2>&1 || return 0
	local ips ip
	ips="$(list_upstream_ips)"
	[ -n "$ips" ] || return 0
	for ip in $ips; do
		if ! resolve_route_for_ip "$ip" >/dev/null 2>&1; then
			return 1
		fi
	done
	return 0
}

write_iface_state() {
	compute_route_signature >"$IFACE_STATE_FILE" 2>/dev/null || true
}

routes_changed() {
	[ -f "$IFACE_STATE_FILE" ] || return 0
	local current saved
	current="$(compute_route_signature)"
	saved="$(cat "$IFACE_STATE_FILE" 2>/dev/null || true)"
	[ "$current" != "$saved" ]
}

uses_device() {
	local target_dev="${1:-}"
	[ -n "$target_dev" ] || return 1
	command -v ip >/dev/null 2>&1 || return 1
	if [ -f "$IFACE_STATE_FILE" ] && grep -q "|${target_dev}|" "$IFACE_STATE_FILE" 2>/dev/null; then
		return 0
	fi
	if [ -s "$CONFIG_JSON" ] && compute_route_signature | grep -q "|${target_dev}|"; then
		return 0
	fi
	return 1
}

prepare_runtime() {
	local bin_path rust_log
	bin_path="$(uci_get_opt bin_path)"
	[ -z "$bin_path" ] && bin_path="/usr/bin/sni-spoof-rs"
	rust_log="$(uci_get_opt rust_log)"
	[ -z "$rust_log" ] && rust_log="info"

	if [ ! -f "$bin_path" ]; then
		local msg="Binary not found at $bin_path; upload or download sni-spoof-rs first."
		log_line "ERROR: $msg"
		echo "$msg" >&2
		return 2
	fi

	chmod 0755 "$bin_path" 2>/dev/null || true
	if [ ! -x "$bin_path" ]; then
		local msg="Binary at $bin_path is not executable."
		log_line "ERROR: $msg"
		echo "$msg" >&2
		return 2
	fi

	local preflight
	if ! preflight="$(SNI_CHECK_BIN="$bin_path" lua -e '
		local p = os.getenv("SNI_CHECK_BIN")
		local ss = require "luci.passwall2.sni_spoofer"
		local bin = ss.inspect_binary(p)
		if not bin.exists or not bin.elf or not bin.elf.valid then
			io.stderr:write("File at " .. tostring(p) .. " is not a valid ELF binary.\n")
			os.exit(1)
		end
		if not bin.arch_match then
			io.stderr:write(string.format("Architecture mismatch: binary is ELF %s, host is %s.\n", tostring(bin.elf.arch), tostring(bin.host_arch)))
			os.exit(2)
		end
	' 2>&1)"; then
		log_line "ERROR: $preflight"
		echo "$preflight" >&2
		return 2
	fi

	local cfg_err
	if ! cfg_err="$(lua -e '
		local ss = require "luci.passwall2.sni_spoofer"
		local ok, err = ss.write_runtime_config()
		if not ok then
			io.stderr:write(tostring(err) .. "\n")
			os.exit(1)
		end
		ss.cap_log_file()
	' 2>&1)"; then
		log_line "ERROR: Config validation failed: $cfg_err"
		echo "$cfg_err" >&2
		return 2
	fi

	PREPARED_BIN="$bin_path"
	PREPARED_RUST_LOG="$rust_log"
	return 0
}

launch_prepared() {
	log_line "Starting daemon ($PREPARED_BIN, RUST_LOG=$PREPARED_RUST_LOG)"
	RUST_LOG="$PREPARED_RUST_LOG" NO_COLOR="1" "$PREPARED_BIN" "$CONFIG_JSON" >>"$LOG_FILE" 2>&1 </dev/null &
	local child_pid=$!
	printf '%s\n' "$child_pid" >"$PID_FILE"

	sleep_short
	sleep_short
	if ! kill -0 "$child_pid" 2>/dev/null; then
		rm -f "$PID_FILE" "$IFACE_STATE_FILE"
		local err_msg="SNI Spoofer daemon exited immediately on startup; see logs for details."
		log_line "ERROR: $err_msg"
		echo "$err_msg" >&2
		return 3
	fi

	write_iface_state
	echo "SNI Spoofer started (PID $child_pid)"
	return 0
}

do_start() {
	acquire_lock
	local running_pid
	if running_pid="$(read_pid_alive 2>/dev/null)"; then
		echo "SNI Spoofer already running (PID $running_pid)"
		return 0
	fi
	rm -f "$PID_FILE"

	prepare_runtime || return $?
	launch_prepared || return $?
	return 0
}

do_stop() {
	acquire_lock
	local pid
	if ! pid="$(read_pid_alive 2>/dev/null)"; then
		rm -f "$PID_FILE" "$IFACE_STATE_FILE"
		return 0
	fi

	local graceful wait_ticks i
	graceful="$(uci_get_opt graceful_shutdown_sec)"
	case "$graceful" in
		''|*[!0-9]*) graceful=0 ;;
	esac
	wait_ticks=$(((graceful + 2) * 5))
	[ "$wait_ticks" -lt 10 ] && wait_ticks=10

	log_line "Stopping daemon (PID $pid)"
	kill -TERM "$pid" 2>/dev/null || true

	i=0
	while kill -0 "$pid" 2>/dev/null && [ "$i" -lt "$wait_ticks" ]; do
		i=$((i + 1))
		sleep_short
	done

	if kill -0 "$pid" 2>/dev/null; then
		log_line "WARN: Daemon did not exit cleanly within ${graceful}s; sending SIGKILL"
		kill -KILL "$pid" 2>/dev/null || true
		sleep_short
	fi

	rm -f "$PID_FILE" "$IFACE_STATE_FILE"
	echo "SNI Spoofer stopped"
	return 0
}

do_boot() {
	local enabled
	enabled="$(uci_get_opt enabled)"
	[ "$enabled" = "1" ] || return 0

	rm -f "$MANUAL_STOP_FILE"
	stop_boot_wait

	acquire_lock
	if read_pid_alive >/dev/null 2>&1; then
		return 0
	fi
	rm -f "$PID_FILE"

	local rc=0
	prepare_runtime || rc=$?
	if [ "$rc" -ne 0 ]; then
		return "$rc"
	fi

	if ! check_upstreams_routable; then
		log_line "Boot start deferred: waiting for upstream network route"
		release_lock
		trap - EXIT INT TERM
		/usr/share/passwall2/sni_spoofer.sh _boot_wait </dev/null >/dev/null 2>&1 &
		return 0
	fi

	rc=0
	launch_prepared || rc=$?
	if [ "$rc" -eq 3 ]; then
		log_line "Boot start retrying in background while network initializes"
		release_lock
		trap - EXIT INT TERM
		/usr/share/passwall2/sni_spoofer.sh _boot_wait </dev/null >/dev/null 2>&1 &
		return 0
	fi
	return "$rc"
}

cleanup_boot_wait() {
	rm -f "$BOOT_PID_FILE"
	release_lock
}

do_boot_wait() {
	printf '%s\n' "$$" >"$BOOT_PID_FILE"
	trap 'cleanup_boot_wait' EXIT INT TERM

	local i=0
	while [ "$i" -lt 30 ]; do
		i=$((i + 1))
		[ -f "$MANUAL_STOP_FILE" ] && return 0
		[ "$(uci_get_opt enabled)" = "1" ] || return 0

		acquire_lock
		trap 'cleanup_boot_wait' EXIT INT TERM
		if read_pid_alive >/dev/null 2>&1; then
			return 0
		fi
		if prepare_runtime >/dev/null 2>&1 && check_upstreams_routable; then
			if launch_prepared >/dev/null 2>&1; then
				return 0
			fi
		fi
		release_lock
		sleep 3
	done

	if [ ! -f "$MANUAL_STOP_FILE" ] && [ "$(uci_get_opt enabled)" = "1" ] && ! read_pid_alive >/dev/null 2>&1; then
		log_line "WARN: Timed out waiting for network readiness on boot"
	fi
	return 0
}

do_status() {
	local pid
	if pid="$(read_pid_alive 2>/dev/null)"; then
		echo "running (PID $pid)"
		return 0
	fi
	echo "stopped"
	return 1
}

action="${1:-}"
case "$action" in
	start)
		rm -f "$MANUAL_STOP_FILE"
		stop_boot_wait
		do_start
		;;
	stop)
		: >"$MANUAL_STOP_FILE"
		stop_boot_wait
		do_stop
		;;
	restart)
		rm -f "$MANUAL_STOP_FILE"
		stop_boot_wait
		do_stop
		do_start
		;;
	boot)
		do_boot
		;;
	_boot_wait)
		do_boot_wait
		;;
	_routes_changed)
		routes_changed
		;;
	_uses_device)
		uses_device "${2:-}"
		;;
	status)
		do_status
		;;
	*)
		echo "Usage: $0 {start|stop|restart|boot|status}" >&2
		exit 2
		;;
esac
