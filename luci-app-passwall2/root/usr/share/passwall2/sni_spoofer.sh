#!/bin/sh
set -eu

LOG_FILE="/tmp/log/passwall2_sni_spoofer.log"
PID_FILE="/var/run/passwall2_sni_spoofer.pid"
RUNTIME_DIR="/tmp/etc/passwall2/sni_spoofer"
CONFIG_JSON="$RUNTIME_DIR/config.json"
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

do_start() {
	acquire_lock
	local running_pid
	if running_pid="$(read_pid_alive 2>/dev/null)"; then
		echo "SNI Spoofer already running (PID $running_pid)"
		return 0
	fi
	rm -f "$PID_FILE"

	local bin_path rust_log
	bin_path="$(uci_get_opt bin_path)"
	[ -z "$bin_path" ] && bin_path="/usr/bin/sni-spoof-rs"
	rust_log="$(uci_get_opt rust_log)"
	[ -z "$rust_log" ] && rust_log="warn"

	if [ ! -f "$bin_path" ]; then
		local msg="Binary not found at $bin_path; upload or download sni-spoof-rs first."
		log_line "ERROR: $msg"
		echo "$msg" >&2
		return 1
	fi

	chmod 0755 "$bin_path" 2>/dev/null || true
	if [ ! -x "$bin_path" ]; then
		local msg="Binary at $bin_path is not executable."
		log_line "ERROR: $msg"
		echo "$msg" >&2
		return 1
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
		return 1
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
		return 1
	fi

	log_line "Starting daemon ($bin_path, RUST_LOG=$rust_log)"
	RUST_LOG="$rust_log" NO_COLOR="1" "$bin_path" "$CONFIG_JSON" >>"$LOG_FILE" 2>&1 </dev/null &
	local child_pid=$!
	printf '%s\n' "$child_pid" >"$PID_FILE"

	sleep_short
	sleep_short
	if ! kill -0 "$child_pid" 2>/dev/null; then
		rm -f "$PID_FILE"
		local err_msg="SNI Spoofer daemon exited immediately on startup; see logs for details."
		log_line "ERROR: $err_msg"
		echo "$err_msg" >&2
		return 1
	fi

	echo "SNI Spoofer started (PID $child_pid)"
	return 0
}

do_stop() {
	acquire_lock
	local pid
	if ! pid="$(read_pid_alive 2>/dev/null)"; then
		rm -f "$PID_FILE"
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

	rm -f "$PID_FILE"
	echo "SNI Spoofer stopped"
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
	start) do_start ;;
	stop) do_stop ;;
	restart) do_stop; do_start ;;
	status) do_status ;;
	*)
		echo "Usage: $0 {start|stop|restart|status}" >&2
		exit 2
		;;
esac
