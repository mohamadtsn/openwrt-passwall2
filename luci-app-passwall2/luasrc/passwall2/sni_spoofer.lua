local api = require "luci.passwall2.api"
local nixio = api.nixio
local fs = api.fs
local sys = api.sys
local util = api.util
local jsonc = api.jsonc
local datatypes = api.datatypes
local luci_ip = require "luci.ip"

local M = {}

M.GITHUB_REPO = "mohamadtsn/sni-spoofing-rust"
M.DEFAULT_GITHUB_ASSET = "sni-spoof-rs-google-wifi-armv7-musl"
M.KNOWN_ASSETS = {
	"sni-spoof-rs-google-wifi-armv7-musl",
	"sni-spoof-rs-linux-amd64-musl",
	"sni-spoof-rs-linux-arm64",
	"sni-spoof-rs-linux-amd64",
}
M.DEFAULT_BIN_PATH = "/usr/bin/sni-spoof-rs"
M.LOG_FILE = "/tmp/log/passwall2_sni_spoofer.log"
M.PID_FILE = "/var/run/passwall2_sni_spoofer.pid"
M.RUNTIME_DIR = "/tmp/etc/passwall2/sni_spoofer"
M.CONFIG_JSON_PATH = "/tmp/etc/passwall2/sni_spoofer/config.json"
M.LOG_MAX_BYTES = 524288
M.LOG_KEEP_BYTES = 262144
M.FAKE_SNI_MAX_BYTES = 219

local VALID_RUST_LOG = {
	error = true,
	warn = true,
	info = true,
	debug = true,
	trace = true,
}

local ELF_MACHINES = {
	[0x03] = "x86",
	[0x08] = "mips",
	[0x28] = "armv7",
	[0x3E] = "x86_64",
	[0xB7] = "aarch64",
	[0xF3] = "riscv64",
}

local function new_cursor(uci_dir)
	local cursor = require("luci.model.uci").cursor()
	if uci_dir and uci_dir ~= "" and cursor.set_confdir then
		cursor:set_confdir(uci_dir)
	end
	return cursor
end

local function trim(s)
	if type(s) ~= "string" then return "" end
	return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function file_size_bytes(path)
	if type(path) ~= "string" or path == "" then return 0 end
	local sz = fs.stat(path, "size")
	return tonumber(sz) or 0
end

local function read_file(path, limit)
	local f, err = io.open(path, "rb")
	if not f then return nil, err end
	local data = limit and f:read(limit) or f:read("*a")
	f:close()
	return data
end

local function write_file_atomic(path, content, mode_str)
	local dir = fs.dirname(path)
	if dir and dir ~= "" then fs.mkdirr(dir) end
	local tmp = path .. ".tmp." .. tostring(os.time())
	local f, err = io.open(tmp, "wb")
	if not f then return false, err end
	local ok, werr = f:write(content)
	f:close()
	if not ok then
		fs.unlink(tmp)
		return false, werr
	end
	if mode_str then
		api.exec("/bin/chmod", { mode_str, tmp })
	end
	local rok, rerr = os.rename(tmp, path)
	if not rok then
		fs.unlink(tmp)
		return false, rerr
	end
	return true
end

local function parse_int(val, min_v, max_v)
	if type(val) == "number" then
		if val ~= math.floor(val) then return nil end
	elseif type(val) == "string" then
		local s = trim(val)
		if not s:match("^%-?%d+$") then return nil end
		val = tonumber(s)
	else
		return nil
	end
	if not val then return nil end
	if min_v and val < min_v then return nil end
	if max_v and val > max_v then return nil end
	return val
end

local function is_valid_utf8(s)
	if type(s) ~= "string" or s:find("\0", 1, true) then return false end
	local i, n = 1, #s
	while i <= n do
		local c = s:byte(i)
		if c < 0x80 then
			i = i + 1
		elseif c >= 0xC2 and c <= 0xDF then
			local b2 = s:byte(i + 1)
			if not b2 or b2 < 0x80 or b2 > 0xBF then return false end
			i = i + 2
		elseif c >= 0xE0 and c <= 0xEF then
			local b2, b3 = s:byte(i + 1), s:byte(i + 2)
			if not b2 or not b3 or b2 < 0x80 or b2 > 0xBF or b3 < 0x80 or b3 > 0xBF then return false end
			if c == 0xE0 and b2 < 0xA0 then return false end
			if c == 0xED and b2 > 0x9F then return false end
			i = i + 3
		elseif c >= 0xF0 and c <= 0xF4 then
			local b2, b3, b4 = s:byte(i + 1), s:byte(i + 2), s:byte(i + 3)
			if not b2 or not b3 or not b4 or b2 < 0x80 or b2 > 0xBF or b3 < 0x80 or b3 > 0xBF or b4 < 0x80 or b4 > 0xBF then return false end
			if c == 0xF0 and b2 < 0x90 then return false end
			if c == 0xF4 and b2 > 0x8F then return false end
			i = i + 4
		else
			return false
		end
	end
	return true
end

function M.parse_socket_addr(val)
	if type(val) ~= "string" or val == "" or val ~= trim(val) then
		return nil, "Address must be non-empty without surrounding spaces"
	end
	if val:find("/", 1, true) then
		return nil, "CIDR suffix is not allowed"
	end

	local addr, port_str = val:match("^%[([%da-fA-F:%.]+)%]:(%d+)$")
	local is_ipv6 = false
	if addr then
		is_ipv6 = true
		if not datatypes.ip6addr(addr) then
			return nil, "Invalid IPv6 address"
		end
		local parsed = luci_ip.IPv6(addr)
		if not parsed then return nil, "Invalid IPv6 address" end
		addr = parsed:string()
	else
		addr, port_str = val:match("^(%d+%.%d+%.%d+%.%d+):(%d+)$")
		if not addr or not datatypes.ip4addr(addr) then
			return nil, "Expected IPv4:port or [IPv6]:port"
		end
		if addr:match("^0%d") or addr:match("%.0%d") then
			return nil, "Leading zeros in IPv4 octets are not allowed"
		end
		local parsed = luci_ip.IPv4(addr)
		if not parsed then return nil, "Invalid IPv4 address" end
		addr = parsed:string()
	end

	if port_str:match("^0%d") then
		return nil, "Leading zeros in port are not allowed"
	end
	local port = tonumber(port_str)
	if not port or port < 1 or port > 65535 or port ~= math.floor(port) then
		return nil, "Port must be between 1 and 65535"
	end

	return addr, port, is_ipv6
end

local function is_loopback_ip(ip, is6)
	if is6 then return ip == "::1" end
	return tonumber(ip:match("^(%d+)%.")) == 127
end

local function is_unspecified_ip(ip, is6)
	if is6 then return ip == "::" end
	return ip == "0.0.0.0"
end

function M.connects_to_listener(listen_addr, connect_addr)
	local lip, lport, l6 = M.parse_socket_addr(listen_addr)
	local cip, cport, c6 = M.parse_socket_addr(connect_addr)
	if not lip or not cip then return false end
	if lip == cip and lport == cport and l6 == c6 then
		return true
	end
	return lport == cport
		and is_loopback_ip(cip, c6)
		and (is_loopback_ip(lip, l6) or is_unspecified_ip(lip, l6))
end

local function validate_bin_path(path)
	if type(path) ~= "string" then return nil, "Binary path is required" end
	local p = trim(path)
	if p == "" or p:sub(1, 1) ~= "/" or #p > 512 then
		return nil, "Binary path must be an absolute path (<= 512 chars)"
	end
	if p:find("[;&|`$<>\\'\n\r\t%s\"]") then
		return nil, "Binary path contains invalid shell or whitespace characters"
	end
	if p:match("/%.%./") or p:match("/%.%.$") or p:find("//", 1, true) then
		return nil, "Binary path cannot contain traversal or empty segments"
	end
	if fs.stat(p, "type") == "dir" then
		return nil, "Binary path cannot point to a directory"
	end
	return p
end

local function validate_global(raw, errs)
	local g = type(raw) == "table" and raw or {}
	local out = {}

	out.enabled = tostring(g.enabled or "0") == "1" and "1" or "0"

	local bp, bp_err = validate_bin_path(g.bin_path or M.DEFAULT_BIN_PATH)
	if bp_err then errs["global.bin_path"] = bp_err else out.bin_path = bp end

	local rlog = trim(tostring(g.rust_log or "warn")):lower()
	if not VALID_RUST_LOG[rlog] then
		errs["global.rust_log"] = "Must be one of error, warn, info, debug, trace"
	else
		out.rust_log = rlog
	end

	local idle_raw = trim(tostring(g.idle_timeout or ""))
	if idle_raw == "" then
		out.idle_timeout = ""
	else
		local idle_v = parse_int(idle_raw, 1)
		if not idle_v then
			errs["global.idle_timeout"] = "Idle timeout must be empty or integer >= 1"
		else
			out.idle_timeout = tostring(idle_v)
		end
	end

	local buf_v = parse_int(g.buffer_size ~= nil and g.buffer_size or "8", 1, 1024)
	if not buf_v then
		errs["global.buffer_size"] = "Buffer size must be integer between 1 and 1024 KiB"
	else
		out.buffer_size = tostring(buf_v)
	end

	local shut_v = parse_int(g.graceful_shutdown_sec ~= nil and g.graceful_shutdown_sec or "0", 0, 3600)
	if not shut_v then
		errs["global.graceful_shutdown_sec"] = "Graceful shutdown must be integer >= 0"
	else
		out.graceful_shutdown_sec = tostring(shut_v)
	end

	local asset = trim(tostring(g.github_asset or M.DEFAULT_GITHUB_ASSET))
	if asset ~= "" and (not asset:match("^[%w%.%_%-]+$") or asset:find("..", 1, true)) then
		errs["global.github_asset"] = "Invalid release asset filename"
	else
		out.github_asset = asset ~= "" and asset or M.DEFAULT_GITHUB_ASSET
	end

	return out
end

local function validate_listener(item, idx, seen_listen, errs)
	local prefix = string.format("listeners[%d].", idx)
	local l = type(item) == "table" and item or {}
	local enabled = tostring(l.enabled or "1") == "1" and "1" or "0"
	local remarks = trim(tostring(l.remarks or "")):gsub("[\r\n]", " ")
	if #remarks > 128 then
		errs[prefix .. "remarks"] = "Remarks must be <= 128 bytes"
	end

	local listen_raw = trim(tostring(l.listen or ""))
	local connect_raw = trim(tostring(l.connect or ""))
	local lip, lport, l6, lerr = M.parse_socket_addr(listen_raw)
	if not lip then errs[prefix .. "listen"] = lerr or "Invalid listen IP:port" end

	local cip, cport, c6, cerr = M.parse_socket_addr(connect_raw)
	if not cip then errs[prefix .. "connect"] = cerr or "Invalid connect IP:port" end

	local fmt_listen = lip and ((l6 and ("[" .. lip .. "]") or lip) .. ":" .. lport) or listen_raw
	local fmt_connect = cip and ((c6 and ("[" .. cip .. "]") or cip) .. ":" .. cport) or connect_raw

	if lip and cip and M.connects_to_listener(fmt_listen, fmt_connect) then
		errs[prefix .. "connect"] = "Connect address must not loop back to this listener"
	end

	if enabled == "1" and lip then
		if seen_listen[fmt_listen] then
			errs[prefix .. "listen"] = "Duplicate enabled listen address: " .. fmt_listen
		else
			seen_listen[fmt_listen] = true
		end
	end

	local sni = trim(tostring(l.fake_sni or ""))
	if sni == "" then
		errs[prefix .. "fake_sni"] = "Fake SNI is required"
	elseif not is_valid_utf8(sni) or sni:find("[\r\n\t ]") then
		errs[prefix .. "fake_sni"] = "Fake SNI must be valid UTF-8 without whitespace"
	elseif #sni > M.FAKE_SNI_MAX_BYTES then
		errs[prefix .. "fake_sni"] = string.format("Fake SNI exceeds %d UTF-8 bytes (%d B)", M.FAKE_SNI_MAX_BYTES, #sni)
	end

	local timing_specs = {
		{ "conn_timeout_sec", "5", "Connection timeout" },
		{ "handshake_timeout_sec", "2", "Handshake timeout" },
		{ "keepalive_time_sec", "11", "Keepalive time" },
		{ "keepalive_interval_sec", "2", "Keepalive interval" },
	}
	local timings = {}
	for _, spec in ipairs(timing_specs) do
		local key, defv, label = spec[1], spec[2], spec[3]
		local raw_val = l[key]
		if raw_val == nil or trim(tostring(raw_val)) == "" then
			raw_val = defv
		end
		local iv = parse_int(raw_val, 1, 86400)
		if not iv then
			errs[prefix .. key] = label .. " must be an integer >= 1"
		else
			timings[key] = tostring(iv)
		end
	end

	return {
		enabled = enabled,
		remarks = remarks,
		listen = fmt_listen,
		connect = fmt_connect,
		fake_sni = sni,
		conn_timeout_sec = timings.conn_timeout_sec,
		handshake_timeout_sec = timings.handshake_timeout_sec,
		keepalive_time_sec = timings.keepalive_time_sec,
		keepalive_interval_sec = timings.keepalive_interval_sec,
	}
end

function M.validate_payload(payload, opts)
	if type(payload) ~= "table" then
		return false, nil, { _global = "Invalid payload" }
	end
	local errs = {}
	local global_norm = validate_global(payload.global, errs)

	local raw_listeners = type(payload.listeners) == "table" and payload.listeners or {}
	local listeners_norm = {}
	local seen_listen = {}
	local enabled_count = 0

	for idx, item in ipairs(raw_listeners) do
		local norm_l = validate_listener(item, idx, seen_listen, errs)
		listeners_norm[#listeners_norm + 1] = norm_l
		if norm_l.enabled == "1" then
			enabled_count = enabled_count + 1
		end
	end

	if opts and opts.require_enabled_listener and enabled_count == 0 then
		errs._global = "At least one enabled listener is required"
	end

	if next(errs) ~= nil then
		return false, nil, errs
	end

	return true, { global = global_norm, listeners = listeners_norm }, {}
end

function M.build_runtime_config(cfg)
	local g = cfg and cfg.global or {}
	local list = setmetatable({}, { __type = "array" })

	for _, l in ipairs(cfg and cfg.listeners or {}) do
		if tostring(l.enabled or "0") == "1" then
			list[#list + 1] = {
				listen = l.listen,
				connect = l.connect,
				fake_sni = l.fake_sni,
				conn_timeout_sec = tonumber(l.conn_timeout_sec) or 5,
				handshake_timeout_sec = tonumber(l.handshake_timeout_sec) or 2,
				keepalive_time_sec = tonumber(l.keepalive_time_sec) or 11,
				keepalive_interval_sec = tonumber(l.keepalive_interval_sec) or 2,
			}
		end
	end

	local out = {
		buffer_size = tonumber(g.buffer_size) or 8,
		graceful_shutdown_sec = tonumber(g.graceful_shutdown_sec) or 0,
		listeners = list,
	}
	local idle = tonumber(g.idle_timeout)
	if idle and idle >= 1 then
		out.idle_timeout = idle
	end
	return out
end

function M.get_config(uci_dir)
	local u = new_cursor(uci_dir)
	local g = u:get_all(api.c_config, "global_sni_spoofer") or {}
	local global_cfg = {
		enabled = tostring(g.enabled or "0") == "1" and "1" or "0",
		bin_path = (type(g.bin_path) == "string" and g.bin_path ~= "") and g.bin_path or M.DEFAULT_BIN_PATH,
		rust_log = (type(g.rust_log) == "string" and g.rust_log ~= "") and g.rust_log or "warn",
		idle_timeout = tostring(g.idle_timeout or ""),
		buffer_size = tostring(g.buffer_size or "8"),
		graceful_shutdown_sec = tostring(g.graceful_shutdown_sec or "0"),
		github_asset = (type(g.github_asset) == "string" and g.github_asset ~= "") and g.github_asset or M.DEFAULT_GITHUB_ASSET,
		bin_version = tostring(g.bin_version or ""),
		bin_sha256 = tostring(g.bin_sha256 or ""),
	}

	local listeners = {}
	u:foreach(api.c_config, "sni_spoofer_listener", function(s)
		listeners[#listeners + 1] = {
			id = s[".name"],
			enabled = tostring(s.enabled or "1") == "1" and "1" or "0",
			remarks = tostring(s.remarks or ""),
			listen = tostring(s.listen or ""),
			connect = tostring(s.connect or ""),
			fake_sni = tostring(s.fake_sni or "security.vercel.com"),
			conn_timeout_sec = tostring(s.conn_timeout_sec or "5"),
			handshake_timeout_sec = tostring(s.handshake_timeout_sec or "2"),
			keepalive_time_sec = tostring(s.keepalive_time_sec or "11"),
			keepalive_interval_sec = tostring(s.keepalive_interval_sec or "2"),
		}
	end)

	return { global = global_cfg, listeners = listeners }
end

function M.register_sysupgrade_path(path, sysupgrade_conf)
	local bp, err = validate_bin_path(path)
	if not bp then return false, err end
	local conf = sysupgrade_conf or "/etc/sysupgrade.conf"
	local existing = read_file(conf) or ""
	for line in existing:gmatch("[^\r\n]+") do
		if line == bp then return true end
	end
	local dir = fs.dirname(conf)
	if dir and dir ~= "" then fs.mkdirr(dir) end
	local prefix = (existing == "" or existing:sub(-1) == "\n") and "" or "\n"
	local f = io.open(conf, "a")
	if not f then return false, "Cannot write " .. conf end
	f:write(prefix .. bp .. "\n")
	f:close()
	return true
end

function M.save_config(payload, opts)
	opts = opts or {}
	local ok, norm, errs = M.validate_payload(payload, { require_enabled_listener = false })
	if not ok then
		return { ok = false, errors = errs }
	end

	local u = new_cursor(opts.uci_dir)
	if not u:get(api.c_config, "global_sni_spoofer") then
		u:set(api.c_config, "global_sni_spoofer", "global_sni_spoofer")
	end

	local g = norm.global
	u:set(api.c_config, "global_sni_spoofer", "enabled", g.enabled)
	u:set(api.c_config, "global_sni_spoofer", "bin_path", g.bin_path)
	u:set(api.c_config, "global_sni_spoofer", "rust_log", g.rust_log)
	if g.idle_timeout ~= "" then
		u:set(api.c_config, "global_sni_spoofer", "idle_timeout", g.idle_timeout)
	else
		u:delete(api.c_config, "global_sni_spoofer", "idle_timeout")
	end
	u:set(api.c_config, "global_sni_spoofer", "buffer_size", g.buffer_size)
	u:set(api.c_config, "global_sni_spoofer", "graceful_shutdown_sec", g.graceful_shutdown_sec)
	u:set(api.c_config, "global_sni_spoofer", "github_asset", g.github_asset)

	u:delete_all(api.c_config, "sni_spoofer_listener")
	for _, l in ipairs(norm.listeners) do
		local sid = u:add(api.c_config, "sni_spoofer_listener")
		u:set(api.c_config, sid, "enabled", l.enabled)
		if l.remarks ~= "" then u:set(api.c_config, sid, "remarks", l.remarks) end
		u:set(api.c_config, sid, "listen", l.listen)
		u:set(api.c_config, sid, "connect", l.connect)
		u:set(api.c_config, sid, "fake_sni", l.fake_sni)
		u:set(api.c_config, sid, "conn_timeout_sec", l.conn_timeout_sec)
		u:set(api.c_config, sid, "handshake_timeout_sec", l.handshake_timeout_sec)
		u:set(api.c_config, sid, "keepalive_time_sec", l.keepalive_time_sec)
		u:set(api.c_config, sid, "keepalive_interval_sec", l.keepalive_interval_sec)
	end

	u:commit(api.c_config)
	M.register_sysupgrade_path(g.bin_path, opts.sysupgrade_conf)
	return { ok = true, errors = {}, config = M.get_config(opts.uci_dir) }
end

function M.write_runtime_config(target_path, uci_dir)
	local out_path = target_path or M.CONFIG_JSON_PATH
	local cfg = M.get_config(uci_dir)
	local ok, norm, errs = M.validate_payload(cfg, { require_enabled_listener = true })
	if not ok then
		local first_err = errs._global
		if not first_err then
			local _, msg = next(errs)
			first_err = msg
		end
		return false, first_err or "Invalid SNI Spoofer configuration", nil
	end
	local json_str = jsonc.stringify(M.build_runtime_config(norm), true)
	local wok, werr = write_file_atomic(out_path, json_str .. "\n")
	if not wok then
		return false, "Failed writing runtime config: " .. tostring(werr), nil
	end
	return true, nil, json_str
end

function M.parse_elf_header(bytes)
	if type(bytes) ~= "string" or #bytes < 20 then
		return { valid = false, error = "File too small to be an ELF binary" }
	end
	if bytes:sub(1, 4) ~= "\127ELF" then
		return { valid = false, error = "Invalid ELF magic header" }
	end
	local class_b, data_b = bytes:byte(5, 6)
	local bits = (class_b == 1 and 32) or (class_b == 2 and 64) or nil
	local endian = (data_b == 1 and "little") or (data_b == 2 and "big") or nil
	if not bits or not endian then
		return { valid = false, error = "Unsupported ELF class or endianness" }
	end
	local b19, b20 = bytes:byte(19, 20)
	local e_machine = endian == "little" and (b19 + b20 * 256) or (b19 * 256 + b20)
	local arch = ELF_MACHINES[e_machine] or string.format("unknown(0x%02x)", e_machine)
	return { valid = true, bits = bits, endian = endian, arch = arch }
end

local function normalize_host_arch(raw)
	local s = trim(raw or "")
	if s == "x86_64" or s == "amd64" then return "x86_64" end
	if s == "aarch64" or s == "arm64" then return "aarch64" end
	if s:match("^armv7") or s:match("^arm") then return "armv7" end
	if s == "i686" or s == "i386" then return "x86" end
	if s:match("^mips") then return "mips" end
	return s
end

local function compute_sha256(path)
	local code, out = api.exec_call("sha256sum " .. util.shellquote(path))
	if code ~= 0 or type(out) ~= "string" then return nil end
	local hex = out:match("^(%x+)%s")
	return hex and hex:lower() or nil
end

function M.inspect_binary(path, stored_meta)
	local cfg_g = (stored_meta == nil) and M.get_config().global or (stored_meta or {})
	local target = path or cfg_g.bin_path or M.DEFAULT_BIN_PATH
	local host_raw = trim(sys.exec("uname -m"))
	local host_arch = normalize_host_arch(host_raw)

	local info = {
		exists = false,
		executable = false,
		path = target,
		size_bytes = 0,
		sha256 = "",
		elf = { valid = false },
		host_arch = host_raw ~= "" and host_raw or host_arch,
		arch_match = false,
		help_ok = false,
		version_tag = "",
		error = nil,
	}

	local st = fs.stat(target)
	if not st or st.type ~= "reg" then
		return info
	end

	info.exists = true
	info.size_bytes = tonumber(st.size) or 0
	info.executable = fs.access(target, "x") == true
	local hdr = read_file(target, 64)
	info.elf = M.parse_elf_header(hdr or "")
	if not info.elf.valid then
		info.error = info.elf.error
		return info
	end

	local sha = compute_sha256(target) or ""
	info.sha256 = sha
	local saved_sha = tostring(cfg_g.bin_sha256 or cfg_g.sha256 or ""):lower()
	local saved_ver = tostring(cfg_g.bin_version or cfg_g.version_tag or "")
	if sha ~= "" and saved_sha == sha and saved_ver ~= "" then
		info.version_tag = saved_ver
	end

	info.arch_match = (info.elf.arch == host_arch)
	if info.arch_match and info.executable then
		-- sni-spoof-rs accepts --help; never pass --version (treated as config path).
		local hcode, hout = api.exec_call("timeout 3 " .. util.shellquote(target) .. " --help 2>&1")
		if hcode == 0 and type(hout) == "string" and (hout:find("sni-spoof-rs", 1, true) or hout:find("Usage:", 1, true)) then
			info.help_ok = true
		end
	end
	return info
end

function M.get_pid_status(bin_path)
	local active_bin = bin_path or M.get_config().global.bin_path or M.DEFAULT_BIN_PATH
	local raw_pid = trim(read_file(M.PID_FILE) or "")
	local pid = tonumber(raw_pid)
	if not pid or pid <= 0 or pid ~= math.floor(pid) then
		return { running = false, pid = nil, uptime_sec = nil }
	end

	local proc_dir = "/proc/" .. tostring(pid)
	local pstat = fs.stat(proc_dir)
	if not pstat then
		return { running = false, pid = nil, uptime_sec = nil }
	end

	local cmdline = read_file(proc_dir .. "/cmdline") or ""
	local base = fs.basename(active_bin)
	if cmdline == "" or (not cmdline:find(base, 1, true) and not cmdline:find(active_bin, 1, true)) then
		return { running = false, pid = nil, uptime_sec = nil }
	end

	local started = tonumber(pstat.mtime or pstat.ctime)
	local uptime = started and math.max(0, os.time() - started) or 0
	return { running = true, pid = pid, uptime_sec = uptime }
end

function M.install_verified_binary(tmp_file, target_path, meta)
	meta = meta or {}
	local bp, berr = validate_bin_path(target_path or M.DEFAULT_BIN_PATH)
	if not bp then
		return { ok = false, code = 0, error = berr }
	end
	if type(tmp_file) ~= "string" or fs.stat(tmp_file, "type") ~= "reg" then
		return { ok = false, code = 0, error = "Downloaded or uploaded file does not exist" }
	end

	local elf = M.parse_elf_header(read_file(tmp_file, 64) or "")
	if not elf.valid then
		return { ok = false, code = 0, error = elf.error or "Invalid ELF binary" }
	end

	if type(meta.expected_digest) == "string" and meta.expected_digest ~= "" then
		if not api.verify_sha256(tmp_file, meta.expected_digest) then
			return { ok = false, code = 0, error = "SHA-256 verification failed for downloaded binary" }
		end
	end

	local need_kb = tonumber(api.get_file_space(tmp_file)) or 0
	local old_kb = fs.access(bp) and (tonumber(api.get_file_space(bp)) or 0) or 0
	local dest_dir = fs.dirname(bp)
	fs.mkdirr(dest_dir)
	local free_kb = tonumber(api.get_free_space(api.get_final_dir(dest_dir))) or 0
	if free_kb + old_kb < need_kb + 32 then
		return { ok = false, code = 0, error = string.format("Insufficient destination space (%d KB free, %d KB needed)", free_kb, need_kb) }
	end

	local was_running = false
	if not meta.skip_service and bp == M.get_config(meta.uci_dir).global.bin_path then
		was_running = M.get_pid_status(bp).running
		if was_running and fs.access("/etc/init.d/passwall2_sni_spoofer") then
			api.exec_call("/etc/init.d/passwall2_sni_spoofer stop >/dev/null 2>&1")
		end
	end

	local mv_code, mv_out = api.exec_call("mv -f " .. util.shellquote(tmp_file) .. " " .. util.shellquote(bp) .. " 2>&1")
	if mv_code ~= 0 then
		return { ok = false, code = 0, error = "Failed installing binary: " .. trim(mv_out or "") }
	end
	api.exec("/bin/chmod", { "0755", bp })

	local sha = compute_sha256(bp) or ""
	local version_tag = tostring(meta.version_tag or "")
	if not meta.skip_uci then
		local u = new_cursor(meta.uci_dir)
		if not u:get(api.c_config, "global_sni_spoofer") then
			u:set(api.c_config, "global_sni_spoofer", "global_sni_spoofer")
		end
		u:set(api.c_config, "global_sni_spoofer", "bin_path", bp)
		u:set(api.c_config, "global_sni_spoofer", "bin_sha256", sha)
		u:set(api.c_config, "global_sni_spoofer", "bin_version", version_tag)
		u:commit(api.c_config)
	end
	M.register_sysupgrade_path(bp, meta.sysupgrade_conf)

	local binary = M.inspect_binary(bp, { sha256 = sha, version_tag = version_tag })
	if was_running and binary.arch_match and fs.access("/etc/init.d/passwall2_sni_spoofer") then
		api.exec_call("/etc/init.d/passwall2_sni_spoofer start >/dev/null 2>&1")
	end
	return { ok = true, code = 1, binary = binary }
end

function M.handle_upload_chunk(params)
	params = params or {}
	local uid = tostring(params.upload_id or "")
	if uid == "" or not uid:match("^[%w_%-]+$") or #uid > 64 then
		return { status = "error", message = "Invalid upload_id" }
	end

	local cidx = parse_int(params.chunk_index, 0)
	local total = parse_int(params.total_chunks, 1)
	if not cidx or not total or cidx >= total or total > 4096 then
		return { status = "error", message = "Invalid chunk bounds" }
	end

	local raw_b64 = params.chunk
	if type(raw_b64) ~= "string" or raw_b64 == "" then
		return { status = "error", message = "Empty upload chunk" }
	end
	local decoded = nixio.bin.b64decode(raw_b64)
	if not decoded or #decoded == 0 then
		return { status = "error", message = "Invalid Base64 chunk payload" }
	end

	fs.mkdirr(M.RUNTIME_DIR)
	local part_path = M.RUNTIME_DIR .. "/upload_" .. uid .. ".part"
	local f, err = io.open(part_path, cidx == 0 and "wb" or "ab")
	if not f then
		return { status = "error", message = "Failed writing upload buffer: " .. tostring(err) }
	end
	f:write(decoded)
	f:close()

	if cidx + 1 < total then
		return { status = "success", message = "chunk_received", chunk_index = cidx }
	end

	local target = params.target_path or params.bin_path or M.get_config().global.bin_path or M.DEFAULT_BIN_PATH
	local res = M.install_verified_binary(part_path, target, {
		version_tag = "",
		skip_uci = params.skip_uci,
		skip_service = params.skip_service,
		uci_dir = params.uci_dir,
		sysupgrade_conf = params.sysupgrade_conf,
	})
	if fs.access(part_path) then fs.unlink(part_path) end
	if not res.ok then
		return { status = "error", message = res.error }
	end
	return { status = "success", message = "Binary uploaded and installed", binary = res.binary }
end

local function build_fallback_assets()
	local out = {}
	for _, name in ipairs(M.KNOWN_ASSETS) do
		out[#out + 1] = {
			name = name,
			size = 0,
			browser_download_url = string.format("https://github.com/%s/releases/latest/download/%s", M.GITHUB_REPO, name),
			digest = "",
			recommended = (name == M.DEFAULT_GITHUB_ASSET),
		}
	end
	return out
end

function M.fetch_latest_release()
	local api_url = string.format("https://api.github.com/repos/%s/releases/latest", M.GITHUB_REPO)
	local data = api.get_api_json(api_url)
	if type(data) ~= "table" or not data.tag_name then
		return {
			ok = false,
			code = 0,
			tag_name = "",
			published_at = "",
			html_url = string.format("https://github.com/%s/releases/latest", M.GITHUB_REPO),
			assets = build_fallback_assets(),
			error = (type(data) == "table" and data.message) or "Unable to query GitHub release metadata; direct download URL remains available.",
		}
	end

	local priority = {}
	for i, name in ipairs(M.KNOWN_ASSETS) do priority[name] = i end
	local assets = {}
	for _, a in ipairs(type(data.assets) == "table" and data.assets or {}) do
		if type(a.name) == "string" and type(a.browser_download_url) == "string" then
			assets[#assets + 1] = {
				name = a.name,
				size = tonumber(a.size) or 0,
				browser_download_url = a.browser_download_url,
				digest = type(a.digest) == "string" and a.digest or "",
				recommended = (a.name == M.DEFAULT_GITHUB_ASSET),
				_ord = priority[a.name] or 99,
			}
		end
	end
	table.sort(assets, function(a, b)
		if a._ord ~= b._ord then return a._ord < b._ord end
		return a.name < b.name
	end)
	for _, a in ipairs(assets) do a._ord = nil end

	return {
		ok = true,
		code = 1,
		tag_name = tostring(data.tag_name),
		published_at = tostring(data.published_at or ""),
		html_url = tostring(data.html_url or ""),
		assets = #assets > 0 and assets or build_fallback_assets(),
	}
end

local function is_allowed_download_url(url, gh_proxy)
	if type(url) ~= "string" or url == "" then return false end
	local clean = url
	if gh_proxy ~= "" and clean:sub(1, #gh_proxy) == gh_proxy then
		clean = clean:sub(#gh_proxy + 1)
	end
	local prefix = "https://github.com/" .. M.GITHUB_REPO .. "/"
	if clean:sub(1, #prefix) == prefix then return true end
	if clean:match("^https://[%w%-%.]*githubusercontent%.com/") then return true end
	return false
end

local function write_dl_state(state)
	fs.mkdirr(M.RUNTIME_DIR)
	write_file_atomic(M.RUNTIME_DIR .. "/dl_" .. state.task_id .. ".json", jsonc.stringify(state))
end

local function read_dl_state(task_id)
	if type(task_id) ~= "string" or not task_id:match("^[%w_%-]+$") then return nil end
	local raw = read_file(M.RUNTIME_DIR .. "/dl_" .. task_id .. ".json")
	return raw and jsonc.parse(raw) or nil
end

function M._run_download_worker(task_id)
	local state = read_dl_state(task_id)
	if not state then return end
	local pid_file = M.RUNTIME_DIR .. "/dl_" .. state.task_id .. ".pid"

	local args = { "-sSkfL", "--connect-timeout 8", "--max-time 180", "--retry 2", "-H 'User-Agent: luci-app-passwall2'" }
	local code, out
	for attempt = 1, 2 do
		if state.gh_proxy and state.gh_proxy ~= "" then
			code, out = api.curl_direct(state.url, state.bin_file, args)
		else
			code, out = api.curl_auto(state.url, state.bin_file, args)
		end
		if code == 0 and fs.stat(state.bin_file, "type") == "reg" then
			break
		end
		if attempt == 1 and (code == 6 or code == 28 or code == 56) then
			api.exec("/bin/sleep", { "1" })
		else
			break
		end
	end
	if code ~= 0 or fs.stat(state.bin_file, "type") ~= "reg" then
		state.status = "error"
		state.error = "Download failed (curl exit " .. tostring(code) .. "): " .. trim(tostring(out or ""))
		if fs.access(state.bin_file) then fs.unlink(state.bin_file) end
		if fs.access(pid_file) then fs.unlink(pid_file) end
		write_dl_state(state)
		return
	end

	local downloaded = fs.stat(state.bin_file, "size") or 0
	state.downloaded_bytes = downloaded
	if (tonumber(state.total_bytes) or 0) == 0 then state.total_bytes = downloaded end

	local res = M.install_verified_binary(state.bin_file, state.target_path, {
		expected_digest = state.expected_digest,
		version_tag = state.version_tag,
	})
	if fs.access(state.bin_file) then fs.unlink(state.bin_file) end
	if fs.access(pid_file) then fs.unlink(pid_file) end

	if not res.ok then
		state.status = "error"
		state.error = res.error
	else
		state.status = "done"
		state.percent = 100
		state.binary = res.binary
	end
	write_dl_state(state)
end

function M.start_download(params)
	params = params or {}
	local asset = trim(tostring(params.asset or M.DEFAULT_GITHUB_ASSET))
	if asset == "" or not asset:match("^[%w%.%_%-]+$") or asset:find("..", 1, true) then
		return { ok = false, code = 0, error = "Invalid asset name" }
	end

	local target, terr = validate_bin_path(params.target_path or params.bin_path or M.get_config().global.bin_path or M.DEFAULT_BIN_PATH)
	if not target then
		return { ok = false, code = 0, error = terr }
	end

	local rel = M.fetch_latest_release()
	local chosen
	for _, a in ipairs(rel.assets or {}) do
		if a.name == asset then chosen = a break end
	end

	local gh_proxy = trim(tostring(api.uci_get_c("@global_app[0]", "gh_proxy_url") or ""))
	local url = trim(tostring(params.download_url or ""))
	if url == "" or not is_allowed_download_url(url, gh_proxy) then
		url = chosen and chosen.browser_download_url or string.format("https://github.com/%s/releases/latest/download/%s", M.GITHUB_REPO, asset)
	end
	if gh_proxy ~= "" and url:sub(1, #gh_proxy) ~= gh_proxy then
		url = gh_proxy .. url
	end

	local task_id = string.format("%d_%04d", os.time(), math.random(1000, 9999))
	local bin_file = M.RUNTIME_DIR .. "/dl_" .. task_id .. ".part"
	local state = {
		task_id = task_id,
		status = "downloading",
		asset = asset,
		url = url,
		gh_proxy = gh_proxy,
		target_path = target,
		bin_file = bin_file,
		expected_digest = chosen and chosen.digest or tostring(params.expected_digest or ""),
		version_tag = (rel.ok and rel.tag_name) or tostring(params.version_tag or ""),
		total_bytes = chosen and tonumber(chosen.size) or tonumber(params.total_bytes) or 0,
		downloaded_bytes = 0,
		percent = 0,
	}
	write_dl_state(state)

	local u = new_cursor()
	if u:get(api.c_config, "global_sni_spoofer") then
		u:set(api.c_config, "global_sni_spoofer", "github_asset", asset)
		u:commit(api.c_config)
	end

	local pid_file = M.RUNTIME_DIR .. "/dl_" .. task_id .. ".pid"
	if fs.access(pid_file) then fs.unlink(pid_file) end
	local cmd = string.format(
		"start-stop-daemon -S -b -m -p %s -x /bin/sh -- -c %s",
		util.shellquote(pid_file),
		util.shellquote("SNI_DL_TASK_ID=" .. util.shellquote(task_id) .. " lua -e 'require(\"luci.passwall2.sni_spoofer\")._run_download_worker(os.getenv(\"SNI_DL_TASK_ID\"))'")
	)
	local rc, out = api.exec_call(cmd .. " 2>&1")
	if rc ~= 0 then
		if fs.access(pid_file) then fs.unlink(pid_file) end
		state.status = "error"
		state.error = "Failed to spawn download worker (exit " .. tostring(rc) .. "): " .. trim(tostring(out or ""))
		write_dl_state(state)
		return { ok = false, code = 0, error = state.error }
	end
	return { ok = true, code = 1, task_id = task_id, asset = asset, version_tag = state.version_tag }
end

function M.get_download_progress(task_id)
	local state = read_dl_state(task_id)
	if not state then
		return { ok = false, code = 0, status = "error", error = "Download task not found" }
	end
	if state.status == "downloading" and fs.access(state.bin_file) then
		local sz = file_size_bytes(state.bin_file)
		state.downloaded_bytes = sz
		if (tonumber(state.total_bytes) or 0) > 0 then
			state.percent = math.min(99, math.floor((sz * 100) / state.total_bytes))
		end
	end
	return {
		ok = (state.status ~= "error"),
		code = (state.status ~= "error") and 1 or 0,
		task_id = state.task_id,
		status = state.status,
		asset = state.asset,
		downloaded_bytes = state.downloaded_bytes or 0,
		total_bytes = state.total_bytes or 0,
		percent = state.percent or 0,
		binary = state.binary,
		error = state.error,
	}
end

function M.strip_ansi(str)
	if type(str) ~= "string" then return "" end
	local clean = str:gsub("\27%[[0-9:;<=>?]*[ -/]*[@-~]", "")
	clean = clean:gsub("\27[@-Z\\-_]", "")
	return clean
end

function M.cap_log_file(path, max_bytes, keep_bytes)
	local target = path or M.LOG_FILE
	local limit = tonumber(max_bytes) or M.LOG_MAX_BYTES
	local keep = tonumber(keep_bytes) or M.LOG_KEEP_BYTES
	local sz = file_size_bytes(target)
	if sz <= limit then return false end

	local f = io.open(target, "rb")
	if not f then return false end
	local offset = math.max(0, sz - keep)
	f:seek("set", offset)
	local tail = f:read("*a") or ""
	f:close()

	if offset > 0 then
		local nl = tail:find("\n", 1, true)
		if nl then tail = tail:sub(nl + 1) end
	end

	-- Preserve inode for running daemon O_APPEND descriptor via wronly+trunc.
	local flags = nixio.open_flags("wronly", "trunc")
	local fd = nixio.open(target, flags)
	if not fd then return false end
	fd:writeall("[log truncated to keep latest entries]\n" .. tail)
	fd:close()
	return true
end

function M.get_log(limit, log_path)
	local target = log_path or M.LOG_FILE
	local max_lines = math.min(2000, math.max(1, tonumber(limit) or 300))
	local truncated = M.cap_log_file(target)
	local total_bytes = file_size_bytes(target)
	if total_bytes == 0 then
		return { ok = true, code = 1, lines = {}, total_bytes = 0, truncated = truncated }
	end

	local read_offset = math.max(0, total_bytes - M.LOG_KEEP_BYTES)
	local f = io.open(target, "rb")
	if not f then
		return { ok = true, code = 1, lines = {}, total_bytes = total_bytes, truncated = truncated }
	end
	if read_offset > 0 then f:seek("set", read_offset) end
	local raw = f:read("*a") or ""
	f:close()

	if read_offset > 0 then
		local nl = raw:find("\n", 1, true)
		if nl then raw = raw:sub(nl + 1) end
	end

	local lines = {}
	for line in M.strip_ansi(raw):gmatch("[^\r\n]+") do
		lines[#lines + 1] = line
	end
	if #lines > max_lines then
		local sliced = {}
		for i = #lines - max_lines + 1, #lines do
			sliced[#sliced + 1] = lines[i]
		end
		lines = sliced
	end
	return { ok = true, code = 1, lines = lines, total_bytes = total_bytes, truncated = truncated }
end

function M.clear_log(log_path)
	local target = log_path or M.LOG_FILE
	if fs.access(target) then
		local fd = nixio.open(target, nixio.open_flags("wronly", "trunc"))
		if fd then fd:close() end
	end
	return { ok = true, code = 1, total_bytes = 0 }
end

function M.get_status(uci_dir)
	local cfg = M.get_config(uci_dir)
	local pid_info = M.get_pid_status(cfg.global.bin_path)
	local bin_info = M.inspect_binary(cfg.global.bin_path, cfg.global)
	local valid, norm, errs = M.validate_payload(cfg, { require_enabled_listener = true })
	local preview_tbl = M.build_runtime_config(valid and norm or cfg)
	local preview_json = jsonc.stringify(preview_tbl, true)
	local log_bytes = file_size_bytes(M.LOG_FILE)

	return {
		running = pid_info.running,
		pid = pid_info.pid,
		uptime_sec = pid_info.uptime_sec,
		enabled = (cfg.global.enabled == "1"),
		host_arch = bin_info.host_arch,
		binary = bin_info,
		config = cfg,
		json_preview = preview_json,
		config_valid = valid,
		validation_errors = errs,
		log_bytes = log_bytes,
	}
end

return M
