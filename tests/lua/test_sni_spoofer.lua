local nixio = require "nixio"
require "nixio.util"
local fs = nixio.fs
local jsonc = require "luci.jsonc"

local function fail(msg)
	io.stderr:write("FAIL: " .. tostring(msg) .. "\n")
	os.exit(1)
end

local function assert_eq(actual, expected, label)
	if actual ~= expected then
		fail(string.format("%s: expected '%s', got '%s'", tostring(label), tostring(expected), tostring(actual)))
	end
end

local function assert_true(cond, label)
	if not cond then
		fail(tostring(label) .. ": expected truthy value")
	end
end

local function assert_false(cond, label)
	if cond then
		fail(tostring(label) .. ": expected falsy value")
	end
end

local function make_elf(bits, machine_lo, machine_hi, size)
	local b = {
		"\127ELF",
		string.char(bits == 64 and 2 or 1), -- EI_CLASS
		"\1", -- EI_DATA = little endian
		"\1", -- EI_VERSION
		string.rep("\0", 9),
		"\2\0", -- ET_EXEC (LE)
		string.char(machine_lo, machine_hi or 0),
	}
	local hdr = table.concat(b)
	local pad = (size or 128) - #hdr
	if pad > 0 then
		hdr = hdr .. string.rep("\0", pad)
	end
	return hdr
end

local function write_bytes(path, data)
	local f, err = io.open(path, "wb")
	if not f then error(err) end
	f:write(data)
	f:close()
end

local function read_bytes(path)
	local f, err = io.open(path, "rb")
	if not f then error(err) end
	local d = f:read("*a")
	f:close()
	return d
end

local ss = require "luci.passwall2.sni_spoofer"

-- 1. parse_socket_addr
local ip, port, is6 = ss.parse_socket_addr("127.0.0.1:40443")
assert_eq(ip, "127.0.0.1", "parse v4 ip")
assert_eq(port, 40443, "parse v4 port")
assert_false(is6, "parse v4 not ipv6")

ip, port, is6 = ss.parse_socket_addr("[::1]:40443")
assert_eq(ip, "::1", "parse v6 ip")
assert_eq(port, 40443, "parse v6 port")
assert_true(is6, "parse v6 flag")

ip, port, is6 = ss.parse_socket_addr("[0:0::1]:443")
assert_eq(ip, "::1", "parse canonical v6 ip")
assert_eq(port, 443, "parse canonical v6 port")

for _, bad in ipairs({ "example.com:443", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "::1:443", "127.0.0.1:80/24", "" }) do
	local a = ss.parse_socket_addr(bad)
	assert_eq(a, nil, "reject socket addr " .. bad)
end

-- 2. connects_to_listener
assert_true(ss.connects_to_listener("127.0.0.1:40443", "127.0.0.1:40443"), "identical v4 self-loop")
assert_true(ss.connects_to_listener("0.0.0.0:40443", "127.0.0.1:40443"), "wildcard v4 to loopback")
assert_true(ss.connects_to_listener("0.0.0.0:40443", "127.0.5.1:40443"), "wildcard v4 to 127/8")
assert_true(ss.connects_to_listener("[::]:40443", "[::1]:40443"), "wildcard v6 to ::1")
assert_true(ss.connects_to_listener("[::]:40443", "127.0.0.1:40443"), "wildcard v6 to v4 loopback")
assert_false(ss.connects_to_listener("127.0.0.1:40443", "172.67.139.236:443"), "normal external connect")
assert_false(ss.connects_to_listener("0.0.0.0:40443", "127.0.0.1:443"), "different port not loop")

-- 3. validate_payload + build_runtime_config
local base_payload = {
	global = {
		enabled = "0",
		bin_path = "/tmp/nonexistent-test-bin-path",
		rust_log = "warn",
		idle_timeout = "",
		buffer_size = "8",
		graceful_shutdown_sec = "0",
		github_asset = "sni-spoof-rs-google-wifi-armv7-musl"
	},
	listeners = {
		{
			enabled = "1",
			remarks = "CF",
			listen = "127.0.0.1:40443",
			connect = "172.67.139.236:443",
			fake_sni = "security.vercel.com",
			conn_timeout_sec = "5",
			handshake_timeout_sec = "2",
			keepalive_time_sec = "11",
			keepalive_interval_sec = "2"
		},
		{
			enabled = "0",
			remarks = "Draft",
			listen = "127.0.0.1:40444",
			connect = "104.18.4.130:443",
			fake_sni = "security.vercel.com",
			conn_timeout_sec = "5",
			handshake_timeout_sec = "2",
			keepalive_time_sec = "11",
			keepalive_interval_sec = "2"
		}
	}
}

local ok, norm, errs = ss.validate_payload(base_payload)
assert_true(ok, "valid payload passes")

-- Blank timing strings fall back cleanly to defaults (matching JS frontend)
local blank_timings = {
	global = base_payload.global,
	listeners = { {
		enabled = "1",
		listen = "127.0.0.1:40443",
		connect = "172.67.139.236:443",
		fake_sni = "security.vercel.com",
		conn_timeout_sec = "",
		handshake_timeout_sec = "",
		keepalive_time_sec = "",
		keepalive_interval_sec = "",
	} }
}
local ok_blank, norm_blank, errs_blank = ss.validate_payload(blank_timings)
assert_true(ok_blank, "blank listener timings default cleanly")
assert_eq(norm_blank.listeners[1].conn_timeout_sec, "5", "blank conn_timeout_sec fallback")
assert_eq(norm_blank.listeners[1].keepalive_interval_sec, "2", "blank keepalive_interval_sec fallback")

local cfg_tbl = ss.build_runtime_config(norm)
assert_eq(cfg_tbl.idle_timeout, nil, "blank idle_timeout omitted")
assert_eq(cfg_tbl.buffer_size, 8, "numeric buffer_size")
assert_eq(cfg_tbl.graceful_shutdown_sec, 0, "numeric graceful_shutdown_sec")
assert_eq(#cfg_tbl.listeners, 1, "disabled listener excluded from runtime config")
assert_eq(cfg_tbl.listeners[1].listen, "127.0.0.1:40443", "enabled listener retained")

local bad_ascii = {
	global = base_payload.global,
	listeners = { {
		enabled = "1",
		listen = "127.0.0.1:40443",
		connect = "172.67.139.236:443",
		fake_sni = string.rep("a", 220),
		conn_timeout_sec = "5", handshake_timeout_sec = "2",
		keepalive_time_sec = "11", keepalive_interval_sec = "2"
	} }
}
local ok_a, _, err_a = ss.validate_payload(bad_ascii)
assert_false(ok_a, "reject 220 ASCII fake_sni")
assert_true(err_a["listeners[1].fake_sni"] ~= nil, "ascii fake_sni error keyed")

local bad_utf8 = {
	global = base_payload.global,
	listeners = { {
		enabled = "1",
		listen = "127.0.0.1:40443",
		connect = "172.67.139.236:443",
		fake_sni = string.rep("\216\167", 110), -- 110 chars = 220 UTF-8 bytes
		conn_timeout_sec = "5", handshake_timeout_sec = "2",
		keepalive_time_sec = "11", keepalive_interval_sec = "2"
	} }
}
local ok_u = ss.validate_payload(bad_utf8)
assert_false(ok_u, "reject 220 UTF-8 bytes fake_sni")

local ok_219 = {
	global = base_payload.global,
	listeners = { {
		enabled = "1",
		listen = "127.0.0.1:40443",
		connect = "172.67.139.236:443",
		fake_sni = "a" .. string.rep("\216\167", 109), -- 219 UTF-8 bytes
		conn_timeout_sec = "5", handshake_timeout_sec = "2",
		keepalive_time_sec = "11", keepalive_interval_sec = "2"
	} }
}
assert_true(ss.validate_payload(ok_219), "accept exactly 219 UTF-8 bytes")

local dup_listen = {
	global = base_payload.global,
	listeners = {
		{
			enabled = "1", listen = "127.0.0.1:40443", connect = "172.67.139.236:443",
			fake_sni = "security.vercel.com", conn_timeout_sec = "5", handshake_timeout_sec = "2",
			keepalive_time_sec = "11", keepalive_interval_sec = "2"
		},
		{
			enabled = "1", listen = "127.0.0.1:40443", connect = "104.18.4.130:443",
			fake_sni = "security.vercel.com", conn_timeout_sec = "5", handshake_timeout_sec = "2",
			keepalive_time_sec = "11", keepalive_interval_sec = "2"
		}
	}
}
assert_false(ss.validate_payload(dup_listen), "reject duplicate enabled listen")

local drafts_only = {
	global = base_payload.global,
	listeners = { {
		enabled = "0", listen = "127.0.0.1:40443", connect = "172.67.139.236:443",
		fake_sni = "security.vercel.com", conn_timeout_sec = "5", handshake_timeout_sec = "2",
		keepalive_time_sec = "11", keepalive_interval_sec = "2"
	} }
}
assert_true(ss.validate_payload(drafts_only, { require_enabled_listener = false }), "allow disabled draft save")
assert_false(ss.validate_payload(drafts_only, { require_enabled_listener = true }), "require enabled listener for start")

-- Temp workspace for FS / ELF / log / upload / UCI tests
local tmp = "/tmp/test_sni_spoofer_lua_" .. tostring(os.time())
fs.mkdirr(tmp)

-- 4. parse_elf_header & inspect_binary
local arm_elf = make_elf(32, 0x28, 0x00, 128)
local amd_elf = make_elf(64, 0x3E, 0x00, 128)
local p_arm = ss.parse_elf_header(arm_elf)
assert_true(p_arm.valid, "arm ELF valid")
assert_eq(p_arm.bits, 32, "arm ELF 32-bit")
assert_eq(p_arm.endian, "little", "arm ELF little endian")
assert_eq(p_arm.arch, "armv7", "arm ELF arch")

local p_amd = ss.parse_elf_header(amd_elf)
assert_true(p_amd.valid, "amd64 ELF valid")
assert_eq(p_amd.bits, 64, "amd64 ELF 64-bit")
assert_eq(p_amd.arch, "x86_64", "amd64 ELF arch")

local p_html = ss.parse_elf_header("<html>404 Not Found</html>")
assert_false(p_html.valid, "HTML rejected by parse_elf_header")

local arm_bin_path = tmp .. "/bin-armv7"
write_bytes(arm_bin_path, arm_elf)
nixio.fs.chmod(arm_bin_path, 755)
local insp = ss.inspect_binary(arm_bin_path, { sha256 = "", version_tag = "" })
assert_true(insp.exists, "arm bin exists")
assert_eq(insp.elf.arch, "armv7", "inspected armv7")
assert_false(insp.arch_match, "cross-arch mismatch detected cleanly")
assert_false(insp.help_ok, "cross-arch --help not executed")
assert_eq(insp.error, nil, "no error inspecting cross-arch binary")

-- 5. install_verified_binary
local target_bin = tmp .. "/installed-bin"
local bad_tmp = tmp .. "/bad.html"
local good_tmp = tmp .. "/good.arm"
local sysupgrade_tmp = tmp .. "/sysupgrade.conf"
write_bytes(target_bin, amd_elf)
write_bytes(bad_tmp, "<html>404 Not Found</html>")
write_bytes(good_tmp, arm_elf)
write_bytes(sysupgrade_tmp, "")

local bad_res = ss.install_verified_binary(bad_tmp, target_bin, { skip_uci = true, sysupgrade_conf = sysupgrade_tmp })
assert_eq(bad_res.code, 0, "reject non-ELF upload")
assert_eq(read_bytes(target_bin), amd_elf, "existing valid binary preserved untouched")

local good_res = ss.install_verified_binary(good_tmp, target_bin, {
	skip_uci = true,
	sysupgrade_conf = sysupgrade_tmp,
	version_tag = "v1.0.3"
})
assert_eq(good_res.code, 1, "install verified ELF succeeds")
assert_eq(read_bytes(target_bin), arm_elf, "installed binary matches payload")
assert_eq(fs.stat(target_bin, "modestr"), "rwxr-xr-x", "installed binary chmod 0755")
ss.register_sysupgrade_path(target_bin, sysupgrade_tmp)
ss.register_sysupgrade_path(target_bin, sysupgrade_tmp)
local sys_content = read_bytes(sysupgrade_tmp)
local sys_lines = 0
for line in sys_content:gmatch("[^\r\n]+") do
	if line == target_bin then sys_lines = sys_lines + 1 end
end
assert_eq(sys_lines, 1, "sysupgrade.conf single entry")

-- 6. cap_log_file & strip_ansi
assert_eq(ss.strip_ansi("\27[32mINFO\27[0m ready \27[1;33mwarn\27[0m"), "INFO ready warn", "strip_ansi strips escapes")
local log_p = tmp .. "/service.log"
local lines = {}
for i = 1, 80 do
	lines[#lines + 1] = string.format("2026-11-13 line-%03d %s\n", i, string.rep("x", 20))
end
write_bytes(log_p, table.concat(lines))
local ino_before = fs.stat(log_p, "ino")
local size_before = fs.stat(log_p, "size")
assert_true(size_before > 512, "precondition log > 512")
local truncated = ss.cap_log_file(log_p, 512, 256)
local ino_after = fs.stat(log_p, "ino")
local size_after = fs.stat(log_p, "size")
assert_true(truncated, "cap_log_file truncated")
assert_eq(ino_after, ino_before, "cap_log_file preserved exact inode")
assert_true(size_after <= 512, "cap_log_file shrank within max_bytes")

-- 7. handle_upload_chunk
local upload_elf = make_elf(64, 0x3E, 0x00, 512)
local up_target = tmp .. "/uploaded-bin"
local trav = ss.handle_upload_chunk({ upload_id = "../bad", chunk_index = 0, total_chunks = 1, chunk = "AAAA" })
assert_eq(trav.status, "error", "reject upload_id traversal")

local csize = 192 -- multiple of 3 for clean chunk boundaries
local total_c = math.ceil(#upload_elf / csize)
local last_res
for idx = 0, total_c - 1 do
	local slice = upload_elf:sub(idx * csize + 1, (idx + 1) * csize)
	last_res = ss.handle_upload_chunk({
		upload_id = "testup_01",
		chunk_index = idx,
		total_chunks = total_c,
		chunk = nixio.bin.b64encode(slice),
		target_path = up_target,
		skip_uci = true,
		sysupgrade_conf = sysupgrade_tmp
	})
end
assert_eq(last_res.status, "success", "chunked upload completes")
assert_eq(read_bytes(up_target), upload_elf, "chunked upload matches original ELF")

-- 8. Isolated UCI roundtrip & runtime config JSON file
local tmp_uci = tmp .. "/uci"
fs.mkdirr(tmp_uci)
write_bytes(tmp_uci .. "/passwall2", "config global 'global'\n\toption enabled '0'\n")
local save_res = ss.save_config(base_payload, { uci_dir = tmp_uci, sysupgrade_conf = sysupgrade_tmp })
assert_true(save_res.ok, "save_config persists valid UCI")
local loaded = ss.get_config(tmp_uci)
assert_eq(#loaded.listeners, 2, "both enabled and draft listeners persisted")
assert_eq(loaded.global.bin_path, base_payload.global.bin_path, "saved bin_path loaded")

local out_json = tmp .. "/runtime/config.json"
local w_ok, w_err = ss.write_runtime_config(out_json, tmp_uci)
assert_true(w_ok, "write_runtime_config succeeds: " .. tostring(w_err))
local parsed = jsonc.parse(read_bytes(out_json))
assert_eq(#parsed.listeners, 1, "runtime JSON contains only enabled listener")
assert_eq(parsed.idle_timeout, nil, "runtime JSON omits nil idle_timeout")

nixio.fs.remover(tmp)
os.execute("rm -rf " .. tmp)

-- Group 9: Official App Update release metadata endpoint in com.lua
package.loaded["luci.passwall2.com"] = nil
local com = require "luci.passwall2.com"
assert_eq(com.passwall2.repo, "mohamadtsn/openwrt-passwall2", "com.passwall2 repo configured")
assert_eq(
	com.passwall2:get_url(),
	"https://github.com/mohamadtsn/openwrt-passwall2/releases/latest/download/passwall2-release-api.json",
	"com.passwall2 release API URL points to fork latest release asset"
)

print("PASS: test_sni_spoofer.lua (all 9 groups)")
