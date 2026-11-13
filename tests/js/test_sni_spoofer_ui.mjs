import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ui = require("../../luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.js");

// Group 1: UTF-8 byte counting & fake_sni / global form validation
{
  assert.equal("سلام".length, 4);
  assert.equal(ui.utf8ByteLength("سلام"), 8);
  assert.equal(ui.utf8ByteLength("cdn.example.com"), 15);

  const baseConfig = () => ({
    global: {
      enabled: "0",
      bin_path: "/usr/bin/sni-spoof-rs",
      rust_log: "warn",
      idle_timeout: "",
      buffer_size: "8",
      graceful_shutdown_sec: "0",
      github_asset: "sni-spoof-rs-google-wifi-armv7-musl",
    },
    listeners: [
      {
        enabled: "1",
        remarks: "Gov",
        listen: "127.0.0.1:40443",
        connect: "192.0.2.10:443",
        fake_sni: "a".repeat(219),
        conn_timeout_sec: "5",
        handshake_timeout_sec: "2",
        keepalive_time_sec: "11",
        keepalive_interval_sec: "2",
      },
    ],
  });

  const okAscii = ui.validateConfigForm(baseConfig());
  assert.equal(okAscii.valid, true, JSON.stringify(okAscii.errors));

  const badAscii = baseConfig();
  badAscii.listeners[0].fake_sni = "a".repeat(220);
  const resAscii = ui.validateConfigForm(badAscii);
  assert.equal(resAscii.valid, false);
  assert.match(resAscii.errors["listeners[0].fake_sni"], /219/);

  const badUtf8 = baseConfig();
  badUtf8.listeners[0].fake_sni = "ب".repeat(110); // 110 chars = 220 UTF-8 bytes
  assert.equal(badUtf8.listeners[0].fake_sni.length, 110);
  assert.equal(ui.utf8ByteLength(badUtf8.listeners[0].fake_sni), 220);
  const resUtf8 = ui.validateConfigForm(badUtf8);
  assert.equal(resUtf8.valid, false);
  assert.match(resUtf8.errors["listeners[0].fake_sni"], /219/);

  const okUtf8 = baseConfig();
  okUtf8.listeners[0].fake_sni = "ب".repeat(109) + "a"; // 218 + 1 = 219 bytes
  assert.equal(ui.utf8ByteLength(okUtf8.listeners[0].fake_sni), 219);
  assert.equal(ui.validateConfigForm(okUtf8).valid, true);
}

// Group 2: parseSocketAddr
{
  const v4 = ui.parseSocketAddr("127.0.0.1:40443");
  assert.deepEqual(v4, { ok: true, ip: "127.0.0.1", port: 40443, isIPv6: false, canonical: "127.0.0.1:40443" });

  const v6 = ui.parseSocketAddr("[::1]:40443");
  assert.equal(v6.ok, true);
  assert.equal(v6.port, 40443);
  assert.equal(v6.isIPv6, true);
  assert.equal(v6.canonical, "[::1]:40443");

  const v6Expanded = ui.parseSocketAddr("[2001:0db8::1]:443");
  assert.equal(v6Expanded.ok, true);
  assert.equal(v6Expanded.isIPv6, true);

  for (const bad of [
    "",
    "cf.example.com:443",
    "127.0.0.1",
    "127.0.0.1:0",
    "127.0.0.1:65536",
    "127.0.0.01:443",
    "127.0.0.1:0443",
    "127.0.0.1/24:443",
    "::1:40443",
  ]) {
    assert.equal(ui.parseSocketAddr(bad).ok, false, `expected reject for ${bad}`);
  }
}

// Group 3: hasListenerConflict & connectsToListener
{
  assert.equal(ui.connectsToListener("0.0.0.0:40443", "127.0.0.1:40443"), true);
  assert.equal(ui.connectsToListener("[::]:40443", "[::1]:40443"), true);
  assert.equal(ui.connectsToListener("127.0.0.1:40443", "192.0.2.10:443"), false);
  assert.equal(ui.connectsToListener("0.0.0.0:40443", "127.0.0.1:40444"), false);

  assert.equal(
    ui.hasListenerConflict([
      { enabled: "1", listen: "0.0.0.0:40443", connect: "198.51.100.10:443" },
      { enabled: "1", listen: "127.0.0.1:40443", connect: "198.51.100.11:443" },
    ]),
    true,
  );

  assert.equal(
    ui.hasListenerConflict([
      { enabled: "1", listen: "[::]:40443", connect: "198.51.100.10:443" },
      { enabled: "1", listen: "[::1]:40443", connect: "198.51.100.11:443" },
    ]),
    true,
  );

  assert.equal(
    ui.hasListenerConflict([
      { enabled: "1", listen: "127.0.0.1:40443", connect: "198.51.100.10:443" },
      { enabled: "1", listen: "127.0.0.1:40443", connect: "198.51.100.11:443" },
    ]),
    true,
  );

  // Disabled duplicates do not conflict
  assert.equal(
    ui.hasListenerConflict([
      { enabled: "1", listen: "127.0.0.1:40443", connect: "198.51.100.10:443" },
      { enabled: "0", listen: "127.0.0.1:40443", connect: "198.51.100.11:443" },
    ]),
    false,
  );
}

// Group 4: buildJsonPreview matches sni-spoof-rs/src/config.rs schema
{
  const preview = ui.buildJsonPreview({
    global: {
      enabled: "1",
      bin_path: "/usr/bin/sni-spoof-rs",
      rust_log: "info",
      idle_timeout: "",
      buffer_size: "16",
      graceful_shutdown_sec: "5",
    },
    listeners: [
      {
        enabled: "1",
        remarks: "Active",
        listen: "127.0.0.1:40443",
        connect: "198.51.100.10:443",
        fake_sni: "example.com",
        conn_timeout_sec: "5",
        handshake_timeout_sec: "2",
        keepalive_time_sec: "11",
        keepalive_interval_sec: "2",
      },
      {
        enabled: "0",
        remarks: "Disabled",
        listen: "127.0.0.1:40444",
        connect: "198.51.100.11:443",
        fake_sni: "disabled.example",
        conn_timeout_sec: "5",
        handshake_timeout_sec: "2",
        keepalive_time_sec: "11",
        keepalive_interval_sec: "2",
      },
    ],
  });

  assert.equal("idle_timeout" in preview, false);
  assert.equal(preview.buffer_size, 16);
  assert.equal(preview.graceful_shutdown_sec, 5);
  assert.equal(preview.listeners.length, 1);
  assert.deepEqual(preview.listeners[0], {
    listen: "127.0.0.1:40443",
    connect: "198.51.100.10:443",
    fake_sni: "example.com",
    conn_timeout_sec: 5,
    handshake_timeout_sec: 2,
    keepalive_time_sec: 11,
    keepalive_interval_sec: 2,
  });

  const withIdle = ui.buildJsonPreview({
    global: { buffer_size: "8", graceful_shutdown_sec: "0", idle_timeout: "300" },
    listeners: [],
  });
  assert.equal(withIdle.idle_timeout, 300);
  assert.deepEqual(withIdle.listeners, []);
}

// Group 5: splitIntoChunks Base64 at 196608 bytes
{
  const totalBytes = 196608 * 2 + 1234;
  const src = new Uint8Array(totalBytes);
  for (let i = 0; i < totalBytes; i++) {
    src[i] = (i * 31 + 7) & 0xff;
  }

  const chunks = ui.splitIntoChunks(src, 196608);
  assert.equal(chunks.length, 3);
  assert.equal(chunks[0].chunkIndex, 0);
  assert.equal(chunks[0].totalChunks, 3);
  assert.equal(chunks[2].chunkIndex, 2);

  const decodedParts = chunks.map((c) => Uint8Array.from(Buffer.from(c.chunkBase64, "base64")));
  const combined = new Uint8Array(decodedParts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const part of decodedParts) {
    combined.set(part, offset);
    offset += part.length;
  }
  assert.deepEqual(combined, src);

  // Empty buffer yields 0 chunks cleanly
  assert.deepEqual(ui.splitIntoChunks(new Uint8Array(0)), []);
}

// Group 6: parseLogLine classifies levels and preserves raw XSS-unsafe string safely without HTML conversion
{
  const errLine = ui.parseLogLine("2026-11-13T12:00:00Z ERROR <script>alert(1)</script> failed");
  assert.equal(errLine.level, "error");
  assert.equal(errLine.cssClass, "ss-console-err");
  assert.equal(errLine.text, "2026-11-13T12:00:00Z ERROR <script>alert(1)</script> failed");

  assert.equal(ui.parseLogLine("2026 WARN retrying").level, "warn");
  assert.equal(ui.parseLogLine("2026 WARN retrying").cssClass, "ss-console-warn");
  assert.equal(ui.parseLogLine("2026 INFO listening").level, "info");
  assert.equal(ui.parseLogLine("2026 DEBUG handshake").level, "debug");
  assert.equal(ui.parseLogLine("2026 TRACE frame").level, "trace");
}

console.log("PASS: test_sni_spoofer_ui.mjs (all 6 groups)");
