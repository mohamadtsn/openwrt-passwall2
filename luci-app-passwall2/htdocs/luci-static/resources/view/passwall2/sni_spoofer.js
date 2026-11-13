(function (root, factory) {
  "use strict";
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.PasswallSniSpoofer = api;
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", function () {
        api.mount();
      });
    } else {
      api.mount();
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var FAKE_SNI_MAX_BYTES = 219;
  var DEFAULT_CHUNK_BYTES = 24576; // Fits OpenWrt 24.10 HTTP_MAX_CONTENT (102400 B) even with worst-case URL encoding
  var DEFAULT_BIN_PATH = "/usr/bin/sni-spoof-rs";
  var VALID_LOG_LEVELS = { error: true, warn: true, info: true, debug: true, trace: true };
  var FALLBACK_ASSETS = [
    { name: "sni-spoof-rs-google-wifi-armv7-musl", recommended: true },
    { name: "sni-spoof-rs-linux-amd64-musl", recommended: false },
    { name: "sni-spoof-rs-linux-arm64", recommended: false },
  ];

  function utf8ByteLength(value) {
    var str = String(value == null ? "" : value);
    if (typeof TextEncoder === "function") {
      return new TextEncoder().encode(str).length;
    }
    if (typeof Buffer === "function") {
      return Buffer.byteLength(str, "utf8");
    }
    return unescape(encodeURIComponent(str)).length;
  }

  function isValidUtf8String(value) {
    var str = String(value == null ? "" : value);
    return /^(?:[^\uD800-\uDFFF]|[\uD800-\uDBFF][\uDC00-\uDFFF])*$/.test(str);
  }

  function parseNonNegInt(val, minVal, maxVal) {
    var raw = String(val == null ? "" : val).trim();
    if (!/^\d+$/.test(raw)) return null;
    var num = Number(raw);
    if (!Number.isSafeInteger(num)) return null;
    if (num < minVal) return null;
    if (maxVal != null && num > maxVal) return null;
    return num;
  }

  function expandAndNormalizeIPv6(raw) {
    if (!raw || raw.indexOf("%") !== -1) return null;
    var halves = raw.split("::");
    if (halves.length > 2) return null;

    var left = halves[0] === "" ? [] : halves[0].split(":");
    var right = halves.length === 2 && halves[1] !== "" ? halves[1].split(":") : [];
    var groups;

    if (halves.length === 2) {
      if (left.length + right.length >= 8) return null;
      var missing = 8 - (left.length + right.length);
      groups = left.concat(new Array(missing).fill("0")).concat(right);
    } else {
      if (left.length !== 8) return null;
      groups = left;
    }

    var nums = [];
    for (var i = 0; i < groups.length; i++) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null;
      nums.push(parseInt(groups[i], 16));
    }

    // RFC 5952 longest zero-run compression
    var bestStart = -1;
    var bestLen = 0;
    var curStart = -1;
    var curLen = 0;
    for (var j = 0; j < 8; j++) {
      if (nums[j] === 0) {
        if (curStart === -1) curStart = j;
        curLen++;
        if (curLen > bestLen) {
          bestStart = curStart;
          bestLen = curLen;
        }
      } else {
        curStart = -1;
        curLen = 0;
      }
    }

    var hextets = nums.map(function (n) {
      return n.toString(16);
    });
    if (bestLen < 2) {
      return hextets.join(":");
    }
    var prefix = hextets.slice(0, bestStart).join(":");
    var suffix = hextets.slice(bestStart + bestLen).join(":");
    return prefix + "::" + suffix;
  }

  function parseSocketAddr(raw) {
    if (typeof raw !== "string" || raw === "" || raw !== raw.trim()) {
      return { ok: false, error: "Address must be non-empty without surrounding spaces" };
    }
    if (raw.indexOf("/") !== -1) {
      return { ok: false, error: "CIDR suffix is not allowed" };
    }

    var ip = null;
    var portStr = null;
    var isIPv6 = false;

    var v6Match = /^\[([0-9a-fA-F:]+)\]:(\d+)$/.exec(raw);
    if (v6Match) {
      isIPv6 = true;
      ip = expandAndNormalizeIPv6(v6Match[1]);
      if (!ip) {
        return { ok: false, error: "Invalid IPv6 address" };
      }
      portStr = v6Match[2];
    } else {
      var v4Match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d+)$/.exec(raw);
      if (!v4Match) {
        return { ok: false, error: "Expected IPv4:port or [IPv6]:port" };
      }
      var octets = [];
      for (var i = 1; i <= 4; i++) {
        var part = v4Match[i];
        if (/^0\d/.test(part)) {
          return { ok: false, error: "Leading zeros in IPv4 octets are not allowed" };
        }
        var oct = Number(part);
        if (oct < 0 || oct > 255) {
          return { ok: false, error: "Invalid IPv4 octet" };
        }
        octets.push(String(oct));
      }
      ip = octets.join(".");
      portStr = v4Match[5];
    }

    if (/^0\d/.test(portStr)) {
      return { ok: false, error: "Leading zeros in port are not allowed" };
    }
    var port = Number(portStr);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
      return { ok: false, error: "Port must be between 1 and 65535" };
    }

    return {
      ok: true,
      ip: ip,
      port: port,
      isIPv6: isIPv6,
      canonical: (isIPv6 ? "[" + ip + "]" : ip) + ":" + port,
    };
  }

  function isLoopbackParsed(parsed) {
    if (!parsed || !parsed.ok) return false;
    if (parsed.isIPv6) return parsed.ip === "::1";
    return parsed.ip.indexOf("127.") === 0;
  }

  function isUnspecifiedParsed(parsed) {
    if (!parsed || !parsed.ok) return false;
    return parsed.isIPv6 ? parsed.ip === "::" : parsed.ip === "0.0.0.0";
  }

  function connectsToListener(listenAddr, connectAddr) {
    var l = parseSocketAddr(listenAddr);
    var c = parseSocketAddr(connectAddr);
    if (!l.ok || !c.ok) return false;
    if (l.canonical === c.canonical) return true;
    return (
      l.port === c.port &&
      isLoopbackParsed(c) &&
      (isLoopbackParsed(l) || isUnspecifiedParsed(l))
    );
  }

  function isEnabledFlag(val) {
    return val === true || val === 1 || String(val || "0") === "1";
  }

  function findListenerConflicts(listeners) {
    var errors = {};
    var enabledList = [];
    var seenCanonical = Object.create(null);

    (listeners || []).forEach(function (item, idx) {
      if (!isEnabledFlag(item && item.enabled)) return;
      var lp = parseSocketAddr(String((item && item.listen) || "").trim());
      if (!lp.ok) return;

      if (seenCanonical[lp.canonical] != null) {
        errors["listeners[" + idx + "].listen"] = "Duplicate enabled listen address: " + lp.canonical;
      } else {
        seenCanonical[lp.canonical] = idx;
      }

      for (var i = 0; i < enabledList.length; i++) {
        var prev = enabledList[i];
        if (prev.parsed.isIPv6 === lp.isIPv6 && prev.parsed.port === lp.port) {
          if (isUnspecifiedParsed(prev.parsed) || isUnspecifiedParsed(lp)) {
            if (!errors["listeners[" + idx + "].listen"]) {
              errors["listeners[" + idx + "].listen"] =
                "Listen address overlaps wildcard bind on port " + lp.port;
            }
          }
        }
      }
      enabledList.push({ idx: idx, parsed: lp, item: item });
    });

    enabledList.forEach(function (entry) {
      var connRaw = String((entry.item && entry.item.connect) || "").trim();
      var cp = parseSocketAddr(connRaw);
      if (!cp.ok) return;
      for (var k = 0; k < enabledList.length; k++) {
        var target = enabledList[k];
        if (connectsToListener(target.parsed.canonical, cp.canonical)) {
          errors["listeners[" + entry.idx + "].connect"] =
            "Connect address must not loop back to an active listener";
          break;
        }
      }
    });

    return errors;
  }

  function hasListenerConflict(listeners) {
    return Object.keys(findListenerConflicts(listeners)).length > 0;
  }

  function validateConfigForm(config) {
    var errors = {};
    var g = (config && config.global) || {};
    var binPath = String(g.bin_path == null ? DEFAULT_BIN_PATH : g.bin_path).trim();
    if (!binPath || binPath.charAt(0) !== "/" || binPath.indexOf("..") !== -1 || /[\s\0]/.test(binPath)) {
      errors["global.bin_path"] = "Binary path must be an absolute path without '..' or whitespace";
    }

    var rustLog = String(g.rust_log || "warn").trim().toLowerCase();
    if (!VALID_LOG_LEVELS[rustLog]) {
      errors["global.rust_log"] = "Must be one of error, warn, info, debug, trace";
    }

    var idleRaw = String(g.idle_timeout == null ? "" : g.idle_timeout).trim();
    if (idleRaw !== "" && parseNonNegInt(idleRaw, 1, null) === null) {
      errors["global.idle_timeout"] = "Idle timeout must be blank or integer >= 1";
    }

    if (parseNonNegInt(g.buffer_size == null ? "8" : g.buffer_size, 1, 1024) === null) {
      errors["global.buffer_size"] = "Buffer size must be integer between 1 and 1024 KiB";
    }

    if (parseNonNegInt(g.graceful_shutdown_sec == null ? "0" : g.graceful_shutdown_sec, 0, 3600) === null) {
      errors["global.graceful_shutdown_sec"] = "Graceful shutdown must be integer between 0 and 3600";
    }

    var listeners = Array.isArray(config && config.listeners) ? config.listeners : [];
    var timingKeys = [
      ["conn_timeout_sec", "5", "Connect timeout"],
      ["handshake_timeout_sec", "2", "Handshake timeout"],
      ["keepalive_time_sec", "11", "Keepalive time"],
      ["keepalive_interval_sec", "2", "Keepalive interval"],
    ];

    listeners.forEach(function (item, idx) {
      var prefix = "listeners[" + idx + "].";
      var remarks = String((item && item.remarks) || "").trim();
      if (utf8ByteLength(remarks) > 128) {
        errors[prefix + "remarks"] = "Remarks must be <= 128 UTF-8 bytes";
      }

      var listenStr = String((item && item.listen) || "").trim();
      var connectStr = String((item && item.connect) || "").trim();
      var lp = parseSocketAddr(listenStr);
      if (!lp.ok) {
        errors[prefix + "listen"] = lp.error;
      }
      var cp = parseSocketAddr(connectStr);
      if (!cp.ok) {
        errors[prefix + "connect"] = cp.error;
      }
      if (lp.ok && cp.ok && connectsToListener(lp.canonical, cp.canonical)) {
        errors[prefix + "connect"] = "Connect address must not loop back to this listener";
      }

      var sni = String((item && item.fake_sni) || "").trim();
      var sniBytes = utf8ByteLength(sni);
      if (!sni) {
        errors[prefix + "fake_sni"] = "Fake SNI is required";
      } else if (!isValidUtf8String(sni) || /[\r\n\t\s]/.test(sni)) {
        errors[prefix + "fake_sni"] = "Fake SNI must be valid UTF-8 without whitespace";
      } else if (sniBytes > FAKE_SNI_MAX_BYTES) {
        errors[prefix + "fake_sni"] =
          "Fake SNI exceeds " + FAKE_SNI_MAX_BYTES + " UTF-8 bytes (" + sniBytes + " B)";
      }

      timingKeys.forEach(function (spec) {
        var key = spec[0];
        var val = item && item[key] != null && String(item[key]).trim() !== "" ? item[key] : spec[1];
        if (parseNonNegInt(val, 1, 86400) === null) {
          errors[prefix + key] = spec[2] + " must be integer between 1 and 86400";
        }
      });
    });

    var conflicts = findListenerConflicts(listeners);
    Object.keys(conflicts).forEach(function (k) {
      if (!errors[k]) errors[k] = conflicts[k];
    });

    return { valid: Object.keys(errors).length === 0, errors: errors };
  }

  function buildJsonPreview(config) {
    var g = (config && config.global) || {};
    var listeners = Array.isArray(config && config.listeners) ? config.listeners : [];
    var outListeners = [];

    listeners.forEach(function (l) {
      if (!isEnabledFlag(l && l.enabled)) return;
      outListeners.push({
        listen: String((l && l.listen) || "").trim(),
        connect: String((l && l.connect) || "").trim(),
        fake_sni: String((l && l.fake_sni) || "").trim(),
        conn_timeout_sec: parseNonNegInt(l && l.conn_timeout_sec, 1, 86400) || 5,
        handshake_timeout_sec: parseNonNegInt(l && l.handshake_timeout_sec, 1, 86400) || 2,
        keepalive_time_sec: parseNonNegInt(l && l.keepalive_time_sec, 1, 86400) || 11,
        keepalive_interval_sec: parseNonNegInt(l && l.keepalive_interval_sec, 1, 86400) || 2,
      });
    });

    var out = {
      buffer_size: parseNonNegInt(g.buffer_size, 1, 1024) || 8,
      graceful_shutdown_sec:
        parseNonNegInt(g.graceful_shutdown_sec, 0, 3600) !== null
          ? parseNonNegInt(g.graceful_shutdown_sec, 0, 3600)
          : 0,
      listeners: outListeners,
    };

    var idle = parseNonNegInt(g.idle_timeout, 1, null);
    if (idle !== null) {
      out.idle_timeout = idle;
    }

    return out;
  }

  function uint8ToBase64(bytes) {
    if (typeof Buffer === "function") {
      return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
    }
    var bin = "";
    var step = 8192;
    for (var i = 0; i < bytes.length; i += step) {
      var sub = bytes.subarray(i, Math.min(i + step, bytes.length));
      bin += String.fromCharCode.apply(null, sub);
    }
    return btoa(bin);
  }

  function splitIntoChunks(input, chunkBytes) {
    var bytes =
      input instanceof Uint8Array
        ? input
        : input instanceof ArrayBuffer
          ? new Uint8Array(input)
          : new Uint8Array(0);
    if (bytes.length === 0) return [];
    var size = chunkBytes && chunkBytes > 0 ? chunkBytes : DEFAULT_CHUNK_BYTES;
    var totalChunks = Math.ceil(bytes.length / size);
    var chunks = [];
    for (var idx = 0; idx < totalChunks; idx++) {
      var start = idx * size;
      var end = Math.min(start + size, bytes.length);
      chunks.push({
        chunkIndex: idx,
        totalChunks: totalChunks,
        byteLength: end - start,
        chunkBase64: uint8ToBase64(bytes.subarray(start, end)),
      });
    }
    return chunks;
  }

  function parseLogLine(line) {
    var text = String(line == null ? "" : line);
    var m = /\b(ERROR|WARN|INFO|DEBUG|TRACE)\b/.exec(text);
    var level = m ? m[1].toLowerCase() : "info";
    var cssClass = "";
    if (level === "error") cssClass = "ss-console-err";
    else if (level === "warn") cssClass = "ss-console-warn";
    else if (level === "debug" || level === "trace") cssClass = "ss-console-muted";
    return { level: level, cssClass: cssClass, text: text };
  }

  function formatBytes(num) {
    var n = Number(num);
    if (!Number.isFinite(n) || n < 0) return "-";
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
    return (n / (1024 * 1024)).toFixed(2) + " MiB";
  }

  function formatUptime(sec) {
    if (sec == null || sec === "" || Number(sec) < 0) return "-";
    var s = Math.floor(Number(sec));
    if (!Number.isFinite(s)) return "-";
    var d = Math.floor(s / 86400);
    s %= 86400;
    var h = Math.floor(s / 3600);
    s %= 3600;
    var m = Math.floor(s / 60);
    s %= 60;
    if (d > 0) return d + "d " + h + "h";
    if (h > 0) return h + "h " + m + "m";
    if (m > 0) return m + "m " + s + "s";
    return s + "s";
  }

  function cloneConfig(cfg) {
    var g = (cfg && cfg.global) || {};
    var listeners = Array.isArray(cfg && cfg.listeners) ? cfg.listeners : [];
    return {
      global: {
        enabled: isEnabledFlag(g.enabled) ? "1" : "0",
        bin_path: String(g.bin_path || DEFAULT_BIN_PATH),
        rust_log: String(g.rust_log || "warn"),
        idle_timeout: String(g.idle_timeout || ""),
        buffer_size: String(g.buffer_size || "8"),
        graceful_shutdown_sec: String(g.graceful_shutdown_sec || "0"),
        github_asset: String(g.github_asset || FALLBACK_ASSETS[0].name),
      },
      listeners: listeners.map(function (l) {
        return {
          id: l.id ? String(l.id) : "",
          enabled: isEnabledFlag(l.enabled == null ? "1" : l.enabled) ? "1" : "0",
          remarks: String(l.remarks || ""),
          listen: String(l.listen || ""),
          connect: String(l.connect || ""),
          fake_sni: String(l.fake_sni || ""),
          conn_timeout_sec: String(l.conn_timeout_sec || "5"),
          handshake_timeout_sec: String(l.handshake_timeout_sec || "2"),
          keepalive_time_sec: String(l.keepalive_time_sec || "11"),
          keepalive_interval_sec: String(l.keepalive_interval_sec || "2"),
        };
      }),
    };
  }

  function mount() {
    if (typeof document === "undefined") return null;
    var rootEl = document.getElementById("sni-spoofer-app");
    if (!rootEl || rootEl.dataset.mounted === "1") return null;
    rootEl.dataset.mounted = "1";

    var bootEl = document.getElementById("sni-spoofer-boot");
    var boot = { token: "", urls: {}, i18n: {} };
    if (bootEl && bootEl.textContent) {
      try {
        boot = JSON.parse(bootEl.textContent);
      } catch (_) {}
    }
    var i18n = boot.i18n || {};
    function tr(key, fallback) {
      return i18n[key] || fallback;
    }

    function getToken() {
      return (
        boot.token ||
        (typeof window !== "undefined" && window.L && window.L.env && window.L.env.token) ||
        ""
      );
    }

    var state = {
      status: null,
      draft: cloneConfig(null),
      dirty: false,
      busy: false,
      releaseAssets: FALLBACK_ASSETS.slice(),
      releaseTag: "",
      logLines: [],
      logTotalBytes: 0,
      logTruncated: false,
      logPollHandle: null,
      logFallbackTimer: null,
      validation: { valid: true, errors: {} },
    };

    var el = {
      banner: document.getElementById("ss-global-banner"),
      statusBadge: document.getElementById("ss-status-badge"),
      statusText: document.getElementById("ss-status-text"),
      headerPid: document.getElementById("ss-header-pid"),
      headerUptime: document.getElementById("ss-header-uptime"),
      bootEnabled: document.getElementById("ss-boot-enabled"),
      btnStart: document.getElementById("ss-btn-start"),
      btnStop: document.getElementById("ss-btn-stop"),
      btnRestart: document.getElementById("ss-btn-restart"),
      btnRefresh: document.getElementById("ss-btn-refresh"),
      archBadge: document.getElementById("ss-arch-badge"),
      kvBinPath: document.getElementById("ss-kv-bin-path"),
      kvHostArch: document.getElementById("ss-kv-host-arch"),
      kvElf: document.getElementById("ss-kv-elf"),
      kvHelp: document.getElementById("ss-kv-help"),
      kvVersion: document.getElementById("ss-kv-version"),
      kvSha256: document.getElementById("ss-kv-sha256"),
      binWarning: document.getElementById("ss-binary-warning"),
      tabBtnRelease: document.getElementById("ss-tab-btn-release"),
      tabBtnUpload: document.getElementById("ss-tab-btn-upload"),
      tabPanelRelease: document.getElementById("ss-tab-panel-release"),
      tabPanelUpload: document.getElementById("ss-tab-panel-upload"),
      releaseSelect: document.getElementById("ss-release-asset"),
      releaseMeta: document.getElementById("ss-release-meta"),
      releaseLink: document.getElementById("ss-release-link"),
      btnCheckRelease: document.getElementById("ss-btn-check-release"),
      btnDownload: document.getElementById("ss-btn-download"),
      dlProgressWrap: document.getElementById("ss-dl-progress-wrap"),
      dlProgressBar: document.getElementById("ss-dl-progressbar"),
      dlProgressFill: document.getElementById("ss-dl-progress-fill"),
      dlProgressText: document.getElementById("ss-dl-progress-text"),
      uploadFile: document.getElementById("ss-upload-file"),
      uploadFileMeta: document.getElementById("ss-upload-file-meta"),
      uploadHint: document.getElementById("ss-upload-hint"),
      btnUpload: document.getElementById("ss-btn-upload"),
      ulProgressWrap: document.getElementById("ss-ul-progress-wrap"),
      ulProgressBar: document.getElementById("ss-ul-progressbar"),
      ulProgressFill: document.getElementById("ss-ul-progress-fill"),
      ulProgressText: document.getElementById("ss-ul-progress-text"),
      dirtyBadge: document.getElementById("ss-dirty-badge"),
      gBinPath: document.getElementById("ss-g-bin-path"),
      gRustLog: document.getElementById("ss-g-rust-log"),
      gBufferSize: document.getElementById("ss-g-buffer-size"),
      gIdleTimeout: document.getElementById("ss-g-idle-timeout"),
      gGracefulShutdown: document.getElementById("ss-g-graceful-shutdown"),
      btnAddListener: document.getElementById("ss-btn-add-listener"),
      listenersSummary: document.getElementById("ss-listeners-summary"),
      validationSummary: document.getElementById("ss-validation-summary"),
      listenersContainer: document.getElementById("ss-listeners-container"),
      jsonPreview: document.getElementById("ss-json-preview"),
      btnCopyJson: document.getElementById("ss-btn-copy-json"),
      btnReset: document.getElementById("ss-btn-reset"),
      btnSave: document.getElementById("ss-btn-save"),
      btnSaveRestart: document.getElementById("ss-btn-save-restart"),
      logAutorefresh: document.getElementById("ss-log-autorefresh"),
      logAutoscroll: document.getElementById("ss-log-autoscroll"),
      logFilter: document.getElementById("ss-log-level-filter"),
      logBytesBadge: document.getElementById("ss-log-bytes-badge"),
      btnLogRefresh: document.getElementById("ss-btn-log-refresh"),
      btnLogCopy: document.getElementById("ss-btn-log-copy"),
      btnLogClear: document.getElementById("ss-btn-log-clear"),
      logError: document.getElementById("ss-log-error"),
      logConsole: document.getElementById("ss-log-console"),
    };

    function showBanner(kind, title, detail) {
      el.banner.className = "ss-alert";
      if (kind === "ok") el.banner.classList.add("ss-alert-ok");
      else if (kind === "warn") el.banner.classList.add("ss-alert-warn");
      else if (kind === "err") el.banner.classList.add("ss-alert-err");
      el.banner.textContent = "";
      if (title) {
        var strong = document.createElement("strong");
        strong.className = "ss-alert-title";
        strong.textContent = title;
        el.banner.appendChild(strong);
      }
      if (detail) {
        var span = document.createElement("span");
        span.textContent = detail;
        el.banner.appendChild(span);
      }
      el.banner.hidden = false;
    }

    function hideBanner() {
      el.banner.hidden = true;
      el.banner.textContent = "";
    }

    function setBusy(flag) {
      state.busy = flag;
      [
        el.btnStart,
        el.btnStop,
        el.btnRestart,
        el.btnRefresh,
        el.bootEnabled,
        el.btnCheckRelease,
        el.btnDownload,
        el.btnReset,
        el.btnSave,
        el.btnSaveRestart,
      ].forEach(function (ctrl) {
        if (ctrl) ctrl.disabled = flag;
      });
      if (el.btnUpload) {
        el.btnUpload.disabled = flag || !(el.uploadFile && el.uploadFile.files && el.uploadFile.files[0]);
      }
    }

    function parseApiEnvelope(res, body) {
      if (res && res.status === 403) {
        return {
          ok: false,
          error: "Session expired or invalid CSRF token. Reload the page and log in again.",
        };
      }
      if (!body || typeof body !== "object") {
        return { ok: false, error: "Invalid server JSON response (HTTP " + (res ? res.status : "?") + ")" };
      }
      if (body.code === 1) {
        return { ok: true, data: body.data };
      }
      var errData = body.data || {};
      return {
        ok: false,
        error: errData.error || errData.message || body.error || "Request failed",
        data: errData,
      };
    }

    function apiGet(url) {
      return fetch(url, { credentials: "same-origin" }).then(function (res) {
        return res
          .json()
          .catch(function () {
            return null;
          })
          .then(function (json) {
            return parseApiEnvelope(res, json);
          });
      });
    }

    function apiPostForm(url, paramsObj) {
      var body = new URLSearchParams();
      body.set("token", getToken());
      Object.keys(paramsObj || {}).forEach(function (k) {
        if (paramsObj[k] != null) body.set(k, String(paramsObj[k]));
      });
      return fetch(url, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" },
        body: body.toString(),
      }).then(function (res) {
        return res
          .json()
          .catch(function () {
            return null;
          })
          .then(function (json) {
            return parseApiEnvelope(res, json);
          });
      });
    }

    function updateDirtyBadge() {
      el.dirtyBadge.className = "ss-badge " + (state.dirty ? "ss-badge-warn" : "ss-badge-ok");
      el.dirtyBadge.textContent = state.dirty ? tr("unsaved", "Unsaved changes") : tr("synced", "Saved");
    }

    function renderGlobalFieldsFromDraft() {
      var g = state.draft.global;
      el.gBinPath.value = g.bin_path;
      el.gRustLog.value = g.rust_log;
      el.gBufferSize.value = g.buffer_size;
      el.gIdleTimeout.value = g.idle_timeout;
      el.gGracefulShutdown.value = g.graceful_shutdown_sec;
      if (el.releaseSelect && g.github_asset) {
        el.releaseSelect.value = g.github_asset;
      }
    }

    function renderStatusPanel() {
      var s = state.status;
      if (!s) return;
      var bin = s.binary || {};
      var cfg = s.config || {};
      var g = cfg.global || {};

      el.bootEnabled.checked = String(s.enabled || g.enabled || "0") === "1";
      el.bootEnabled.setAttribute("aria-checked", el.bootEnabled.checked ? "true" : "false");

      el.statusBadge.className = "ss-badge";
      if (!bin.exists) {
        el.statusBadge.classList.add("ss-badge-err");
        el.statusText.textContent = tr("missing", "Binary Missing");
      } else if (s.running) {
        el.statusBadge.classList.add("ss-badge-ok");
        el.statusText.textContent = tr("running", "Running");
      } else {
        el.statusBadge.classList.add("ss-badge-warn");
        el.statusText.textContent = tr("stopped", "Stopped");
      }

      el.headerPid.textContent = s.running && s.pid ? String(s.pid) : "-";
      el.headerUptime.textContent = s.running ? formatUptime(s.uptime_sec) : "-";

      el.kvBinPath.textContent = bin.path || g.bin_path || DEFAULT_BIN_PATH;
      el.kvHostArch.textContent = s.host_arch || bin.host_arch || "unknown";

      if (!bin.exists) {
        el.kvElf.textContent = "Binary file not installed at " + (bin.path || DEFAULT_BIN_PATH);
        el.archBadge.className = "ss-badge ss-badge-err ss-ltr";
        el.archBadge.textContent = tr("missing", "Binary Missing");
      } else if (bin.elf && bin.elf.valid) {
        var elfDesc = "ELF" + bin.elf.bits + " " + (bin.elf.endian || "") + " " + (bin.elf.arch || "unknown");
        el.kvElf.textContent = elfDesc + (bin.arch_match ? " (" + tr("compatible", "Compatible") + ")" : " (" + tr("crossArch", "Arch Mismatch") + ")");
        el.archBadge.className = "ss-badge ss-ltr " + (bin.arch_match ? "ss-badge-ok" : "ss-badge-warn");
        el.archBadge.textContent = (bin.elf.arch || "?") + (bin.arch_match ? " OK" : " != " + (s.host_arch || "?"));
      } else {
        el.kvElf.textContent = bin.error || "Invalid ELF executable";
        el.archBadge.className = "ss-badge ss-badge-err ss-ltr";
        el.archBadge.textContent = "Invalid ELF";
      }

      if (!bin.exists) {
        el.kvHelp.textContent = "-";
      } else if (!bin.arch_match) {
        el.kvHelp.textContent = tr("helpSkipped", "Skipped (cross-arch binary)");
      } else {
        el.kvHelp.textContent = bin.help_ok ? tr("helpPassed", "Passed") : tr("helpFailed", "Failed");
      }

      el.kvVersion.textContent = bin.version_tag || g.bin_version || "-";
      if (bin.exists && bin.sha256) {
        el.kvSha256.textContent = formatBytes(bin.size_bytes) + " | " + bin.sha256.slice(0, 16) + "...";
        el.kvSha256.title = bin.sha256;
      } else {
        el.kvSha256.textContent = bin.exists ? formatBytes(bin.size_bytes) : "-";
        el.kvSha256.title = "";
      }

      if (bin.exists && bin.elf && bin.elf.valid && !bin.arch_match) {
        el.binWarning.textContent =
          "Cross-arch binary installed (" +
          bin.elf.arch +
          " vs host " +
          (s.host_arch || "unknown") +
          "). Execution is blocked on this host; flashing to a matching router remains supported.";
        el.binWarning.hidden = false;
      } else if (bin.exists && !bin.executable) {
        el.binWarning.textContent = "Binary exists but is missing execute permissions (chmod 0755).";
        el.binWarning.hidden = false;
      } else {
        el.binWarning.hidden = true;
      }

      if (el.uploadHint) {
        el.uploadHint.textContent =
          "Target path: " +
          (state.draft.global.bin_path || DEFAULT_BIN_PATH) +
          " (24 KiB Base64 chunks, validated ELF, registered in /etc/sysupgrade.conf).";
      }
    }

    function renderReleaseOptions() {
      var currentVal = el.releaseSelect.value || state.draft.global.github_asset || FALLBACK_ASSETS[0].name;
      el.releaseSelect.textContent = "";
      var hostArch = (state.status && state.status.host_arch) || "";
      state.releaseAssets.forEach(function (asset) {
        var opt = document.createElement("option");
        opt.value = asset.name;
        var parts = [asset.name];
        if (asset.size) parts.push("(" + formatBytes(asset.size) + ")");
        if (asset.recommended) parts.push("[" + tr("recommended", "recommended") + "]");
        if (hostArch && asset.name.indexOf(hostArch) !== -1) parts.push("[host match]");
        opt.textContent = parts.join(" ");
        el.releaseSelect.appendChild(opt);
      });
      if (
        Array.prototype.some.call(el.releaseSelect.options, function (o) {
          return o.value === currentVal;
        })
      ) {
        el.releaseSelect.value = currentVal;
      }
    }

    function updateValidationAndPreview() {
      state.validation = validateConfigForm(state.draft);
      var errs = state.validation.errors;

      ["bin_path", "rust_log", "buffer_size", "idle_timeout", "graceful_shutdown_sec"].forEach(
        function (field) {
          var errEl = document.getElementById("ss-err-global-" + field);
          var msg = errs["global." + field];
          if (errEl) {
            errEl.textContent = msg || "";
            errEl.hidden = !msg;
          }
        },
      );
      el.gBinPath.classList.toggle("ss-input-error", Boolean(errs["global.bin_path"]));
      el.gRustLog.classList.toggle("ss-input-error", Boolean(errs["global.rust_log"]));
      el.gBufferSize.classList.toggle("ss-input-error", Boolean(errs["global.buffer_size"]));
      el.gIdleTimeout.classList.toggle("ss-input-error", Boolean(errs["global.idle_timeout"]));
      el.gGracefulShutdown.classList.toggle("ss-input-error", Boolean(errs["global.graceful_shutdown_sec"]));

      var enabledCount = 0;
      state.draft.listeners.forEach(function (l, idx) {
        var isOn = isEnabledFlag(l.enabled);
        if (isOn) enabledCount += 1;

        var card = el.listenersContainer.querySelector('[data-listener-idx="' + idx + '"]');
        if (!card) return;
        card.classList.toggle("ss-listener-disabled", !isOn);

        var enCheck = card.querySelector("#ss-l-" + idx + "-enabled");
        if (enCheck) {
          enCheck.checked = isOn;
          enCheck.setAttribute("aria-checked", isOn ? "true" : "false");
        }
        var enState = card.querySelector("[data-enabled-badge]");
        if (enState) {
          enState.textContent = isOn ? tr("enabled", "Enabled") : tr("disabled", "Disabled");
          enState.className = "ss-badge " + (isOn ? "ss-badge-ok" : "ss-badge-muted");
        }
        var titleEl = card.querySelector(".ss-listener-id");
        if (titleEl) {
          titleEl.textContent = "Listener #" + (idx + 1) + (l.remarks ? " - " + l.remarks : "");
        }
        var routeEl = card.querySelector(".ss-listener-route");
        if (routeEl) {
          var routeText = (String(l.listen || "").trim() || "?") + " -> " + (String(l.connect || "").trim() || "?");
          var sniText = String(l.fake_sni || "").trim();
          routeEl.textContent = sniText ? routeText + " (" + sniText + ")" : routeText;
        }

        ["remarks", "listen", "connect", "fake_sni", "conn_timeout_sec", "handshake_timeout_sec", "keepalive_time_sec", "keepalive_interval_sec"].forEach(
          function (field) {
            var errMsg = errs["listeners[" + idx + "]." + field];
            var inputEl = card.querySelector('[data-field="' + field + '"]');
            var errNode = card.querySelector('[data-error-for="' + field + '"]');
            if (inputEl) inputEl.classList.toggle("ss-input-error", Boolean(errMsg));
            if (errNode) {
              errNode.textContent = errMsg || "";
              errNode.hidden = !errMsg;
            }
          },
        );

        var counterEl = card.querySelector("[data-byte-counter]");
        if (counterEl) {
          var byteLen = utf8ByteLength(String(l.fake_sni || "").trim());
          counterEl.textContent = byteLen + " / " + FAKE_SNI_MAX_BYTES + " B";
          counterEl.className = "ss-byte-counter ss-ltr";
          if (byteLen > FAKE_SNI_MAX_BYTES) counterEl.classList.add("ss-byte-counter-err");
          else if (byteLen >= 180) counterEl.classList.add("ss-byte-counter-warn");
        }
      });

      if (el.listenersSummary) {
        var totalCount = state.draft.listeners.length;
        el.listenersSummary.textContent = enabledCount + " / " + totalCount + " " + tr("enabledSummary", "enabled");
        el.listenersSummary.className = "ss-badge ss-ltr " + (totalCount === 0 ? "ss-badge-muted" : enabledCount > 0 ? "ss-badge-ok" : "ss-badge-warn");
      }

      var keys = Object.keys(errs);
      if (keys.length === 0) {
        el.validationSummary.hidden = true;
        el.validationSummary.textContent = "";
      } else {
        el.validationSummary.textContent = "";
        var title = document.createElement("strong");
        title.className = "ss-alert-title";
        title.textContent = "Configuration validation issues (" + keys.length + "):";
        el.validationSummary.appendChild(title);
        var ul = document.createElement("ul");
        ul.className = "ss-alert-list";
        keys.forEach(function (k) {
          var li = document.createElement("li");
          li.textContent = k + ": " + errs[k];
          ul.appendChild(li);
        });
        el.validationSummary.appendChild(ul);
        el.validationSummary.hidden = false;
      }

      el.jsonPreview.textContent = JSON.stringify(buildJsonPreview(state.draft), null, 2);
      updateDirtyBadge();
    }

    function createListenerField(idx, field, labelText, opts) {
      var fieldId = "ss-l-" + idx + "-" + field;
      var wrap = document.createElement("div");
      wrap.className = "ss-field" + (opts.full ? " ss-field-full" : "");

      var labelRow = document.createElement("div");
      labelRow.className = "ss-field-label-row";
      var label = document.createElement("label");
      label.className = "ss-label";
      label.htmlFor = fieldId;
      label.textContent = labelText;
      labelRow.appendChild(label);

      if (opts.byteCounter) {
        var counter = document.createElement("span");
        counter.className = "ss-byte-counter ss-ltr";
        counter.setAttribute("data-byte-counter", "1");
        labelRow.appendChild(counter);
      }
      wrap.appendChild(labelRow);

      var input = document.createElement("input");
      input.id = fieldId;
      input.type = opts.type || "text";
      if (opts.min != null) input.min = String(opts.min);
      if (opts.max != null) input.max = String(opts.max);
      if (opts.ltr) {
        input.dir = "ltr";
        input.className = "ss-input ss-mono ss-ltr";
      } else {
        input.className = "ss-input";
      }
      input.placeholder = opts.placeholder || "";
      input.value = String(opts.value == null ? "" : opts.value);
      input.setAttribute("data-field", field);
      input.addEventListener("input", function () {
        state.draft.listeners[idx][field] = input.value;
        state.dirty = true;
        updateValidationAndPreview();
      });
      wrap.appendChild(input);

      var errEl = document.createElement("span");
      errEl.className = "ss-field-error";
      errEl.setAttribute("data-error-for", field);
      errEl.hidden = true;
      wrap.appendChild(errEl);

      return wrap;
    }

    function renderListeners() {
      el.listenersContainer.textContent = "";
      if (state.draft.listeners.length === 0) {
        var emptyBox = document.createElement("div");
        emptyBox.className = "ss-empty-state";
        var msg = document.createElement("p");
        msg.style.margin = "0";
        msg.textContent = tr(
          "emptyListeners",
          "No listeners configured yet. Add a listener defining Listen IP:Port, Connect IP:Port, and Fake SNI.",
        );
        var addBtn = document.createElement("button");
        addBtn.type = "button";
        addBtn.className = "ss-btn ss-btn-primary";
        addBtn.textContent = tr("addFirstListener", "Add First Listener");
        addBtn.addEventListener("click", addEmptyListener);
        emptyBox.appendChild(msg);
        emptyBox.appendChild(addBtn);
        el.listenersContainer.appendChild(emptyBox);
        updateValidationAndPreview();
        return;
      }

      state.draft.listeners.forEach(function (item, idx) {
        var isOn = isEnabledFlag(item.enabled);
        var card = document.createElement("article");
        card.className = "ss-listener-card" + (isOn ? "" : " ss-listener-disabled");
        card.setAttribute("data-listener-idx", String(idx));

        var head = document.createElement("div");
        head.className = "ss-listener-head";

        var leftGroup = document.createElement("div");
        leftGroup.className = "ss-row-inline ss-listener-head-left";

        var enId = "ss-l-" + idx + "-enabled";
        var enLabel = document.createElement("label");
        enLabel.className = "ss-switch ss-switch-bare";
        enLabel.htmlFor = enId;
        var enCheck = document.createElement("input");
        enCheck.id = enId;
        enCheck.type = "checkbox";
        enCheck.className = "ss-switch-input";
        enCheck.setAttribute("role", "switch");
        enCheck.checked = isOn;
        enCheck.setAttribute("aria-checked", isOn ? "true" : "false");
        enCheck.setAttribute("aria-label", tr("enabled", "Enabled") + " Listener #" + (idx + 1));
        enCheck.addEventListener("change", function () {
          state.draft.listeners[idx].enabled = enCheck.checked ? "1" : "0";
          state.dirty = true;
          updateValidationAndPreview();
        });
        var enTrack = document.createElement("span");
        enTrack.className = "ss-switch-track";
        enTrack.setAttribute("aria-hidden", "true");
        var enThumb = document.createElement("span");
        enThumb.className = "ss-switch-thumb";
        enTrack.appendChild(enThumb);
        var enState = document.createElement("span");
        enState.setAttribute("data-enabled-badge", "1");
        enState.className = "ss-badge " + (isOn ? "ss-badge-ok" : "ss-badge-muted");
        enState.textContent = isOn ? tr("enabled", "Enabled") : tr("disabled", "Disabled");
        enLabel.appendChild(enCheck);
        enLabel.appendChild(enTrack);
        enLabel.appendChild(enState);
        leftGroup.appendChild(enLabel);

        var title = document.createElement("span");
        title.className = "ss-listener-id";
        title.textContent = "Listener #" + (idx + 1) + (item.remarks ? " - " + item.remarks : "");
        leftGroup.appendChild(title);

        var route = document.createElement("span");
        route.className = "ss-listener-route ss-mono ss-ltr";
        var routeText = (String(item.listen || "").trim() || "?") + " -> " + (String(item.connect || "").trim() || "?");
        var sniText = String(item.fake_sni || "").trim();
        route.textContent = sniText ? routeText + " (" + sniText + ")" : routeText;
        leftGroup.appendChild(route);

        head.appendChild(leftGroup);

        var rightActions = document.createElement("div");
        rightActions.className = "ss-row-inline ss-listener-head-actions";
        var dupBtn = document.createElement("button");
        dupBtn.type = "button";
        dupBtn.className = "ss-btn ss-btn-sm";
        dupBtn.textContent = tr("duplicate", "Duplicate");
        dupBtn.addEventListener("click", function () {
          var copy = cloneConfig({ listeners: [state.draft.listeners[idx]] }).listeners[0];
          copy.id = "";
          copy.remarks = (copy.remarks ? copy.remarks + " Copy" : "Listener Copy").slice(0, 128);
          state.draft.listeners.splice(idx + 1, 0, copy);
          state.dirty = true;
          renderListeners();
        });

        var rmBtn = document.createElement("button");
        rmBtn.type = "button";
        rmBtn.className = "ss-btn ss-btn-outline-danger ss-btn-sm";
        rmBtn.textContent = tr("remove", "Remove");
        rmBtn.addEventListener("click", function () {
          state.draft.listeners.splice(idx, 1);
          state.dirty = true;
          renderListeners();
        });

        rightActions.appendChild(dupBtn);
        rightActions.appendChild(rmBtn);
        head.appendChild(rightActions);
        card.appendChild(head);

        var body = document.createElement("div");
        body.className = "ss-listener-body";

        var grid = document.createElement("div");
        grid.className = "ss-form-grid";
        grid.appendChild(
          createListenerField(idx, "remarks", tr("remarks", "Remarks"), {
            placeholder: "Optional label",
            value: item.remarks,
          }),
        );
        grid.appendChild(
          createListenerField(idx, "listen", tr("listen", "Listen IP:Port"), {
            ltr: true,
            placeholder: "127.0.0.1:40443",
            value: item.listen,
          }),
        );
        grid.appendChild(
          createListenerField(idx, "connect", tr("connect", "Connect IP:Port"), {
            ltr: true,
            placeholder: "198.51.100.10:443",
            value: item.connect,
          }),
        );
        grid.appendChild(
          createListenerField(idx, "fake_sni", tr("fakeSni", "Fake SNI Hostname"), {
            ltr: true,
            byteCounter: true,
            placeholder: "cdn.example.com",
            value: item.fake_sni,
          }),
        );
        body.appendChild(grid);

        var details = document.createElement("details");
        var summary = document.createElement("summary");
        summary.className = "ss-hint";
        summary.style.fontWeight = "600";
        summary.textContent = tr("advancedTimeouts", "Advanced Timeouts");
        details.appendChild(summary);

        var advGrid = document.createElement("div");
        advGrid.className = "ss-form-grid";
        advGrid.style.marginTop = "10px";
        advGrid.appendChild(
          createListenerField(idx, "conn_timeout_sec", tr("connTimeout", "Connect Timeout (sec)"), {
            ltr: true,
            type: "number",
            min: 1,
            max: 86400,
            value: item.conn_timeout_sec,
          }),
        );
        advGrid.appendChild(
          createListenerField(
            idx,
            "handshake_timeout_sec",
            tr("handshakeTimeout", "Handshake Timeout (sec)"),
            {
              ltr: true,
              type: "number",
              min: 1,
              max: 86400,
              value: item.handshake_timeout_sec,
            },
          ),
        );
        advGrid.appendChild(
          createListenerField(idx, "keepalive_time_sec", tr("keepaliveTime", "Keepalive Time (sec)"), {
            ltr: true,
            type: "number",
            min: 1,
            max: 86400,
            value: item.keepalive_time_sec,
          }),
        );
        advGrid.appendChild(
          createListenerField(
            idx,
            "keepalive_interval_sec",
            tr("keepaliveInterval", "Keepalive Interval (sec)"),
            {
              ltr: true,
              type: "number",
              min: 1,
              max: 86400,
              value: item.keepalive_interval_sec,
            },
          ),
        );
        details.appendChild(advGrid);
        body.appendChild(details);
        card.appendChild(body);

        el.listenersContainer.appendChild(card);
      });

      updateValidationAndPreview();
    }

    function addEmptyListener() {
      var nextPort = 40443 + state.draft.listeners.length;
      state.draft.listeners.push({
        id: "",
        enabled: "1",
        remarks: "Listener " + (state.draft.listeners.length + 1),
        listen: "127.0.0.1:" + nextPort,
        connect: "198.51.100.10:443",
        fake_sni: "example.com",
        conn_timeout_sec: "5",
        handshake_timeout_sec: "2",
        keepalive_time_sec: "11",
        keepalive_interval_sec: "2",
      });
      state.dirty = true;
      renderListeners();
    }

    function applyServerStatus(data, overwriteDraft) {
      if (!data || typeof data !== "object") return;
      state.status = data;
      if (overwriteDraft || !state.dirty) {
        state.draft = cloneConfig(data.config);
        state.dirty = false;
        renderGlobalFieldsFromDraft();
        renderListeners();
      }
      renderReleaseOptions();
      renderStatusPanel();
      updateValidationAndPreview();
    }

    function refreshStatus(overwriteDraft) {
      if (!boot.urls.status) return Promise.resolve();
      return apiGet(boot.urls.status)
        .then(function (res) {
          if (!res.ok) {
            showBanner("err", "Failed to load service status", res.error);
            return;
          }
          applyServerStatus(res.data, overwriteDraft);
        })
        .catch(function (err) {
          showBanner("err", "Network error loading status", String(err && err.message ? err.message : err));
        });
    }

    function runServiceAction(action, extra) {
      setBusy(true);
      hideBanner();
      var params = Object.assign({ action: action }, extra || {});
      return apiPostForm(boot.urls.control, params)
        .then(function (res) {
          if (res.data && res.data.status) {
            applyServerStatus(res.data.status, false);
          } else if (res.ok) {
            applyServerStatus(res.data, action === "set_boot" ? false : false);
          }
          if (!res.ok) {
            if (action === "set_boot" && state.status) {
              el.bootEnabled.checked = String(state.status.enabled || "0") === "1";
              el.bootEnabled.setAttribute("aria-checked", el.bootEnabled.checked ? "true" : "false");
            }
            showBanner("err", "Service action '" + action + "' failed", res.error);
            return;
          }
          showBanner("ok", "Service action completed", "Action '" + action + "' applied.");
        })
        .catch(function (err) {
          showBanner("err", "Service request failed", String(err && err.message ? err.message : err));
        })
        .finally(function () {
          setBusy(false);
        });
    }

    function saveConfiguration(doRestart) {
      var check = validateConfigForm(state.draft);
      updateValidationAndPreview();
      if (!check.valid) {
        showBanner("err", "Cannot save invalid configuration", "Fix highlighted fields below before saving.");
        var firstErrInput = rootEl.querySelector(".ss-input-error, .ss-select.ss-input-error");
        if (firstErrInput && typeof firstErrInput.focus === "function") {
          firstErrInput.focus();
        }
        return;
      }

      setBusy(true);
      hideBanner();
      var payload = {
        global: state.draft.global,
        listeners: state.draft.listeners,
        restart: Boolean(doRestart),
      };
      apiPostForm(boot.urls.save, { payload: JSON.stringify(payload) })
        .then(function (res) {
          if (!res.ok) {
            if (res.data && res.data.status) {
              applyServerStatus(res.data.status, true);
            }
            var detail = res.error;
            if (res.data && res.data.errors) {
              detail += " (" + Object.values(res.data.errors).join("; ") + ")";
            }
            showBanner("err", doRestart ? "Save & Restart failed" : "Save failed", detail);
            return;
          }
          applyServerStatus(res.data, true);
          showBanner(
            "ok",
            doRestart ? "Configuration saved and service restarted" : "Configuration saved",
            "Runtime config.json and UCI settings updated.",
          );
        })
        .catch(function (err) {
          showBanner("err", "Network error saving configuration", String(err && err.message ? err.message : err));
        })
        .finally(function () {
          setBusy(false);
        });
    }

    function checkRelease() {
      setBusy(true);
      el.releaseMeta.textContent = "Checking releases...";
      apiGet(boot.urls.release_info)
        .then(function (res) {
          var d = res.data || {};
          if (Array.isArray(d.assets) && d.assets.length > 0) {
            state.releaseAssets = d.assets;
            renderReleaseOptions();
          }
          if (!res.ok) {
            el.releaseMeta.textContent = "Using fallback asset list";
            showBanner("warn", "Could not reach GitHub Releases API", res.error || "Check WAN connectivity or upload binary locally.");
            return;
          }
          state.releaseTag = d.tag_name || "";
          el.releaseMeta.textContent =
            (d.tag_name || "latest") +
            (d.published_at ? " (" + String(d.published_at).slice(0, 10) + ")" : "");
          if (d.html_url) el.releaseLink.href = d.html_url;
          showBanner("ok", "Latest release fetched", "Tag: " + (d.tag_name || "unknown"));
        })
        .catch(function (err) {
          el.releaseMeta.textContent = "Release check failed";
          showBanner("err", "Failed to query releases", String(err && err.message ? err.message : err));
        })
        .finally(function () {
          setBusy(false);
        });
    }

    function updateProgressUI(wrap, bar, fill, textEl, pct, message) {
      var clamped = Math.max(0, Math.min(100, Number(pct) || 0));
      wrap.hidden = false;
      bar.setAttribute("aria-valuenow", String(clamped));
      fill.style.width = clamped + "%";
      textEl.textContent = message;
    }

    function downloadSelectedAsset() {
      var assetName = el.releaseSelect.value || state.draft.global.github_asset || FALLBACK_ASSETS[0].name;
      var meta = state.releaseAssets.find(function (a) {
        return a.name === assetName;
      }) || {};

      setBusy(true);
      hideBanner();
      updateProgressUI(
        el.dlProgressWrap,
        el.dlProgressBar,
        el.dlProgressFill,
        el.dlProgressText,
        0,
        "Starting download of " + assetName + "...",
      );

      apiPostForm(boot.urls.download, {
        task: "start",
        asset: assetName,
        download_url: meta.browser_download_url || "",
        bin_path: state.draft.global.bin_path || DEFAULT_BIN_PATH,
        expected_digest: meta.digest || "",
        version_tag: state.releaseTag || "",
        total_bytes: meta.size || 0,
      })
        .then(function (res) {
          if (!res.ok) {
            setBusy(false);
            updateProgressUI(el.dlProgressWrap, el.dlProgressBar, el.dlProgressFill, el.dlProgressText, 0, "Download failed: " + res.error);
            showBanner("err", "Download could not start", res.error);
            return;
          }
          var taskId = res.data.task_id;
          pollDownloadTask(taskId, assetName, 0);
        })
        .catch(function (err) {
          setBusy(false);
          showBanner("err", "Download request error", String(err && err.message ? err.message : err));
        });
    }

    function pollDownloadTask(taskId, assetName, consecutiveFailures) {
      setTimeout(function () {
        apiPostForm(boot.urls.download, { task: "progress", task_id: taskId })
          .then(function (res) {
            if (!res.ok) {
              setBusy(false);
              var errText = res.error || "Verification or download failed";
              updateProgressUI(el.dlProgressWrap, el.dlProgressBar, el.dlProgressFill, el.dlProgressText, 0, "Failed: " + errText);
              showBanner("err", "Download failed", errText);
              return;
            }
            var d = res.data || {};
            if (d.status === "done") {
              setBusy(false);
              updateProgressUI(
                el.dlProgressWrap,
                el.dlProgressBar,
                el.dlProgressFill,
                el.dlProgressText,
                100,
                "Installed " + assetName + " (" + formatBytes(d.total_bytes || d.downloaded_bytes) + ")",
              );
              showBanner("ok", "Binary installed from GitHub Release", assetName + " verified and saved.");
              refreshStatus(false);
              return;
            }
            var pct = d.percent || 0;
            var msg =
              "Downloading " +
              assetName +
              ": " +
              pct +
              "% (" +
              formatBytes(d.downloaded_bytes) +
              (d.total_bytes ? " / " + formatBytes(d.total_bytes) : "") +
              ")";
            updateProgressUI(el.dlProgressWrap, el.dlProgressBar, el.dlProgressFill, el.dlProgressText, pct, msg);
            pollDownloadTask(taskId, assetName, 0);
          })
          .catch(function (err) {
            if (consecutiveFailures >= 3) {
              setBusy(false);
              showBanner("err", "Lost connection while polling download", String(err && err.message ? err.message : err));
              return;
            }
            pollDownloadTask(taskId, assetName, consecutiveFailures + 1);
          });
      }, 600);
    }

    function uploadSelectedFile() {
      var file = el.uploadFile && el.uploadFile.files && el.uploadFile.files[0];
      if (!file) {
        showBanner("err", "No file selected", "Choose a compiled sni-spoof-rs ELF binary first.");
        return;
      }
      if (file.size === 0) {
        showBanner("err", "Empty file selected", "Select a non-empty compiled executable binary.");
        return;
      }

      setBusy(true);
      hideBanner();
      updateProgressUI(
        el.ulProgressWrap,
        el.ulProgressBar,
        el.ulProgressFill,
        el.ulProgressText,
        0,
        "Preparing " + file.name + " (" + formatBytes(file.size) + ")...",
      );

      file
        .arrayBuffer()
        .then(function (buf) {
          var chunks = splitIntoChunks(new Uint8Array(buf), DEFAULT_CHUNK_BYTES);
          var uploadId = "ul_" + Date.now() + "_" + Math.random().toString(16).slice(2, 8);
          var binPath = state.draft.global.bin_path || DEFAULT_BIN_PATH;

          function sendNext(idx) {
            if (idx >= chunks.length) return Promise.resolve();
            var c = chunks[idx];
            return apiPostForm(boot.urls.upload, {
              upload_id: uploadId,
              chunk_index: c.chunkIndex,
              total_chunks: c.totalChunks,
              chunk: c.chunkBase64,
              bin_path: binPath,
              filename: file.name,
            }).then(function (res) {
              if (!res.ok) {
                throw new Error(res.error || "Upload chunk " + (idx + 1) + " failed");
              }
              var pct = Math.round(((idx + 1) / c.totalChunks) * 100);
              updateProgressUI(
                el.ulProgressWrap,
                el.ulProgressBar,
                el.ulProgressFill,
                el.ulProgressText,
                pct,
                "Uploaded chunk " + (idx + 1) + " / " + c.totalChunks + " (" + pct + "%)",
              );
              if (idx + 1 < chunks.length) {
                return sendNext(idx + 1);
              }
              return res.data;
            });
          }

          return sendNext(0);
        })
        .then(function () {
          showBanner("ok", "Binary uploaded and verified", file.name + " installed to " + (state.draft.global.bin_path || DEFAULT_BIN_PATH));
          return refreshStatus(false);
        })
        .catch(function (err) {
          var msg = String(err && err.message ? err.message : err);
          updateProgressUI(el.ulProgressWrap, el.ulProgressBar, el.ulProgressFill, el.ulProgressText, 0, "Upload failed: " + msg);
          showBanner("err", "Local binary upload failed", msg);
        })
        .finally(function () {
          setBusy(false);
        });
    }

    function renderLogConsole() {
      var filter = (el.logFilter && el.logFilter.value) || "all";
      el.logBytesBadge.textContent = formatBytes(state.logTotalBytes) + (state.logTruncated ? " (tail)" : "");
      el.logConsole.textContent = "";

      if (state.logLines.length === 0) {
        var emptySpan = document.createElement("span");
        emptySpan.className = "ss-console-muted";
        emptySpan.textContent = tr("emptyLogs", "No log entries yet. Start the service or handle connections to inspect output.");
        el.logConsole.appendChild(emptySpan);
        return;
      }

      var renderedCount = 0;
      state.logLines.forEach(function (rawLine) {
        var parsed = parseLogLine(rawLine);
        if (filter !== "all" && parsed.level !== filter) return;
        var span = document.createElement("span");
        span.className = "ss-console-line" + (parsed.cssClass ? " " + parsed.cssClass : "");
        span.textContent = parsed.text;
        el.logConsole.appendChild(span);
        renderedCount++;
      });

      if (renderedCount === 0) {
        var noneSpan = document.createElement("span");
        noneSpan.className = "ss-console-muted";
        noneSpan.textContent = "No lines matching filter '" + filter.toUpperCase() + "'.";
        el.logConsole.appendChild(noneSpan);
      }

      if (el.logAutoscroll && el.logAutoscroll.checked) {
        el.logConsole.scrollTop = el.logConsole.scrollHeight;
      }
    }

    function applyLogPayload(payload) {
      el.logError.hidden = true;
      var d = payload || {};
      state.logLines = Array.isArray(d.lines) ? d.lines : [];
      state.logTotalBytes = Number(d.total_bytes || 0);
      state.logTruncated = Boolean(d.truncated);
      renderLogConsole();
    }

    function fetchLogsNow() {
      if (!boot.urls.log) return;
      apiGet(boot.urls.log + "?limit=300")
        .then(function (res) {
          if (!res.ok) {
            el.logError.textContent = "Failed to load logs: " + res.error + ". Click Refresh to retry.";
            el.logError.hidden = false;
            return;
          }
          applyLogPayload(res.data);
        })
        .catch(function (err) {
          el.logError.textContent = "Failed to load logs: " + String(err && err.message ? err.message : err) + ". Click Refresh to retry.";
          el.logError.hidden = false;
        });
    }

    function stopLogPoll() {
      if (state.logPollHandle && typeof window !== "undefined" && window.XHR && typeof window.XHR.stop === "function") {
        try {
          window.XHR.stop(state.logPollHandle);
        } catch (_) {}
      }
      state.logPollHandle = null;
      if (state.logFallbackTimer) {
        clearInterval(state.logFallbackTimer);
        state.logFallbackTimer = null;
      }
    }

    function startLogPoll() {
      stopLogPoll();
      if (!boot.urls.log) return;
      if (typeof window !== "undefined" && window.XHR && typeof window.XHR.poll === "function") {
        state.logPollHandle = window.XHR.poll(2.5, boot.urls.log, { limit: 300 }, function (res, json) {
          if (!json && res && typeof res.responseText === "string") {
            try {
              json = JSON.parse(res.responseText);
            } catch (_) {}
          }
          var parsed = parseApiEnvelope(res, json);
          if (!parsed.ok) {
            el.logError.textContent = "Log poll error: " + parsed.error;
            el.logError.hidden = false;
            return;
          }
          applyLogPayload(parsed.data);
        });
        if (typeof window.XHR.run === "function") {
          window.XHR.run();
        }
      } else {
        state.logFallbackTimer = setInterval(fetchLogsNow, 2500);
      }
    }

    function copyTextToClipboard(text, btn, originalLabel) {
      function done() {
        var prev = originalLabel || btn.textContent;
        btn.textContent = tr("copied", "Copied");
        setTimeout(function () {
          btn.textContent = prev;
        }, 1200);
      }
      if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () {});
        return;
      }
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        done();
      } catch (_) {}
    }

    function activateTab(which) {
      var isRelease = which === "release";
      el.tabBtnRelease.setAttribute("aria-selected", isRelease ? "true" : "false");
      el.tabBtnRelease.tabIndex = isRelease ? 0 : -1;
      el.tabPanelRelease.hidden = !isRelease;

      el.tabBtnUpload.setAttribute("aria-selected", isRelease ? "false" : "true");
      el.tabBtnUpload.tabIndex = isRelease ? -1 : 0;
      el.tabPanelUpload.hidden = isRelease;
    }

    // Event wiring
    el.tabBtnRelease.addEventListener("click", function () {
      activateTab("release");
    });
    el.tabBtnUpload.addEventListener("click", function () {
      activateTab("upload");
    });
    [el.tabBtnRelease, el.tabBtnUpload].forEach(function (tabBtn) {
      tabBtn.addEventListener("keydown", function (ev) {
        if (ev.key === "ArrowLeft" || ev.key === "ArrowRight") {
          ev.preventDefault();
          var target = tabBtn === el.tabBtnRelease ? "upload" : "release";
          activateTab(target);
          (target === "release" ? el.tabBtnRelease : el.tabBtnUpload).focus();
        } else if (ev.key === "Home") {
          ev.preventDefault();
          activateTab("release");
          el.tabBtnRelease.focus();
        } else if (ev.key === "End") {
          ev.preventDefault();
          activateTab("upload");
          el.tabBtnUpload.focus();
        }
      });
    });

    el.btnStart.addEventListener("click", function () {
      runServiceAction("start");
    });
    el.btnStop.addEventListener("click", function () {
      runServiceAction("stop");
    });
    el.btnRestart.addEventListener("click", function () {
      runServiceAction("restart");
    });
    el.btnRefresh.addEventListener("click", function () {
      refreshStatus(false);
    });
    el.bootEnabled.addEventListener("change", function () {
      el.bootEnabled.setAttribute("aria-checked", el.bootEnabled.checked ? "true" : "false");
      runServiceAction("set_boot", { enabled: el.bootEnabled.checked ? "1" : "0" });
    });

    el.btnCheckRelease.addEventListener("click", checkRelease);
    el.btnDownload.addEventListener("click", downloadSelectedAsset);
    el.releaseSelect.addEventListener("change", function () {
      state.draft.global.github_asset = el.releaseSelect.value;
      state.dirty = true;
      updateDirtyBadge();
    });

    el.uploadFile.addEventListener("change", function () {
      var f = el.uploadFile.files && el.uploadFile.files[0];
      el.btnUpload.disabled = state.busy || !f;
      el.uploadFileMeta.textContent = f ? f.name + " (" + formatBytes(f.size) + ")" : "";
    });
    el.btnUpload.addEventListener("click", uploadSelectedFile);

    [
      [el.gBinPath, "bin_path"],
      [el.gRustLog, "rust_log"],
      [el.gBufferSize, "buffer_size"],
      [el.gIdleTimeout, "idle_timeout"],
      [el.gGracefulShutdown, "graceful_shutdown_sec"],
    ].forEach(function (pair) {
      var node = pair[0];
      var key = pair[1];
      node.addEventListener("input", function () {
        state.draft.global[key] = node.value;
        state.dirty = true;
        if (key === "bin_path") renderStatusPanel();
        updateValidationAndPreview();
      });
    });

    el.btnAddListener.addEventListener("click", addEmptyListener);
    el.btnReset.addEventListener("click", function () {
      if (state.status) {
        applyServerStatus(state.status, true);
        hideBanner();
      } else {
        refreshStatus(true);
      }
    });
    el.btnSave.addEventListener("click", function () {
      saveConfiguration(false);
    });
    el.btnSaveRestart.addEventListener("click", function () {
      saveConfiguration(true);
    });
    el.btnCopyJson.addEventListener("click", function () {
      copyTextToClipboard(el.jsonPreview.textContent || "{}", el.btnCopyJson, tr("copyJson", "Copy JSON"));
    });

    el.logFilter.addEventListener("change", renderLogConsole);
    el.btnLogRefresh.addEventListener("click", fetchLogsNow);
    el.btnLogCopy.addEventListener("click", function () {
      copyTextToClipboard(state.logLines.join("\n"), el.btnLogCopy, tr("copyLog", "Copy Log"));
    });
    el.btnLogClear.addEventListener("click", function () {
      apiPostForm(boot.urls.log, { action: "clear" })
        .then(function (res) {
          if (!res.ok) {
            el.logError.textContent = "Failed to clear logs: " + res.error;
            el.logError.hidden = false;
            return;
          }
          state.logLines = [];
          state.logTotalBytes = 0;
          state.logTruncated = false;
          renderLogConsole();
        })
        .catch(function (err) {
          el.logError.textContent = "Clear log request failed: " + String(err && err.message ? err.message : err);
          el.logError.hidden = false;
        });
    });
    el.logAutorefresh.addEventListener("change", function () {
      if (el.logAutorefresh.checked) startLogPoll();
      else stopLogPoll();
    });

    // Initial boot load
    refreshStatus(true);
    fetchLogsNow();
    if (el.logAutorefresh.checked) startLogPoll();

    return state;
  }

  return {
    FAKE_SNI_MAX_BYTES: FAKE_SNI_MAX_BYTES,
    DEFAULT_CHUNK_BYTES: DEFAULT_CHUNK_BYTES,
    utf8ByteLength: utf8ByteLength,
    parseSocketAddr: parseSocketAddr,
    connectsToListener: connectsToListener,
    hasListenerConflict: hasListenerConflict,
    findListenerConflicts: findListenerConflicts,
    validateConfigForm: validateConfigForm,
    buildJsonPreview: buildJsonPreview,
    splitIntoChunks: splitIntoChunks,
    parseLogLine: parseLogLine,
    formatBytes: formatBytes,
    formatUptime: formatUptime,
    mount: mount,
  };
});
