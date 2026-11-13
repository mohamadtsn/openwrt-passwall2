#!/usr/bin/env bash
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CSS_FILE="$ROOT_DIR/luci-app-passwall2/htdocs/luci-static/resources/view/passwall2/sni_spoofer.css"
CONTRAST_SCRIPT="${CONTRAST_SCRIPT:-/home/mohamadtsn/.gemini/config/skills/antislop-human/contrast-check.py}"

if [ ! -f "$CSS_FILE" ]; then
	echo "FAIL: missing stylesheet at $CSS_FILE" >&2
	exit 1
fi

python3 - "$CSS_FILE" "$CONTRAST_SCRIPT" <<'PY'
import pathlib
import re
import subprocess
import sys

css_path = pathlib.Path(sys.argv[1])
contrast_py = pathlib.Path(sys.argv[2])
css = css_path.read_text(encoding="utf-8")

if "\u2014" in css:
    sys.exit("FAIL: em dash (U+2014) found in CSS")

required_markers = [
    ".sni-spoofer-page",
    ':root[data-darkmode="true"]',
    '[data-theme="dark"]',
    "prefers-color-scheme: dark",
    ":focus-visible",
    ".ss-ltr",
    "direction: ltr",
    "prefers-reduced-motion: reduce",
    "min-height: 44px",
]
for marker in required_markers:
    if marker not in css:
        sys.exit(f"FAIL: missing required selector/rule marker: {marker!r}")

def parse_vars(block: str) -> dict[str, str]:
    return dict(re.findall(r"(--ss-[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;", block))

# Light tokens live in the first .sni-spoofer-page custom-property block.
light_match = re.search(r"\.sni-spoofer-page\s*\{([^}]+)\}", css)
if not light_match:
    sys.exit("FAIL: could not locate light .sni-spoofer-page variable block")
light_vars = parse_vars(light_match.group(1))

# Dark tokens live inside the dark mode custom-property blocks.
dark_attr_match = re.search(
    r':root\[data-darkmode="true"\]\s+\.sni-spoofer-page[^{]*\{([^}]+)\}', css
)
dark_media_match = re.search(
    r"@media\s*\(\s*prefers-color-scheme:\s*dark\s*\)\s*\{\s*[^{]*\.sni-spoofer-page[^{]*\{([^}]+)\}",
    css,
)
if not dark_attr_match or not dark_media_match:
    sys.exit("FAIL: missing dark mode token override blocks")

dark_attr_vars = parse_vars(dark_attr_match.group(1))
dark_media_vars = parse_vars(dark_media_match.group(1))
if dark_attr_vars != dark_media_vars:
    sys.exit("FAIL: attribute dark tokens and prefers-color-scheme dark tokens diverged")

# Inherit any invariant token from light_vars if identically shared, though both define full palettes.
dark_vars = {**light_vars, **dark_attr_vars}

TEXT_PAIRS = [
    ("--ss-text", "--ss-bg", "primary text on page bg"),
    ("--ss-text", "--ss-surface", "primary text on card surface"),
    ("--ss-text", "--ss-surface-muted", "primary text on muted band"),
    ("--ss-text-muted", "--ss-bg", "muted text on page bg"),
    ("--ss-text-muted", "--ss-surface", "muted text on card surface"),
    ("--ss-text-muted", "--ss-surface-muted", "muted text on muted band"),
    ("--ss-accent-text", "--ss-accent", "accent button label on accent bg"),
    ("--ss-accent-text", "--ss-accent-hover", "accent button hover label"),
    ("--ss-save-text", "--ss-save", "save button label on save bg"),
    ("--ss-save-text", "--ss-save-hover", "save button hover label"),
    ("--ss-link", "--ss-surface", "link/tab active text on surface"),
    ("--ss-link", "--ss-surface-muted", "link/tab text on muted band"),
    ("--ss-accent-text", "--ss-danger", "danger button label on danger bg"),
    ("--ss-accent-text", "--ss-danger-hover", "danger button hover label"),
    ("--ss-ok-text", "--ss-ok-bg", "ok badge/alert text"),
    ("--ss-warn-text", "--ss-warn-bg", "warn badge/alert text"),
    ("--ss-err-text", "--ss-err-bg", "error badge/alert text"),
    ("--ss-log-text", "--ss-log-bg", "console log text on log bg"),
    ("--ss-log-muted", "--ss-log-bg", "console muted timestamp on log bg"),
    ("--ss-log-warn", "--ss-log-bg", "console WARN text on log bg"),
    ("--ss-log-err", "--ss-log-bg", "console ERROR text on log bg"),
]

UI_NON_TEXT_PAIRS = [
    ("--ss-control-border", "--ss-surface", "control border on surface"),
    ("--ss-control-border", "--ss-bg", "control border on page bg"),
    ("--ss-focus", "--ss-surface", "focus outline on surface"),
    ("--ss-focus", "--ss-bg", "focus outline on page bg"),
    ("--ss-ok-border", "--ss-surface", "ok border/dot on surface"),
    ("--ss-warn-border", "--ss-surface", "warn border/dot on surface"),
    ("--ss-err-border", "--ss-surface", "error border/dot on surface"),
]

def _luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    vals = []
    for i in (0, 2, 4):
        c = int(h[i : i + 2], 16) / 255.0
        vals.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * vals[0] + 0.7152 * vals[1] + 0.0722 * vals[2]

def check_pair(c1: str, c2: str, min_kind: str) -> tuple[bool, str]:
    if contrast_py.is_file():
        proc = subprocess.run(
            [sys.executable, str(contrast_py), c1, c2],
            capture_output=True,
            text=True,
        )
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"contrast-check.py error ({proc.returncode}): {proc.stderr.strip()}")
        out = proc.stdout.strip()
        normal_pass = bool(re.search(r"normal text\s*\([^)]+\):\s*PASS", out))
        large_pass = bool(re.search(r"large text\s*\([^)]+\):\s*PASS", out))
        if "ratio:" not in out:
            raise RuntimeError(f"unexpected contrast-check.py output: {out!r} / {proc.stderr.strip()!r}")
        return (normal_pass if min_kind == "normal" else large_pass), out.replace("\n", " | ")
    l1, l2 = _luminance(c1), _luminance(c2)
    ratio = (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)
    threshold = 4.5 if min_kind == "normal" else 3.0
    return ratio >= threshold, f"ratio: {ratio:.2f}:1 (threshold {threshold}:1)"

failures = []
checked = 0
for theme_name, tokens in (("light", light_vars), ("dark", dark_vars)):
    for fg, bg, desc in TEXT_PAIRS:
        if fg not in tokens or bg not in tokens:
            failures.append(f"{theme_name}: missing token {fg} or {bg}")
            continue
        ok, detail = check_pair(tokens[fg], tokens[bg], "normal")
        checked += 1
        if not ok:
            failures.append(f"{theme_name} TEXT {desc} ({fg}={tokens[fg]} on {bg}={tokens[bg]}): {detail}")

    for fg, bg, desc in UI_NON_TEXT_PAIRS:
        if fg not in tokens or bg not in tokens:
            failures.append(f"{theme_name}: missing token {fg} or {bg}")
            continue
        ok, detail = check_pair(tokens[fg], tokens[bg], "large")
        checked += 1
        if not ok:
            failures.append(f"{theme_name} UI {desc} ({fg}={tokens[fg]} on {bg}={tokens[bg]}): {detail}")

if failures:
    print("FAIL contrast checks:", file=sys.stderr)
    for item in failures:
        print(f"  - {item}", file=sys.stderr)
    sys.exit(1)

print(f"PASS: verify_contrast.sh ({checked} light+dark WCAG AA pairs verified)")
PY
