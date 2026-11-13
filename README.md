# PassWall2

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02%2B-blue)](https://openwrt.org/)
[![LuCI](https://img.shields.io/badge/LuCI-17.01%2B-green)](https://github.com/openwrt/luci)

PassWall2 is a powerful LuCI web interface application for OpenWrt that provides advanced proxy functionality. It's a comprehensive solution for network traffic management, proxy services, and access control on OpenWrt-based routers.

## 🛠️ Installation

### ⚠️ Pre-installation

```bash
# find it in releases,base of your router Arch
```
**Visit [GitHub Releases](https://github.com/mohamadtsn/openwrt-passwall2/releases/latest) to download the latest `.apk` or `.ipk` package for your router.**

Choose the package format based on your **router's OpenWrt package manager**:

### For OpenWrt 25.12+ with APK

1. **Download the APK package** from the releases page (`luci-app-passwall2-{VERSION}-r{REL}.apk` in the Assets section).
   > **Note:** If you need localization (Chinese/Persian/Russian), download the corresponding language package as well (e.g., `luci-i18n-passwall2-fa-{VERSION}.apk`).

2. **Install (first-time setup requires the PassWall APK repository below for dependencies; on existing PassWall 2 routers just run `apk add --allow-untrusted`):**
   ```bash
   # Replace {VERSION} and {REL} with the actual release values (e.g., 26.11.11 and 2)
   wget -O /tmp/luci-app-passwall2.apk https://github.com/mohamadtsn/openwrt-passwall2/releases/download/{VERSION}-{REL}/luci-app-passwall2-{VERSION}-r{REL}.apk
   apk add --allow-untrusted /tmp/luci-app-passwall2.apk
   /etc/init.d/rpcd restart
   ```
   > ⚠️ **Security Note:** `--allow-untrusted` bypasses package signature verification for GitHub Release APK downloads. After this one-time install, you can receive future updates directly from **Services -> PassWall 2 -> App Update** inside LuCI.

### For OpenWrt 21.02–24.10 with OPKG

1. **Download the IPK package** from the releases page (`luci-app-passwall2_{VERSION}-r{REL}_all.ipk` in the Assets section).
   > **Note:** If you need localization (Chinese/Persian/Russian), download the corresponding language package as well (e.g., `luci-i18n-passwall2-fa_{VERSION}_all.ipk`).

2. **Upload or download to your router:**
   ```bash
   # Replace {VERSION} and {REL} with the actual release values (e.g., 26.11.11 and 2)
   wget -O /tmp/luci-app-passwall2.ipk https://github.com/mohamadtsn/openwrt-passwall2/releases/download/{VERSION}-{REL}/luci-app-passwall2_{VERSION}-r{REL}_all.ipk
   ```

3. **Install:**
   ```bash
   opkg update
   opkg install /tmp/luci-app-passwall2.ipk
   /etc/init.d/rpcd restart
   ```
   
   > If installation fails due to missing dependencies (e.g., `xray-core`), add the PassWall packages feed to `/etc/opkg/customfeeds.conf` first. Subsequent updates can also be applied directly via **Services -> PassWall 2 -> App Update**.

> **How to check your package manager:** Run `command -v apk` or `command -v opkg` to see which one your router uses.

### 🧩 Add PassWall2 APK repository (recommended)
**Instead of installing .apk packages manually**, you can add the PassWall2 APK repository and signing key to enable installation and updates via apk.

1. Add repository signing key

```bash
wget -O passwall.pub https://sourceforge.net/projects/openwrt-passwall-build/files/apk.pub
mv passwall.pub /etc/apk/keys/
```

2. Add PassWall2 repositories

```bash
. /etc/openwrt_release

release="${DISTRIB_RELEASE%.*}"
arch="$DISTRIB_ARCH"

wget -O /etc/apk/keys/passwall.pub \
  https://sourceforge.net/projects/openwrt-passwall-build/files/apk.pub

cat >> /etc/apk/repositories.d/customfeeds.list <<EOF
https://sourceforge.net/projects/openwrt-passwall-build/files/releases/packages-${release}/${arch}/passwall_packages/packages.adb
https://sourceforge.net/projects/openwrt-passwall-build/files/releases/packages-${release}/${arch}/passwall_luci/packages.adb
https://sourceforge.net/projects/openwrt-passwall-build/files/releases/packages-${release}/${arch}/passwall2/packages.adb
EOF
```

3. Update package index

```bash
apk update
```

4. Install optional dependency packages (depending on your configuration) and PassWall2 from repository

```bash
apk add tcping geoview # add other dependencies

apk add luci-app-passwall2
```


## 📋 System Requirements

### OpenWrt Version
- OpenWrt 21.02 or later
- LuCI 17.01 or later

### Hardware Requirements
- **Minimum 256MB RAM**
- Sufficient storage for packages (varies by protocol selection)

### Core Dependencies
The following packages should be resolved automatically by the package manager (if available in your feeds):

- `coreutils`, `coreutils-base64`, `coreutils-nohup`
- `curl`, `ip-full`, `libuci-lua`, `lua`, `luci-compat`, `luci-lib-jsonc`
- `resolveip`, `tcping`, `unzip`
- `geoview`, `v2ray-geoip`, `v2ray-geosite` (geo-routing data)

> **Note:** Actual dependencies may vary based on selected features and your OpenWrt build. Ensure you have the necessary feeds configured.

### Optional Protocol Packages
Selected during installation based on your needs:
- Xray
- Sing-Box
- Shadowsocks-Rust
- ShadowsocksR
- HAProxy

## 🚀 Features

### Multi-Protocol Support
- **Xray** (HTTP, Socks, Shadowsocks, VMess, VLESS, Trojan, Hysteria2, WireGuard)
- **Sing-Box** (HTTP, Socks, SSH, Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria, Hysteria2, WireGuard, AnyTLS)
- **Shadowsocks-Rust**
- **ShadowsocksR** legacy support
- **HAProxy** The Reliable, High Performance TCP/HTTP Load Balancer

### Traffic Management
- **Load Balancing**: Distribute traffic across multiple nodes
- **Smart Routing**: Domain-based and geo-based routing rules
- **DNS Control**: Advanced DNS filtering and DoH/DoT support
- **Transparent Proxy**: Seamless network-wide proxy
- **SNI Spoofer (`sni-spoof-rs`)**: Integrated procd service manager, binary downloader/uploader, multi-listener configuration, and live log viewer in LuCI

### Node Management
- **Subscription Support**: Import nodes from subscription URLs
- **Node Testing**: Built-in latency and connectivity testing
- **Failover Support**: Automatic failover to backup nodes
- **QR Code**: Generate and scan QR codes for node sharing

### Access Control
- **Per-Device Rules**: Configure proxy settings per device
- **Domain/IP Filtering**: Whitelist/blacklist support
- **Time-based Rules**: Schedule proxy usage

## ⚙️ Configuration

### Basic Setup

1. **Access LuCI Interface:**
   - Navigate to `Services` → `PassWall2`

2. **Add Your First Node:**
   - Go to `Node List` → `Add Node`
   - Select protocol and fill in server details

3. **Configure Basic Settings:**
   - Select your default node
   - Configure DNS settings
   - Enable transparent proxy

4. **Apply Configuration:**
   - Click `Save & Apply`

## 🌐 Language Support

PassWall2 supports multiple languages:
- 🇨🇳 Chinese (Simplified/Traditional)
- 🇮🇷 Persian (فارسی)

Language files are organized in `luci-app-passwall2/po/` subdirectories.

## 🔧 Troubleshooting

### Common Issues

**Service Won't Start**
```bash
logread | grep passwall2
```
Check system logs, verify node configuration, and ensure required packages are installed.

**DNS Issues**
- Disable built-in DNS in browsers (Chrome: Settings → Privacy → Security → Disable "Use secure DNS")
- Clear DNS cache after reboot: `ipconfig /flushdns` (Windows) or toggle airplane mode (mobile)

**Connection Problems**
- Test node connectivity
- Check firewall rules
- Verify transparent proxy settings

### Debug Mode

Enable debug logging in `Other Settings` and check:
- Main log: `/tmp/log/passwall2.log`
- Server log: `/tmp/log/passwall2_server.log`

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

**Note**: This software is intended for legal use only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.

---

## Stargazers over time
[![Stargazers over time](https://starchart.cc/Openwrt-Passwall/openwrt-passwall2.svg?variant=adaptive)](https://starchart.cc/Openwrt-Passwall/openwrt-passwall2)
