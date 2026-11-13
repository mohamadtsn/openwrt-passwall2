#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$REPO_ROOT/luci-app-passwall2"
CONTAINER="${PASSWALL2_CONTAINER:-passwall2-dev}"

if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -qx 'true'; then
	echo "Container '$CONTAINER' is not running. Start it with: docker compose -f docker/compose.yml up -d --build" >&2
	exit 1
fi

echo "Syncing luci-app-passwall2 into '$CONTAINER'..."

tar -C "$PKG_DIR/luasrc" -cf - . | docker exec -i "$CONTAINER" tar -xof - -C /usr/lib/lua/luci/
tar -C "$PKG_DIR/root" -cf - . | docker exec -i "$CONTAINER" tar -xof - -C /
tar -C "$PKG_DIR/htdocs" -cf - . | docker exec -i "$CONTAINER" tar -xof - -C /www/

docker exec "$CONTAINER" sh -c '
	set -e
	mkdir -p /tmp/log /tmp/etc/passwall2/sni_spoofer /var/lock /var/run
	chmod 0755 /usr/share/passwall2/*.sh 2>/dev/null || true
	chmod 0755 /etc/init.d/passwall2* 2>/dev/null || true
	if [ -f /etc/uci-defaults/luci-app-passwall2 ]; then
		sh /etc/uci-defaults/luci-app-passwall2 >/dev/null 2>&1 || true
	fi
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache
	if ! ubus list session >/dev/null 2>&1; then
		rm -f /var/run/rpcd.pid
		start-stop-daemon -S -b -m -p /var/run/rpcd.pid -x /sbin/rpcd -- -s /var/run/ubus/ubus.sock
		i=0
		while [ "$i" -lt 20 ] && ! ubus list session >/dev/null 2>&1; do
			i=$((i + 1))
			usleep 100000 2>/dev/null || sleep 1
		done
	fi
'

echo "Sync complete. LuCI is ready at http://localhost:8080 (login: root / root)"
