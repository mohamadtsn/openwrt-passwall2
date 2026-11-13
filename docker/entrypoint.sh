#!/bin/sh
set -e

mkdir -p /tmp/log /tmp/etc/passwall2/sni_spoofer /tmp/lock /var/lock /var/run/ubus /etc/crontabs

/sbin/ubusd &
UBUS_PID=$!

i=0
while [ ! -S /var/run/ubus/ubus.sock ] && [ "$i" -lt 30 ]; do
	i=$((i + 1))
	sleep 0.1 2>/dev/null || sleep 1
done

/sbin/rpcd -s /var/run/ubus/ubus.sock &
RPCD_PID=$!

if [ -x /etc/init.d/passwall2_sni_spoofer ]; then
	/etc/init.d/passwall2_sni_spoofer boot >/dev/null 2>&1 || true
fi

UHTTPD_PID=""
cleanup() {
	[ -n "$UHTTPD_PID" ] && kill "$UHTTPD_PID" 2>/dev/null || true
	kill "$RPCD_PID" "$UBUS_PID" 2>/dev/null || true
	wait 2>/dev/null || true
}
trap cleanup TERM INT EXIT

/usr/sbin/uhttpd -f -h /www -r OpenWrt -x /cgi-bin -u /ubus -t 60 -T 30 -k 20 -A 1 -n 3 -N 100 -R -p 0.0.0.0:80 &
UHTTPD_PID=$!
wait "$UHTTPD_PID"
