FROM openwrt/rootfs:x86-64-24.10.1

ARG ROOT_PASSWORD=root

RUN mkdir -p /var/lock /var/run /var/run/ubus /tmp /tmp/log /tmp/etc /etc/crontabs /www && \
    for attempt in 1 2 3; do opkg update && break; sleep 2; done && \
    opkg install \
        uhttpd \
        uhttpd-mod-ubus \
        rpcd \
        rpcd-mod-luci \
        rpcd-mod-file \
        luci-base \
        luci-compat \
        luci-lua-runtime \
        luci-mod-admin-full \
        luci-theme-bootstrap \
        coreutils \
        coreutils-base64 \
        coreutils-nohup \
        coreutils-timeout \
        curl \
        ca-bundle \
        ip-full \
        libuci-lua \
        lua \
        luci-lib-jsonc \
        lyaml \
        resolveip \
        jsonfilter \
        unzip && \
    for script in /etc/uci-defaults/*; do \
        [ -f "$script" ] || continue; \
        sh "$script" >/dev/null 2>&1 && rm -f "$script" || true; \
    done && \
    uci -q set uhttpd.main.redirect_https='0' || true && \
    uci -q delete uhttpd.main.listen_https || true && \
    uci -q set uhttpd.main.listen_http='0.0.0.0:80' || true && \
    uci -q commit uhttpd || true && \
    printf '%s\n%s\n' "$ROOT_PASSWORD" "$ROOT_PASSWORD" | passwd root && \
    rm -rf /var/opkg-lists/* /tmp/opkg-* /tmp/luci-* /tmp/run /tmp/lock /tmp/state

COPY rpcd-system.uc /usr/share/rpcd/ucode/system
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0644 /usr/share/rpcd/ucode/system && chmod 0755 /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
