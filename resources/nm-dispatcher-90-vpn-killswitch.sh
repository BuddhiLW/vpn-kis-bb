#!/usr/bin/env bash
# Reapply VPN killswitch DROP rule when the underlying PHYSICAL interface
# changes (dock/undock, wifi<->ethernet). Never follow the default route
# onto a VPN tunnel — doing so would rewrite the DROP rule to target the
# VPN iface and lock the host out.
set -u

IFACE="${1:-}"
ACTION="${2:-}"
LOG_TAG="vpn-killswitch"
RULES=/etc/ufw/before.rules
LOCK=/var/lock/vpn-killswitch.nm.lock
BAK="$RULES.nm-bak"

log() { logger -t "$LOG_TAG" -- "$*"; }

is_virtual() {
    case "$1" in
        lo|tun*|wg*|tailscale*|Eddie|ppp*|docker*|veth*|virbr*|br-*|zt*) return 0 ;;
    esac
    return 1
}

case "$ACTION" in
    up|down|connectivity-change) ;;
    *) exit 0 ;;
esac

if [ -n "$IFACE" ] && is_virtual "$IFACE"; then
    exit 0
fi

exec 9>"$LOCK" 2>/dev/null || exit 0
command -v flock >/dev/null 2>&1 && { flock -n 9 || { log "lock held, skip"; exit 0; }; }

NEW_IF=""
while read -r dev; do
    is_virtual "$dev" && continue
    [ -d "/sys/class/net/$dev" ] || continue
    NEW_IF="$dev"
    break
done < <(ip -4 route ls 2>/dev/null | awk '/^default/ {print $5}')

if [ -z "$NEW_IF" ]; then
    for d in /sys/class/net/*; do
        n=$(basename "$d")
        is_virtual "$n" && continue
        ip -4 addr show "$n" 2>/dev/null | grep -q 'inet ' || continue
        NEW_IF="$n"
        break
    done
fi

[ -z "$NEW_IF" ] && { log "no physical IF candidate, skip"; exit 0; }

CURRENT=$(grep -oP '(?<=-o )[A-Za-z0-9_.-]+(?= -j DROP)' "$RULES" 2>/dev/null | head -1)
if [ -z "$CURRENT" ]; then
    log "cannot parse current IF from $RULES, skip"
    exit 0
fi

if is_virtual "$CURRENT"; then
    log "current IF '$CURRENT' looks virtual — refusing rewrite"
    exit 0
fi
if is_virtual "$NEW_IF"; then
    log "candidate '$NEW_IF' is virtual — refusing rewrite"
    exit 0
fi

[ "$NEW_IF" = "$CURRENT" ] && exit 0

log "physical IF changed: $CURRENT -> $NEW_IF, reapplying"

cp -a "$RULES" "$BAK" || { log "backup failed, abort"; exit 0; }

if ! sed -i "s/-o ${CURRENT} /-o ${NEW_IF} /g; s/-i ${CURRENT} /-i ${NEW_IF} /g" "$RULES"; then
    log "sed failed, restoring backup"
    cp -a "$BAK" "$RULES"
    exit 0
fi

if ! grep -qE -- "-o ${NEW_IF} -j DROP" "$RULES"; then
    log "post-sed validation failed, restoring"
    cp -a "$BAK" "$RULES"
    exit 0
fi

if ! ufw reload >/dev/null 2>&1; then
    log "ufw reload failed, restoring backup"
    cp -a "$BAK" "$RULES"
    ufw reload >/dev/null 2>&1 || log "restore reload also failed — MANUAL INTERVENTION NEEDED"
    exit 0
fi

log "killswitch retargeted: $CURRENT -> $NEW_IF"
exit 0
