#!/usr/bin/env bash
# bin/parity-vm.sh — live parity capture between bash vpn-kis and bb vpn-kis-bb.
#
# Intended to run inside a throwaway Ubuntu VM (Multipass / LXD container with
# nesting / dedicated test box). Snapshots the relevant host state, runs both
# implementations against the same input, and emits a unified diff.
#
# Usage:
#   sudo ./bin/parity-vm.sh capture <scenario>     # capture both impls' state
#   sudo ./bin/parity-vm.sh diff    <scenario>     # diff the captures
#   sudo ./bin/parity-vm.sh clean                  # reset VM to baseline
#
# Scenarios (mirror bash subcommands):
#   permissive
#   strict-mullvad
#   strict-multi
#   split-example
#
# This script never touches a non-VM host without explicit consent.
set -euo pipefail

BASH_IMPL="${BASH_IMPL:-$HOME/PP/vpn-kis/vpn-firewall-setup.sh}"
BB_IMPL="${BB_IMPL:-$HOME/PP/vpn-kis-bb}"
OUT_DIR="${OUT_DIR:-/tmp/vpn-kis-parity}"
SAFETY_FLAG="${VPN_KIS_PARITY_I_AM_IN_A_VM:-}"

die() { echo "[parity] ERROR: $*" >&2; exit 1; }

require_vm_consent() {
    if [[ -z "$SAFETY_FLAG" ]]; then
        die "Refusing to run without VPN_KIS_PARITY_I_AM_IN_A_VM=1. This rewires UFW + iptables — only run inside a throwaway VM."
    fi
}

snapshot() {
    local tag="$1"
    local d="$OUT_DIR/$tag"
    mkdir -p "$d"
    iptables-save        > "$d/iptables-v4.rules"        2>/dev/null || true
    ip6tables-save       > "$d/iptables-v6.rules"        2>/dev/null || true
    ipset save           > "$d/ipset.save"               2>/dev/null || true
    ip rule show         > "$d/ip-rule.txt"              2>/dev/null || true
    ip route show table all > "$d/ip-route.txt"          2>/dev/null || true
    ufw status verbose   > "$d/ufw-status.txt"           2>/dev/null || true
    cp -a /etc/ufw/before.rules "$d/before.rules"        2>/dev/null || true
    cp -a /etc/ufw/before6.rules "$d/before6.rules"      2>/dev/null || true
    ls -1 /etc/systemd/system/vpn-killswitch-*.service > "$d/units.txt" 2>/dev/null || true
    ls -1 /etc/dnsmasq.d                                > "$d/dnsmasq-dropins.txt" 2>/dev/null || true
    echo "[parity] snapshot written to $d"
}

run_bash() {
    require_vm_consent
    local scenario="$1"
    case "$scenario" in
        permissive)     "$BASH_IMPL" ;;
        strict-mullvad) "$BASH_IMPL" providers mullvad ;;
        strict-multi)   "$BASH_IMPL" providers mullvad airvpn tailscale ;;
        split-example)  echo "[parity] split-example NYI in bash side; manual" ;;
        *)              die "Unknown scenario: $scenario" ;;
    esac
}

run_bb() {
    require_vm_consent
    local scenario="$1"
    cd "$BB_IMPL"
    case "$scenario" in
        permissive)     bb cli setup ;;
        strict-mullvad) bb cli providers mullvad ;;
        strict-multi)   bb cli providers mullvad airvpn tailscale ;;
        split-example)  bb cli split add example ;;
        *)              die "Unknown scenario: $scenario" ;;
    esac
}

capture() {
    local scenario="${1:?scenario required}"
    mkdir -p "$OUT_DIR"
    echo "[parity] === bash run: $scenario ==="
    snapshot "before-$scenario"
    run_bash "$scenario"
    snapshot "bash-$scenario"
    echo "[parity] reverting via panic..."
    "$BASH_IMPL" panic >/dev/null || true
    echo "[parity] === bb run: $scenario ==="
    snapshot "after-panic-$scenario"
    run_bb "$scenario"
    snapshot "bb-$scenario"
    echo "[parity] captures complete under $OUT_DIR"
}

diff_captures() {
    local scenario="${1:?scenario required}"
    local bash_d="$OUT_DIR/bash-$scenario"
    local bb_d="$OUT_DIR/bb-$scenario"
    [[ -d "$bash_d" ]] || die "missing $bash_d"
    [[ -d "$bb_d" ]]   || die "missing $bb_d"
    for f in iptables-v4.rules iptables-v6.rules ipset.save ip-rule.txt \
             before.rules before6.rules units.txt dnsmasq-dropins.txt; do
        echo "[parity] --- diff $f ---"
        diff -u "$bash_d/$f" "$bb_d/$f" || true
    done
}

clean() {
    require_vm_consent
    "$BASH_IMPL" panic >/dev/null || true
    rm -rf "$OUT_DIR"
    echo "[parity] cleaned"
}

cmd="${1:?Usage: $0 capture|diff|clean <scenario>}"
shift || true
case "$cmd" in
    capture) capture "$@" ;;
    diff)    diff_captures "$@" ;;
    clean)   clean ;;
    *)       die "Unknown cmd: $cmd" ;;
esac
