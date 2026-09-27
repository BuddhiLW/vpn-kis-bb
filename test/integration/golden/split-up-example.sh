#!/bin/sh
# openvpn --up hook for split 'example'.
# Args from openvpn: $1=dev $2=tun_mtu $3=link_mtu $4=ifconfig_local $5=ifconfig_remote
set -eu
DEV="${1:-tun-example}"
ip route replace default dev "$DEV" table 142
logger -t vpn-kis-split "[example] route table 142 -> $DEV"
