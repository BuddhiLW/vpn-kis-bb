#!/bin/sh
# openvpn --up hook for split 'example'.
set -eu
DEV="${1:-tun-example}"
ip route replace default dev "$DEV" table 142
logger -t vpn-kis-split "[example] route table 142 -> $DEV"
