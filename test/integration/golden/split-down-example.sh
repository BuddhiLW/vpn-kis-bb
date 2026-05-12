#!/bin/sh
# openvpn --down hook for split 'example'.
set -eu
ip route flush table 142 2>/dev/null || true
logger -t vpn-kis-split "[example] route table 142 flushed"
