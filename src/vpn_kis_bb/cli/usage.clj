(ns vpn-kis-bb.cli.usage
  "Pure: the help text (bash `usage`), with `prog` standing for $0.")

(def split-conf-dir "/etc/vpn-killswitch/split")
(def providers-dir "/etc/vpn-killswitch/providers")

(defn text
  "Help text for the program invoked as `prog`."
  [prog]
  (str
   "VPN Kill-Switch Firewall v5

Usage:
  " prog " [setup]                       Install kill-switch (permissive: any host on VPN ports)
  " prog " auto                          Auto-detect live VPN peer IPs, strict-lock to them
  " prog " providers <name> [name ...]   Strict-lock to union of provider profiles
                                   (e.g. '" prog " providers mullvad airvpn')
  " prog " fetch [name ...]              Refresh provider IP lists (default: all known)
  " prog " refresh [name ...]            Re-fetch providers + atomically rebuild the
                                   vpn_endpoints ipset (no UFW reload, no leak
                                   window). Default: providers from last
                                   'providers' run. Use after a server IP
                                   rotates and OpenVPN logs EPERM writes.
  " prog " refresh install [interval]    Systemd timer running 'refresh' periodically
                                   (default: 15min). Keeps dynamic-IP/DDNS
                                   endpoints unblocked automatically.
  " prog " refresh uninstall             Remove the refresh timer
  " prog " tailscale-routes [apply|install|remove]
                                   Tailnet traffic bypasses Mullvad by Mullvad's
                                   own marks (nft table vpn-killswitch-tailscale).
                                   install also adds the boot unit + NM hook.
  " prog " tailscale-web [apply|remove]  OpenClaw HTTPS-only Mullvad exception + local hostname
                                   Runtime firewall rule; preserves general DNS/VPN policy.
  " prog " detect                        Print detected VPN endpoints, exit
  " prog " test [passive|active]         Run killswitch self-tests (default: passive)
                                   passive = non-disruptive rule checks
                                   active  = drops VPN, checks for leak, reconnects
                                   FORCE=1 skips confirm prompt
  " prog " split add <name>              Install per-domain split tunnel
                                   (reads " split-conf-dir "/<name>.conf)
  " prog " split rm <name>               Remove split (ip rule, mangle, dnsmasq drop-in, unit)
  " prog " split list                    List configured/installed splits
  " prog " split status [name]           Show ipset, route table, unit state
  " prog " split connect <name>          Launch openvpn with split-tunnel flags
                                   (route-nopull, --dev pin, up/down hooks,
                                   wraps with mullvad-exclude if Mullvad up)
  " prog " exclude run [--as U] -- <cmd> Run <cmd> with its traffic BYPASSING the VPN
                                   (out the physical IF, punched through the
                                   killswitch). Runs as root by default so root
                                   commands work; --as U drops to user U.
                                   Auto-enables on first use. Keyed on a cgroup,
                                   so root commands (apt, etc.) work too.
                                   e.g. sudo " prog " exclude run -- apt-get update
                                        sudo " prog " exclude run --as $USER -- curl ifconfig.me
  " prog " exclude on                    Enable exclusion infra explicitly (unit +
                                   routing + before.rules ACCEPT). Persists
                                   across reboot + ufw reload.
  " prog " exclude off                   Disable + tear everything down
  " prog " exclude status                Show state (cgroup members, routing, fw)
  " prog " unlock                        Restore UFW from latest backup
  " prog " panic                         EMERGENCY: drop all firewall rules, reset
                                   DNS, re-enable IPv6, restart network stack.
                                   Keeps the Tailscale bypass (cluster access).
                                   Run from local TTY when locked out.
                                   Aliases: rescue, emergency
  " prog " help                          Show this message

Global flags (anywhere before a '--'):
  --lan <cidrs>                    Allow LAN traffic to/from these CIDRs to
                                   bypass the killswitch on the physical IF.
                                   Quote multi-value: --lan \"192.168.100.0/24 10.0.5.0/24\"
                                   Use for cluster LAN, NAS, printer, etc.
                                   SECURITY: opens machine to LAN-initiated
                                   connections: wired-home OK, coworking risky.
  --physical-iface <if>            Override physical interface auto-detection
  --dry-run                        Show the plan; run no privileged command

Env:
  VPN_ENDPOINTS=\"1.2.3.4 5.6.7.8\"   Manual strict mode (overrides auto/providers)
  LAN_ALLOW_CIDRS=\"192.168.100.0/24\"   Same as --lan, env-var form.
  STRICT_PORTS=1                   Strict mode also locks endpoints to the VPN
                                   ports (default: any port, as Mullvad needs)
  DNS_BOOTSTRAP_IPS=\"1.1.1.1\"      Resolvers reachable on port 53 while the VPN
                                   is down (default 1.1.1.1 8.8.8.8 9.9.9.9;
                                   empty disables)

Providers:
  mullvad   : fetched from api.mullvad.net plus the local Mullvad daemon cache
  airvpn    : scanned from /etc/openvpn + Eddie config dirs
  tailscale : DERP relays + control plane (login.tailscale.com derpmap)
              Strict mode forces peer traffic via DERP relay (no direct UDP).
  <custom>  : drop IPs (one per line) into " providers-dir "/<name>.ips, OR
              create " split-conf-dir "/<name>.conf with OVPN_CONFIG=; fetch
              then resolves the .ovpn 'remote' hosts (DDNS-friendly).

Modes:
  PERMISSIVE  Default. DNS + 443 + VPN ports open to any host on physical IF.
              Works with any provider, hostname-based configs. Some leak surface.
  STRICT      IP-locked. No DNS/443 pre-holes. Lock via 'auto', 'providers', or
              VPN_ENDPOINTS env var. Endpoints are reachable on any port (Mullvad
              picks random WireGuard ports); nothing else is. Fails if the server
              IP is not in the whitelist: refresh with 'fetch' when providers rotate.

Example workflows:
  # One-shot per session, exact peer:
  sudo " prog " auto

  # Always-on both providers:
  sudo " prog " fetch mullvad airvpn
  sudo " prog " providers mullvad airvpn

  # Cluster-LAN management exception (Talos apid :50000, kubelet, etc.):
  sudo " prog " --lan 192.168.100.0/24 providers mullvad tailscale airvpn

  # Custom dynamic-IP provider (corporate OpenVPN behind DDNS) that never
  # goes stale: lock once, then auto-refresh every 15 min:
  sudo " prog " providers mullvad airvpn tailscale funeraria
  sudo " prog " refresh install 15min

  # Rollback:
  sudo " prog " unlock
"))
