# vpn-kis-bb

The Clojure implementation of [vpn-kis](https://github.com/BuddhiLW/vpn-kis), the strict VPN kill-switch for Linux (UFW + ipset + nft). It runs natively through [ClojureWasm](https://github.com/BuddhiLW/ClojureWasm) (`cljw`), or on Babashka for development.

vpn-kis's `vpn-firewall-setup.sh` is a thin shim over this program; every command, alias and env knob of the bash v4 script works the same way.

Why it left bash:

- **Testable**: rules, units and hooks are rendered by pure functions and pinned by golden files, byte-identical to the bash output; every shell effect goes through a recording shell in tests.
- **Safe to run half-way**: `panic` never aborts on the first failing step (the bash one did, and cut the tailnet); setup validates everything before it changes anything.
- **Fixes the Mullvad reconnect bugs**: tailnet traffic bypasses Mullvad by Mullvad's own marks instead of racing its ip-rule priorities, and strict mode lets endpoints through on any port (Mullvad picks random WireGuard ports and API bridges).

## Quick start

```bash
bin/dry-run-check                        # every command family, dry, no root needed
sudo bin/vpn-kis help                    # every command
sudo bin/vpn-kis --dry-run providers mullvad tailscale   # print the plan, change nothing
sudo bin/vpn-kis fetch mullvad tailscale
sudo bin/vpn-kis providers mullvad tailscale             # strict lock
sudo bin/vpn-kis panic                   # emergency: open everything, keep the tailnet
```

`bin/vpn-kis` picks the runtime: `$VPN_KIS_BIN`, then the `cljw` interpreter (the default; it starts in about 0.1 s), then `bb`. `bin/build-native` produces `build/vpn-kis` with `cljw build`, used only with `VPN_KIS_NATIVE=1`: cljw 1.14.11's build still miscompiles parts of setup and refresh. It also looks for them in `/usr/local/bin` and the linuxbrew prefix, since sudo and NetworkManager hooks run with a minimal PATH. It exports `VPN_KIS_SELF` (its absolute path: what systemd units and the NetworkManager hook invoke) and `VPN_KIS_PROG` (the name shown in help), and runs the command that `exclude run` or `split connect` asks for in its own process, through the file named by `VPN_KIS_EXEC_FILE`.

## Commands

The bash surface, unchanged: `setup` (default), `auto`, `providers`, `fetch`, `refresh [install|uninstall]`, `detect`, `test [passive|active]`, `split add|rm|list|status|connect`, `exclude run|on|off|status`, `tailscale-routes [apply|install|remove]`, `tailscale-web [apply|remove]`, `unlock`, `panic` (`rescue`, `emergency`), `help`. `nm-dispatch IF ACTION` is what the NetworkManager hook calls.

Global flags, accepted anywhere before a `--`: `--lan CIDRS` (repeatable, `--lan-allow` alias), `--physical-iface IF`, `--dry-run`.

Environment: `VPN_ENDPOINTS`, `LAN_ALLOW_CIDRS`, `STRICT_PORTS=1` (lock endpoints to the VPN ports again), `DNS_BOOTSTRAP_IPS` (resolvers reachable on port 53 while the VPN is down; empty disables), `PHYSICAL_IF`, `VPN_IFACES`, `FORCE=1`, `TAILSCALE_WEB_HELPER`, `VPN_KIS_DEBUG=1` (print whole error values).

`tailscale-web` pins one tailnet peer, read from `/etc/vpn-killswitch/tailscale-web.conf` (`HOST=<name>.<tailnet>.ts.net` and `IP=<its 100.x address>`) or from `TAILSCALE_WEB_HOST` / `TAILSCALE_WEB_IP`; without one it changes nothing.

## Architecture

```
domain/    pure: rule and unit text, parsers, plans as data
ports/     protocols (fetchers, DNS, HTTP, firewall, ipset, systemd, ...)
adapters/  shell-backed implementations, provider fetchers, exec hand-off
app/       workflows over a `system` map, each returning a hive-dsl Result
cli/       argument parsing, help text, dispatch, composition root (system.clj)
cljw/      compat layer mounted only on ClojureWasm (babashka.fs subset,
           cheshire over data.json, hive-dsl/hive-system/hive-weave shims)
lib/tailscale-web/  python helper for the OpenClaw HTTPS exception
```

ClojureWasm notes that shape the code: regex operations that return vectors are intermittently corrupted in cljw 1.14.11, so every regex call goes through `vpn-kis-bb.domain.re` (repeat until two answers agree) and hot paths such as `ipv4?` are regex-free; `io/resource` is unavailable, so data lives in code; a native build only contains namespaces required statically from `cli.main`.

## Testing

```bash
bb test                                   # whole suite on Babashka
bb tns tailscale setup                    # only namespaces matching the substrings
cljw -cp cljw:src:test -m cljw-runner     # the same suite on ClojureWasm
python3 -m unittest discover -s test/python   # tailscale-web helper
```

No root is needed: adapters run against a recording shell, workflows against recorded writes, and `test/integration/golden/` holds the byte-exact bash outputs (`before.rules` in five modes, split units and scripts).

For live parity against the legacy bash in a throwaway VM, see `bin/parity-vm.sh` (guarded by `VPN_KIS_PARITY_I_AM_IN_A_VM=1`: it rewires the host firewall).

## License

MIT, same as vpn-kis.
