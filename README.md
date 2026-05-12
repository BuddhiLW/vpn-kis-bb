# vpn-kis-bb

Babashka Clojure CLI port of [vpn-kis](https://github.com/BuddhiLW/vpn-kis), the strict VPN kill-switch for Linux.

Goals over the bash original:

- **Testable**: pure-functional rule generation, side effects pushed to the boundary.
- **Extensible**: provider fetchers (Mullvad, AirVPN, Tailscale, …) are protocol-based — drop in new ones without touching shell glue.
- **Diagnosable**: nREPL into the running process; emit a full dry-run plan before any privileged op.
- **Composable**: leverages [hive-system](https://github.com/hive-agi/hive-system) (`IPathQuery`/`IShell`/`INetwork`), [hive-weave](https://github.com/hive-agi/hive-weave) (`parallel`/`gate`/`safe`), and an `IWebFetcher` ported from [basic-tools-mcp](https://github.com/hive-agi/basic-tools-mcp).

The upstream bash version remains the canonical public OSS distribution. This is a parallel implementation, not a replacement.

## Status

**Phase 0–3 (safe, no sudo)** — provider fetchers + domain logic.
Privileged ops (UFW/ipset/iptables/systemd) land in Phase 4+ and require a VM for integration testing.

## Requirements

- Babashka 1.3.0+ (primary)
- Java 11+ (for `java.net.http` HTTP client)
- `clojure` CLI tool (JVM fallback for tests / heavier deps)

## Quick start

```bash
bb hello            # smoke test
bb test             # run unit tests
bb cli fetch mullvad --dry-run   # dry-run fetch
```

## CLI surface (target)

```
vpn-kis-bb setup [--strict] [--lan CIDR...]
vpn-kis-bb fetch  [provider...]
vpn-kis-bb providers <name>...
vpn-kis-bb auto
vpn-kis-bb detect
vpn-kis-bb split add|rm|list|status|connect <name>
vpn-kis-bb test [passive|active]
vpn-kis-bb unlock
vpn-kis-bb panic
```

Subcommands track the upstream bash 1:1 for muscle-memory.

## Architecture

```
domain/      pure rule generators, priority calc, config schema
ports/       IProviderFetcher, IFirewallBackend, IIpset, IIpRoute, ISystemdUnit, IDnsResolver
adapters/    concrete impls (shell-backed for privileged ops, java.net.http for HTTP)
app/         workflow composition — subcommand handlers
cli/         babashka/cli entry + system wiring (composition root)
```

## Testing

```bash
bb test
```

Runs three layers of tests bb-side, no root needed:

1. **Domain tests** — pure rule generators, priority calc, config readers, IPv4 utils.
2. **Adapter tests** — every shell-backed adapter (ipset, iproute, systemd, ufw, dnsmasq, NM dispatcher, http, dns) goes through a `RecordingShell` that asserts the exact command sequence emitted. Zero live shell + zero network.
3. **Integration tests** under `test/integration/`:
   - **Trace tests** — drive `app.{setup,split,…}` through `cli/system :dry-run` mode and assert key command sequences appear in the recorded trace.
   - **Golden parity** — bb's generated `before.rules`, dnsmasq drop-ins, openvpn up/down scripts, and systemd unit bodies must match byte-for-byte against snapshotted reference files under `test/integration/golden/`.

### Live parity vs upstream bash

Trace tests catch regressions in *our* implementation; they don't prove parity with the bash original. For live parity:

```bash
sudo VPN_KIS_PARITY_I_AM_IN_A_VM=1 \
    ./bin/parity-vm.sh capture strict-mullvad
sudo ./bin/parity-vm.sh diff strict-mullvad
```

`parity-vm.sh` snapshots `iptables-save`, `ipset save`, `ip rule`, `ufw status`, `before.rules`, and the installed systemd units before/after running each implementation against the same scenario, then unified-diffs the captures.

**Run only inside a throwaway VM** (Multipass / LXD with nesting). The `VPN_KIS_PARITY_I_AM_IN_A_VM=1` guard exists because the harness rewires the host firewall — and `panic` is the only way back out.

Scenarios: `permissive`, `strict-mullvad`, `strict-multi`, `split-example`.

## License

MIT — same as upstream vpn-kis.
