(ns vpn-kis-bb.ports.firewall
  "IFirewallBackend — apply a generated rule plan to the host firewall.

   The rule plan is produced by `domain.rules` as a pure value. Backends
   render it into their concrete representation (UFW text rules, nftables
   tables, raw iptables-restore) and commit it atomically.")

(defprotocol IFirewallBackend
  (-backend-id [this])
  (-snapshot [this]
    "Capture current firewall state into an opaque blob. Returns Result.")
  (-apply-rules! [this rule-plan opts]
    "Render and apply rule-plan (a value, see domain.rules/rule-plan?).
     opts may carry :dry-run? :reload-cmd. Returns Result.")
  (-restore! [this snapshot]
    "Roll back to a previously captured snapshot. Returns Result.")
  (-reload! [this]
    "Force a reload (e.g. `ufw reload`). Returns Result."))
