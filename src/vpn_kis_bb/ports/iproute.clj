(ns vpn-kis-bb.ports.iproute
  "IIpRoute — `ip rule` / `ip route` seam.

   Used by Tailscale coexistence (priority 5100-ish rules) and the
   split-tunnel feature (per-domain rule → table).")

(defprotocol IIpRoute
  (-rule-show [this]
    "Returns Result<[{:priority N :selectors {...} :lookup table-name} ...]>
     Parsed `ip rule show`. Pure data for downstream priority detection.")
  (-rule-add! [this {:keys [fwmark to lookup priority]}]
    "Add an ip rule. Returns Result. Idempotent via pre-delete at same priority.")
  (-rule-del! [this priority]
    "Drop all rules at a given priority. Returns Result.")
  (-route-add! [this {:keys [dst dev table]}]
    "Add a route into a custom table. Returns Result.")
  (-route-replace-default! [this {:keys [dev table]}]
    "Replace `default dev <dev> table <table>`. Used by openvpn up hooks.")
  (-table-flush! [this table]
    "Flush a route table. Used by openvpn down hooks."))
