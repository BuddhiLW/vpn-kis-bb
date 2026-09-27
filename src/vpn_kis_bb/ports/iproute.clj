(ns vpn-kis-bb.ports.iproute
  "IIpRoute: the `ip rule` / `ip route` seam. Used by the split-tunnel
   feature (per-split fwmark rule -> table).")

(defprotocol IIpRoute
  (-rule-show [this]
    "Parsed `ip rule show`: Result<[{:priority N :raw \"selectors\"} ...]>
     (vpn-kis-bb.domain.priority/parse-ip-rule-output); err on a non-zero exit.")
  (-rule-add! [this {:keys [fwmark to lookup priority]}]
    "`ip rule add [fwmark M] [to X] [lookup T] [priority P]`. Returns Result;
     err on a non-zero exit.")
  (-rule-del! [this priority]
    "`ip rule del priority P`: deletes ONE rule. Always ok, with the
     command's :exit, so callers can repeat it until it fails (drain).")
  (-route-add! [this {:keys [dst dev table]}]
    "Add a route into a custom table. Returns Result.")
  (-route-replace-default! [this {:keys [dev table]}]
    "Replace `default dev <dev> table <table>`. Used by openvpn up hooks.")
  (-table-flush! [this table]
    "Flush a route table. Used by openvpn down hooks."))
