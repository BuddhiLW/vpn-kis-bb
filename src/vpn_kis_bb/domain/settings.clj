(ns vpn-kis-bb.domain.settings
  "Pure: runtime settings read from the environment.

   Mirrors the bash original's env knobs so existing invocations keep
   working (sudo VPN_ENDPOINTS=... ./vpn-firewall-setup.sh, FORCE=1, ...)."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.rules :as rules]
            [vpn-kis-bb.domain.re :as rx]))

(def default-dns-bootstrap
  "Public resolvers added to the endpoint ipset in strict mode so
   'refresh' can re-resolve provider hostnames while the VPN is down."
  ["1.1.1.1" "8.8.8.8" "9.9.9.9"])

(def default-prog "vpn-kis")

(defn words
  "Whitespace-separated tokens of s ([] for nil/blank)."
  [s]
  (if (str/blank? s) [] (rx/split* (str/trim s) #"\s+")))

(defn from-env
  "env: map of environment variable name -> value."
  [env]
  {:vpn-interfaces (let [w (words (get env "VPN_IFACES"))]
                     (if (seq w) w rules/default-vpn-interfaces))
   :endpoints      (words (get env "VPN_ENDPOINTS"))
   :lan-allow      (words (get env "LAN_ALLOW_CIDRS"))
   ;; ${DNS_BOOTSTRAP_IPS-default}: unset -> defaults, set-but-empty -> none.
   :dns-bootstrap  (if (contains? env "DNS_BOOTSTRAP_IPS")
                     (words (get env "DNS_BOOTSTRAP_IPS"))
                     default-dns-bootstrap)
   :physical-iface (not-empty (get env "PHYSICAL_IF"))
   ;; Legacy strict mode: endpoints reachable on VPN ports only. Off by
   ;; default: Mullvad picks random WireGuard ports (4000-60000) and API
   ;; bridge ports (e.g. 1082), so a port lock breaks its reconnects.
   :strict-ports?  (= "1" (get env "STRICT_PORTS"))
   :force?         (= "1" (get env "FORCE"))
   ;; Command that systemd units and the NM hook invoke (set by bin/vpn-kis).
   :self-path      (not-empty (get env "VPN_KIS_SELF"))
   ;; Name shown in help and hints (the bash shim passes the path typed).
   :prog           (or (not-empty (get env "VPN_KIS_PROG")) default-prog)
   ;; File the launcher sources to exec a command (see adapters.exec).
   :exec-file      (not-empty (get env "VPN_KIS_EXEC_FILE"))})
