(ns vpn-kis-bb.app.verify
  "Passive kill-switch check-list. Inspects live state: no traffic
   manipulation, no VPN bounce.

   Mirrors bash `test_passive` (vpn-firewall-setup.sh ~line 491). Pure
   parsers for each piece of shell output, with shell I/O at the boundary.
   The post-setup VERIFICATION printout (bash `verify`) is
   vpn-kis-bb.app.selftest/verify-report."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.domain.re :as rx]))

;; ---------------------------------------------------------------- parsers

(defn parse-ufw-active?
  "Pure: true when `ufw status` reports Status: active."
  [s] (boolean (rx/re-find* #"(?i)Status:\s*active" (or s ""))))

(defn parse-default-policies
  "Pure: extract default in/out/routed verdicts from `ufw status verbose`."
  [s]
  (let [s (or s "")]
    (cond-> {}
      (rx/re-find* #"(?i)deny\s+\(incoming\)" s) (assoc :incoming :deny)
      (rx/re-find* #"(?i)allow\s+\(incoming\)" s) (assoc :incoming :allow)
      (rx/re-find* #"(?i)deny\s+\(outgoing\)" s) (assoc :outgoing :deny)
      (rx/re-find* #"(?i)allow\s+\(outgoing\)" s) (assoc :outgoing :allow)
      (rx/re-find* #"(?i)deny\s+\(routed\)" s) (assoc :routed   :deny)
      (rx/re-find* #"(?i)allow\s+\(routed\)" s) (assoc :routed   :allow))))

(defn parse-drop-iface
  "Pure: extract the physical-IF name pinned in the kill-switch DROP rule.

   Matches lines like:
     -A ufw-before-output -o wlan0 -j DROP"
  [s]
  (when-let [m (rx/re-find* #"-A ufw-before-output -o (\S+) -j DROP" (or s ""))]
    (second m)))

(defn parse-strict?
  "Pure: true when the rule chain references the vpn_endpoints ipset
   (i.e. strict mode is wired in)."
  [s] (boolean (rx/re-find* #"match-set\s+vpn_endpoints" (or s ""))))

(defn parse-ipv6-disabled?
  "Pure: true when /proc/sys/net/ipv6/conf/all/disable_ipv6 == \"1\"."
  [s] (= "1" (str/trim (or s ""))))

;; ---------------------------------------------------------------- I/O glue

(defn- exec-stdout [shell cmd]
  (let [r (proto/shell-exec! shell cmd {})]
    (if (r/ok? r) (-> r :ok :stdout) "")))

(defn- read-file
  "File contents via the system's :read-fn (slurp when absent), nil when
   missing or unreadable."
  [system path]
  (try (if-let [rf (:read-fn system)] (rf path) (slurp path))
       (catch Throwable _ nil)))

;; ---------------------------------------------------------------- checks

(defn run-checks
  "Collect every check into a vector of {:name :pass? :detail} maps
   (:informational? true on checks that never fail the run). Pure-data
   result: formatters live in the caller / CLI. An absent IPv6 stack (no
   /proc/sys/net/ipv6/conf/all/disable_ipv6) passes, as in bash."
  [system]
  (let [shell        (:shell system)
        ufw-status   (exec-stdout shell ["sh" "-c" "ufw status verbose 2>/dev/null"])
        before-rules (exec-stdout shell ["sh" "-c" "iptables -S ufw-before-output 2>/dev/null"])
        ipv6-disable (read-file system "/proc/sys/net/ipv6/conf/all/disable_ipv6")
        ipset-list   (exec-stdout shell ["sh" "-c" "ipset list -name 2>/dev/null"])
        sets         (->> (rx/split-lines* ipset-list)
                          (map str/trim)
                          (remove str/blank?)
                          vec)]
    [{:name "UFW active"
      :pass? (parse-ufw-active? ufw-status)
      :detail (str/replace ufw-status #"\n+" " | ")}

     (let [pol (parse-default-policies ufw-status)]
       {:name "Default outgoing policy deny"
        :pass? (= :deny (:outgoing pol))
        :detail pol})

     (let [drop-if (parse-drop-iface before-rules)]
       {:name "Killswitch DROP rule present"
        :pass? (boolean drop-if)
        :detail {:pinned-iface drop-if}})

     {:name "IPv6 disabled"
      :pass? (or (nil? ipv6-disable) (parse-ipv6-disabled? ipv6-disable))
      :detail {:disable_ipv6 (if (nil? ipv6-disable) :absent (str/trim ipv6-disable))}}

     (let [strict? (parse-strict? before-rules)]
       {:name "Strict mode (ipset-locked)"
        :pass? strict?
        :detail (if strict? "ipset vpn_endpoints referenced"
                            "permissive: pre-VPN DNS/443 open")
        :informational? true})

     {:name "vpn_endpoints ipset present"
      :pass? (boolean (some #{"vpn_endpoints"} sets))
      :detail {:sets sets}
      :informational? true}

     {:name "vpn_dns_bootstrap ipset present (strict-mode DNS, port 53 only)"
      :pass? (boolean (some #{"vpn_dns_bootstrap"} sets))
      :detail {:sets sets}
      :informational? true}]))

(defn verify
  "Run passive checks. Returns Result<{:checks [...] :failed [...]}> where
   :failed lists only non-informational checks that did NOT pass."
  [system]
  (let [checks (run-checks system)
        failed (->> checks
                    (remove :informational?)
                    (remove :pass?)
                    vec)]
    (r/ok {:checks checks :failed failed :ok? (empty? failed)})))
