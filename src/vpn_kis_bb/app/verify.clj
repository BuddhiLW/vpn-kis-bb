(ns vpn-kis-bb.app.verify
  "Passive kill-switch verification. Inspects live state — no traffic
   manipulation, no VPN bounce.

   Mirrors bash `test_passive` (vpn-firewall-setup.sh ~line 491).
   Pure parsers for each piece of shell output, with shell I/O at the
   boundary."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]))

;; ---------------------------------------------------------------- parsers

(defn parse-ufw-active?
  "Pure: true when `ufw status` reports Status: active."
  [s] (boolean (re-find #"(?i)Status:\s*active" (or s ""))))

(defn parse-default-policies
  "Pure: extract default in/out/routed verdicts from `ufw status verbose`."
  [s]
  (let [s (or s "")]
    (cond-> {}
      (re-find #"(?i)deny\s+\(incoming\)"  s) (assoc :incoming :deny)
      (re-find #"(?i)allow\s+\(incoming\)" s) (assoc :incoming :allow)
      (re-find #"(?i)deny\s+\(outgoing\)"  s) (assoc :outgoing :deny)
      (re-find #"(?i)allow\s+\(outgoing\)" s) (assoc :outgoing :allow)
      (re-find #"(?i)deny\s+\(routed\)"    s) (assoc :routed   :deny)
      (re-find #"(?i)allow\s+\(routed\)"   s) (assoc :routed   :allow))))

(defn parse-drop-iface
  "Pure: extract the physical-IF name pinned in the kill-switch DROP rule.

   Matches lines like:
     -A ufw-before-output -o wlan0 -j DROP"
  [s]
  (when-let [m (re-find #"-A ufw-before-output -o (\S+) -j DROP" (or s ""))]
    (second m)))

(defn parse-strict?
  "Pure: true when the rule chain references the vpn_endpoints ipset
   (i.e. strict mode is wired in)."
  [s] (boolean (re-find #"match-set\s+vpn_endpoints" (or s ""))))

(defn parse-ipv6-disabled?
  "Pure: true when /proc/sys/net/ipv6/conf/all/disable_ipv6 == \"1\"."
  [s] (= "1" (str/trim (or s ""))))

;; ---------------------------------------------------------------- I/O glue

(defn- exec-stdout [shell cmd]
  (let [r (proto/shell-exec! shell cmd {})]
    (if (r/ok? r) (-> r :ok :stdout) "")))

(defn- read-file [path]
  (try (slurp path) (catch Throwable _ "")))

;; ---------------------------------------------------------------- checks

(defn run-checks
  "Collect every check into a vector of {:name :pass? :detail} maps.
   Pure-data result — formatters live in the caller / CLI."
  [system]
  (let [shell           (:shell system)
        ufw-status      (exec-stdout shell ["sh" "-c" "ufw status verbose 2>/dev/null"])
        before-rules    (exec-stdout shell ["sh" "-c" "iptables -S ufw-before-output 2>/dev/null"])
        ipv6-disable    (read-file "/proc/sys/net/ipv6/conf/all/disable_ipv6")
        ipset-list      (exec-stdout shell ["sh" "-c" "ipset list -name 2>/dev/null"])]
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
      :pass? (parse-ipv6-disabled? ipv6-disable)
      :detail {:disable_ipv6 (str/trim ipv6-disable)}}

     (let [strict? (parse-strict? before-rules)]
       {:name "Strict mode (ipset-locked)"
        :pass? strict?
        :detail (if strict? "ipset vpn_endpoints referenced"
                            "permissive — pre-VPN DNS/443 open")
        :informational? true})

     {:name "vpn_endpoints ipset present"
      :pass? (str/includes? ipset-list "vpn_endpoints")
      :detail {:sets (->> (str/split-lines ipset-list)
                          (remove str/blank?)
                          vec)}
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
