(ns vpn-kis-bb.app.setup
  "Top-level firewall install.

   Permissive: open DNS+443+VPN-ports pre-tunnel to any host.
   Strict:     pre-tunnel surface locked to `vpn_endpoints` ipset.

   Both modes write /etc/ufw/before.rules from the pure generator in
   `domain.rules` and apply via `IFirewallBackend`.

   In strict mode, the ipset is populated from the IP union returned by
   `app.providers/load-union`."
  (:require [hive-dsl.result :as r]
            [vpn-kis-bb.app.providers :as providers]
            [vpn-kis-bb.domain.rules :as rules]
            [vpn-kis-bb.ports.firewall :as fw-port]
            [vpn-kis-bb.ports.ipset :as ipset-port]))

(def default-ipset-name "vpn_endpoints")

(defn detect-physical-iface
  "Best-effort physical-IF detection: parses `ip -4 route ls` from the
   shell. Returns Result<string>."
  [system]
  (let [shell (:shell system)
        resp ((requiring-resolve 'hive-system.protocols/shell-exec!)
              shell ["sh" "-c" "ip -4 route ls | awk '/^default/ {print $5; exit}'"] {})]
    (cond
      (r/err? resp) resp
      :else
      (let [out (-> resp :ok :stdout clojure.string/trim)]
        (if (clojure.string/blank? out)
          (r/err :setup/no-physical-iface {:hint "set --physical-iface manually"})
          (r/ok out))))))

(defn build-plan
  "Pure: assemble the rule-plan map domain.rules expects.

   opts:
     :mode :permissive|:strict
     :physical-iface (required)
     :lan-allow [cidr ...]
     :ipset-name <s>     (default vpn_endpoints)
     :vpn-interfaces [...]
     :vpn-ports-udp [...]
     :vpn-ports-tcp [...]"
  [{:keys [mode physical-iface lan-allow ipset-name
           vpn-interfaces vpn-ports-udp vpn-ports-tcp]
    :or {ipset-name default-ipset-name lan-allow []}}]
  (cond-> {:mode mode
           :physical-iface physical-iface
           :lan-allow lan-allow}
    (= mode :strict) (assoc :ipset-name ipset-name)
    vpn-interfaces   (assoc :vpn-interfaces vpn-interfaces)
    vpn-ports-udp    (assoc :vpn-ports-udp  vpn-ports-udp)
    vpn-ports-tcp    (assoc :vpn-ports-tcp  vpn-ports-tcp)))

(defn populate-ipset!
  "Populate the strict-mode ipset from the requested providers."
  [system providers ipset-name]
  (let [union (providers/load-union providers)]
    (if (r/err? union)
      union
      (let [ips (-> union :ok :union)]
        (-> (r/ok :start)
            ((fn [acc]
               (if (r/err? acc) acc
                   (ipset-port/-create! (:ipset system) ipset-name {}))))
            ((fn [acc]
               (if (r/err? acc) acc
                   (ipset-port/-add-bulk! (:ipset system) ipset-name ips))))
            ((fn [acc]
               (if (r/err? acc) acc
                   (r/ok {:ipset ipset-name :count (count ips)})))))))))

(defn setup!
  "Top-level install. Returns Result.

   opts:
     :mode :permissive|:strict   (required)
     :providers [name ...]        (required when :strict)
     :physical-iface <s>          (auto-detected when nil)
     :lan-allow [cidr ...]
     :ipset-name <s>
     :dry-run? bool"
  [system {:keys [mode providers physical-iface dry-run?] :as opts}]
  (let [phys-r (if physical-iface
                 (r/ok physical-iface)
                 (detect-physical-iface system))]
    (if (r/err? phys-r)
      phys-r
      (let [phys (:ok phys-r)
            opts (assoc opts :physical-iface phys)
            plan (build-plan opts)
            populate-r (if (and (= mode :strict) (not dry-run?))
                         (populate-ipset! system providers (:ipset-name plan default-ipset-name))
                         (r/ok :skip))]
        (if (r/err? populate-r)
          populate-r
          (fw-port/-apply-rules! (:firewall system) plan
                                 {:dry-run? dry-run?}))))))
