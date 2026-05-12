(ns vpn-kis-bb.adapters.fetcher.tailscale
  "TailscaleFetcher — DERP relay IPs from login.tailscale.com/derpmap/default
   plus the hardcoded bootstrap-DNS list and the control plane hostnames.

   Strict-mode caveat: peer-to-peer UDP (41641) cannot be enumerated, so
   peers fall back to DERP relays automatically. Slower, still works."
  (:require [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [hive-dsl.result :as r]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.dns :as dns]
            [vpn-kis-bb.ports.fetcher :as port]
            [vpn-kis-bb.ports.http :as http]))

(def derpmap-url "https://login.tailscale.com/derpmap/default")

(def control-hosts
  ["login.tailscale.com" "controlplane.tailscale.com" "log.tailscale.io"])

(defn load-bootstrap-ips
  "Read the bundled bootstrap-IPs resource (set of IPv4 strings)."
  []
  (when-let [u (io/resource "tailscale-bootstrap-ips.edn")]
    (edn/read-string (slurp u))))

(defn parse-derpmap-json
  "Pure: extract DERP node IPv4s + hostnames from the parsed derpmap."
  [json-data]
  (let [nodes (mapcat #(get-in % [:Nodes]) (vals (get json-data :Regions {})))]
    {:ips       (u/normalize-ips (keep :IPv4 nodes))
     :hostnames (->> nodes (keep :HostName) distinct vec)}))

(defn resolve-hostnames
  [resolver hostnames]
  (reduce (fn [acc h]
            (let [res (dns/-resolve-a resolver h)]
              (if (r/ok? res)
                (into acc (:ok res))
                acc)))
          #{}
          hostnames))

(defrecord TailscaleFetcher [fetcher resolver]
  port/IProviderFetcher
  (-provider-id [_] :tailscale)
  (-supports? [_ pname] (= "tailscale" (name pname)))
  (-fetch-ips [_ {:keys [timeout-ms] :or {timeout-ms 30000}}]
    (let [bootstrap (or (load-bootstrap-ips) #{})
          resp (http/-fetch fetcher derpmap-url
                            {:timeout-ms timeout-ms
                             :headers {"Accept" "application/json"}})
          derp (when (r/ok? resp)
                 (try
                   (parse-derpmap-json
                    (json/parse-string (-> resp :ok :body) keyword))
                   (catch Throwable _ nil)))
          derp-ips      (or (:ips derp) #{})
          derp-hosts    (or (:hostnames derp) [])
          ctrl-ips      (resolve-hostnames resolver control-hosts)
          derp-host-ips (resolve-hostnames resolver derp-hosts)]
      (r/ok {:provider   :tailscale
             :ips        (u/merge-ip-sets bootstrap derp-ips
                                          ctrl-ips derp-host-ips)
             :source     derpmap-url
             :fetched-at (java.time.Instant/now)}))))

(defn make [fetcher resolver]
  (->TailscaleFetcher fetcher resolver))
