(ns vpn-kis-bb.adapters.fetcher.tailscale
  "TailscaleFetcher — DERP relay IPs from login.tailscale.com/derpmap/default
   plus the hardcoded bootstrap-DNS list and the control plane hostnames.

   Strict-mode caveat: peer-to-peer UDP (41641) cannot be enumerated, so
   peers fall back to DERP relays automatically. Slower, still works."
  (:require [cheshire.core :as json]
            [hive-dsl.result :as r]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.dns :as dns]
            [vpn-kis-bb.ports.fetcher :as port]
            [vpn-kis-bb.ports.http :as http]))

(def derpmap-url "https://login.tailscale.com/derpmap/default")

(def control-hosts
  ["login.tailscale.com" "controlplane.tailscale.com" "log.tailscale.io"])

(def bootstrap-ips
  "Bootstrap-DNS servers compiled into tailscaled (tailscale
   net/dnsfallback/dns-fallback-servers.json, mirrored from the bash
   vpn-kis). Without them tailscaled cannot resolve
   controlplane.tailscale.com under a strict kill switch and never logs in.
   Kept as code, not a resource: cljw has no io/resource and a cljw build
   bundles namespaces only."
  #{"134.122.74.153"
    "176.58.93.248"
    "102.67.165.90"
    "208.111.34.178"
    "192.73.252.4"
    "199.38.181.92"
    "192.73.252.51"
    "192.73.252.52"
    "198.244.226.197"
    "192.241.144.189"
    "96.30.103.51"
    "199.38.183.124"
    "148.79.39.83"
    "169.150.246.180"
    "5.180.146.4"
    "195.201.197.155"})

(defn load-bootstrap-ips
  "The bootstrap-DNS IPv4 set."
  []
  bootstrap-ips)

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
             :fetched-at (u/now-iso)}))))

(defn make [fetcher resolver]
  (->TailscaleFetcher fetcher resolver))
