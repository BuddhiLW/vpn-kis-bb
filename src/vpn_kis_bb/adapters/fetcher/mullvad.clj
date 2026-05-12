(ns vpn-kis-bb.adapters.fetcher.mullvad
  "MullvadFetcher — pull WireGuard + OpenVPN + bridge relay IPs from
   api.mullvad.net plus the api host IPs themselves (required pre-tunnel
   for Quantum-Resistance PSK handshake)."
  (:require [cheshire.core :as json]
            [hive-dsl.result :as r]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.dns :as dns]
            [vpn-kis-bb.ports.fetcher :as port]
            [vpn-kis-bb.ports.http :as http]))

(def api-url "https://api.mullvad.net/app/v1/relays")
(def api-host "api.mullvad.net")

(defn parse-relays-json
  "Pure: extract relay IPv4s from the parsed Mullvad relays JSON."
  [json-data]
  (let [pull (fn [path]
               (->> (get-in json-data path)
                    (keep :ipv4_addr_in)))]
    (u/normalize-ips
     (concat (pull [:wireguard :relays])
             (pull [:openvpn   :relays])
             (pull [:bridge    :relays])))))

(defrecord MullvadFetcher [fetcher resolver]
  port/IProviderFetcher
  (-provider-id [_] :mullvad)
  (-supports? [_ pname] (= "mullvad" (name pname)))
  (-fetch-ips [_ {:keys [timeout-ms] :or {timeout-ms 30000}}]
    (let [resp (http/-fetch fetcher api-url
                            {:timeout-ms timeout-ms
                             :headers {"Accept" "application/json"}})]
      (if-not (r/ok? resp)
        (r/err :fetcher/mullvad-http-failed {:cause resp})
        (try
          (let [body  (-> resp :ok :body)
                data  (json/parse-string body keyword)
                relay (parse-relays-json data)
                api-r (dns/-resolve-a resolver api-host)
                api-ips (if (r/ok? api-r) (:ok api-r) #{})]
            (r/ok {:provider   :mullvad
                   :ips        (u/merge-ip-sets relay api-ips)
                   :source     api-url
                   :fetched-at (java.time.Instant/now)}))
          (catch Throwable t
            (r/err :fetcher/mullvad-parse-failed {:cause (str t)})))))))

(defn make [fetcher resolver]
  (->MullvadFetcher fetcher resolver))
