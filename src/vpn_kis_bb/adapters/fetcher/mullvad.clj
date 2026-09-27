(ns vpn-kis-bb.adapters.fetcher.mullvad
  "MullvadFetcher: the IPs Mullvad needs before its tunnel is up (bash
   fetch_mullvad): WireGuard, OpenVPN and bridge relays from
   api.mullvad.net; every ipv4_addr_in in the daemon's cached relay list;
   the API address the daemon last used; the builtin API address; the A
   records of api.mullvad.net (Quantum-Resistance PSK handshake and relay
   list refresh on reconnect).

   An unreachable or empty relay list is an error, so the caller keeps the
   cached .ips file instead of shrinking it to the API addresses."
  (:require [cheshire.core :as json]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.dns :as dns]
            [vpn-kis-bb.ports.fetcher :as port]
            [vpn-kis-bb.ports.http :as http]
            [vpn-kis-bb.domain.re :as rx]))

(def api-url "https://api.mullvad.net/app/v1/relays")
(def api-host "api.mullvad.net")

(def builtin-api-ip
  "API address built into the daemon, used when api.mullvad.net DNS differs."
  "45.83.223.196")

(def cache-relays-path "/var/cache/mullvad-vpn/relays.json")
(def cache-api-endpoint-path "/var/cache/mullvad-vpn/api-endpoint.json")

(def resolve-rounds
  "A lookups of api.mullvad.net per fetch (bash: 3, to catch rotation)."
  3)

(def relay-list-failed-hint "mullvad: relay list download failed; keeping the cached list")

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

(defn cache-relay-ips
  "Pure: every ipv4_addr_in anywhere in the daemon's relays.json text
   (jq `.. | objects | .ipv4_addr_in?`), valid IPv4 only; #{} for nil,
   blank or unparsable text."
  [text]
  (if (str/blank? text)
    #{}
    (try
      (->> (tree-seq coll? seq (json/parse-string text keyword))
           (filter map?)
           (keep :ipv4_addr_in)
           u/normalize-ips)
      (catch Throwable _ #{}))))

(defn api-endpoint-ips
  "Pure: the dotted quads in the daemon's api-endpoint.json text (bash
   `grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'`), valid IPv4 only."
  [text]
  (u/normalize-ips (rx/re-seq* #"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" (or text ""))))

(defn- relay-ips
  "Result<#{ip}> from the API response body; an error when it is not JSON
   or names no relay."
  [body]
  (let [parsed (try {:data (json/parse-string body keyword)}
                    (catch Throwable t {:error (str t)}))]
    (if (:error parsed)
      (r/err :fetcher/mullvad-parse-failed {:cause (:error parsed) :hint relay-list-failed-hint})
      (let [ips (try (parse-relays-json (:data parsed))
                     (catch Throwable _ #{}))]
        (if (empty? ips)
          (r/err :fetcher/mullvad-empty-relays {:hint relay-list-failed-hint})
          (r/ok ips))))))

(defn- safe-read [read-fn path]
  (try (read-fn path) (catch Throwable _ nil)))

(defn- api-host-ips
  "Union of resolve-rounds A lookups of api.mullvad.net; failures add nothing."
  [resolver]
  (apply u/merge-ip-sets
         (for [_ (range resolve-rounds)]
           (let [res (try (dns/-resolve-a resolver api-host)
                          (catch Throwable _ nil))]
             (if (r/ok? res) (:ok res) #{})))))

;; Method params stay distinct: on cljw a record method written [_ _]
;; resolves its fields through the second `_`.
(defrecord MullvadFetcher [fetcher resolver read-fn]
  port/IProviderFetcher
  (-provider-id [_this] :mullvad)
  (-supports? [_this pname] (= "mullvad" (name pname)))
  (-fetch-ips [_this {:keys [timeout-ms] :or {timeout-ms 30000}}]
    (let [resp (http/-fetch fetcher api-url
                            {:timeout-ms timeout-ms
                             :headers {"Accept" "application/json"}})]
      (if-not (r/ok? resp)
        (r/err :fetcher/mullvad-http-failed {:cause resp :hint relay-list-failed-hint})
        (let [relays (relay-ips (-> resp :ok :body))]
          (if (r/err? relays)
            relays
            (r/ok {:provider   :mullvad
                   :ips        (u/merge-ip-sets
                                (:ok relays)
                                (cache-relay-ips (safe-read read-fn cache-relays-path))
                                (api-endpoint-ips (safe-read read-fn cache-api-endpoint-path))
                                [builtin-api-ip]
                                (api-host-ips resolver))
                   :source     api-url
                   :fetched-at (u/now-iso)})))))))

(defn make
  "MullvadFetcher over an IWebFetcher and an IDnsResolver.
   opts: {:read-fn (fn [path] -> string | nil)} reads the daemon caches
   under /var/cache/mullvad-vpn; without it the caches are not read."
  ([fetcher resolver] (make fetcher resolver {}))
  ([fetcher resolver {:keys [read-fn]}]
   (->MullvadFetcher fetcher resolver (or read-fn (constantly nil)))))
