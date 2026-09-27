(ns vpn-kis-bb.adapters.fetcher.ovpn-file
  "OvpnFileFetcher — derive a provider IP set from a single .ovpn config.

   The use case: a corporate / private VPN where you have the .ovpn but
   want to drive the IPs through vpn-kis-bb's machinery. We parse `remote
   <host> [port]` lines and DNS-resolve any hostnames via the injected
   IDnsResolver.

   Stable hosts → stable IP set. Refresh periodically if your VPN
   endpoint floats."
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.fetcher :as port]
            [vpn-kis-bb.ports.dns :as dns]
            [vpn-kis-bb.domain.re :as rx]))

(defn parse-remote-lines
  "Returns a vector of hostnames from `remote <host> [port]` lines.
   Pure: takes the file's content as a string."
  [content]
  (->> (rx/split-lines* (or content ""))
       (keep (fn [line]
               (when-let [m (rx/re-find* #"^\s*remote\s+(\S+)" line)]
                 (second m))))
       distinct
       vec))

(defrecord OvpnFileFetcher [provider-id ovpn-path resolver]
  port/IProviderFetcher
  (-provider-id [_] provider-id)
  (-supports? [_ pname]
    (= (name pname) (name provider-id)))
  (-fetch-ips [_ _opts]
    (cond
      (not (fs/exists? ovpn-path))
      (r/err :fetcher/no-ovpn {:provider provider-id :path (str ovpn-path)})

      :else
      (let [content (-> ovpn-path fs/file slurp)
            hosts   (parse-remote-lines content)
            literal (filter u/ipv4? hosts)
            named   (remove u/ipv4? hosts)
            resolved (reduce (fn [acc h]
                               (let [r (dns/-resolve-a resolver h)]
                                 (if (r/ok? r)
                                   (into acc (:ok r))
                                   acc)))
                             (set literal)
                             named)]
        (r/ok {:provider   provider-id
               :ips        (u/normalize-ips resolved)
               :source     (str ovpn-path)
               :hosts      hosts
               :fetched-at (u/now-iso)})))))

(defn make
  [provider-name ovpn-path resolver]
  (->OvpnFileFetcher (keyword provider-name) ovpn-path resolver))
