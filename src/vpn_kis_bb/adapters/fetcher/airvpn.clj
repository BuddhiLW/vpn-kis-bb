(ns vpn-kis-bb.adapters.fetcher.airvpn
  "AirvpnFetcher — scan Eddie / OpenVPN / user config dirs for `remote`
   directives (OpenVPN) and `Endpoint =` (WireGuard), DNS-resolve any
   hostnames. AirVPN clusters DNS-round-robin so we merge with a cached
   list to grow coverage across runs."
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.dns :as dns]
            [vpn-kis-bb.ports.fetcher :as port]))

(def default-scan-dirs
  ["/etc/openvpn"
   "/etc/openvpn/airvpn"
   "/etc/AirVPN"
   "/etc/eddie"
   "/opt/AirVPN"])

(defn user-scan-dirs
  "Per-user candidate dirs. Reads $HOME so an injected env can override."
  [home]
  (when home
    [home
     (str home "/Downloads")
     (str home "/.airvpn")
     (str home "/AirVPN")]))

(defn parse-ovpn-remotes
  "Extract hostnames from `remote <host>` lines in an OpenVPN .ovpn/.conf."
  [content]
  (->> (str/split-lines (or content ""))
       (keep #(some-> (re-find #"^\s*remote\s+(\S+)" %) second))))

(defn parse-wg-endpoints
  "Extract hostnames from `Endpoint = <host>:<port>` lines (WireGuard)."
  [content]
  (->> (str/split-lines (or content ""))
       (keep (fn [line]
               (when-let [m (re-find #"^\s*Endpoint\s*=\s*([^:\s]+)" line)]
                 (second m))))))

(defn collect-hosts
  "Walk dirs, find *.ovpn / *.conf, return distinct hostnames."
  [dirs]
  (->> dirs
       (filter #(and % (fs/exists? %) (fs/directory? %)))
       (mapcat #(fs/glob % "{*.ovpn,*.conf,*/*.ovpn,*/*.conf}"))
       (mapcat (fn [path]
                 (let [content (slurp (fs/file path))]
                   (concat (parse-ovpn-remotes content)
                           (parse-wg-endpoints content)))))
       distinct
       vec))

(defn resolve-many
  [resolver hosts]
  (reduce (fn [acc h]
            (if (u/ipv4? h)
              (conj acc h)
              (let [res (dns/-resolve-a resolver h)]
                (if (r/ok? res)
                  (into acc (:ok res))
                  acc))))
          #{}
          hosts))

(defrecord AirvpnFetcher [resolver dirs home]
  port/IProviderFetcher
  (-provider-id [_] :airvpn)
  (-supports? [_ pname] (= "airvpn" (name pname)))
  (-fetch-ips [_ _opts]
    (let [all-dirs (concat dirs (user-scan-dirs home))
          hosts    (collect-hosts all-dirs)]
      (if (empty? hosts)
        (r/err :fetcher/airvpn-no-configs
               {:scanned-dirs all-dirs
                :hint "Drop AirVPN .ovpn files in ~/Downloads or /etc/openvpn/"})
        (r/ok {:provider   :airvpn
               :ips        (resolve-many resolver hosts)
               :hosts      hosts
               :source     "scanned ovpn/wg configs"
               :fetched-at (java.time.Instant/now)})))))

(defn make
  ([resolver]
   (->AirvpnFetcher resolver default-scan-dirs (System/getenv "HOME")))
  ([resolver dirs home]
   (->AirvpnFetcher resolver dirs home)))
