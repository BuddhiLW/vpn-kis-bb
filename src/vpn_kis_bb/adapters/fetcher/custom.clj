(ns vpn-kis-bb.adapters.fetcher.custom
  "CustomFileFetcher — read a static IP list from
   /etc/vpn-killswitch/providers/<name>.ips. Drops blanks + comments.

   Use this for any provider whose IPs you can enumerate manually
   (small fleets, internal corporate VPNs)."
  (:require [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.fetcher :as port]))

(def default-dir "/etc/vpn-killswitch/providers")

(defrecord CustomFileFetcher [provider-id dir]
  port/IProviderFetcher
  (-provider-id [_] provider-id)
  (-supports? [_ pname]
    (= (name pname) (name provider-id)))
  (-fetch-ips [_ _opts]
    (let [path (fs/path dir (str (name provider-id) ".ips"))]
      (if (fs/exists? path)
        (let [lines (-> path fs/file slurp clojure.string/split-lines)
              ips   (u/normalize-ips lines)]
          (r/ok {:provider    provider-id
                 :ips         ips
                 :source      (str path)
                 :fetched-at  (java.time.Instant/now)}))
        (r/err :fetcher/no-cache {:provider provider-id :path (str path)})))))

(defn make
  ([provider-name]     (->CustomFileFetcher (keyword provider-name) default-dir))
  ([provider-name dir] (->CustomFileFetcher (keyword provider-name) dir)))
