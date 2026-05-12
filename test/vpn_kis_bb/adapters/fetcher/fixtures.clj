(ns vpn-kis-bb.adapters.fetcher.fixtures
  "Mock IWebFetcher + IDnsResolver used across fetcher tests."
  (:require [hive-dsl.result :as r]
            [vpn-kis-bb.ports.http :as http]
            [vpn-kis-bb.ports.dns :as dns]))

(defrecord StubWebFetcher [url->body]
  http/IWebFetcher
  (-fetcher-id [_] :stub)
  (-fetch [_ url _opts]
    (if-let [body (get url->body url)]
      (r/ok {:status 200 :body body :url url :content-type "application/json"
             :duration-ms 1 :bytes (count body)})
      (r/err :stub/no-mapping {:url url}))))

(defrecord StubDnsResolver [host->ips]
  dns/IDnsResolver
  (-resolve-a [_ hostname]
    (r/ok (set (get host->ips hostname #{})))))

(defn web [m]  (->StubWebFetcher  (or m {})))
(defn rsv [m]  (->StubDnsResolver (or m {})))
