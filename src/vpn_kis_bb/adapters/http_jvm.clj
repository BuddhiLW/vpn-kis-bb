(ns vpn-kis-bb.adapters.http-jvm
  "JvmHttpFetcher — concrete IWebFetcher backed by java.net.http (JDK 11+).

   Ported from basic-tools-mcp.web.collect (MIT, BuddhiLW / hive-agi).
   We carry our own copy rather than depending on basic-tools-mcp directly
   so the dep graph stays lean (the upstream lib also pulls cljfmt,
   parinferish, rewrite-clj, and modex-bb — all dead weight here).

   Uses hive-weave.safe to bound the blocking .send call so a misbehaving
   HTTP server can't hang the process."
  (:require [hive-dsl.result :as r]
            [hive-weave.safe :as weave]
            [vpn-kis-bb.ports.http :as port])
  (:import [java.net URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.time Duration]))

(def ^:private ^HttpClient default-http-client
  (.. (HttpClient/newBuilder)
      (connectTimeout (Duration/ofSeconds 10))
      build))

(defn- build-request
  ^HttpRequest [^String url ^long timeout-ms headers]
  (let [b (.. (HttpRequest/newBuilder (URI/create url))
              (timeout (Duration/ofMillis timeout-ms))
              (header "User-Agent" "vpn-kis-bb/0.1")
              (header "Accept" "application/json,text/plain,*/*;q=0.8"))]
    (doseq [[k v] headers]
      (.header b (name k) (str v)))
    (.build b)))

(defn- shape-response
  [^HttpResponse$BodyHandlers _ resp url start-ms]
  (let [body (.body resp)
        ct   (-> resp .headers (.firstValue "content-type")
                 (.orElse ""))]
    {:status       (.statusCode resp)
     :body         body
     :url          url
     :content-type ct
     :duration-ms  (- (System/currentTimeMillis) start-ms)
     :bytes        (count (or body ""))}))

(defrecord JvmHttpFetcher [^HttpClient client]
  port/IWebFetcher
  (-fetcher-id [_] :jvm-http)
  (-fetch [_ url {:keys [timeout-ms headers]
                  :or   {timeout-ms 30000}}]
    (let [start (System/currentTimeMillis)
          req   (build-request url timeout-ms headers)
          fut-r (weave/safe-future-call
                 {:timeout-ms (+ timeout-ms 5000) :name "web/fetch"}
                 #(.send client req (HttpResponse$BodyHandlers/ofString)))]
      (if (r/ok? fut-r)
        (r/ok (shape-response nil (:ok fut-r) url start))
        (r/err :web/fetch-failed
               {:message (or (:message fut-r) "fetch failed")
                :url     url
                :cause   (:error fut-r)})))))

(defn make-jvm-fetcher
  ([]                   (->JvmHttpFetcher default-http-client))
  ([^HttpClient client] (->JvmHttpFetcher client)))
