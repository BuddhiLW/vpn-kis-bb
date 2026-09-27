(ns vpn-kis-bb.adapters.http-curl
  "CurlHttpFetcher — IWebFetcher over the `curl` binary via IShell.

   Portable across Babashka and ClojureWasm (cljw has no java.net.http),
   and it is what the bash original used, so redirects, TLS and proxy
   environment behave the same. The HTTP status is appended by curl's
   --write-out after a marker and split off the body.

   Like the JVM adapter, any HTTP response is (ok {:status ...}); only a
   transport failure (DNS, connect, TLS, timeout) is an err."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.ports.http :as port]))

(def status-marker "\n__VPNKIS_HTTP_STATUS__:")

(def default-headers
  {"User-Agent" "vpn-kis-bb/0.2"
   "Accept"     "application/json,text/plain,*/*;q=0.8"})

(defn curl-argv
  "Pure: the curl argv for a GET of url."
  [url {:keys [timeout-ms headers] :or {timeout-ms 30000}}]
  (let [hdrs (merge default-headers
                    (into {} (map (fn [[k v]] [(name k) (str v)])) headers))]
    (-> ["curl" "-sS" "-L" "--max-time" (str (max 1 (quot timeout-ms 1000)))]
        (into (mapcat (fn [[k v]] ["-H" (str k ": " v)]) (sort hdrs)))
        (into ["-w" (str status-marker "%{http_code}") url]))))

(defn parse-output
  "Pure: split curl stdout into {:body :status}."
  [stdout]
  (let [out (or stdout "")
        i   (str/last-index-of out status-marker)]
    (if (nil? i)
      {:body out :status nil}
      {:body   (subs out 0 i)
       :status (parse-long (str/trim (subs out (+ i (count status-marker)))))})))

(defrecord CurlHttpFetcher [shell]
  port/IWebFetcher
  (-fetcher-id [_] :curl)
  (-fetch [_ url opts]
    (let [timeout-ms (or (:timeout-ms opts) 30000)
          resp       (proto/shell-exec! shell (curl-argv url opts)
                                        {:timeout-ms (+ timeout-ms 5000)})
          {:keys [exit stdout stderr duration-ms]} (:ok resp)]
      (cond
        (r/err? resp)
        (r/err :web/fetch-failed {:url url :message "curl did not run" :cause resp})

        (not (zero? exit))
        (r/err :web/fetch-failed {:url url :exit exit
                                  :message (str/trim (or stderr ""))})

        :else
        (let [{:keys [body status]} (parse-output stdout)]
          (r/ok {:status       status
                 :body         body
                 :url          url
                 :content-type ""
                 :duration-ms  duration-ms
                 :bytes        (count body)}))))))

(defn make
  "shell: an IShell that really executes (fetches are read-only, so even
   a dry-run system uses a live shell here)."
  [shell]
  (->CurlHttpFetcher shell))
