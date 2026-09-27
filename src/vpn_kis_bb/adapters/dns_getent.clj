(ns vpn-kis-bb.adapters.dns-getent
  "GetentResolver — IDnsResolver over `getent ahostsv4`, with optional
   `dig @server` fallbacks.

   Portable across Babashka and ClojureWasm (no java.net.InetAddress).
   The fallbacks matter in strict mode with the VPN down: the system
   resolver's upstream is blocked by the killswitch, but the bootstrap
   resolvers (1.1.1.1, 8.8.8.8, ...) sit in the endpoint ipset, so
   `refresh` can still re-resolve provider hostnames.

   NXDOMAIN / no A records is (ok #{}); only a failure to run anything
   is an err."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.dns :as port]
            [vpn-kis-bb.domain.re :as rx]))

(defn parse-getent
  "Pure: IPv4s from `getent ahostsv4` output (first column)."
  [s]
  (->> (rx/split-lines* (or s ""))
       (keep #(first (rx/split* (str/trim %) #"\s+")))
       u/normalize-ips))

(defn parse-dig
  "Pure: IPv4s from `dig +short` output (CNAME lines are dropped)."
  [s]
  (u/normalize-ips (rx/split-lines* (or s ""))))

(defn- getent [shell hostname timeout-ms]
  (let [resp (proto/shell-exec! shell ["getent" "ahostsv4" hostname]
                                {:timeout-ms timeout-ms})]
    (cond
      (r/err? resp)                resp
      (zero? (-> resp :ok :exit))  (r/ok (parse-getent (-> resp :ok :stdout)))
      ;; 2 = key not found (NXDOMAIN / no A record)
      (= 2 (-> resp :ok :exit))    (r/ok #{})
      :else (r/err :dns/resolve-failed {:hostname hostname :exit (-> resp :ok :exit)}))))

(defn- dig [shell server hostname timeout-ms]
  (let [resp (proto/shell-exec! shell ["dig" "+short" "+time=2" "+tries=1"
                                       (str "@" server) hostname "A"]
                                {:timeout-ms timeout-ms})]
    (if (and (r/ok? resp) (zero? (-> resp :ok :exit)))
      (parse-dig (-> resp :ok :stdout))
      #{})))

(defrecord GetentResolver [shell timeout-ms fallback-servers]
  port/IDnsResolver
  (-resolve-a [_ hostname]
    (let [primary (getent shell hostname timeout-ms)]
      (if (and (r/ok? primary) (seq (:ok primary)))
        primary
        (let [found (some #(not-empty (dig shell % hostname timeout-ms))
                          fallback-servers)]
          (cond
            found           (r/ok found)
            (r/ok? primary) primary
            :else           (r/err :dns/resolve-failed
                                   {:hostname hostname :cause primary})))))))

(defn make-resolver
  "opts: {:timeout-ms 5000 :fallback-servers [\"1.1.1.1\" ...]}"
  ([shell] (make-resolver shell {}))
  ([shell {:keys [timeout-ms fallback-servers]
           :or   {timeout-ms 5000 fallback-servers []}}]
   (->GetentResolver shell timeout-ms (vec fallback-servers))))
