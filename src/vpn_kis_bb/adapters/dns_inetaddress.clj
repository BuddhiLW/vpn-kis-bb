(ns vpn-kis-bb.adapters.dns-inetaddress
  "InetAddressResolver — IDnsResolver backed by java.net.InetAddress.

   Resolves A records only (IPv4). For NXDOMAIN / no A records we
   return an empty set with :ok?; transport errors come back as :err.

   The result is wrapped with hive-weave.safe so a stuck resolver can't
   hang the calling thread."
  (:require [hive-dsl.result :as r]
            [hive-weave.safe :as weave]
            [vpn-kis-bb.ports.dns :as port])
  (:import [java.net InetAddress Inet4Address UnknownHostException]))

(defn- resolve-once
  "Synchronous DNS A lookup. Returns Result<#{ipv4-str ...}>."
  [hostname]
  (try
    (let [addrs (InetAddress/getAllByName hostname)
          v4    (into #{} (comp (filter #(instance? Inet4Address %))
                                (map #(.getHostAddress ^InetAddress %)))
                      addrs)]
      (r/ok v4))
    (catch UnknownHostException _
      (r/ok #{}))
    (catch Throwable t
      (r/err :dns/resolve-failed {:hostname hostname :cause (str t)}))))

(defrecord InetAddressResolver [timeout-ms]
  port/IDnsResolver
  (-resolve-a [_ hostname]
    (let [fut-r (weave/safe-future-call
                 {:timeout-ms timeout-ms :name (str "dns/resolve " hostname)}
                 #(resolve-once hostname))]
      (if (r/ok? fut-r)
        (:ok fut-r)
        (r/err :dns/timeout {:hostname hostname :timeout-ms timeout-ms})))))

(defn make-resolver
  "Build the default DNS resolver. timeout-ms defaults to 3000."
  ([]             (->InetAddressResolver 3000))
  ([timeout-ms]   (->InetAddressResolver timeout-ms)))
