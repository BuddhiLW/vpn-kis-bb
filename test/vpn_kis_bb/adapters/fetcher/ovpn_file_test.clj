(ns vpn-kis-bb.adapters.fetcher.ovpn-file-test
  (:require [clojure.test :refer [deftest is]]
            [babashka.fs :as fs]
            [vpn-kis-bb.adapters.fetcher.fixtures :as fx]
            [vpn-kis-bb.adapters.fetcher.ovpn-file :as ovpn]
            [vpn-kis-bb.ports.fetcher :as port]))

(def sample-ovpn
  "client
dev tun
proto udp
remote example.vpn.host 1194 udp
remote example.vpn.host 443 tcp
remote 198.51.100.10 1194 udp
")

(deftest parse-remote-lines-test
  (is (= ["example.vpn.host" "198.51.100.10"]
         (ovpn/parse-remote-lines sample-ovpn))))

(deftest fetch-with-dns-resolution
  (let [tmp (fs/create-temp-file {:prefix "vpnkis-" :suffix ".ovpn"})]
    (try
      (spit (fs/file tmp) sample-ovpn)
      (let [resolver (fx/rsv {"example.vpn.host" #{"203.0.113.1" "203.0.113.2"}})
            f (ovpn/make :acme (str tmp) resolver)
            r (port/-fetch-ips f {})]
        (is (:ok r))
        (is (= #{"198.51.100.10" "203.0.113.1" "203.0.113.2"}
               (-> r :ok :ips))))
      (finally (fs/delete-if-exists tmp)))))

(deftest missing-ovpn-errs
  (let [resolver (fx/rsv {})
        f (ovpn/make :nowhere "/nonexistent.ovpn" resolver)
        r (port/-fetch-ips f {})]
    (is (not (:ok r)))
    (is (= :fetcher/no-ovpn (:error r)))))
