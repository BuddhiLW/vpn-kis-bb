(ns vpn-kis-bb.adapters.fetcher.airvpn-test
  (:require [clojure.test :refer [deftest is testing]]
            [babashka.fs :as fs]
            [vpn-kis-bb.adapters.fetcher.fixtures :as fx]
            [vpn-kis-bb.adapters.fetcher.airvpn :as airvpn]
            [vpn-kis-bb.ports.fetcher :as port]))

(def ovpn-text
  "client
dev tun
remote earth3.vpn.airdns.org 443 tcp
remote 198.51.100.10 1194 udp
")

(def wg-text
  "[Interface]
PrivateKey = redacted
Address = 10.4.0.2/24
DNS = 10.4.0.1

[Peer]
PublicKey = redacted
Endpoint = earth3.vpn.airdns.org:1637
AllowedIPs = 0.0.0.0/0
")

(defn with-tmp-dir [f]
  (let [dir (fs/create-temp-dir {:prefix "vpn-kis-bb-air-"})]
    (try (f (str dir)) (finally (fs/delete-tree dir)))))

(deftest scans-ovpn-and-wg
  (with-tmp-dir
    (fn [dir]
      (spit (str dir "/server.ovpn") ovpn-text)
      (spit (str dir "/server.conf") wg-text)
      (let [resolver (fx/rsv {"earth3.vpn.airdns.org" #{"203.0.113.50" "203.0.113.51"}})
            f (airvpn/make resolver [dir] nil)
            r (port/-fetch-ips f {})]
        (is (:ok r))
        (testing "literal IP + resolved hostnames merged"
          (is (= #{"198.51.100.10" "203.0.113.50" "203.0.113.51"}
                 (-> r :ok :ips))))))))

(deftest empty-dirs-errs
  (with-tmp-dir
    (fn [dir]
      (let [resolver (fx/rsv {})
            f (airvpn/make resolver [dir] nil)
            r (port/-fetch-ips f {})]
        (is (not (:ok r)))
        (is (= :fetcher/airvpn-no-configs (:error r)))))))

(deftest parse-helpers
  (is (= ["earth3.vpn.airdns.org" "198.51.100.10"]
         (airvpn/parse-ovpn-remotes ovpn-text)))
  (is (= ["earth3.vpn.airdns.org"]
         (airvpn/parse-wg-endpoints wg-text))))
