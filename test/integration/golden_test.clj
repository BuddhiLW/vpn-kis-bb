(ns integration.golden-test
  "Golden-file parity: bb's pure generators must produce byte-equal
   output to the snapshotted reference files under test/integration/
   golden/. Any drift in domain.rules or domain.split surfaces here
   first."
  (:require [clojure.test :refer [deftest is testing]]
            [babashka.fs :as fs]
            [vpn-kis-bb.domain.rules :as rules]
            [vpn-kis-bb.domain.split :as split]))

(def golden-dir "test/integration/golden")

(defn- read-golden [name]
  (let [p (str golden-dir "/" name)]
    (when (fs/exists? p) (slurp p))))

;; ---------------------------------------------------------------- before.rules

(deftest before-rules-permissive-wlan0
  (is (= (read-golden "before-rules-permissive-wlan0.txt")
         (rules/before-rules-text {:mode :permissive :physical-iface "wlan0"}))))

(deftest before-rules-strict-eth0
  (is (= (read-golden "before-rules-strict-eth0.txt")
         (rules/before-rules-text {:mode :strict :physical-iface "eth0"
                                   :ipset-name "vpn_endpoints"}))))

(deftest before-rules-with-lan-allow
  (is (= (read-golden "before-rules-permissive-lan.txt")
         (rules/before-rules-text {:mode :permissive
                                   :physical-iface "wlan0"
                                   :lan-allow ["192.168.100.0/24"]}))))

;; ---------------------------------------------------------------- split

(def example-cfg
  (:value (split/validate {:name "example"
                           :domains ["*.example.com" "other.example.org"]
                           :dev "tun-example"
                           :priority 5089})))

(deftest split-systemd-unit-byte-parity
  (is (= (read-golden "split-systemd-example.service")
         (split/systemd-unit-text example-cfg))))

(deftest split-dnsmasq-drop-in-byte-parity
  (is (= (read-golden "split-dnsmasq-example.conf")
         (split/dnsmasq-drop-in-text example-cfg))))

(deftest split-up-script-byte-parity
  (is (= (read-golden "split-up-example.sh")
         (split/openvpn-up-script-text example-cfg))))

(deftest split-down-script-byte-parity
  (is (= (read-golden "split-down-example.sh")
         (split/openvpn-down-script-text example-cfg))))
