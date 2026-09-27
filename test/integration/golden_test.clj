(ns integration.golden-test
  "Golden-file parity: bb's pure generators must produce byte-equal
   output to the snapshotted reference files under test/integration/
   golden/. Any drift in domain.rules or domain.split surfaces here
   first. The before.rules goldens without a DNS bootstrap section are
   the output of the bash add_killswitch_before_rules (run under the
   vpn-kis stub harness) for the same inputs."
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
  (testing "bash VPN_ENDPOINTS=\"1.2.3.4 5.6.7.8\": any port to the endpoint set"
    (is (= (read-golden "before-rules-strict-eth0.txt")
           (rules/before-rules-text {:mode :strict :physical-iface "eth0"
                                     :ipset-name "vpn_endpoints" :endpoint-count 2})))))

(deftest before-rules-strict-ports
  (testing "bash STRICT_PORTS=1 VPN_ENDPOINTS=1.2.3.4: the legacy per-port lock"
    (is (= (read-golden "before-rules-strict-ports.txt")
           (rules/before-rules-text {:mode :strict :physical-iface "eth0"
                                     :ipset-name "vpn_endpoints" :endpoint-count 1
                                     :strict-ports? true})))))

(deftest before-rules-strict-dns-bootstrap-lan
  (testing "strict + LAN + DNS bootstrap set (port 53 only)"
    (is (= (read-golden "before-rules-strict-dns-lan.txt")
           (rules/before-rules-text {:mode :strict :physical-iface "eth0"
                                     :ipset-name "vpn_endpoints" :endpoint-count 2
                                     :lan-allow ["192.168.100.0/24"]
                                     :dns-ipset-name "vpn_dns_bootstrap" :dns-count 3})))))

(deftest before-rules-permissive-exclude
  (testing "cgroup exclusion enabled: the ACCEPT block sits right before the DROP"
    (is (= (read-golden "before-rules-permissive-exclude.txt")
           (rules/before-rules-text {:mode :permissive :physical-iface "wlan0"
                                     :exclude? true})))))

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
