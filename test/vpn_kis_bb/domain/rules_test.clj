(ns vpn-kis-bb.domain.rules-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [vpn-kis-bb.domain.rules :as r]))

(deftest permissive-test
  (let [out (r/before-rules-text {:physical-iface "wlan0" :mode :permissive})]
    (testing "structural anchors"
      (is (str/starts-with? out "*filter"))
      (is (str/ends-with? out "COMMIT\n")))
    (testing "loopback + conntrack"
      (is (str/includes? out "ufw-before-input -i lo -j ACCEPT"))
      (is (str/includes? out "ESTABLISHED,RELATED")))
    (testing "permissive pre-tunnel"
      (is (str/includes? out "-A ufw-before-output -o wlan0 -p udp --dport 53 -j ACCEPT"))
      (is (str/includes? out "-A ufw-before-output -o wlan0 -p tcp --dport 443 -j ACCEPT"))
      (is (str/includes? out "-A ufw-before-output -o wlan0 -p udp --dport 1194 -j ACCEPT")))
    (testing "kill-switch DROP at the end"
      (is (str/includes? out "-A ufw-before-output -o wlan0 -j DROP"))
      (is (str/includes? out "-A ufw-before-input  -i wlan0 -j DROP")))))

(deftest strict-test
  (let [out (r/before-rules-text {:physical-iface "eth0"
                                  :mode :strict
                                  :ipset-name "vpn_endpoints"})]
    (testing "ipset gating on pre-tunnel ports"
      (is (str/includes? out "-m set --match-set vpn_endpoints dst -j ACCEPT")))
    (testing "no permissive DNS hole"
      (is (not (str/includes? out "-p udp --dport 53 -j ACCEPT"))))))

(deftest lan-allow-test
  (let [out (r/before-rules-text {:physical-iface "eth0"
                                  :mode :permissive
                                  :lan-allow ["192.168.100.0/24"]})]
    (is (str/includes? out "-A ufw-before-output -o eth0 -d 192.168.100.0/24 -j ACCEPT"))
    (is (str/includes? out "-A ufw-before-input  -i eth0 -s 192.168.100.0/24 -j ACCEPT"))))

(deftest strict-requires-ipset-test
  (is (thrown? clojure.lang.ExceptionInfo
               (r/before-rules-text {:physical-iface "eth0" :mode :strict}))))

(deftest physical-iface-required
  (is (thrown? clojure.lang.ExceptionInfo
               (r/before-rules-text {:mode :permissive}))))
