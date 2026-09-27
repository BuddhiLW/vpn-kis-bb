(ns vpn-kis-bb.domain.rules-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [vpn-kis-bb.domain.rules :as r]
            [vpn-kis-bb.domain.re :as rx]))

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

(defn- lines [s] (rx/split-lines* s))

(defn- index-of-line [out line]
  (first (keep-indexed (fn [i l] (when (= l line) i)) (lines out))))

(deftest strict-test
  (let [out (r/before-rules-text {:physical-iface "eth0"
                                  :mode :strict
                                  :ipset-name "vpn_endpoints"
                                  :endpoint-count 2})]
    (testing "one any-port ACCEPT to the endpoint set (the bash strict rule)"
      (is (some #{"-A ufw-before-output -o eth0 -m set --match-set vpn_endpoints dst -j ACCEPT"}
                (lines out)))
      (is (str/includes? out "(ipset vpn_endpoints: 2 IPs; STRICT_PORTS=1 for the old port lock)")))
    (testing "no per-port lock by default"
      (is (not (str/includes? out "--dport 51820 -m set"))))
    (testing "no permissive DNS or HTTPS hole"
      (is (not (str/includes? out "-p udp --dport 53 -j ACCEPT")))
      (is (not (str/includes? out "--dport 443 -j ACCEPT"))))
    (testing "no DNS bootstrap section without a set name"
      (is (not (str/includes? out "vpn_dns_bootstrap"))))
    (testing "kill-switch DROP exactly once"
      (is (= 1 (count (filter #{"-A ufw-before-output -o eth0 -j DROP"} (lines out))))))))

(deftest strict-ports-test
  (let [out (r/before-rules-text {:physical-iface "eth0" :mode :strict
                                  :ipset-name "vpn_endpoints" :endpoint-count 1
                                  :strict-ports? true})]
    (testing "STRICT_PORTS=1 keeps the legacy lock: set members on the VPN ports only"
      (is (str/includes? out "-A ufw-before-output -o eth0 -p udp --dport 51820 -m set --match-set vpn_endpoints dst -j ACCEPT"))
      (is (str/includes? out "-A ufw-before-output -o eth0 -p tcp --dport 443 -m set --match-set vpn_endpoints dst -j ACCEPT"))
      (is (str/includes? out "# --- VPN tunnel ports (locked to ipset vpn_endpoints: 1 IPs) ---")))
    (testing "no any-port rule"
      (is (not (some #{"-A ufw-before-output -o eth0 -m set --match-set vpn_endpoints dst -j ACCEPT"}
                     (lines out)))))))

(deftest strict-dns-bootstrap-test
  (let [out (r/before-rules-text {:physical-iface "eth0" :mode :strict
                                  :ipset-name "vpn_endpoints" :endpoint-count 2
                                  :dns-ipset-name "vpn_dns_bootstrap" :dns-count 3})
        udp "-A ufw-before-output -o eth0 -p udp --dport 53 -m set --match-set vpn_dns_bootstrap dst -j ACCEPT"
        tcp "-A ufw-before-output -o eth0 -p tcp --dport 53 -m set --match-set vpn_dns_bootstrap dst -j ACCEPT"]
    (testing "bootstrap resolvers reachable on udp and tcp 53 only"
      (is (some #{udp} (lines out)))
      (is (some #{tcp} (lines out)))
      (is (= 2 (count (filter #(str/includes? % "vpn_dns_bootstrap dst") (lines out))))))
    (testing "after the endpoint rule, before the VPN interfaces and the DROP"
      (let [ep   (index-of-line out "-A ufw-before-output -o eth0 -m set --match-set vpn_endpoints dst -j ACCEPT")
            dns  (index-of-line out udp)
            drop (index-of-line out "-A ufw-before-output -o eth0 -j DROP")]
        (is (< ep dns drop))))
    (testing "STRICT_PORTS=1 keeps the port-53 bootstrap rules"
      (let [legacy (r/before-rules-text {:physical-iface "eth0" :mode :strict
                                         :ipset-name "vpn_endpoints" :strict-ports? true
                                         :dns-ipset-name "vpn_dns_bootstrap"})]
        (is (some #{udp} (lines legacy)))
        (is (str/includes? legacy "(ipset vpn_dns_bootstrap) ---"))))
    (testing "permissive mode ignores the DNS set (port 53 is open to any host)"
      (is (not (str/includes? (r/before-rules-text {:physical-iface "eth0" :mode :permissive
                                                     :dns-ipset-name "vpn_dns_bootstrap"})
                              "vpn_dns_bootstrap"))))))

(deftest exclude-block-test
  (let [out  (r/before-rules-text {:physical-iface "wlan0" :mode :permissive :exclude? true})
        acc  "-A ufw-before-output -o wlan0 -m mark --mark 0x51 -j ACCEPT"
        drop "-A ufw-before-output -o wlan0 -j DROP"]
    (testing "the exclusion ACCEPT comes right before the kill-switch section"
      (is (some #{acc} (lines out)))
      (is (< (index-of-line out acc) (index-of-line out drop))))
    (testing "absent unless enabled"
      (is (not (str/includes? (r/before-rules-text {:physical-iface "wlan0" :mode :permissive})
                              "--mark 0x51"))))))

(deftest lan-allow-test
  (let [out (r/before-rules-text {:physical-iface "eth0"
                                  :mode :permissive
                                  :lan-allow ["192.168.100.0/24"]})]
    (is (str/includes? out "-A ufw-before-output -o eth0 -d 192.168.100.0/24 -j ACCEPT"))
    (is (str/includes? out "-A ufw-before-input  -i eth0 -s 192.168.100.0/24 -j ACCEPT"))
    (testing "after NTP and before the pre-tunnel rules, as in bash"
      (is (< (index-of-line out "-A ufw-before-output -o eth0 -p udp --dport 123 -j ACCEPT")
             (index-of-line out "-A ufw-before-output -o eth0 -d 192.168.100.0/24 -j ACCEPT")
             (index-of-line out "-A ufw-before-output -o eth0 -p udp --dport 53 -j ACCEPT"))))))

(deftest mode-required-test
  (is (thrown? clojure.lang.ExceptionInfo
               (r/before-rules-text {:physical-iface "eth0"})))
  (is (thrown? clojure.lang.ExceptionInfo
               (r/before-rules-text {:physical-iface "eth0" :mode :open}))))

(deftest strict-requires-ipset-test
  (is (thrown? clojure.lang.ExceptionInfo
               (r/before-rules-text {:physical-iface "eth0" :mode :strict}))))

(deftest physical-iface-required
  (is (thrown? clojure.lang.ExceptionInfo
               (r/before-rules-text {:mode :permissive}))))
