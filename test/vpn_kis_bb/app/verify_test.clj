(ns vpn-kis-bb.app.verify-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.app.verify :as v]))

(deftest parse-ufw-active?-test
  (is (true?  (v/parse-ufw-active? "Status: active\n")))
  (is (false? (v/parse-ufw-active? "Status: inactive\n")))
  (is (false? (v/parse-ufw-active? nil))))

(deftest parse-default-policies-test
  (let [s "Default: deny (incoming), deny (outgoing), deny (routed)"]
    (is (= {:incoming :deny :outgoing :deny :routed :deny}
           (v/parse-default-policies s))))
  (let [s "Default: allow (incoming), deny (outgoing)"]
    (is (= {:incoming :allow :outgoing :deny}
           (v/parse-default-policies s)))))

(deftest parse-drop-iface-test
  (let [s "-A ufw-before-output -o wlan0 -j DROP\n-A ufw-before-input -i wlan0 -j DROP\n"]
    (is (= "wlan0" (v/parse-drop-iface s))))
  (is (nil? (v/parse-drop-iface "no drop rule here"))))

(deftest parse-strict?-test
  (is (true?  (v/parse-strict? "-A ufw-before-output -m set --match-set vpn_endpoints dst -j ACCEPT")))
  (is (false? (v/parse-strict? "-A ufw-before-output -p udp --dport 53 -j ACCEPT"))))

(deftest parse-ipv6-disabled?-test
  (is (true?  (v/parse-ipv6-disabled? "1\n")))
  (is (false? (v/parse-ipv6-disabled? "0\n")))
  (is (false? (v/parse-ipv6-disabled? ""))))

(def ^:private strict-live
  {["sh" "-c" "ufw status verbose 2>/dev/null"]
   "Status: active\nDefault: deny (incoming), deny (outgoing), deny (routed)\n"
   ["sh" "-c" "iptables -S ufw-before-output 2>/dev/null"]
   (str "-A ufw-before-output -o wlan0 -m set --match-set vpn_endpoints dst -j ACCEPT\n"
        "-A ufw-before-output -o wlan0 -p udp -m udp --dport 53 -m set --match-set vpn_dns_bootstrap dst -j ACCEPT\n"
        "-A ufw-before-output -o wlan0 -j DROP\n")
   ["sh" "-c" "ipset list -name 2>/dev/null"]
   "vpn_endpoints\nvpn_dns_bootstrap\n"})

(defn- system [outputs files]
  {:shell   (rec/make {:respond (fn [cmd _] (when-let [out (get outputs cmd)] {:stdout out}))})
   :read-fn (fn [p] (get files p))})

(defn- check [checks check-name]
  (first (filter #(= check-name (:name %)) checks)))

(deftest verify-strict-install
  (let [res    (v/verify (system strict-live {"/proc/sys/net/ipv6/conf/all/disable_ipv6" "1\n"}))
        checks (-> res :ok :checks)]
    (is (true? (-> res :ok :ok?)))
    (is (empty? (-> res :ok :failed)))
    (is (= {:pinned-iface "wlan0"} (:detail (check checks "Killswitch DROP rule present"))))
    (is (:pass? (check checks "Strict mode (ipset-locked)")))
    (is (:pass? (check checks "vpn_dns_bootstrap ipset present (strict-mode DNS, port 53 only)")))))

(deftest verify-reads-through-read-fn
  (testing "an absent IPv6 stack passes, as in bash"
    (let [checks (v/run-checks (system strict-live {}))]
      (is (:pass? (check checks "IPv6 disabled")))
      (is (= {:disable_ipv6 :absent} (:detail (check checks "IPv6 disabled"))))))
  (testing "IPv6 still on fails the run"
    (let [res (v/verify (system strict-live {"/proc/sys/net/ipv6/conf/all/disable_ipv6" "0\n"}))]
      (is (false? (-> res :ok :ok?)))
      (is (= ["IPv6 disabled"] (mapv :name (-> res :ok :failed)))))))

(deftest verify-permissive-and-down
  (let [res (v/verify (system {} {"/proc/sys/net/ipv6/conf/all/disable_ipv6" "1"}))
        checks (-> res :ok :checks)]
    (testing "UFW off and no DROP rule fail; informational checks never do"
      (is (= #{"UFW active" "Default outgoing policy deny" "Killswitch DROP rule present"}
             (set (map :name (-> res :ok :failed)))))
      (is (not (:pass? (check checks "vpn_endpoints ipset present")))))))
