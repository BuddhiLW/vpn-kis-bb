(ns vpn-kis-bb.app.verify-test
  (:require [clojure.test :refer [deftest is testing]]
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
