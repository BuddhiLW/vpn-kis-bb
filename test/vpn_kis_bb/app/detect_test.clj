(ns vpn-kis-bb.app.detect-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.app.detect :as detect]))

(deftest parse-wg-endpoints
  (let [s "tun-pedro PUBKEY1 198.51.100.10:51820\nfoo PUBKEY2 203.0.113.5:1637\n"]
    (is (= #{"198.51.100.10" "203.0.113.5"}
           (detect/parse-wg-endpoints s)))))

(deftest parse-ss-openvpn
  (let [s (str
           "udp ESTAB 0 0 192.168.1.5:50000 198.51.100.10:1194 users:((\"openvpn\",pid=123,fd=4))\n"
           "tcp ESTAB 0 0 127.0.0.1:5000 127.0.0.1:6000 users:((\"sshd\",pid=99,fd=3))\n")]
    (is (= #{"192.168.1.5" "198.51.100.10"} (detect/parse-ss-openvpn s)))))

(deftest parse-route-peers
  (let [s "10.0.0.0/24 via 198.51.100.10 dev tun0 metric 0\n192.168.1.0/24 dev wlan0 proto kernel\n"]
    (is (= #{"198.51.100.10"} (detect/parse-route-peers s)))))

(deftest detect-endpoints-merges-sources
  ;; All three sub-shells return canned output via the recording shell's
  ;; :responses (keyed by first token — here "sh" for the wrapper).
  (let [shell (rec/make {:responses {"sh" {:exit 0
                                           :stdout "tun-pedro PUBKEY 198.51.100.10:51820"}}})
        sys   {:shell shell}
        r     (detect/detect-endpoints sys)]
    (is (:ok r))
    ;; The same canned stdout flows to all 3 invocations, so only WG parser
    ;; finds a hit. We just assert that the parser is wired and the union
    ;; isn't empty.
    (is (contains? (:ok r) "198.51.100.10"))))
