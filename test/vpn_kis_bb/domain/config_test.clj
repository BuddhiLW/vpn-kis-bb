(ns vpn-kis-bb.domain.config-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.config :as c]))

(def legacy-sample
  "# comment
DOMAINS=\"*.example.com other.example.org\"
DEV=tun-example
TABLE=142
MARK=0x42
PRIORITY=auto
OVPN_CONFIG=/path/to.ovpn
")

(deftest parse-key-value-test
  (let [m (c/parse-key-value legacy-sample)]
    (is (= "*.example.com other.example.org" (:domains m)))
    (is (= "tun-example" (:dev m)))
    (is (= "142" (:table m)))
    (is (= "0x42" (:mark m)))
    (is (= "auto" (:priority m)))
    (is (= "/path/to.ovpn" (:ovpn-config m)))))

(deftest legacy->split-edn-test
  (let [out (c/legacy->split-edn (assoc (c/parse-key-value legacy-sample) :name "example"))]
    (is (= "example" (:name out)))
    (is (= ["*.example.com" "other.example.org"] (:domains out)))
    (is (= "tun-example" (:dev out)))
    (is (= 142 (:table out)))
    (is (= "0x42" (:mark out)))
    (is (= :auto (:priority out)))
    (is (= "/path/to.ovpn" (:ovpn-config out)))))
