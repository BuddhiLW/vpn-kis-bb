(ns vpn-kis-bb.domain.priority-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.priority :as p]))

(def sample-output
  "0:      from all lookup local
5199:   not from all fwmark 0x6d6f6c65 lookup 5099
5270:   from all to 100.64.0.0/10 lookup 52
32766:  from all lookup main
32767:  from all lookup default")

(deftest parse-ip-rule-line-test
  (is (= {:priority 5199 :raw "not from all fwmark 0x6d6f6c65 lookup 5099"}
         (p/parse-ip-rule-line "5199:   not from all fwmark 0x6d6f6c65 lookup 5099")))
  (is (nil? (p/parse-ip-rule-line "")))
  (is (nil? (p/parse-ip-rule-line nil))))

(deftest parse-ip-rule-output-test
  (let [parsed (p/parse-ip-rule-output sample-output)]
    (is (= 5 (count parsed)))
    (is (= [0 5199 5270 32766 32767] (mapv :priority parsed)))))

(deftest mullvad-priority-test
  (is (= 5199 (p/mullvad-priority (p/parse-ip-rule-output sample-output))))
  (is (nil? (p/mullvad-priority [{:priority 0 :raw "from all lookup local"}]))))

(deftest choose-priority-test
  (testing "mullvad present → one below"
    (is (= 5198 (p/choose-priority (p/parse-ip-rule-output sample-output)))))
  (testing "mullvad absent → fallback"
    (is (= p/fallback-priority (p/choose-priority [])))))

(deftest choose-split-priority-test
  (testing "10 below the auxiliary priority"
    (is (= 5188 (p/choose-split-priority (p/parse-ip-rule-output sample-output)))))
  (testing "clamps to ≥1"
    (is (= 1 (p/choose-split-priority
              [{:priority 5 :raw "fwmark 0x6d6f6c65 lookup 5099"}])))))
