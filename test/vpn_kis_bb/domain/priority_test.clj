(ns vpn-kis-bb.domain.priority-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.priority :as p]))

(def sample-output
  "0:      from all lookup local
5199:   not from all fwmark 0x6d6f6c65 lookup 1836018789
5270:   from all to 100.64.0.0/10 lookup 52
32766:  from all lookup main
32767:  from all lookup default")

(deftest parse-ip-rule-line-test
  (is (= {:priority 5199 :raw "not from all fwmark 0x6d6f6c65 lookup 5099"}
         (p/parse-ip-rule-line "5199:   not from all fwmark 0x6d6f6c65 lookup 5099")))
  (is (= {:priority 0 :raw "from all lookup local"}
         (p/parse-ip-rule-line "0:\tfrom all lookup local")))
  (testing "no priority, no selectors, junk"
    (is (nil? (p/parse-ip-rule-line "")))
    (is (nil? (p/parse-ip-rule-line nil)))
    (is (nil? (p/parse-ip-rule-line "5199:")))
    (is (nil? (p/parse-ip-rule-line ":  from all lookup main")))
    (is (nil? (p/parse-ip-rule-line "abc: from all lookup main")))
    (is (nil? (p/parse-ip-rule-line "-5: from all lookup main")))))

(deftest parse-ip-rule-output-test
  (let [parsed (p/parse-ip-rule-output sample-output)]
    (is (= 5 (count parsed)))
    (is (= [0 5199 5270 32766 32767] (mapv :priority parsed))))
  (is (= [] (p/parse-ip-rule-output nil))))

(deftest parse-is-stable-under-repetition
  ;; ClojureWasm 1.14.11 corrupts some regex results; the parse avoids them.
  (let [expected (p/parse-ip-rule-output sample-output)]
    (is (every? #(= expected %)
                (repeatedly 500 #(p/parse-ip-rule-output sample-output))))))

(deftest mullvad-priority-test
  (is (= 5199 (p/mullvad-priority (p/parse-ip-rule-output sample-output))))
  (is (nil? (p/mullvad-priority [{:priority 0 :raw "from all lookup local"}]))))

(deftest choose-priority-test
  (testing "one below Mullvad's fwmark rule"
    (is (= 5198 (p/choose-priority (p/parse-ip-rule-output sample-output)))))
  (testing "Mullvad absent, or at priority 1: fallback"
    (is (= p/fallback-priority (p/choose-priority [])))
    (is (= p/fallback-priority
           (p/choose-priority [{:priority 1 :raw "not from all fwmark 0x6d6f6c65 lookup 1"}])))))

(deftest choose-split-priority-test
  (testing "ten below the base: Mullvad at 5199 -> 5188"
    (is (= 5188 (p/choose-split-priority (p/parse-ip-rule-output sample-output)))))
  (testing "no Mullvad rule: bash SPLIT_RULE_PRIO_FALLBACK"
    (is (= 5090 p/split-fallback-priority))
    (is (= 5090 (p/choose-split-priority []))))
  (testing "a base of 11 or less falls back to 5090 (bash); a base of 12 gives 2"
    (is (= 5090 (p/choose-split-priority [{:priority 12 :raw "fwmark 0x6d6f6c65 lookup 1"}])))
    (is (= 5090 (p/choose-split-priority [{:priority 5 :raw "fwmark 0x6d6f6c65 lookup 1"}])))
    (is (= 2 (p/choose-split-priority [{:priority 13 :raw "fwmark 0x6d6f6c65 lookup 1"}])))))
