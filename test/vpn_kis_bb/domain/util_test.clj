(ns vpn-kis-bb.domain.util-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.util :as u]))

(deftest ipv4?-test
  (testing "valid"
    (is (u/ipv4? "1.2.3.4"))
    (is (u/ipv4? "0.0.0.0"))
    (is (u/ipv4? "255.255.255.255"))
    (is (u/ipv4? "179.126.56.45")))
  (testing "invalid"
    (is (not (u/ipv4? "256.0.0.0")))
    (is (not (u/ipv4? "1.2.3")))
    (is (not (u/ipv4? "1.2.3.4.5")))
    (is (not (u/ipv4? "abc.def.ghi.jkl")))
    (is (not (u/ipv4? "")))
    (is (not (u/ipv4? nil)))))

(deftest normalize-ips-test
  (testing "strips blanks + comments + invalid; dedupes; sorts"
    (is (= #{"1.1.1.1" "8.8.8.8"}
           (u/normalize-ips ["1.1.1.1" "" "# comment" "8.8.8.8" "1.1.1.1" "bogus"]))))
  (testing "whitespace tolerance"
    (is (= #{"1.1.1.1"} (u/normalize-ips ["  1.1.1.1  "]))))
  (testing "empty input"
    (is (= #{} (u/normalize-ips nil)))
    (is (= #{} (u/normalize-ips [])))))

(deftest merge-ip-sets-test
  (is (= #{"1.1.1.1" "8.8.8.8" "9.9.9.9"}
         (u/merge-ip-sets ["1.1.1.1" "8.8.8.8"]
                          ["8.8.8.8" "9.9.9.9"]))))
