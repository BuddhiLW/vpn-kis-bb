(ns vpn-kis-bb.adapters.shell-recording-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.shell-recording :as rec]))

(deftest records-calls
  (let [s (rec/make)]
    (proto/shell-exec! s ["ipset" "create" "foo"] {})
    (proto/shell-exec! s ["ip" "rule" "show"] {})
    (let [c (rec/calls s)]
      (is (= 2 (count c)))
      (is (= ["ipset" "create" "foo"] (-> c first :cmd)))
      (is (= ["ip" "rule" "show"] (-> c second :cmd))))))

(deftest default-ok-response
  (let [s (rec/make)
        r (proto/shell-exec! s ["true"] {})]
    (is (= 0 (-> r :ok :exit)))
    (is (= "" (-> r :ok :stdout)))))

(deftest response-override
  (let [s (rec/make {:responses {"ip" {:exit 0 :stdout "5199:\tfwmark 0x6d6f6c65 lookup 5099\n"}}})
        r (proto/shell-exec! s ["ip" "rule" "show"] {})]
    (is (= 0 (-> r :ok :exit)))
    (is (re-find #"fwmark" (-> r :ok :stdout)))))

(deftest reset-empties-log
  (let [s (rec/make)]
    (proto/shell-exec! s ["x"] {})
    (rec/reset! s)
    (is (= [] (rec/calls s)))))
