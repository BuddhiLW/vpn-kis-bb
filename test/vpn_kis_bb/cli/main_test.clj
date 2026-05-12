(ns vpn-kis-bb.cli.main-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.cli.main :as main]))

(deftest parse-args-no-cmd-defaults-help
  (is (= "help" (:cmd (main/parse-args [])))))

(deftest parse-args-dry-run-flag
  (let [p (main/parse-args ["--dry-run" "fetch" "mullvad"])]
    (is (true? (-> p :global-opts :dry-run)))
    (is (= "fetch" (:cmd p)))
    (is (= ["mullvad"] (:cmd-args p)))))

(deftest parse-args-split-subcommand
  (let [p (main/parse-args ["split" "add" "funeraria"])]
    (is (= "split" (:cmd p)))
    (is (= ["add" "funeraria"] (:cmd-args p)))))

(deftest parse-args-providers-multi
  (let [p (main/parse-args ["providers" "mullvad" "airvpn" "tailscale"])]
    (is (= "providers" (:cmd p)))
    (is (= ["mullvad" "airvpn" "tailscale"] (:cmd-args p)))))

(deftest commands-table-covers-bash-set
  (let [keys (set (keys main/commands))]
    (doseq [c ["setup" "fetch" "providers" "auto" "detect" "split" "help"]]
      (is (contains? keys c) (str "missing dispatch for " c)))))
