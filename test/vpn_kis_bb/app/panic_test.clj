(ns vpn-kis-bb.app.panic-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.app.panic :as panic]))

(deftest panic-dry-run-emits-plan
  (let [sys {:shell    (rec/make)
             :write-fn (fn [_ _] (r/ok {}))
             :delete-fn (fn [_]   (r/ok {}))}
        r (panic/panic! sys {:dry-run? true})]
    (is (r/ok? r))
    (is (true? (-> r :ok :dry-run?)))
    (is (pos? (count (-> r :ok :steps))))
    (is (some #(clojure.string/includes? % "ufw") (-> r :ok :steps)))
    (is (some #(clojure.string/includes? % "iptables") (-> r :ok :steps)))))

(deftest panic-real-iterates-recorded-shell
  (let [shell (rec/make {:responses {"ipset" {:exit 0 :stdout "vpn_endpoints\nvpnkis_split_foo_dst\n"}}})
        sys {:shell shell
             :write-fn (fn [_ _] (r/ok {}))
             :delete-fn (fn [_]   (r/ok {}))}
        r (panic/panic! sys {})
        cmds (mapv :cmd (rec/calls shell))]
    (is (r/ok? r))
    (testing "ufw disable issued"
      (is (some #{["ufw" "--force" "disable"]} cmds)))
    (testing "iptables flush issued for both v4 and v6"
      (is (some #(= ["iptables" "-t" "filter" "-F"] %) cmds))
      (is (some #(= ["ip6tables" "-t" "filter" "-F"] %) cmds)))
    (testing "ipset destroy for each enumerated set"
      (is (some #{["ipset" "destroy" "vpn_endpoints"]} cmds))
      (is (some #{["ipset" "destroy" "vpnkis_split_foo_dst"]} cmds)))
    (testing "NetworkManager restart attempted"
      (is (some #{["systemctl" "restart" "NetworkManager"]} cmds)))
    (testing "connectivity probe issued"
      (is (some (fn [c] (= "ping" (first c))) cmds)))))
