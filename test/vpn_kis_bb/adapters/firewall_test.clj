(ns vpn-kis-bb.adapters.firewall-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.firewall-ufw :as fw]
            [vpn-kis-bb.ports.firewall :as port]))

(defn- cmds [shell] (mapv :cmd (rec/calls shell)))

(defn- recording-fs []
  (let [writes (atom [])
        reads  (atom [])
        rfn    (fn [p] (swap! reads conj p) (r/err :ufw/no-file {:path p}))
        wfn    (fn [p body] (swap! writes conj {:path p :body body}) (r/ok {:path p}))
        ufw    (fw/make (rec/make) {:write-fn wfn :read-fn rfn})]
    {:ufw ufw :writes writes :reads reads}))

(deftest dry-run-emits-rendered-text
  (let [{:keys [ufw]} (recording-fs)
        r (port/-apply-rules! ufw
                              {:physical-iface "wlan0" :mode :permissive}
                              {:dry-run? true})]
    (is (:ok r))
    (is (true? (-> r :ok :dry-run?)))
    (is (str/includes? (-> r :ok :before-rules) "*filter"))
    (is (str/includes? (-> r :ok :before-rules) "-j DROP"))))

(deftest apply-rules-writes-and-shells
  (let [shell (rec/make)
        writes (atom [])
        ufw (fw/make shell
                     {:write-fn (fn [p body]
                                  (swap! writes conj p)
                                  (r/ok {:path p}))
                      :read-fn (fn [_] (r/err :no-file {}))})
        r (port/-apply-rules! ufw
                              {:physical-iface "eth0"
                               :mode :strict
                               :ipset-name "vpn_endpoints"}
                              {})]
    (is (:ok r))
    (testing "writes both v4 and v6 before.rules"
      (is (some #{"/etc/ufw/before.rules"}  @writes))
      (is (some #{"/etc/ufw/before6.rules"} @writes)))
    (testing "issues expected ufw command sequence"
      (let [c (cmds shell)]
        (is (= ["ufw" "--force" "reset"]      (first c)))
        (is (= ["ufw" "default" "deny" "incoming"] (second c)))
        (is (= ["ufw" "default" "deny" "outgoing"] (nth c 2)))
        (is (some #{["ufw" "--force" "enable"]} c))
        (is (some #{["ufw" "reload"]} c))))))

(deftest skip-reset-preserves-existing-rules
  (let [shell (rec/make)
        ufw (fw/make shell
                     {:write-fn (fn [_ _] (r/ok {}))
                      :read-fn (fn [_] (r/err :no-file {}))})
        _ (port/-apply-rules! ufw
                              {:physical-iface "eth0" :mode :permissive}
                              {:skip-reset? true})]
    (is (not (some #{["ufw" "--force" "reset"]} (cmds shell))))))

(deftest reload-shells-out
  (let [{:keys [ufw]} (recording-fs)]
    (port/-reload! ufw)))
