(ns vpn-kis-bb.adapters.dnsmasq-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.dnsmasq-shell :as dnsmasq]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.ports.dnsmasq :as port]))

(defn- cmds [shell] (mapv :cmd (rec/calls shell)))

(defn- recording-fs []
  (let [writes  (atom [])
        deletes (atom [])
        d       (dnsmasq/make
                 (rec/make)
                 {:write-fn  (fn [p body] (swap! writes conj {:path p :body body}) (r/ok {:path p}))
                  :delete-fn (fn [p] (swap! deletes conj p) (r/ok {:path p}))})]
    {:d d :writes writes :deletes deletes}))

(deftest write-and-remove-drop-in
  (let [{:keys [d writes deletes]} (recording-fs)]
    (port/-write-drop-in! d "vpn-kis-split-foo.conf" "ipset=/example.com/foo\n")
    (port/-remove-drop-in! d "vpn-kis-split-foo.conf")
    (is (= [{:path "/etc/dnsmasq.d/vpn-kis-split-foo.conf" :body "ipset=/example.com/foo\n"}]
           @writes))
    (is (= ["/etc/dnsmasq.d/vpn-kis-split-foo.conf"] @deletes))))

(deftest reload-via-systemctl-when-active
  (let [s (rec/make {:responses {"systemctl" {:exit 0}}})
        r (port/-reload! (dnsmasq/make s))]
    (is (= {:reloaded? true :via :systemctl-reload} (:ok r)))
    (is (= [["systemctl" "is-active" "--quiet" "dnsmasq"]
            ["systemctl" "reload" "dnsmasq"]]
           (cmds s)))))

(deftest reload-falls-back-to-restart
  (let [s (rec/make {:respond (fn [cmd _opts]
                                (when (= cmd ["systemctl" "reload" "dnsmasq"]) {:exit 1}))})
        r (port/-reload! (dnsmasq/make s))]
    (is (= :systemctl-restart (-> r :ok :via)))
    (is (= [["systemctl" "is-active" "--quiet" "dnsmasq"]
            ["systemctl" "reload" "dnsmasq"]
            ["systemctl" "restart" "dnsmasq"]]
           (cmds s)))))

(deftest reload-and-restart-failing-is-an-error
  (let [s (rec/make {:respond (fn [cmd _opts]
                                (when (#{["systemctl" "reload" "dnsmasq"]
                                         ["systemctl" "restart" "dnsmasq"]} cmd)
                                  {:exit 1 :stderr "Job failed"}))})
        r (port/-reload! (dnsmasq/make s))]
    (is (= :dnsmasq/reload-failed (:error r)))
    (is (str/includes? (:hint r) "reload and restart both failed"))
    (is (= "Job failed" (:stderr r)))))

(deftest reload-via-pkill-when-pgrep-finds-it
  (let [s (rec/make {:responses {"systemctl" {:exit 3}
                                 "pgrep"     {:exit 0}}})
        r (port/-reload! (dnsmasq/make s))]
    (is (= :sighup (-> r :ok :via)))
    (is (= [["systemctl" "is-active" "--quiet" "dnsmasq"]
            ["pgrep" "-x" "dnsmasq"]
            ["pkill" "-HUP" "-x" "dnsmasq"]]
           (cmds s)))))

(deftest reload-no-process-is-ok-with-hint
  (let [s (rec/make {:responses {"systemctl" {:exit 3}
                                 "pgrep"     {:exit 1}}})
        r (port/-reload! (dnsmasq/make s))]
    (is (r/ok? r))
    (is (false? (-> r :ok :reloaded?)))
    (is (str/includes? (-> r :ok :hint) "no dnsmasq"))))

(deftest preflight-checks
  (testing "directory present, resolved active, NM dnsmasq plugin present: fronted"
    (let [s (rec/make)]
      (is (= {:drop-in-dir? true :fronted? true} (:ok (port/-preflight (dnsmasq/make s)))))
      (is (= [["test" "-d" "/etc/dnsmasq.d"]
              ["systemctl" "is-active" "--quiet" "systemd-resolved"]
              ["test" "-f" "/etc/NetworkManager/conf.d/dnsmasq.conf"]]
             (cmds s)))))
  (testing "no /etc/dnsmasq.d: nothing else is checked"
    (let [s (rec/make {:respond (fn [cmd _opts] (when (= "test" (first cmd)) {:exit 1}))})]
      (is (= {:drop-in-dir? false :fronted? nil} (:ok (port/-preflight (dnsmasq/make s)))))
      (is (= 1 (count (cmds s))))))
  (testing "resolved active, no NM plugin, dnsmasq unit inactive: not fronted"
    (let [s (rec/make {:respond (fn [cmd _opts]
                                  (cond
                                    (= cmd ["test" "-f" "/etc/NetworkManager/conf.d/dnsmasq.conf"]) {:exit 1}
                                    (= cmd ["systemctl" "is-active" "--quiet" "dnsmasq"]) {:exit 3}))})]
      (is (= {:drop-in-dir? true :fronted? false} (:ok (port/-preflight (dnsmasq/make s)))))))
  (testing "resolved inactive: fronted, nothing more checked"
    (let [s (rec/make {:respond (fn [cmd _opts]
                                  (when (= cmd ["systemctl" "is-active" "--quiet" "systemd-resolved"])
                                    {:exit 3}))})]
      (is (true? (-> (port/-preflight (dnsmasq/make s)) :ok :fronted?)))
      (is (= 2 (count (cmds s)))))))
