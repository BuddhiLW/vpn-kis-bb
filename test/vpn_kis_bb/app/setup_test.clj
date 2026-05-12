(ns vpn-kis-bb.app.setup-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.firewall-ufw :as fw]
            [vpn-kis-bb.adapters.ipset-shell :as ipset]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.app.setup :as setup]))

(defn- recording-system []
  (let [shell  (rec/make {:responses {"sh" {:exit 0 :stdout "wlan0\n"}}})
        writes (atom [])
        wf     (fn [p body] (swap! writes conj {:path p :body body}) (r/ok {:path p}))]
    {:system {:shell shell
              :firewall (fw/make shell {:write-fn wf
                                        :read-fn (fn [_] (r/err :no {}))})
              :ipset    (ipset/make shell)}
     :shell shell
     :writes writes}))

(deftest build-plan-permissive
  (let [p (setup/build-plan {:mode :permissive
                             :physical-iface "wlan0"
                             :lan-allow ["192.168.1.0/24"]})]
    (is (= :permissive (:mode p)))
    (is (= "wlan0"     (:physical-iface p)))
    (is (= ["192.168.1.0/24"] (:lan-allow p)))
    (is (not (contains? p :ipset-name)))))

(deftest build-plan-strict
  (let [p (setup/build-plan {:mode :strict
                             :physical-iface "eth0"})]
    (is (= "vpn_endpoints" (:ipset-name p)))))

(deftest setup-permissive-dry-run
  (let [{:keys [system]} (recording-system)
        r (setup/setup! system {:mode :permissive
                                :dry-run? true
                                :physical-iface "wlan0"})]
    (is (r/ok? r))
    (is (true? (-> r :ok :dry-run?)))
    (is (str/includes? (-> r :ok :before-rules) "*filter"))))

(deftest detect-physical-iface-parses-default
  (let [{:keys [system]} (recording-system)
        r (setup/detect-physical-iface system)]
    (is (= "wlan0" (:ok r)))))
