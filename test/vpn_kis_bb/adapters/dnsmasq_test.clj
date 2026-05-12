(ns vpn-kis-bb.adapters.dnsmasq-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.dnsmasq-shell :as dnsmasq]
            [vpn-kis-bb.ports.dnsmasq :as port]))

(defn- cmds [shell] (mapv :cmd (rec/calls shell)))

(defn- recording-fs []
  (let [writes  (atom [])
        deletes (atom [])
        d       (dnsmasq/make
                 (rec/make)
                 {:write-fn  (fn [p body] (swap! writes  conj {:path p :body body}) (r/ok {:path p}))
                  :delete-fn (fn [p]       (swap! deletes conj p) (r/ok {:path p}))})]
    {:d d :writes writes :deletes deletes}))

(deftest write-drop-in
  (let [{:keys [d writes]} (recording-fs)]
    (port/-write-drop-in! d "vpn-kis-split-foo.conf" "ipset=/example.com/foo\n")
    (is (= 1 (count @writes)))
    (is (= "/etc/dnsmasq.d/vpn-kis-split-foo.conf" (-> @writes first :path)))
    (is (clojure.string/includes? (-> @writes first :body) "ipset="))))

(deftest reload-via-systemctl-when-active
  (let [s (rec/make {:responses {"systemctl" {:exit 0}}})
        d (dnsmasq/make s)]
    (port/-reload! d)
    (is (= [["systemctl" "is-active" "--quiet" "dnsmasq"]
            ["systemctl" "reload" "dnsmasq"]]
           (cmds s)))))

(deftest reload-via-pkill-when-pgrep-finds-it
  (let [calls (atom 0)
        s (rec/make {:responses {"systemctl" {:exit 3}
                                 "pgrep"     {:exit 0}}})
        d (dnsmasq/make s)]
    (port/-reload! d)
    (let [c (cmds s)]
      (is (= ["systemctl" "is-active" "--quiet" "dnsmasq"] (first c)))
      (is (= ["pgrep" "-x" "dnsmasq"] (second c)))
      (is (= ["pkill" "-HUP" "-x" "dnsmasq"] (nth c 2))))))

(deftest reload-no-process-is-ok-with-hint
  (let [s (rec/make {:responses {"systemctl" {:exit 3}
                                 "pgrep"     {:exit 1}}})
        d (dnsmasq/make s)
        r (port/-reload! d)]
    (is (r/ok? r))
    (is (false? (-> r :ok :reloaded?)))
    (is (clojure.string/includes? (-> r :ok :hint) "no dnsmasq"))))
