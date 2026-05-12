(ns vpn-kis-bb.adapters.systemd-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.ports.systemd :as port]))

(defn- cmds [shell] (mapv :cmd (rec/calls shell)))

(defn- recording-fs []
  (let [writes  (atom [])
        deletes (atom [])
        sys     (sd/make
                 (rec/make)
                 {:write-fn  (fn [p body] (swap! writes  conj {:path p :body body}) (r/ok {:path p}))
                  :delete-fn (fn [p]       (swap! deletes conj p) (r/ok {:path p}))})]
    {:sys sys :writes writes :deletes deletes}))

(deftest write-targets-systemd-dir
  (let [{:keys [sys writes]} (recording-fs)]
    (port/-write! sys "foo.service" "[Unit]\nDescription=foo\n")
    (is (= 1 (count @writes)))
    (is (= "/etc/systemd/system/foo.service" (-> @writes first :path)))
    (is (clojure.string/includes? (-> @writes first :body) "[Unit]"))))

(deftest remove-deletes-from-systemd-dir
  (let [{:keys [sys deletes]} (recording-fs)]
    (port/-remove! sys "foo.service")
    (is (= ["/etc/systemd/system/foo.service"] @deletes))))

(deftest enable-disable-reload
  (let [s (rec/make)
        i (sd/make s)]
    (port/-enable! i "foo.service")
    (port/-disable! i "bar.service")
    (port/-daemon-reload! i)
    (is (= [["systemctl" "enable" "foo.service"]
            ["systemctl" "disable" "--now" "bar.service"]
            ["systemctl" "daemon-reload"]]
           (cmds s)))))

(deftest active?-returns-bool
  (let [s (rec/make {:responses {"systemctl" {:exit 0}}})
        i (sd/make s)
        r (port/-active? i "foo.service")]
    (is (= true (:ok r))))
  (let [s (rec/make {:responses {"systemctl" {:exit 3}}})
        i (sd/make s)
        r (port/-active? i "foo.service")]
    (is (= false (:ok r)))))
