(ns vpn-kis-bb.app.unlock-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.ipset-shell :as ipset]
            [vpn-kis-bb.app.unlock :as unlock]))

(deftest unlock-dry-run-without-backup
  ;; latest-backup is nil when no /etc/ufw/backup-* exists on this host.
  ;; Force the err path by passing a system that won't be used.
  (let [sys {:shell    (rec/make)
             :ipset    (ipset/make (rec/make))
             :write-fn (fn [_ _] (r/ok {}))
             :delete-fn (fn [_]   (r/ok {}))}]
    (with-redefs [unlock/latest-backup (constantly nil)]
      (let [r (unlock/unlock! sys {:dry-run? false})]
        (is (r/err? r))
        (is (= :unlock/no-backup (:error r)))))))

(deftest unlock-dry-run-with-backup
  (let [sys {:shell    (rec/make)
             :ipset    (ipset/make (rec/make))
             :write-fn (fn [_ _] (r/ok {}))
             :delete-fn (fn [_]   (r/ok {}))}]
    (with-redefs [unlock/latest-backup (constantly "/etc/ufw/backup-20260512-001")]
      (let [r (unlock/unlock! sys {:dry-run? true})]
        (is (r/ok? r))
        (is (true? (-> r :ok :dry-run?)))
        (is (= "/etc/ufw/backup-20260512-001" (-> r :ok :backup)))
        (is (some #(clojure.string/ends-with? % "before.rules")
                  (-> r :ok :will-restore)))))))
