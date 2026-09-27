(ns vpn-kis-bb.cli.system-test
  (:require [babashka.fs :as fs]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.cli.system :as system]))

(defn- mode-of [path]
  (str/trim (:out (sh/sh "stat" "-c" "%a" (str path)))))

(deftest prod-write-replaces-atomically-and-keeps-the-mode
  (let [dir    (fs/create-temp-dir {:prefix "vpnkis-write"})
        target (str dir "/before.rules")
        write  (:write-fn (system/make-system {:profile :prod :env {}}))]
    (try
      (testing "a new file is created, parent dirs included"
        (let [nested (str dir "/etc/ufw/new.rules")]
          (is (r/ok? (write nested "a\n")))
          (is (= "a\n" (slurp nested)))))
      (testing "an existing file is replaced with its mode kept (sed -i parity)"
        (spit target "old\n")
        (sh/sh "chmod" "640" target)
        (is (r/ok? (write target "new\n")))
        (is (= "new\n" (slurp target)))
        (is (= "640" (mode-of target))))
      (testing "no temp file is left behind"
        (is (not (fs/exists? (str target ".vpn-kis-new")))))
      (finally
        (fs/delete-tree dir)))))

(deftest setup-hooks-are-wired
  (let [sys (system/make-system {:profile :dry-run :env {}})]
    (is (fn? (:install-tailscale! sys)))
    (is (fn? (:install-nm-dispatcher! sys)))))
