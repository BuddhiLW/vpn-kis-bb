(ns vpn-kis-bb.adapters.fetcher.custom-test
  (:require [clojure.test :refer [deftest is testing]]
            [babashka.fs :as fs]
            [vpn-kis-bb.adapters.fetcher.fixtures]  ;; ensure fixtures load even if unused here (test-runner discovery)
            [vpn-kis-bb.adapters.fetcher.custom :as custom]
            [vpn-kis-bb.ports.fetcher :as port]))

(defn with-tmp-dir [f]
  (let [dir (fs/create-temp-dir {:prefix "vpn-kis-bb-test-"})]
    (try (f (str dir)) (finally (fs/delete-tree dir)))))

(deftest reads-ips-file
  (with-tmp-dir
    (fn [dir]
      (spit (str dir "/myvpn.ips")
            "# header\n10.0.0.1\n10.0.0.2\n\nbogus\n10.0.0.1\n")
      (let [f (custom/make "myvpn" dir)
            r (port/-fetch-ips f {})]
        (is (:ok r))
        (is (= #{"10.0.0.1" "10.0.0.2"} (-> r :ok :ips)))
        (is (= :myvpn (-> r :ok :provider)))))))

(deftest missing-file-errs
  (with-tmp-dir
    (fn [dir]
      (let [f (custom/make "absent" dir)
            r (port/-fetch-ips f {})]
        (is (not (:ok r)))
        (is (= :fetcher/no-cache (:error r)))))))

(deftest supports-test
  (let [f (custom/make "foo")]
    (is (port/-supports? f "foo"))
    (is (port/-supports? f :foo))
    (is (not (port/-supports? f "bar")))))
