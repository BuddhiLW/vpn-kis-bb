(ns vpn-kis-bb.app.providers-test
  (:require [clojure.test :refer [deftest is testing]]
            [babashka.fs :as fs]
            [vpn-kis-bb.app.providers :as providers]))

(defn- with-tmp [f]
  (let [d (fs/create-temp-dir {:prefix "vpn-kis-bb-pv-"})]
    (try (f (str d)) (finally (fs/delete-tree d)))))

(deftest load-union-merges-files
  (with-tmp
    (fn [dir]
      (spit (str dir "/a.ips") "# header\n1.1.1.1\n8.8.8.8\n")
      (spit (str dir "/b.ips") "8.8.8.8\n9.9.9.9\n")
      (let [r (providers/load-union [:a :b] {:dir dir})]
        (is (:ok r))
        (is (= #{"1.1.1.1" "8.8.8.8" "9.9.9.9"}
               (-> r :ok :union)))
        (is (empty? (-> r :ok :missing)))))))

(deftest load-union-marks-missing
  (with-tmp
    (fn [dir]
      (spit (str dir "/a.ips") "1.1.1.1\n")
      (let [r (providers/load-union [:a :nope] {:dir dir})]
        (is (= #{"1.1.1.1"} (-> r :ok :union)))
        (is (= ["nope"] (-> r :ok :missing)))))))
