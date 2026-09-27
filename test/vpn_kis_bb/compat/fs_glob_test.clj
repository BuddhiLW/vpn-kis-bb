(ns vpn-kis-bb.compat.fs-glob-test
  "Pins the babashka.fs glob behaviour vpn-kis-bb relies on, so the cljw
   shim (cljw/babashka/fs.clj) and the real library cannot drift apart."
  (:require [babashka.fs :as fs]
            [clojure.test :refer [deftest is]]))

(defn- names [paths]
  (vec (sort (map #(str (fs/file-name %)) paths))))

(deftest glob-braces-wildcards-and-hidden-files
  (let [dir (str (fs/create-temp-dir {:prefix "vpnkis-glob"}))]
    (try
      (doseq [f ["a.conf" "b.edn" "c.txt" ".hidden.conf" "ab.conf"]]
        (spit (str dir "/" f) "x"))
      (is (= ["a.conf" "ab.conf" "b.edn"] (names (fs/glob dir "*.{edn,conf}"))))
      (is (= ["a.conf"] (names (fs/glob dir "?.conf"))))
      (is (= [] (names (fs/glob dir "*.nope"))))
      (finally
        (fs/delete-tree dir)))))
