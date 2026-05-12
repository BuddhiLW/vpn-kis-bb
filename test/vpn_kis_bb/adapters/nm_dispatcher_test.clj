(ns vpn-kis-bb.adapters.nm-dispatcher-test
  (:require [clojure.test :refer [deftest is]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.nm-dispatcher :as nm]
            [vpn-kis-bb.adapters.shell-recording :as rec]))

(deftest hook-body-loaded-from-resource
  (let [s (nm/hook-body)]
    (is (string? s))
    (is (clojure.string/starts-with? s "#!/usr/bin/env bash"))
    (is (clojure.string/includes? s "ufw reload"))))

(deftest install-writes-and-chmods
  (let [shell (rec/make)
        writes (atom [])
        sys {:shell shell
             :write-fn (fn [p body] (swap! writes conj {:path p :body body}) (r/ok {:path p}))
             :delete-fn (fn [_] (r/ok {}))}
        r (nm/install! sys)]
    (is (r/ok? r))
    (is (= 1 (count @writes)))
    (is (= nm/dispatcher-path (-> @writes first :path)))
    (is (some (fn [{:keys [cmd]}] (= cmd ["chmod" "755" nm/dispatcher-path]))
              (rec/calls shell)))))
