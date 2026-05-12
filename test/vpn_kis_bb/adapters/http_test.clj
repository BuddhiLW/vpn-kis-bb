(ns vpn-kis-bb.adapters.http-test
  "Network-touching test (tag :integration) — gated on internet reachability."
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.adapters.http-jvm :as http]
            [vpn-kis-bb.ports.http :as port]))

(def online?
  (try
    (let [f (http/make-jvm-fetcher)
          r (port/-fetch f "https://api.mullvad.net/app/v1/relays" {:timeout-ms 5000})]
      (boolean (and (:ok r) (= 200 (-> r :ok :status)))))
    (catch Throwable _ false)))

(deftest fetch-real-url
  (when-not online?
    (println "  [skip] offline — http fetch unavailable"))
  (when online?
    (testing "200 OK + non-empty body"
      (let [f (http/make-jvm-fetcher)
            r (port/-fetch f "https://api.mullvad.net/app/v1/relays" {:timeout-ms 8000})]
        (is (:ok r))
        (is (= 200 (-> r :ok :status)))
        (is (pos? (-> r :ok :bytes)))))))
