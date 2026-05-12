(ns vpn-kis-bb.adapters.dns-test
  "Adapter test that goes against real DNS. Tagged :integration so unit
   runs can opt out when offline."
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.adapters.dns-inetaddress :as dns]
            [vpn-kis-bb.ports.dns :as port]
            [vpn-kis-bb.domain.util :as u]))

(def online?
  (try
    (let [r (port/-resolve-a (dns/make-resolver 2000) "one.one.one.one")]
      (boolean (and (:ok r) (seq (:ok r)))))
    (catch Throwable _ false)))

(deftest resolve-real-host
  (testing "well-known host returns at least one IPv4"
    (when-not online?
      (println "  [skip] offline — dns resolution unavailable"))
    (when online?
      (let [r (port/-resolve-a (dns/make-resolver 3000) "one.one.one.one")]
        (is (= :ok (first (find r :ok))))
        (is (every? u/ipv4? (:ok r)))
        (is (contains? (:ok r) "1.1.1.1"))))))

(deftest resolve-nxdomain
  (testing "NXDOMAIN returns ok with empty set"
    (when online?
      (let [r (port/-resolve-a (dns/make-resolver 2000)
                               "this-host-definitely-does-not-exist-vpn-kis.invalid")]
        (is (= :ok (first (find r :ok))))
        (is (= #{} (:ok r)))))))
