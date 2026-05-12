(ns vpn-kis-bb.adapters.fetcher.mullvad-test
  (:require [clojure.test :refer [deftest is testing]]
            [cheshire.core :as json]
            [vpn-kis-bb.adapters.fetcher.fixtures :as fx]
            [vpn-kis-bb.adapters.fetcher.mullvad :as mullvad]
            [vpn-kis-bb.ports.fetcher :as port]))

(def sample-relays
  {:wireguard {:relays [{:ipv4_addr_in "10.0.0.1"}
                        {:ipv4_addr_in "10.0.0.2"}
                        {:ipv4_addr_in nil}]}
   :openvpn   {:relays [{:ipv4_addr_in "10.0.0.3"}]}
   :bridge    {:relays [{:ipv4_addr_in "10.0.0.4"}]}})

(deftest parse-relays-json-test
  (is (= #{"10.0.0.1" "10.0.0.2" "10.0.0.3" "10.0.0.4"}
         (mullvad/parse-relays-json sample-relays))))

(deftest fetch-mullvad-merges-api-ips
  (let [web (fx/web {"https://api.mullvad.net/app/v1/relays"
                     (json/generate-string sample-relays)})
        dns (fx/rsv {"api.mullvad.net" #{"45.83.220.1"}})
        f   (mullvad/make web dns)
        r   (port/-fetch-ips f {})]
    (is (:ok r))
    (testing "union of relay IPs + API host IPs"
      (is (= #{"10.0.0.1" "10.0.0.2" "10.0.0.3" "10.0.0.4" "45.83.220.1"}
             (-> r :ok :ips))))
    (is (= :mullvad (-> r :ok :provider)))))

(deftest fetch-mullvad-http-err
  (let [web (fx/web {})  ; no mappings
        dns (fx/rsv {})
        f   (mullvad/make web dns)
        r   (port/-fetch-ips f {})]
    (is (not (:ok r)))
    (is (= :fetcher/mullvad-http-failed (:error r)))))
