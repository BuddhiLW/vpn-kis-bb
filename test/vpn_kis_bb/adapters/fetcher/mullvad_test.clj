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
    (testing "union of relay IPs + API host IPs + the builtin API IP"
      (is (= #{"10.0.0.1" "10.0.0.2" "10.0.0.3" "10.0.0.4" "45.83.220.1" "45.83.223.196"}
             (-> r :ok :ips))))
    (is (= :mullvad (-> r :ok :provider)))))

(def daemon-relays
  "Shape of /var/cache/mullvad-vpn/relays.json: relays nested per country
   and city, plus bridges."
  {:relays {:countries [{:name "Sweden"
                         :cities [{:name "Gothenburg"
                                   :relays [{:hostname "se-got-wg-001" :ipv4_addr_in "185.213.154.66"}
                                            {:hostname "se-got-wg-002" :ipv4_addr_in nil}]}]}]}
   :bridge {:relays [{:hostname "se-got-br-001" :ipv4_addr_in "185.213.154.117"}]}
   :wireguard {:port_ranges [[53 53] [4000 33433]] :ipv4_gateway "10.64.0.1"}
   :junk {:ipv4_addr_in "999.1.1.1"}})

(deftest fetch-mullvad-reads-the-daemon-caches
  (let [files {mullvad/cache-relays-path       (json/generate-string daemon-relays)
               mullvad/cache-api-endpoint-path "{\"address\":\"185.65.135.117:1082\",\"bridge\":null}"}
        read  (atom [])
        web   (fx/web {mullvad/api-url (json/generate-string sample-relays)})
        f     (mullvad/make web (fx/rsv {})
                            {:read-fn (fn [p] (swap! read conj p) (get files p))})
        r     (port/-fetch-ips f {})]
    (is (:ok r))
    (is (= #{"10.0.0.1" "10.0.0.2" "10.0.0.3" "10.0.0.4"      ; API relays
             "185.213.154.66" "185.213.154.117"                 ; daemon relay cache
             "185.65.135.117"                                   ; last API endpoint
             "45.83.223.196"}                                  ; builtin API IP
           (-> r :ok :ips)))
    (is (= [mullvad/cache-relays-path mullvad/cache-api-endpoint-path] @read))))

(deftest fetch-mullvad-without-read-fn-skips-the-caches
  (let [web (fx/web {mullvad/api-url (json/generate-string sample-relays)})
        r   (port/-fetch-ips (mullvad/make web (fx/rsv {}) {}) {})]
    (is (= #{"10.0.0.1" "10.0.0.2" "10.0.0.3" "10.0.0.4" "45.83.223.196"}
           (-> r :ok :ips)))))

(deftest fetch-mullvad-refuses-an-empty-or-bad-relay-list
  (testing "no relay in the list: error, so the cached .ips file is kept"
    (let [web (fx/web {mullvad/api-url (json/generate-string {:wireguard {:relays []}})})
          r   (port/-fetch-ips (mullvad/make web (fx/rsv {"api.mullvad.net" #{"45.83.223.193"}})) {})]
      (is (= :fetcher/mullvad-empty-relays (:error r)))
      (is (= mullvad/relay-list-failed-hint (:hint r)))))
  (testing "not JSON"
    (let [web (fx/web {mullvad/api-url "not json"})
          r   (port/-fetch-ips (mullvad/make web (fx/rsv {})) {})]
      (is (= :fetcher/mullvad-parse-failed (:error r)))
      (is (string? (:hint r))))))

(deftest cache-parsers
  (testing "every ipv4_addr_in, at any depth, valid IPv4 only"
    (is (= #{"185.213.154.66" "185.213.154.117"}
           (mullvad/cache-relay-ips (json/generate-string daemon-relays)))))
  (testing "missing or broken cache files add nothing"
    (is (= #{} (mullvad/cache-relay-ips nil)))
    (is (= #{} (mullvad/cache-relay-ips "")))
    (is (= #{} (mullvad/cache-relay-ips "{not json"))))
  (testing "api-endpoint: every dotted quad"
    (is (= #{"45.83.223.196" "185.65.135.117"}
           (mullvad/api-endpoint-ips "{\"a\":\"45.83.223.196:443\",\"b\":\"185.65.135.117:1082\",\"c\":\"1.2.3.999\"}")))
    (is (= #{} (mullvad/api-endpoint-ips nil)))))

(deftest fetch-mullvad-http-err
  (let [web (fx/web {})  ; no mappings
        dns (fx/rsv {})
        f   (mullvad/make web dns)
        r   (port/-fetch-ips f {})]
    (is (not (:ok r)))
    (is (= :fetcher/mullvad-http-failed (:error r)))))
