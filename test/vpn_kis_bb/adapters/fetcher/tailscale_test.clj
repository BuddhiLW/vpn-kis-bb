(ns vpn-kis-bb.adapters.fetcher.tailscale-test
  (:require [clojure.test :refer [deftest is testing]]
            [cheshire.core :as json]
            [vpn-kis-bb.adapters.fetcher.fixtures :as fx]
            [vpn-kis-bb.adapters.fetcher.tailscale :as ts]
            [vpn-kis-bb.ports.fetcher :as port]))

(def sample-derpmap
  {:Regions
   {"1" {:Nodes [{:IPv4 "199.38.181.92" :HostName "derp1.tailscale.com"}
                 {:IPv4 "203.0.113.10"  :HostName "derp1b.tailscale.com"}]}
    "2" {:Nodes [{:IPv4 "192.73.252.4"  :HostName "derp2.tailscale.com"}]}}})

(deftest parse-derpmap-test
  (let [out (ts/parse-derpmap-json sample-derpmap)]
    (is (= #{"199.38.181.92" "203.0.113.10" "192.73.252.4"}
           (:ips out)))
    (is (= ["derp1.tailscale.com" "derp1b.tailscale.com" "derp2.tailscale.com"]
           (:hostnames out)))))

(deftest fetch-tailscale-union
  (let [web (fx/web {"https://login.tailscale.com/derpmap/default"
                     (json/generate-string sample-derpmap)})
        dns (fx/rsv {"login.tailscale.com"       #{"168.220.85.51"}
                     "controlplane.tailscale.com" #{"168.220.85.52"}
                     "log.tailscale.io"           #{"168.220.85.53"}
                     "derp1.tailscale.com"        #{"199.38.181.92"}
                     "derp1b.tailscale.com"       #{"203.0.113.10"}
                     "derp2.tailscale.com"        #{"192.73.252.4"}})
        f   (ts/make web dns)
        r   (port/-fetch-ips f {})]
    (is (:ok r))
    (testing "includes bootstrap + derp + control"
      (is (contains? (-> r :ok :ips) "199.38.181.92"))   ; derp + bootstrap
      (is (contains? (-> r :ok :ips) "168.220.85.51"))   ; control plane
      (is (contains? (-> r :ok :ips) "134.122.74.153"))) ; from bootstrap edn
    (is (= :tailscale (-> r :ok :provider)))))

(deftest bootstrap-ips-load
  (is (set? (ts/load-bootstrap-ips)))
  (is (pos? (count (ts/load-bootstrap-ips)))))
