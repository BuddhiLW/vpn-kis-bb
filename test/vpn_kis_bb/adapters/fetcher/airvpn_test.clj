(ns vpn-kis-bb.adapters.fetcher.airvpn-test
  (:require [clojure.test :refer [deftest is testing]]
            [babashka.fs :as fs]
            [cheshire.core :as json]
            [vpn-kis-bb.adapters.fetcher.fixtures :as fx]
            [vpn-kis-bb.adapters.fetcher.airvpn :as airvpn]
            [vpn-kis-bb.ports.endpoint-source :as src]
            [vpn-kis-bb.ports.fetcher :as port]))

(def ovpn-text
  "client
dev tun
remote earth3.vpn.airdns.org 443 tcp
remote 198.51.100.10 1194 udp
")

(def wg-text
  "[Interface]
PrivateKey = redacted
Address = 10.4.0.2/24
DNS = 10.4.0.1

[Peer]
PublicKey = redacted
Endpoint = earth3.vpn.airdns.org:1637
AllowedIPs = 0.0.0.0/0
")

;; A status payload exercising all four entry-IP slots plus nil/blank holes.
(def sample-status
  {:servers [{:ip_v4_in1 "10.0.0.1" :ip_v4_in2 "10.0.0.2"
              :ip_v4_in3 nil        :ip_v4_in4 nil}
             {:ip_v4_in1 "10.0.0.3" :ip_v4_in2 ""
              :ip_v4_in3 "10.0.0.4" :ip_v4_in4 nil}]})

(defn with-tmp-dir [f]
  (let [dir (fs/create-temp-dir {:prefix "vpn-kis-bb-air-"})]
    (try (f (str dir)) (finally (fs/delete-tree dir)))))

;; --- API (primary source) --------------------------------------------------

(deftest fetch-from-api-merges-host-ip
  (let [web (fx/web {airvpn/api-url (json/generate-string sample-status)})
        dns (fx/rsv {"airvpn.org" #{"104.20.0.1"}})
        f   (airvpn/make web dns)
        r   (port/-fetch-ips f {})]
    (is (:ok r))
    (testing "every server entry IP + API host IP, nils/blanks dropped"
      (is (= #{"10.0.0.1" "10.0.0.2" "10.0.0.3" "10.0.0.4" "104.20.0.1"}
             (-> r :ok :ips))))
    (is (= :airvpn (-> r :ok :provider)))
    (is (= airvpn/api-url (-> r :ok :source)))))

(deftest parses-status-entry-ips
  (is (= #{"10.0.0.1" "10.0.0.2" "10.0.0.3" "10.0.0.4"}
         (airvpn/parse-status-json sample-status))))

(deftest parse-status-json-drops-non-string-ips
  (testing "a numeric/garbage entry value is coerced+rejected, not thrown"
    (is (= #{"1.2.3.4" "5.6.7.8"}
           (airvpn/parse-status-json
            {:servers [{:ip_v4_in1 "1.2.3.4" :ip_v4_in2 192
                        :ip_v4_in3 nil       :ip_v4_in4 "5.6.7.8"}]})))))

;; --- AirvpnApiSource in isolation (each source is independently testable) --

(deftest api-source-malformed-json-errs
  (let [src* (airvpn/->AirvpnApiSource
              (fx/web {airvpn/api-url "this is not json {{{"}) (fx/rsv {}))
        r    (src/-endpoints src* {})]
    (is (not (:ok r)))
    (is (= :fetcher/airvpn-parse-failed (:error r)))))

(deftest api-source-empty-servers-returns-empty-set
  (testing "no real servers → empty ok set (NOT the lone bootstrap CDN IP)"
    (let [src* (airvpn/->AirvpnApiSource
                (fx/web {airvpn/api-url (json/generate-string {:servers []})})
                (fx/rsv {"airvpn.org" #{"104.20.0.1"}}))
          r    (src/-endpoints src* {})]
      (is (:ok r))
      (is (= #{} (:ok r))))))

;; --- Config scan (offline fallback) ----------------------------------------

(deftest falls-back-to-config-scan-when-api-down
  (with-tmp-dir
    (fn [dir]
      (spit (str dir "/server.ovpn") ovpn-text)
      (spit (str dir "/server.conf") wg-text)
      (let [web (fx/web {})                ; no mapping → API http error
            dns (fx/rsv {"earth3.vpn.airdns.org" #{"203.0.113.50" "203.0.113.51"}})
            f   (airvpn/make web dns [dir] nil)
            r   (port/-fetch-ips f {})]
        (is (:ok r))
        (testing "literal IP + resolved hostnames merged from local configs"
          (is (= #{"198.51.100.10" "203.0.113.50" "203.0.113.51"}
                 (-> r :ok :ips))))
        (is (= "scanned ovpn/wg configs" (-> r :ok :source)))))))

(deftest api-empty-servers-falls-back-to-scan
  (testing "API ok-but-empty (no servers, host unresolvable) → config scan"
    (with-tmp-dir
      (fn [dir]
        (spit (str dir "/server.ovpn") ovpn-text)
        (let [web (fx/web {airvpn/api-url (json/generate-string {:servers []})})
              dns (fx/rsv {"earth3.vpn.airdns.org" #{"203.0.113.50"}})] ; airvpn.org absent → unresolvable
          (let [f (airvpn/make web dns [dir] nil)
                r (port/-fetch-ips f {})]
            (is (:ok r))
            (is (= #{"198.51.100.10" "203.0.113.50"} (-> r :ok :ips)))
            (is (= "scanned ovpn/wg configs" (-> r :ok :source)))))))))

(deftest errs-when-api-down-and-no-configs
  (with-tmp-dir
    (fn [dir]
      (let [web (fx/web {})                ; API fails
            dns (fx/rsv {})
            f   (airvpn/make web dns [dir] nil)  ; empty dir → scan finds nothing
            r   (port/-fetch-ips f {})]
        (is (not (:ok r)))
        (is (= :fetcher/airvpn-no-configs (:error r)))))))

(deftest parse-helpers
  (is (= ["earth3.vpn.airdns.org" "198.51.100.10"]
         (airvpn/parse-ovpn-remotes ovpn-text)))
  (is (= ["earth3.vpn.airdns.org"]
         (airvpn/parse-wg-endpoints wg-text))))
