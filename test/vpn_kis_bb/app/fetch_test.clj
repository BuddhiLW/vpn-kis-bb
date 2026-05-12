(ns vpn-kis-bb.app.fetch-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.app.fetch :as fetch]
            [vpn-kis-bb.ports.fetcher :as port]))

(defrecord StubFetcher [pid ips]
  port/IProviderFetcher
  (-provider-id [_] pid)
  (-supports? [_ p] (= (name p) (name pid)))
  (-fetch-ips [_ _]
    (r/ok {:provider pid :ips ips :source :stub
           :fetched-at (java.time.Instant/now)})))

(defn- recording-system [provider-ips]
  (let [writes (atom [])
        write-fn (fn [p body] (swap! writes conj {:path p :body body}) (r/ok {:path p}))]
    {:system {:fetchers (into {} (for [[p ips] provider-ips]
                                   [p (->StubFetcher p ips)]))
              :write-fn write-fn}
     :writes writes}))

(deftest fetch-one-writes-ips-file
  (let [{:keys [system writes]} (recording-system
                                 {:mullvad #{"1.1.1.1" "8.8.8.8"}})
        r (fetch/fetch-one! system :mullvad)]
    (is (r/ok? r))
    (is (= 2 (-> r :ok :count)))
    (is (= "/etc/vpn-killswitch/providers/mullvad.ips"
           (-> r :ok :path)))
    (let [body (-> @writes first :body)]
      (is (clojure.string/includes? body "1.1.1.1"))
      (is (clojure.string/includes? body "8.8.8.8"))
      (is (clojure.string/includes? body "# mullvad server IPs")))))

(deftest fetch-one-unknown-provider
  (let [{:keys [system]} (recording-system {})
        r (fetch/fetch-one! system :nope)]
    (is (r/err? r))
    (is (= :fetch/unknown-provider (:error r)))))

(deftest fetch-many-parallel
  (let [{:keys [system writes]} (recording-system
                                 {:mullvad   #{"1.1.1.1"}
                                  :airvpn    #{"2.2.2.2"}
                                  :tailscale #{"3.3.3.3"}})
        r (fetch/fetch-many! system [:mullvad :airvpn :tailscale]
                             {:concurrency 3 :timeout-ms 5000})]
    (is (r/ok? r))
    (is (= 3 (count @writes)))
    (testing "each provider has its own .ips file"
      (let [paths (set (map :path @writes))]
        (is (contains? paths "/etc/vpn-killswitch/providers/mullvad.ips"))
        (is (contains? paths "/etc/vpn-killswitch/providers/airvpn.ips"))
        (is (contains? paths "/etc/vpn-killswitch/providers/tailscale.ips"))))))

(deftest ips-file-text-format
  (let [out (fetch/ips-file-text :foo #{"1.1.1.1" "0.0.0.0"})]
    (is (clojure.string/starts-with? out "# foo server IPs\n# Fetched: "))
    ;; sorted body
    (is (clojure.string/includes? out "0.0.0.0\n1.1.1.1"))))
