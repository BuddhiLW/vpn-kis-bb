(ns vpn-kis-bb.app.fetch-test
  (:require [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.app.fetch :as fetch]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.fetcher :as port]
            [vpn-kis-bb.ports.dns :as dns]))

(defrecord StubFetcher [pid ips]
  port/IProviderFetcher
  (-provider-id [_this] pid)
  (-supports? [_this p] (= (name p) (name pid)))
  (-fetch-ips [_this _opts]
    (r/ok {:provider pid :ips ips :source :stub
           :fetched-at (u/now-iso)})))

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

;; ---------------------------------------------------------------- fetch-provider!

(defn- stub-resolver
  "IDnsResolver answering from a hostname -> #{ip} map."
  [answers]
  (reify dns/IDnsResolver
    (-resolve-a [_this hostname] (r/ok (get answers hostname #{})))))

(defn- chain-system
  "System for fetch-provider!: fetchers from provider-ips (nil value =
   a fetcher that fails), files readable from `files`, writes recorded."
  [{:keys [provider-ips failing files answers]}]
  (let [writes (atom [])]
    {:writes writes
     :system {:fetchers (merge (into {} (for [[p ips] provider-ips]
                                          [p (->StubFetcher p ips)]))
                               (into {} (for [p failing]
                                          [p (reify port/IProviderFetcher
                                               (-provider-id [_this] p)
                                               (-supports? [_this q] (= (name q) (name p)))
                                               (-fetch-ips [_this _opts]
                                                 (r/err :fetcher/http {:hint "api down"})))])))
              :read-fn  (fn [path] (get files path))
              :write-fn (fn [path body] (swap! writes conj {:path path :body body}) (r/ok {:path path}))
              :dns      (stub-resolver answers)}}))

(deftest fetch-provider-builtin-writes-cache
  (let [{:keys [system writes]} (chain-system {:provider-ips {:mullvad #{"1.1.1.1" "8.8.8.8"}}})
        res (fetch/fetch-provider! system "mullvad")]
    (is (= 2 (-> res :ok :count)))
    (is (= "/etc/vpn-killswitch/providers/mullvad.ips" (:path (first @writes))))))

(deftest fetch-provider-builtin-empty-is-an-error
  (let [{:keys [system writes]} (chain-system {:provider-ips {:mullvad #{}}})
        res (fetch/fetch-provider! system :mullvad)]
    (is (= :fetch/no-ips (:error res)))
    (is (empty? @writes))))

(deftest fetch-provider-builtin-failure-keeps-cache
  (let [{:keys [system writes]} (chain-system {:failing [:mullvad]})
        res (fetch/fetch-provider! system :mullvad)]
    (is (= :fetcher/http (:error res)))
    (is (empty? @writes) "a failed fetch never overwrites the cache")))

(deftest fetch-provider-split-remotes-merge-previous
  (let [{:keys [system writes]}
        (chain-system {:files   {"/etc/vpn-killswitch/split/corp.conf"
                                 "NAME=corp\nOVPN_CONFIG = \"/etc/openvpn/corp.ovpn\"\n"
                                 "/etc/openvpn/corp.ovpn"
                                 "client\nremote 203.0.113.7 1194\nremote vpn.corp.example 443\n"
                                 "/etc/vpn-killswitch/providers/corp.ips"
                                 "# corp server IPs\n198.51.100.1\n"}
                       :answers {"vpn.corp.example" #{"198.51.100.2"}}})
        res (fetch/fetch-provider! system "corp")]
    (is (= #{"203.0.113.7" "198.51.100.2" "198.51.100.1"} (set (-> res :ok :ips))))
    (is (= "/etc/vpn-killswitch/providers/corp.ips" (:path (first @writes))))))

(deftest fetch-provider-split-conf-variants
  (is (= ["/etc/vpn-killswitch/split/corp.conf"
          "/etc/vpn-killswitch/split/corp-vpn.conf"
          "/etc/vpn-killswitch/split/vpn-corp.conf"]
         (fetch/split-conf-candidates "corp"))))

(deftest fetch-provider-static-list-is-kept
  (let [{:keys [system writes]}
        (chain-system {:files {"/etc/vpn-killswitch/providers/lab.ips" "10.9.8.7\n"}})
        res (fetch/fetch-provider! system "lab")]
    (is (= "/etc/vpn-killswitch/providers/lab.ips" (-> res :ok :kept)))
    (is (empty? @writes))))

(deftest fetch-provider-unknown-names-the-options
  (let [{:keys [system]} (chain-system {:provider-ips {:mullvad #{"1.1.1.1"}}})
        res (fetch/fetch-provider! system "nope")]
    (is (= :fetch/unknown-provider (:error res)))
    (is (clojure.string/includes? (:hint res) "Known: mullvad"))))

(deftest ovpn-config-value-trims-quotes-and-blanks
  (is (= "/etc/openvpn/a.ovpn" (fetch/ovpn-config-value "OVPN_CONFIG='/etc/openvpn/a.ovpn'\n")))
  (is (= "/x.ovpn" (fetch/ovpn-config-value "  OVPN_CONFIG =  \"/x.ovpn\"  ")))
  (is (nil? (fetch/ovpn-config-value "OVPN_CONFIGX=/nope\n# none")))
  (is (nil? (fetch/ovpn-config-value nil))))
