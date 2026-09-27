(ns vpn-kis-bb.cli.main-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.cli.main :as main]
            [vpn-kis-bb.cli.system :as system]))

(defn- ctx
  "Handler context over a dry-run system whose shell records every call
   and whose file reads find nothing. opts: {:root? :dry-run? :env}."
  [{:keys [root? dry-run? env] :or {root? true dry-run? false env {}}}]
  (let [shell (rec/make)
        sys   (-> (system/make-system {:profile :dry-run :recorded-shell shell :env env})
                  (assoc :read-fn (constantly nil)))]
    {:shell shell
     :ctx   {:system sys
             :opts   (if dry-run? {:dry-run? true} {})
             :prog   "vpn-kis"
             :root?  root?}}))

(defn- quietly
  "Call f with stdout and stderr swallowed; returns f's value."
  [f]
  (let [v (atom nil)]
    (with-out-str (binding [*err* *out*] (reset! v (f))))
    @v))

(defn- exit [cmd args & [opts]]
  (let [{:keys [ctx]} (ctx (or opts {}))]
    (quietly #(main/dispatch ctx cmd args))))

(deftest every-bash-command-and-alias-dispatches
  (doseq [c ["help" "-h" "--help" "setup" "auto" "providers" "fetch" "refresh"
             "detect" "unlock" "panic" "rescue" "emergency" "tailscale-routes"
             "tailscale-web" "test" "split" "exclude" "nm-dispatch"]]
    (is (contains? main/commands c) c)))

(deftest help-and-unknown
  (is (= 0 (exit "help" [])))
  (is (= 1 (exit "frobnicate" []))))

(deftest usage-errors-exit-1
  (is (= 1 (exit "providers" [])))
  (is (= 1 (exit "tailscale-routes" ["sideways"])))
  (is (= 1 (exit "test" ["loud"])))
  (is (= 1 (exit "split" ["explode"])))
  (is (= 1 (exit "split" ["add"])) "a name is required")
  (is (= 1 (exit "exclude" ["sideways"]))))

(deftest root-is-required-where-bash-required-it
  (let [{:keys [ctx shell]} (ctx {:root? false})]
    (is (= 1 (quietly #(main/dispatch ctx "unlock" []))))
    (is (= 1 (quietly #(main/dispatch ctx "split" ["rm" "corp"]))))
    (is (= 1 (quietly #(main/dispatch ctx "exclude" ["on"]))))
    (is (empty? (rec/calls shell)) "a refused command runs nothing")))

(deftest read-only-commands-need-no-root
  (testing "exclude status on a host without exclusion"
    (is (= 0 (exit "exclude" ["status"] {:root? false})))))

(deftest dry-run-never-needs-root
  (let [{:keys [ctx]} (ctx {:root? false :dry-run? true})]
    (is (= 0 (quietly #(main/dispatch ctx "refresh" ["uninstall"]))))))

(deftest parse-errors-exit-1
  (is (= 1 (quietly #(main/run ["providers" "--lan"] {})))))

(deftest context-applies-global-flags
  (let [c (main/context {:lan ["192.168.100.0/24"] :physical-iface "eth9" :dry-run? true}
                        {"LAN_ALLOW_CIDRS" "10.0.0.0/8" "VPN_KIS_PROG" "./vpn-firewall-setup.sh"})]
    (is (= ["192.168.100.0/24"] (get-in c [:system :settings :lan-allow])) "--lan wins over env")
    (is (= "eth9" (get-in c [:system :settings :physical-iface])))
    (is (= :dry-run (get-in c [:system :profile])))
    (is (= "./vpn-firewall-setup.sh" (:prog c)))))

(deftest providers-without-cached-lists-refuses
  (is (= 1 (exit "providers" ["no-such-provider-vpnkis-test"]))))

(deftest fetch-exit-code-counts-failures
  (is (= 2 (exit "fetch" ["no-such-a" "no-such-b"]))))
