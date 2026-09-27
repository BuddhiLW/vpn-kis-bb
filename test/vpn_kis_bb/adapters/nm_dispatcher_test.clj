(ns vpn-kis-bb.adapters.nm-dispatcher-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [hive-system.shell.core :as shell-core]
            [vpn-kis-bb.adapters.nm-dispatcher :as nm]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.log :as log]))

(use-fixtures :each (fn [f] (binding [log/*quiet* true] (f))))

(def self-path "/opt/vpn-kis/bin/vpn-kis")

(defn- harness
  "Recording system; `respond` answers shell commands by argv."
  ([] (harness {}))
  ([{:keys [respond write-result delete-result self]}]
   (let [shell   (rec/make {:respond (fn [cmd _opts] (get respond cmd))})
         writes  (atom [])
         deletes (atom [])]
     {:system  {:shell     shell
                :self-path (if (some? self) self self-path)
                :write-fn  (fn [p body]
                             (swap! writes conj [p body])
                             (or write-result (r/ok {:path p})))
                :delete-fn (fn [p]
                             (swap! deletes conj p)
                             (or delete-result (r/ok {:path p})))}
      :shell   shell
      :writes  writes
      :deletes deletes})))

(deftest hook-text-golden
  (is (= (str "#!/bin/sh\n"
              "# Managed by vpn-kis: NetworkManager dispatcher hook. Retargets the\n"
              "# kill-switch DROP rule when the physical interface changes and\n"
              "# refreshes the tailnet bypass on tailscale events.\n"
              "exec '/opt/vpn-kis/bin/vpn-kis' nm-dispatch \"$1\" \"$2\"\n")
         (nm/hook-text self-path)))
  (testing "the launcher path is quoted for sh"
    (is (str/includes? (nm/hook-text "/opt/my vpn/it's/vpn-kis")
                       "exec '/opt/my vpn/it'\\''s/vpn-kis' nm-dispatch"))))

(deftest hook-passes-both-arguments-through
  (let [res (proto/shell-exec! (shell-core/make-shell)
                               ["sh" "-c" (nm/hook-text "/bin/echo") "90-vpn-killswitch"
                                "wlp3s0" "up"]
                               {})]
    (is (= "nm-dispatch wlp3s0 up\n" (-> res :ok :stdout)))
    (is (= 0 (-> res :ok :exit)))))

(deftest install-writes-and-chmods
  (let [h   (harness)
        res (nm/install! (:system h))]
    (is (= {:path nm/dispatcher-path :bytes (count (nm/hook-text self-path)) :self-path self-path}
           (:ok res)))
    (is (= [[nm/dispatcher-path (nm/hook-text self-path)]] @(:writes h)))
    (is (= [["test" "-d" "/etc/NetworkManager/dispatcher.d"]
            ["chmod" "755" "/etc/NetworkManager/dispatcher.d/90-vpn-killswitch"]]
           (rec/cmds (:shell h))))))

(deftest install-uses-the-settings-self-path
  (let [h   (harness {:self ""})
        sys (assoc (:system h) :self-path nil :settings {:self-path "/usr/local/bin/vpn-kis"})
        res (nm/install! sys)]
    (is (r/ok? res))
    (is (str/includes? (second (first @(:writes h))) "exec '/usr/local/bin/vpn-kis' nm-dispatch"))))

(deftest install-skips-without-network-manager
  (let [h   (harness {:respond {["test" "-d" "/etc/NetworkManager/dispatcher.d"] {:exit 1}}})
        err (with-out-str (binding [*err* *out*]
                            (is (= {:skipped :no-network-manager}
                                   (:ok (nm/install! (:system h)))))))]
    (is (str/includes? err "NetworkManager not present, skipping IF-change hook."))
    (is (= [] @(:writes h)))))

(deftest install-needs-a-self-path
  (let [h   (harness {:self ""})
        res (nm/install! (:system h))]
    (is (= :nm-dispatcher/no-self-path (:error res)))
    (is (= [] (rec/cmds (:shell h))))))

(deftest install-surfaces-write-and-chmod-failures
  (let [h   (harness {:write-result (r/err :fs/write-failed {:path nm/dispatcher-path})})
        res (nm/install! (:system h))]
    (is (= :fs/write-failed (:error res)))
    (is (not-any? #(= "chmod" (first %)) (rec/cmds (:shell h)))))
  (let [h   (harness {:respond {["chmod" "755" nm/dispatcher-path] {:exit 1}}})
        res (nm/install! (:system h))]
    (is (= :nm-dispatcher/chmod-failed (:error res)))))

(deftest remove-is-best-effort
  (let [h (harness)]
    (is (= {:path nm/dispatcher-path :removed? true} (:ok (nm/remove! (:system h)))))
    (is (= [nm/dispatcher-path] @(:deletes h))))
  (let [h (harness {:delete-result (r/err :fs/delete-failed {})})]
    (is (= {:path nm/dispatcher-path :removed? false} (:ok (nm/remove! (:system h)))))))
