(ns vpn-kis-bb.app.tailscale-web-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.app.tailscale-web :as web]
            [vpn-kis-bb.log :as log]))

(use-fixtures :each (fn [f] (binding [log/*quiet* true] (f))))

(def self-path "/opt/vpn-kis/bin/vpn-kis")
(def default-helper "/opt/vpn-kis/bin/../lib/tailscale-web/configure.py")
(def marker "/etc/vpn-killswitch/tailscale-web.enabled")

(defn- harness
  "Recording system over an in-memory file map; `responses` answers the
   helper commands by argv."
  ([] (harness {}))
  ([{:keys [files responses env self]}]
   (let [fs      (atom (merge {default-helper "#!/usr/bin/env python3\n" marker ""} files))
         deletes (atom [])
         shell   (rec/make {:respond (fn [cmd _opts] (get responses cmd))})]
     {:system  {:shell     shell
                :read-fn   (fn [p] (get @fs p))
                :delete-fn (fn [p] (swap! fs dissoc p) (swap! deletes conj p) (r/ok {:path p}))
                :env       (or env {})
                :self-path (or self self-path)}
      :shell   shell
      :fs      fs
      :deletes deletes})))

(defn- capture
  "Run f; returns [result stdout-text stderr-text]."
  [f]
  (let [res (atom nil)
        err (atom nil)
        out (with-out-str
              (let [out-w *out*]
                (reset! err (with-out-str
                              (let [err-w *out*]
                                (binding [*out* out-w *err* err-w]
                                  (reset! res (f))))))))]
    [@res out @err]))

(deftest helper-path-resolution
  (is (= default-helper (web/helper-path (:system (harness)))))
  (is (= "/srv/configure.py"
         (web/helper-path (:system (harness {:env {"TAILSCALE_WEB_HELPER" "/srv/configure.py"}})))))
  (is (= default-helper
         (web/helper-path {:settings {:self-path self-path}}))
      "falls back to the settings' self-path"))

(deftest apply-runs-the-helper-and-echoes-its-output
  (let [h                (harness {:responses {["python3" default-helper "apply"]
                                               {:stdout "Applied OpenClaw-only rule.\nHTTPS status: 200\n"}}})
        [res out _]      (capture #(web/run! (:system h) "apply"))]
    (is (= {:sub "apply" :helper default-helper} (:ok res)))
    (is (= "Applied OpenClaw-only rule.\nHTTPS status: 200\n" out))
    (is (= [["python3" default-helper "apply"]] (rec/cmds (:shell h))))
    (is (= 120000 (-> (rec/calls (:shell h)) first :opts :timeout-ms)))
    (is (= [] @(:deletes h)) "apply leaves the marker alone")))

(deftest apply-failure-carries-the-helper-message
  (let [h           (harness {:responses {["python3" default-helper "apply"]
                                          {:exit 1 :stderr "Pinned address does not match Tailscale peer identity; no changes made.\n"}}})
        [res _ _]   (capture #(web/run! (:system h) "apply"))]
    (is (= :tailscale-web/helper-failed (:error res)))
    (is (= "Pinned address does not match Tailscale peer identity; no changes made." (:hint res)))
    (is (= 1 (:exit res)))))

(deftest apply-failure-without-stderr
  (let [h         (harness {:responses {["python3" default-helper "apply"] {:exit 2}}})
        [res _ _] (capture #(web/run! (:system h) "apply"))]
    (is (= "tailscale-web apply: helper exited 2" (:hint res)))))

(deftest apply-without-helper
  (testing "file absent"
    (let [h   (harness {:files {default-helper nil}})
          res (web/run! (:system h) "apply")]
      (is (= :tailscale-web/no-helper (:error res)))
      (is (str/includes? (:hint res) default-helper))
      (is (= [] (rec/cmds (:shell h))))))
  (testing "no way to locate it"
    (let [h   (harness {:self "vpn-kis"})
          res (web/run! (:system h) "apply")]
      (is (= :tailscale-web/no-helper (:error res)))
      (is (str/includes? (:hint res) "TAILSCALE_WEB_HELPER")))))

(deftest remove-deletes-the-marker-then-runs-the-helper
  (let [h         (harness {:responses {["python3" default-helper "remove"]
                                        {:stdout "Removed managed rule and hostname entry.\n"}}})
        [res out _] (capture #(web/run! (:system h) "remove"))]
    (is (= {:sub "remove" :helper default-helper :helper-ok? true} (:ok res)))
    (is (= [marker] @(:deletes h)))
    (is (= [["python3" default-helper "remove"]] (rec/cmds (:shell h))))
    (is (str/includes? out "Removed managed rule"))))

(deftest remove-only-warns-when-the-helper-fails
  (let [h             (harness {:responses {["python3" default-helper "remove"]
                                            {:exit 1 :stderr "Requires sudo\n"}}})
        [res _ err]   (capture #(web/run! (:system h) "remove"))]
    (is (r/ok? res))
    (is (false? (-> res :ok :helper-ok?)))
    (is (str/includes? err "Requires sudo"))
    (is (str/includes? err "Could not fully remove the OpenClaw client exception."))
    (is (= [marker] @(:deletes h)))))

(deftest remove-without-helper-still-drops-the-marker
  (let [h           (harness {:files {default-helper nil}})
        [res _ err] (capture #(web/run! (:system h) "remove"))]
    (is (= {:sub "remove" :helper nil :helper-ok? false} (:ok res)))
    (is (= [marker] @(:deletes h)))
    (is (= [] (rec/cmds (:shell h))))
    (is (str/includes? err "Could not fully remove"))))

(deftest unknown-subcommand
  (let [h   (harness)
        res (web/run! (:system h) "status")]
    (is (= :tailscale-web/unknown-sub (:error res)))
    (is (= "tailscale-web: unknown subcommand 'status'. Try: apply|remove" (:hint res)))
    (is (= [] (rec/cmds (:shell h))))))
