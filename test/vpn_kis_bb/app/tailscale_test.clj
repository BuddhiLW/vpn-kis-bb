(ns vpn-kis-bb.app.tailscale-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.nm-dispatcher :as nm]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.app.tailscale :as app]
            [vpn-kis-bb.domain.tailscale :as d]
            [vpn-kis-bb.log :as log]))

(use-fixtures :each (fn [f] (binding [log/*quiet* true] (f))))

(defn- text [& lines] (apply str (map #(str % "\n") lines)))

;; ---------------------------------------------------------------- fixtures

(def self-path "/opt/vpn-kis/bin/vpn-kis")
(def helper "/opt/vpn-kis/bin/../lib/tailscale-web/configure.py")
(def cidrs-file "/etc/vpn-killswitch/tailnet.cidrs")
(def marker "/etc/vpn-killswitch/tailscale-web.enabled")
(def active-file "/etc/vpn-killswitch/providers.active")
(def unit-file "/etc/systemd/system/vpn-killswitch-tailscale-routes.service")
(def dropin-file "/etc/systemd/system/tailscaled.service.d/50-vpn-killswitch-mullvad.conf")

(def t52 ["ip" "route" "show" "table" "52"])
(def rule-show ["ip" "rule" "show"])
(def nft-list ["nft" "list" "table" "inet" "vpn-killswitch-tailscale"])
(def nft-delete ["nft" "delete" "table" "inet" "vpn-killswitch-tailscale"])
(def openclaw-list ["nft" "list" "table" "inet" "hive_openclaw_client"])
(def pid-show ["systemctl" "show" "-p" "MainPID" "--value" "tailscaled"])
(def split-list ["mullvad" "split-tunnel" "list"])
(def split-add ["mullvad" "split-tunnel" "add" "4242"])
(def sd-reload ["systemctl" "daemon-reload"])
(def unit-enable ["systemctl" "enable" "vpn-killswitch-tailscale-routes.service"])
(def unit-restart ["systemctl" "restart" "vpn-killswitch-tailscale-routes.service"])
(def unit-disable ["systemctl" "disable" "--now" "vpn-killswitch-tailscale-routes.service"])
(def nm-test ["test" "-d" "/etc/NetworkManager/dispatcher.d"])
(def nm-chmod ["chmod" "755" "/etc/NetworkManager/dispatcher.d/90-vpn-killswitch"])
(def dropin-rmdir ["rmdir" "--ignore-fail-on-non-empty" "/etc/systemd/system/tailscaled.service.d"])

(def table52-out
  (text "10.96.0.0/12 dev tailscale0 "
        "10.244.0.0/16 dev tailscale0 "
        "100.100.100.100 dev tailscale0 "
        "100.101.12.77 dev tailscale0 "
        "throw 127.0.0.0/8 "
        "192.168.100.0/24 dev tailscale0 "))

(def dests ["100.64.0.0/10" "10.244.0.0/16" "10.96.0.0/12" "192.168.100.0/24"])
(def nft-load (d/nft-load-cmd (d/render-nft dests)))

(def rules-now
  (text "0:\tfrom all lookup local"
        "5209:\tfrom all lookup main suppress_prefixlength 0"
        "5210:\tnot from all fwmark 0x6d6f6c65 lookup 1836018789"
        "5270:\tfrom all lookup 52"
        "32766:\tfrom all lookup main"))

(def live-table
  (text "table inet vpn-killswitch-tailscale {"
        "\tchain route_out {"
        "\t\ttype route hook output priority mangle; policy accept;"
        "\t\tip daddr @tailnet meta mark set 0x6d6f6c65 ct mark set 0x00000f41 comment \"vpn-kis tailnet bypasses Mullvad v3\""
        "\t}"
        "}"))

(def base-table
  {t52           {:stdout table52-out}
   rule-show     {:stdout rules-now}
   nft-list      {:exit 1 :stderr "Error: No such file or directory\n"}
   openclaw-list {:exit 1}
   pid-show      {:stdout "4242\n"}
   split-list    {:stdout "Excluded PIDs:\n"}})

(defn- responder
  "RecordingShell :respond fn: `table` maps a command vector to a response,
   or to a fn of that command's 1-based call count; anything else gets the
   recorder's exit-0 default."
  [table]
  (let [counts (atom {})]
    (fn [cmd _opts]
      (let [n (get (swap! counts update cmd (fnil inc 0)) cmd)
            v (get table cmd)]
        (if (fn? v) (v n) v)))))

(defn- missing
  "shell-fn: a shell on which `programs` are not installed."
  [programs]
  (fn [shell]
    (reify proto/IShell
      (shell-exec! [_this cmd opts] (proto/shell-exec! shell cmd opts))
      (shell-env [_this] (proto/shell-env shell))
      (shell-which [_this program]
        (if (contains? programs program)
          (r/err :shell/not-found {:program program})
          (proto/shell-which shell program))))))

(defn- harness
  "Recording system over an in-memory file map (a nil value reads as
   absent)."
  ([] (harness {}))
  ([{:keys [files table settings shell-fn env]}]
   (let [fs        (atom (or files {}))
         writes    (atom [])
         deletes   (atom [])
         shell     (rec/make {:respond (responder (merge base-table table))})
         write-fn  (fn [p body]
                     (swap! fs assoc p body)
                     (swap! writes conj [p body])
                     (r/ok {:path p}))
         delete-fn (fn [p]
                     (swap! fs dissoc p)
                     (swap! deletes conj p)
                     (r/ok {:path p}))
         sys-shell ((or shell-fn identity) shell)]
     {:system  {:shell     sys-shell
                :systemd   (sd/make sys-shell {:write-fn write-fn :delete-fn delete-fn})
                :read-fn   (fn [p] (get @fs p))
                :write-fn  write-fn
                :delete-fn delete-fn
                :self-path self-path
                :env       (or env {})
                :settings  (merge {:prog "vpn-kis" :vpn-interfaces ["tun+" "wg+" "tailscale0"]}
                                  settings)}
      :shell   shell
      :fs      fs
      :writes  writes
      :deletes deletes})))

(defn- cmds [h] (rec/cmds (:shell h)))

(defn- capture-err
  "Run f with info lines enabled; returns [result stderr-text]."
  [f]
  (let [res (atom nil)
        err (with-out-str (binding [*err* *out* log/*quiet* false] (reset! res (f))))]
    [@res err]))

;; ---------------------------------------------------------------- apply

(deftest apply-first-run
  (let [h         (harness)
        [res err] (capture-err #(app/apply! (:system h) {}))]
    (is (= {:nft                  {:status :applied :dests dests :dropped [] :source :table}
            :legacy-rules-removed 0
            :tailscaled           {:status :excluded :pid "4242"}
            :web                  {:status :disabled}}
           (:ok res)))
    (is (= [t52 nft-list nft-load rule-show pid-show split-list split-add] (cmds h)))
    (is (= [[cidrs-file (text "100.64.0.0/10" "10.244.0.0/16" "10.96.0.0/12" "192.168.100.0/24")]]
           @(:writes h)))
    (testing "progress lines, as the bash prints them"
      (is (str/includes? err (str "[+] Tailnet bypasses Mullvad by mark (nft table inet"
                                  " vpn-killswitch-tailscale): 100.64.0.0/10 10.244.0.0/16"
                                  " 10.96.0.0/12 192.168.100.0/24")))
      (is (str/includes? err "[+] tailscaled (pid 4242) excluded from Mullvad")))))

(deftest apply-is-a-no-op-when-current
  (let [h   (harness {:files {cidrs-file (d/cidrs-text dests)}
                      :table {nft-list   {:stdout live-table}
                              split-list {:stdout "Excluded PIDs:\n    4242\n"}}})
        res (app/apply! (:system h) {})]
    (is (= :current (-> res :ok :nft :status)))
    (is (= {:status :listed :pid "4242"} (-> res :ok :tailscaled)))
    (is (= [t52 nft-list rule-show pid-show split-list] (cmds h)))
    (is (= [] @(:writes h)))))

(deftest apply-keeps-the-stored-set-while-tailscaled-restarts
  (let [stored (text "100.64.0.0/10" "10.96.0.0/12")]
    (let [h   (harness {:files {cidrs-file stored}
                        :table {t52 {:exit 2 :stderr "Error: ipv4: FIB table does not exist.\n"}}})
          res (app/apply! (:system h) {})]
      (is (= {:status :applied :dests ["100.64.0.0/10" "10.96.0.0/12"] :dropped [] :source :stored}
             (-> res :ok :nft)))
      (is (some #{(d/nft-load-cmd (d/render-nft ["100.64.0.0/10" "10.96.0.0/12"]))} (cmds h)))
      (is (= [[cidrs-file stored]] @(:writes h))))
    (testing "and changes nothing when that set is already live"
      (let [h (harness {:files {cidrs-file stored}
                        :table {t52 {:stdout ""} nft-list {:stdout live-table}}})]
        (is (= :current (-> (app/apply! (:system h) {}) :ok :nft :status)))
        (is (= [] @(:writes h)))))))

(deftest apply-reloads-when-the-set-changed
  (let [h   (harness {:files {cidrs-file (text "100.64.0.0/10")}
                      :table {nft-list {:stdout live-table}}})
        res (app/apply! (:system h) {})]
    (is (= :applied (-> res :ok :nft :status)))
    (is (some #{nft-load} (cmds h)))))

(deftest apply-reloads-an-older-table-version
  (let [h (harness {:files {cidrs-file (d/cidrs-text dests)}
                    :table {nft-list {:stdout (str/replace live-table "v3" "v2")}}})]
    (is (= :applied (-> (app/apply! (:system h) {}) :ok :nft :status)))))

(deftest apply-retires-legacy-rules-after-the-marks
  (let [legacy (text "0:\tfrom all lookup local"
                     "5099:\tfrom all to 10.96.0.0/12 lookup 52"
                     "5100:\tfrom all to 10.96.0.0/12 lookup 52"
                     "5101:\tfrom all to 100.64.0.0/10 lookup 52"
                     "5270:\tfrom all lookup 52")
        del-a  ["ip" "rule" "del" "to" "10.96.0.0/12" "lookup" "52"]
        del-b  ["ip" "rule" "del" "to" "100.64.0.0/10" "lookup" "52"]
        h      (harness {:table {rule-show {:stdout legacy}
                                 del-a     (fn [n] {:exit (if (<= n 2) 0 2)})
                                 del-b     (fn [n] {:exit (if (= n 1) 0 2)})}})
        [res err] (capture-err #(app/apply! (:system h) {}))]
    (is (= 3 (-> res :ok :legacy-rules-removed)))
    (is (= [nft-load rule-show del-a del-a del-a del-b del-b]
           (->> (cmds h) (drop-while #(not= nft-load %)) (take 7) vec)))
    (is (str/includes? err "[+] Removed legacy Tailscale ip rules (replaced by the mark-based bypass)"))))

(deftest apply-legacy-drain-is-bounded
  (let [del ["ip" "rule" "del" "to" "10.96.0.0/12" "lookup" "52"]
        h   (harness {:table {rule-show {:stdout "5100:\tfrom all to 10.96.0.0/12 lookup 52\n"}}})]
    (is (= d/drain-limit (-> (app/apply! (:system h) {}) :ok :legacy-rules-removed)))
    (is (= d/drain-limit (count (filter #{del} (cmds h)))))))

(deftest apply-without-nft-keeps-legacy-rules
  (let [h         (harness {:shell-fn (missing #{"nft"})})
        [res err] (capture-err #(app/apply! (:system h) {}))]
    (is (= {:status :no-nft} (-> res :ok :nft)))
    (is (str/includes? err "[!] nft not found, Mullvad will capture tailnet traffic"))
    (testing "no marks, so the old rules stay (make-before-break)"
      (is (= [pid-show split-list split-add] (cmds h))))))

(deftest apply-surfaces-an-nft-rejection
  (let [h   (harness {:table {nft-load {:exit 1 :stderr "Error: syntax error\n"}}})
        res (app/apply! (:system h) {})]
    (is (= :tailscale/nft-failed (:error res)))
    (is (str/includes? (:hint res) "Error: syntax error"))
    (is (= [t52 nft-list nft-load] (cmds h)) "nothing after the failed load")
    (is (= [] @(:writes h)))))

(deftest apply-surfaces-a-failed-cidrs-write
  (let [h   (harness)
        sys (assoc (:system h) :write-fn (fn [p _] (r/err :fs/write-failed {:path p})))
        res (app/apply! sys {})]
    (is (= :tailscale/cidrs-write-failed (:error res)))
    (is (not-any? #{rule-show} (cmds h)))))

(deftest apply-never-marks-mullvad-dns
  (let [h         (harness {:table {t52 {:stdout (text "10.0.0.0/8 dev tailscale0"
                                                       "10.96.0.0/12 dev tailscale0")}}})
        [res err] (capture-err #(app/apply! (:system h) {}))]
    (is (= ["100.64.0.0/10" "10.96.0.0/12"] (-> res :ok :nft :dests)))
    (is (= ["10.0.0.0/8"] (-> res :ok :nft :dropped)))
    (is (str/includes? err "10.0.0.0/8"))
    (is (some #{(d/nft-load-cmd (d/render-nft ["100.64.0.0/10" "10.96.0.0/12"]))} (cmds h)))
    (is (not (str/includes? (get @(:fs h) cidrs-file) "10.0.0.0/8")))))

(deftest apply-tailscaled-exclusion-cases
  (testing "listed with indentation: nothing to add"
    (let [h (harness {:table {split-list {:stdout "Excluded PIDs:\n\t  4242\n"}}})]
      (is (= {:status :listed :pid "4242"} (-> (app/apply! (:system h) {}) :ok :tailscaled)))
      (is (not-any? #{split-add} (cmds h)))))
  (testing "a longer PID that starts with ours does not count"
    (let [h (harness {:table {split-list {:stdout "    42421\n"}}})]
      (is (= :excluded (-> (app/apply! (:system h) {}) :ok :tailscaled :status)))))
  (testing "tailscaled not running"
    (let [h (harness {:table {pid-show {:stdout "0\n"}}})]
      (is (= {:status :not-running} (-> (app/apply! (:system h) {}) :ok :tailscaled)))
      (is (not-any? #{split-list} (cmds h)))))
  (testing "add fails: a warning, apply still ok"
    (let [h         (harness {:table {split-add {:exit 1}}})
          [res err] (capture-err #(app/apply! (:system h) {}))]
      (is (= {:status :failed :pid "4242"} (-> res :ok :tailscaled)))
      (is (str/includes? err (str "[!] Could not exclude tailscaled (pid 4242) from Mullvad,"
                                  " Tailscale login will fail")))))
  (testing "no mullvad CLI"
    (let [h (harness {:shell-fn (missing #{"mullvad"})})]
      (is (= {:status :no-mullvad} (-> (app/apply! (:system h) {}) :ok :tailscaled)))
      (is (not-any? #{pid-show} (cmds h))))))

(deftest apply-runs-tailscale-web-only-when-enabled-and-missing
  (testing "marker and no table: the helper applies"
    (let [h   (harness {:files {marker "" helper "py"}})
          res (app/apply! (:system h) {})]
      (is (= {:status :applied} (-> res :ok :web)))
      (is (= [openclaw-list ["python3" helper "apply"]] (take-last 2 (cmds h))))))
  (testing "table present: nothing to do"
    (let [h (harness {:files {marker "" helper "py"} :table {openclaw-list {:exit 0}}})]
      (is (= {:status :present} (-> (app/apply! (:system h) {}) :ok :web)))
      (is (not-any? #(= "python3" (first %)) (cmds h)))))
  (testing "helper fails: warnings, apply still ok"
    (let [h         (harness {:files {marker "" helper "py"}
                              :table {["python3" helper "apply"]
                                      {:exit 1 :stderr "Destination is not routed through tailscale0; no changes made.\n"}}})
          [res err] (capture-err #(app/apply! (:system h) {}))]
      (is (r/ok? res))
      (is (= :failed (-> res :ok :web :status)))
      (is (str/includes? err "Destination is not routed through tailscale0"))
      (is (str/includes? err (str "OpenClaw client check failed; inspect output and rerun"
                                  " tailscale-routes apply when Tailscale is ready.")))))
  (testing "no marker: the table is never queried"
    (let [h (harness)]
      (app/apply! (:system h) {})
      (is (not-any? #{openclaw-list} (cmds h))))))

(deftest apply-turns-a-throw-into-an-err
  (let [h   (harness)
        sys (assoc (:system h) :read-fn (fn [_] (throw (ex-info "disk on fire" {}))))
        res (app/apply! sys {})]
    (is (= :tailscale/threw (:error res)))
    (is (str/includes? (:hint res) "disk on fire"))))

;; ---------------------------------------------------------------- install

(deftest install-full
  (let [h         (harness {:files {active-file "mullvad tailscale\n"}})
        [res err] (capture-err #(app/install! (:system h) {}))]
    (is (= {:routes        {:web :enabled :dropin dropin-file :unit unit-file}
            :nm-dispatcher {:path      nm/dispatcher-path
                            :bytes     (count (nm/hook-text self-path))
                            :self-path self-path}}
           (:ok res)))
    (is (= [sd-reload sd-reload unit-enable unit-restart nm-test nm-chmod] (cmds h)))
    (is (= [[marker ""]
            [dropin-file d/dropin-text]
            [unit-file (d/unit-text self-path)]
            [nm/dispatcher-path (nm/hook-text self-path)]]
           @(:writes h)))
    (is (= 120000 (:timeout-ms (:opts (first (filter #(= unit-restart (:cmd %))
                                                      (rec/calls (:shell h))))))))
    (is (str/includes? err (str "[+] tailscaled drop-in installed: " dropin-file)))
    (is (str/includes? err (str "[+] Boot-persisted via " unit-file)))
    (is (str/includes? err "[+] Hook installed: /etc/NetworkManager/dispatcher.d/90-vpn-killswitch"))))

(deftest install-without-tailscale-only-installs-the-hook
  (let [h   (harness {:settings {:vpn-interfaces ["tun+" "wg+"]}})
        res (app/install! (:system h) {})]
    (is (= {:skipped :no-tailscale-interface} (-> res :ok :routes)))
    (is (= [nm-test nm-chmod] (cmds h)))
    (is (= [nm/dispatcher-path] (map first @(:writes h))))))

(deftest install-options
  (let [h   (harness {:settings {:vpn-interfaces ["tun+"]}})
        res (app/install! (:system h) {:vpn-interfaces ["tailscale0"] :nm-dispatcher? false})]
    (is (= unit-file (-> res :ok :routes :unit)))
    (is (= {:skipped :by-option} (-> res :ok :nm-dispatcher)))
    (is (not-any? #{nm-test} (cmds h)))))

(deftest install-leaves-web-alone-without-the-provider-pair
  (let [h   (harness {:files {active-file "mullvad airvpn\n"}})
        res (app/install! (:system h) {})]
    (is (= :disabled (-> res :ok :routes :web)))
    (is (not-any? #{marker} (map first @(:writes h))))
    (is (= [] @(:deletes h)))))

(deftest install-removes-tailscale-web-when-no-longer-selected
  (let [h   (harness {:files {active-file "mullvad airvpn\n" marker "" helper "py"}})
        res (app/install! (:system h) {})]
    (is (= :removed (-> res :ok :routes :web)))
    (is (= [marker] @(:deletes h)))
    (is (= ["python3" helper "remove"] (first (cmds h))))))

(deftest install-without-mullvad-skips-the-drop-in
  (let [h   (harness {:shell-fn (missing #{"mullvad"})})
        res (app/install! (:system h) {})]
    (is (= :no-mullvad (-> res :ok :routes :dropin)))
    (is (not-any? #{dropin-file} (map first @(:writes h))))
    (is (= [sd-reload unit-enable unit-restart nm-test nm-chmod] (cmds h)))))

(deftest install-stops-when-the-unit-cannot-start
  (let [h   (harness {:table {unit-restart {:exit 1 :stderr "Job failed"}}})
        res (app/install! (:system h) {})]
    (is (= :tailscale/unit-restart-failed (:error res)))
    (is (str/includes? (:hint res) "journalctl -u vpn-killswitch-tailscale-routes.service"))
    (is (not-any? #{nm-test} (cmds h)))))

(deftest install-ignores-a-failed-enable
  (let [h (harness {:table {unit-enable {:exit 1}}})]
    (is (r/ok? (app/install! (:system h) {})))
    (is (some #{unit-restart} (cmds h)))))

(deftest install-needs-a-self-path
  (let [h   (harness)
        res (app/install! (assoc (:system h) :self-path nil) {})]
    (is (= :tailscale/no-self-path (:error res)))
    (is (= [] (cmds h)))
    (is (= [] @(:writes h)))))

;; ---------------------------------------------------------------- remove

(deftest remove-tears-everything-down
  (let [del ["ip" "rule" "del" "to" "10.96.0.0/12" "lookup" "52"]
        h   (harness {:files {marker "" helper "py" unit-file "unit" dropin-file "dropin"
                              cidrs-file "100.64.0.0/10\n"}
                      :table {rule-show {:stdout "5100:\tfrom all to 10.96.0.0/12 lookup 52\n"}
                              del       (fn [n] {:exit (if (= n 1) 0 2)})}})
        res (app/remove! (:system h) {})]
    (is (= {:web                  {:sub "remove" :helper helper :helper-ok? true}
            :unit-removed?        true
            :legacy-rules-removed 1
            :nft-removed?         true
            :cidrs-removed?       true
            :dropin-removed?      true
            :failures             []}
           (:ok res)))
    (is (= [["python3" helper "remove"] unit-disable sd-reload rule-show del del nft-delete
            dropin-rmdir sd-reload]
           (cmds h)))
    (is (= [marker unit-file cidrs-file dropin-file] @(:deletes h)))))

(deftest remove-when-nothing-is-installed
  (let [h       (harness {:table {nft-delete {:exit 1}}})
        [res _] (capture-err #(app/remove! (:system h) {}))]
    (is (= {:unit-removed?        false
            :legacy-rules-removed 0
            :nft-removed?         false
            :cidrs-removed?       true
            :dropin-removed?      false
            :failures             []}
           (dissoc (:ok res) :web)))
    (is (= [rule-show nft-delete] (cmds h)))))

(deftest remove-reports-a-throwing-step-and-goes-on
  (let [h       (harness {:files {unit-file "unit"}})
        [res _] (capture-err #(app/remove! (assoc (:system h) :systemd nil) {}))]
    (is (r/ok? res))
    (is (= [:unit-removed?] (mapv :step (-> res :ok :failures))))
    (is (= :tailscale/threw (-> res :ok :failures first :error)))
    (is (some #{nft-delete} (cmds h)))))
