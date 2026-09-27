(ns vpn-kis-bb.app.exclude-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.app.exclude :as app]
            [vpn-kis-bb.domain.exclude :as d]
            [vpn-kis-bb.log :as log]))

(use-fixtures :each (fn [f] (binding [log/*quiet* true] (f))))

(defn- text [& lines] (apply str (map #(str % "\n") lines)))

;; ---------------------------------------------------------------- fixtures

(def plain-rules
  (text "*filter"
        ":ufw-before-output - [0:0]"
        "-A ufw-before-output -o lo -j ACCEPT"
        ""
        "# --- KILL-SWITCH: drop anything else on physical IF ---"
        "-A ufw-before-output -o eth0 -j DROP"
        "-A ufw-before-input  -i eth0 -j DROP"
        ""
        "COMMIT"))

(def synced-rules
  (text "*filter"
        ":ufw-before-output - [0:0]"
        "-A ufw-before-output -o lo -j ACCEPT"
        ""
        "# --- KILL-SWITCH: drop anything else on physical IF ---"
        ""
        "# --- BEGIN vpn-kis exclude (mark 0x51 via cgroup vpnkis-exclude) ---"
        "-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"
        "# --- END vpn-kis exclude ---"
        "-A ufw-before-output -o eth0 -j DROP"
        "-A ufw-before-input  -i eth0 -j DROP"
        ""
        "COMMIT"))

(def self-path "/usr/local/bin/vpn-kis")
(def unit-file "/etc/systemd/system/vpn-killswitch-exclude.service")
(def enabled-files {unit-file (d/unit-text self-path)})
(def accept-files (assoc enabled-files "/etc/ufw/before.rules" synced-rules))

(def users #{"bob" "alice"})

(def rule-del ["ip" "rule" "del" "priority" "5080"])
(def rule-add ["ip" "rule" "add" "fwmark" "0x51" "lookup" "151" "priority" "5080"])
(def mkdir-cg ["mkdir" "-p" "/sys/fs/cgroup/vpnkis-exclude"])
(def rmdir-cg ["rmdir" "/sys/fs/cgroup/vpnkis-exclude"])
(def gw-query ["ip" "route" "show" "dev" "eth0"])
(def ufw-reload ["ufw" "reload"])
(def sd-reload ["systemctl" "daemon-reload"])
(def sd-enable ["systemctl" "enable" "vpn-killswitch-exclude.service"])
(def sd-disable ["systemctl" "disable" "--now" "vpn-killswitch-exclude.service"])
(def mark-rule ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-m" "cgroup" "--path"
                "vpnkis-exclude" "-j" "MARK" "--set-mark" "0x51"])
(def route-replace ["ip" "route" "replace" "default" "via" "192.168.1.1" "dev" "eth0"
                    "table" "151"])

(def apply-cmds
  "A first apply on eth0 via 192.168.1.1 with no rule at priority 5080."
  [mkdir-cg
   gw-query
   ["iptables" "-t" "mangle" "-N" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "mangle" "-C" "OUTPUT" "-j" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "mangle" "-A" "OUTPUT" "-j" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "mangle" "-F" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-d" "127.0.0.0/8" "-j" "RETURN"]
   ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-d" "10.0.0.0/8" "-j" "RETURN"]
   ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-d" "172.16.0.0/12" "-j" "RETURN"]
   ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-d" "192.168.0.0/16" "-j" "RETURN"]
   ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-d" "169.254.0.0/16" "-j" "RETURN"]
   ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-d" "224.0.0.0/4" "-j" "RETURN"]
   ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-d" "240.0.0.0/4" "-j" "RETURN"]
   mark-rule
   route-replace
   rule-del
   rule-add
   ["iptables" "-t" "nat" "-N" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-C" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-A" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-F" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-A" "VPNKIS-EXCLUDE-NAT" "-m" "mark" "--mark" "0x51" "-o" "eth0"
    "-j" "MASQUERADE"]])

(def teardown-cmds
  [rule-del
   ["ip" "route" "flush" "table" "151"]
   ["iptables" "-t" "mangle" "-F" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "mangle" "-D" "OUTPUT" "-j" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "mangle" "-X" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "nat" "-F" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-D" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-X" "VPNKIS-EXCLUDE-NAT"]])

(def base-table
  {gw-query {:stdout (text "default via 192.168.1.1 proto dhcp src 192.168.1.50 metric 100"
                           "192.168.1.0/24 proto kernel scope link src 192.168.1.50 metric 100")}
   rule-del {:exit 2 :stderr "RTNETLINK answers: No such file or directory\n"}
   ["iptables" "-t" "mangle" "-C" "OUTPUT" "-j" "VPNKIS-EXCLUDE"] {:exit 1}
   ["iptables" "-t" "nat" "-C" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"] {:exit 1}})

(def base-files
  {"/sys/fs/cgroup/cgroup.controllers" "cpuset cpu io memory pids\n"
   "/etc/ufw/before.rules"             plain-rules})

(defn- responder
  "RecordingShell :respond fn: `table` maps a command vector to a response,
   or to a fn of that command's 1-based call count. `id USER` answers from
   `users`; anything else falls back to the recorder's exit-0 default."
  [table]
  (let [counts (atom {})]
    (fn [cmd _opts]
      (let [n (get (swap! counts update cmd (fnil inc 0)) cmd)
            v (get table cmd)]
        (cond
          (fn? v)              (v n)
          (some? v)            v
          (= "id" (first cmd)) {:exit (if (contains? users (second cmd)) 0 1)}
          :else                nil)))))

(defn- harness
  "Recording system over an in-memory file map. A nil file value reads as
   absent."
  ([] (harness {}))
  ([{:keys [files table settings shell-fn]}]
   (let [fs        (atom (merge base-files files))
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
                :settings  (merge {:prog "vpn-kis"} settings)}
      :shell   shell
      :fs      fs
      :writes  writes
      :deletes deletes})))

(defn- cmds [h] (rec/cmds (:shell h)))
(defn- file [h path] (get @(:fs h) path))

(defn- with-err
  "Run f; returns [result text-written-to-stderr]."
  [f]
  (let [res (atom nil)
        err (with-out-str (binding [*err* *out*] (reset! res (f))))]
    [@res err]))

(defn- failing
  "Response table answering exit 1 to every cmd."
  [cmds]
  (into {} (map (fn [c] [c {:exit 1 :stderr "boom"}]) cmds)))

;; ---------------------------------------------------------------- enabled?

(deftest enabled?-reads-the-unit-file
  (is (false? (app/enabled? (:system (harness)))))
  (is (true? (app/enabled? (:system (harness {:files enabled-files}))))))

;; ---------------------------------------------------------------- apply / teardown

(deftest apply-routing-first-run
  (let [h   (harness {:files enabled-files})
        res (app/apply-routing! (:system h))]
    (is (r/ok? res))
    (is (= {:applied? true :phys "eth0" :gateway "192.168.1.1" :rules-deleted 0 :warnings []}
           (:ok res)))
    (is (= apply-cmds (cmds h)))))

(deftest apply-routing-rerun-is-idempotent
  (let [h   (harness {:files enabled-files
                      :table {["iptables" "-t" "mangle" "-C" "OUTPUT" "-j" "VPNKIS-EXCLUDE"] {:exit 0}
                              ["iptables" "-t" "nat" "-C" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"] {:exit 0}
                              rule-del (fn [n] {:exit (if (<= n 2) 0 2)})}})
        res (app/apply-routing! (:system h))
        c   (cmds h)]
    (is (r/ok? res))
    (is (= 2 (-> res :ok :rules-deleted)))
    (testing "existing jumps are not added again"
      (is (not-any? #{["iptables" "-t" "mangle" "-A" "OUTPUT" "-j" "VPNKIS-EXCLUDE"]
                      ["iptables" "-t" "nat" "-A" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"]}
                    c)))
    (testing "chains are flushed and rebuilt"
      (is (some #{["iptables" "-t" "mangle" "-F" "VPNKIS-EXCLUDE"]} c))
      (is (some #{["iptables" "-t" "nat" "-F" "VPNKIS-EXCLUDE-NAT"]} c)))
    (testing "ip rule del until it fails, then add"
      (is (= [route-replace rule-del rule-del rule-del rule-add]
             (->> c (drop-while #(not= route-replace %)) (take 5) vec))))))

(deftest apply-routing-when-disabled-tears-down
  (let [h   (harness)
        res (app/apply-routing! (:system h))]
    (is (r/ok? res))
    (is (false? (-> res :ok :applied?)))
    (is (= teardown-cmds (cmds h)))))

(deftest apply-routing-without-cgroup-v2
  (let [h         (harness {:files (assoc enabled-files "/sys/fs/cgroup/cgroup.controllers" nil)})
        [res err] (with-err #(app/apply-routing! (:system h)))]
    (is (= :exclude/no-cgroup-v2 (:error res)))
    (is (str/includes? err "not cgroup v2"))
    (is (= [] (cmds h)))))

(deftest apply-routing-cgroup-mkdir-failure
  (let [h         (harness {:files enabled-files :table {mkdir-cg {:exit 1}}})
        [res err] (with-err #(app/apply-routing! (:system h)))]
    (is (= :exclude/cgroup-create-failed (:error res)))
    (is (str/includes? err "cannot create cgroup /sys/fs/cgroup/vpnkis-exclude"))
    (is (= [mkdir-cg] (cmds h)))))

(deftest apply-routing-without-gateway
  (let [h         (harness {:files enabled-files
                            :table {gw-query {:stdout "192.168.1.0/24 proto kernel scope link\n"}}})
        [res err] (with-err #(app/apply-routing! (:system h)))]
    (is (= :exclude/no-gateway (:error res)))
    (is (str/includes? err "cannot determine physical gateway on eth0"))
    (is (= [mkdir-cg gw-query] (cmds h)) "no rule is touched")))

(deftest apply-routing-mark-failure-only-warns
  (let [h         (harness {:files enabled-files :table {mark-rule {:exit 1}}})
        [res err] (with-err #(app/apply-routing! (:system h)))]
    (is (r/ok? res))
    (is (= ["exclude: cgroup mark rule failed (xt_cgroup missing, or cgroup absent)"]
           (-> res :ok :warnings)))
    (is (str/includes? err "cgroup mark rule failed"))
    (is (= apply-cmds (cmds h)) "the rest still runs")))

(deftest apply-routing-stops-at-a-hard-failure
  (let [h   (harness {:files enabled-files
                      :table {route-replace {:exit 2 :stderr "Error: Nexthop has invalid gateway.\n"}}})
        res (app/apply-routing! (:system h))]
    (is (= :exclude/command-failed (:error res)))
    (is (= route-replace (:cmd res)))
    (is (= 2 (:exit res)))
    (is (= "Error: Nexthop has invalid gateway." (:stderr res)))
    (is (str/includes? (:message res) "ip route replace default via 192.168.1.1"))
    (is (= route-replace (last (cmds h))) "nothing after the failure runs")))

(deftest phys-resolution-order
  (testing "the before.rules DROP pin beats settings"
    (let [h (harness {:files enabled-files :settings {:physical-iface "wlan0"}})]
      (is (= "eth0" (-> (app/apply-routing! (:system h)) :ok :phys)))))
  (testing "settings :physical-iface when before.rules has no pin"
    (let [h   (harness {:files    (assoc enabled-files "/etc/ufw/before.rules" "*filter\nCOMMIT\n")
                        :settings {:physical-iface "wlan0"}
                        :table    {["ip" "route" "show" "dev" "wlan0"] {:stdout "default via 10.0.0.1 proto dhcp\n"}}})
          res (app/apply-routing! (:system h))]
      (is (= ["wlan0" "10.0.0.1"] [(-> res :ok :phys) (-> res :ok :gateway)]))
      (is (not-any? #{["ip" "-4" "route" "ls"]} (cmds h)))))
  (testing "detected from default routes, skipping virtual interfaces"
    (let [h   (harness {:files (assoc enabled-files "/etc/ufw/before.rules" nil)
                        :table {["ip" "-4" "route" "ls"]
                                {:stdout (text "default dev wg0-mullvad scope link"
                                               "default via 192.168.7.1 dev enp3s0 proto dhcp")}
                                ["ip" "route" "show" "dev" "enp3s0"]
                                {:stdout "default via 192.168.7.1 proto dhcp\n"}}})
          res (app/apply-routing! (:system h))]
      (is (= "enp3s0" (-> res :ok :phys)))))
  (testing "nothing to go on"
    (let [h       (harness {:files (assoc enabled-files "/etc/ufw/before.rules" nil)})
          [res _] (with-err #(app/apply-routing! (:system h)))]
      (is (= :exclude/no-physical-iface (:error res))))))

(deftest teardown-routing-is-best-effort
  (let [h   (harness {:table (failing teardown-cmds)})
        res (app/teardown-routing! (:system h))]
    (is (r/ok? res))
    (is (= teardown-cmds (cmds h)))))

(deftest rule-drain-is-bounded
  (let [h         (harness {:table {rule-del {:exit 0}}})
        [res err] (with-err #(app/teardown-routing! (:system h)))]
    (is (r/ok? res))
    (is (= d/drain-limit (-> res :ok :rules-deleted)))
    (is (= d/drain-limit (count (filter #{rule-del} (cmds h)))))
    (is (str/includes? err "still succeeding"))))

;; ---------------------------------------------------------------- before.rules

(deftest sync-before-rules-when-enabled
  (let [h   (harness {:files enabled-files})
        res (app/sync-before-rules! (:system h))]
    (is (= {:path "/etc/ufw/before.rules" :phys "eth0" :accept? true :changed? true :reloaded? true}
           (:ok res)))
    (is (= [["/etc/ufw/before.rules" synced-rules]] @(:writes h)))
    (is (= [ufw-reload] (cmds h)))))

(deftest sync-before-rules-when-disabled
  (let [h   (harness {:files {"/etc/ufw/before.rules" synced-rules}})
        res (app/sync-before-rules! (:system h))]
    (is (r/ok? res))
    (is (false? (-> res :ok :accept?)))
    (is (= plain-rules (file h "/etc/ufw/before.rules")))
    (is (= [ufw-reload] (cmds h)))))

(deftest sync-before-rules-is-stable
  (let [h (harness {:files accept-files})]
    (app/sync-before-rules! (:system h))
    (is (= synced-rules (file h "/etc/ufw/before.rules")))))

(deftest sync-before-rules-without-killswitch
  (let [h   (harness {:files {"/etc/ufw/before.rules" nil}})
        res (app/sync-before-rules! (:system h))]
    (is (= :exclude/no-before-rules (:error res)))
    (is (= "no /etc/ufw/before.rules: install the killswitch first (sudo vpn-kis setup ...)"
           (:message res)))
    (is (= [] @(:writes h)))
    (is (= [] (cmds h)))))

(deftest sync-before-rules-reload-failure-only-warns
  (let [h         (harness {:files enabled-files :table {ufw-reload {:exit 1}}})
        [res err] (with-err #(app/sync-before-rules! (:system h)))]
    (is (r/ok? res))
    (is (false? (-> res :ok :reloaded?)))
    (is (= synced-rules (file h "/etc/ufw/before.rules")))
    (is (str/includes? err "ufw reload failed"))))

(deftest sync-before-rules-warns-without-a-drop-line
  (let [h         (harness {:files    (assoc enabled-files "/etc/ufw/before.rules" "*filter\nCOMMIT\n")
                            :settings {:physical-iface "wlan0"}})
        [res err] (with-err #(app/sync-before-rules! (:system h)))]
    (is (r/ok? res))
    (is (false? (-> res :ok :accept?)))
    (is (str/includes? err "mark ACCEPT not inserted"))))

;; ---------------------------------------------------------------- enable / disable

(deftest enable-installs-everything
  (let [h   (harness {:files {"/etc/vpn-killswitch/exclude.users" "1000\n"}})
        res (app/enable! (:system h))]
    (is (r/ok? res))
    (is (true? (-> res :ok :enabled?)))
    (is (= "eth0" (-> res :ok :routing :phys)))
    (testing "legacy uid-mode state dropped"
      (is (= ["/etc/vpn-killswitch/exclude.users"] @(:deletes h))))
    (testing "unit written with the self path, so exclusion now reads as enabled"
      (is (= (d/unit-text self-path) (file h unit-file)))
      (is (app/enabled? (:system h))))
    (testing "before.rules carries the ACCEPT"
      (is (= synced-rules (file h "/etc/ufw/before.rules"))))
    (testing "order: cgroup, unit, routing, before.rules"
      (is (= (concat [mkdir-cg sd-reload sd-enable] apply-cmds [ufw-reload])
             (cmds h))))))

(deftest enable-is-idempotent
  (let [h (harness)]
    (app/enable! (:system h))
    (let [rules (file h "/etc/ufw/before.rules")]
      (is (r/ok? (app/enable! (:system h))))
      (is (= rules (file h "/etc/ufw/before.rules"))))))

(deftest enable-refuses-without-cgroup-v2
  (let [h       (harness {:files {"/sys/fs/cgroup/cgroup.controllers" nil}})
        [res _] (with-err #(app/enable! (:system h)))]
    (is (= :exclude/cgroup-unavailable (:error res)))
    (is (= "exclude: cgroup v2 unavailable, cannot enable" (:message res)))
    (is (nil? (file h unit-file)) "no half-enabled unit left behind")
    (is (= [] (cmds h)))))

(deftest enable-stops-on-daemon-reload-failure
  (let [h   (harness {:table {sd-reload {:exit 1}}})
        res (app/enable! (:system h))]
    (is (= :exclude/daemon-reload-failed (:error res)))
    (is (= [mkdir-cg sd-reload] (cmds h)))))

(deftest disable-removes-everything
  (let [h   (harness {:files accept-files})
        res (app/disable! (:system h))]
    (is (r/ok? res))
    (is (false? (-> res :ok :enabled?)))
    (is (false? (app/enabled? (:system h))))
    (is (= plain-rules (file h "/etc/ufw/before.rules")))
    (is (= [unit-file] @(:deletes h)))
    (is (= (concat [sd-disable sd-reload] teardown-cmds [rmdir-cg ufw-reload])
           (cmds h)))))

(deftest enable-then-disable-round-trips-before-rules
  (let [h (harness)]
    (app/enable! (:system h))
    (app/disable! (:system h))
    (is (= plain-rules (file h "/etc/ufw/before.rules")))))

(deftest disable-without-killswitch-still-tears-down
  (let [h   (harness {:files (assoc enabled-files "/etc/ufw/before.rules" nil)})
        res (app/disable! (:system h))]
    (is (= :exclude/no-before-rules (:error res)))
    (is (false? (app/enabled? (:system h))))
    (is (some #{rmdir-cg} (cmds h)))))

(deftest remove-all-never-fails
  (let [h   (harness {:files enabled-files
                      :table (failing (concat teardown-cmds [sd-disable sd-reload rmdir-cg]))})
        res (app/remove-all! (:system h))]
    (is (r/ok? res))
    (is (= {:legacy-removed? true :unit-removed? true :cgroup-removed? false}
           (select-keys (:ok res) [:legacy-removed? :unit-removed? :cgroup-removed?])))
    (is (= ["/etc/vpn-killswitch/exclude.users" unit-file] @(:deletes h)))
    (is (= (concat teardown-cmds [sd-disable sd-reload rmdir-cg]) (cmds h)))
    (is (= [] @(:writes h)) "before.rules is left alone")))

(deftest remove-all-survives-a-failing-delete
  (let [h   (harness {:files enabled-files})
        sys (assoc (:system h)
                   :delete-fn (fn [p] (r/err :fs/delete-failed {:path p}))
                   :systemd (sd/make (:shell h) {:write-fn (:write-fn (:system h))
                                                 :delete-fn (fn [p] (r/err :fs/delete-failed {:path p}))}))
        res (app/remove-all! sys)]
    (is (r/ok? res))
    (is (false? (-> res :ok :legacy-removed?)))
    (is (false? (-> res :ok :unit-removed?)))
    (is (some #{rmdir-cg} (cmds h)))))

;; ---------------------------------------------------------------- status

(deftest status-when-disabled
  (let [h (harness)]
    (is (= {:enabled? false :prog "vpn-kis"} (:ok (app/status (:system h)))))
    (is (= [] (cmds h)))))

(deftest status-when-enabled
  (let [h   (harness {:files (assoc accept-files "/sys/fs/cgroup/vpnkis-exclude/cgroup.procs" "4242\n4243\n")
                      :table {["ip" "rule" "show" "priority" "5080"]
                              {:stdout "5080:\tfrom all fwmark 0x51 lookup 151\n"}
                              ["ip" "route" "show" "table" "151"]
                              {:stdout "default via 192.168.1.1 dev eth0\n"}
                              ["iptables" "-t" "mangle" "-S" "VPNKIS-EXCLUDE"]
                              {:stdout "-N VPNKIS-EXCLUDE\n-A VPNKIS-EXCLUDE -d 127.0.0.0/8 -j RETURN\n"}
                              ["iptables" "-t" "nat" "-S" "VPNKIS-EXCLUDE-NAT"]
                              {:exit 1 :stderr "iptables: No chain/target/match by that name.\n"}
                              ["systemctl" "is-active" "vpn-killswitch-exclude.service"]
                              {:exit 0 :stdout "active\n"}}})
        st  (:ok (app/status (:system h)))]
    (is (true? (:enabled? st)))
    (is (= "eth0" (:phys st)))
    (is (= ["4242" "4243"] (:members st)))
    (is (= ["5080:\tfrom all fwmark 0x51 lookup 151"] (:ip-rules st)))
    (is (= ["default via 192.168.1.1 dev eth0"] (:routes st)))
    (is (= ["-N VPNKIS-EXCLUDE" "-A VPNKIS-EXCLUDE -d 127.0.0.0/8 -j RETURN"] (:mangle st)))
    (is (= [] (:nat st)))
    (is (= ["-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"] (:before-rules-accept st)))
    (is (= "active" (:unit-active st)))
    (is (= ["exclude: ENABLED (cgroup /sys/fs/cgroup/vpnkis-exclude -> eth0, mark 0x51 table 151)"
            "  members (PIDs in cgroup):"
            "    4242"
            "    4243"]
           (take 4 (d/status-lines st))))))

(deftest status-with-absent-cgroup-and-inactive-unit
  (let [h  (harness {:files enabled-files
                     :table {["systemctl" "is-active" "vpn-killswitch-exclude.service"]
                             {:exit 3 :stdout "inactive\n"}}})
        st (:ok (app/status (:system h)))]
    (is (nil? (:members st)))
    (is (= "inactive" (:unit-active st)))
    (is (some #{"    (none / cgroup absent)"} (d/status-lines st)))))

;; ---------------------------------------------------------------- run

(def procs "/sys/fs/cgroup/vpnkis-exclude/cgroup.procs")

(deftest prepare-run-when-enabled
  (let [h   (harness {:files accept-files})
        res (app/prepare-run! (:system h) ["--" "apt-get" "update"])]
    (is (= {:argv ["apt-get" "update"] :cgroup-procs procs :user nil} (:ok res)))
    (testing "routing re-applied, before.rules untouched, the command itself never run"
      (is (= apply-cmds (cmds h)))
      (is (= [] @(:writes h))))))

(deftest prepare-run-enables-on-first-use
  (let [h   (harness)
        res (app/prepare-run! (:system h) ["curl" "ifconfig.me"])]
    (is (= ["curl" "ifconfig.me"] (-> res :ok :argv)))
    (is (app/enabled? (:system h)))
    (is (= synced-rules (file h "/etc/ufw/before.rules")))
    (testing "enable (apply + sync), then the re-apply; no second sync"
      (is (= (concat [mkdir-cg sd-reload sd-enable] apply-cmds [ufw-reload] apply-cmds)
             (cmds h))))))

(deftest prepare-run-self-heals-a-missing-accept
  (let [h   (harness {:files enabled-files})
        res (app/prepare-run! (:system h) ["--" "true"])]
    (is (r/ok? res))
    (is (= synced-rules (file h "/etc/ufw/before.rules")))
    (is (= (concat apply-cmds [ufw-reload]) (cmds h)))))

(deftest prepare-run-as-user
  (let [h   (harness {:files accept-files})
        res (app/prepare-run! (:system h) ["--as" "bob" "--" "curl" "x"])]
    (is (= {:argv ["runuser" "-u" "bob" "--" "curl" "x"] :cgroup-procs procs :user "bob"}
           (:ok res)))
    (is (= ["id" "bob"] (first (cmds h))))))

(deftest prepare-run-legacy-user-form
  (let [h   (harness {:files accept-files})
        res (app/prepare-run! (:system h) ["alice" "--" "curl"])]
    (is (= ["runuser" "-u" "alice" "--" "curl"] (-> res :ok :argv)))))

(deftest prepare-run-rejects-bad-args-without-side-effects
  (doseq [[args msg] [[["--as" "ghost" "--" "x"] "exclude run: user 'ghost' does not exist"]
                      [["--frob"] "exclude run: unknown flag '--frob'"]
                      [["--as"] "exclude run: --as needs a username"]
                      [[] "exclude run: usage: sudo vpn-kis exclude run [--as USER] -- <command>"]]]
    (let [h   (harness)
          res (app/prepare-run! (:system h) args)]
      (is (= :exclude/usage (:error res)) (pr-str args))
      (is (= msg (:message res)))
      (is (every? #(= "id" (first %)) (cmds h)))
      (is (= [] @(:writes h))))))

(defn- without-runuser [shell]
  (reify proto/IShell
    (shell-exec! [_this cmd opts] (proto/shell-exec! shell cmd opts))
    (shell-env [_this] (proto/shell-env shell))
    (shell-which [_this program]
      (if (= "runuser" program)
        (r/err :shell/not-found {:program program})
        (proto/shell-which shell program)))))

(deftest prepare-run-needs-runuser-for-as
  (let [h   (harness {:files accept-files :shell-fn without-runuser})
        res (app/prepare-run! (:system h) ["--as" "bob" "--" "x"])]
    (is (= :exclude/no-runuser (:error res)))
    (is (= "exclude run: 'runuser' (util-linux) needed for --as" (:message res)))
    (is (= [["id" "bob"]] (cmds h)) "only the user probe ran")
    (testing "a run without --as does not need it"
      (is (r/ok? (app/prepare-run! (:system h) ["--" "x"]))))))

(deftest prepare-run-surfaces-apply-failure
  (let [h       (harness {:files accept-files :table {gw-query {:stdout ""}}})
        [res _] (with-err #(app/prepare-run! (:system h) ["--" "x"]))]
    (is (= :exclude/apply-failed (:error res)))
    (is (= "exclude run: could not apply exclusion rules" (:message res)))
    (is (= :exclude/no-gateway (-> res :cause :error)))))

(deftest prepare-run-surfaces-enable-failure
  (let [h       (harness {:files {"/sys/fs/cgroup/cgroup.controllers" nil}})
        [res _] (with-err #(app/prepare-run! (:system h) ["--" "x"]))]
    (is (= :exclude/cgroup-unavailable (:error res)))
    (is (not (app/enabled? (:system h))))))
