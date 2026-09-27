(ns vpn-kis-bb.app.split-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.dnsmasq-shell :as dnsmasq]
            [vpn-kis-bb.adapters.iproute-shell :as ipr]
            [vpn-kis-bb.adapters.ipset-shell :as ipset]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.app.split :as app]
            [vpn-kis-bb.domain.split :as s]))

;; ---------------------------------------------------------------- harness

(defn- which-shell
  "IShell over a RecordingShell whose shell-which finds only `available`.
   Method params stay distinct: cljw reads fields through a second `_`."
  [recorder available]
  (reify proto/IShell
    (shell-exec! [_this cmd opts] (proto/shell-exec! recorder cmd opts))
    (shell-env [_this] {})
    (shell-which [_this program]
      (if (contains? available program)
        (r/ok {:path (str "/usr/bin/" program)})
        (r/err :shell/not-found {:program program})))))

(defn- glob-match?
  "Test double for :glob-fn: a pattern with one `*`, matched against the
   part of path below dir."
  [dir pattern path]
  (let [prefix (str dir "/")
        i      (str/index-of pattern "*")
        head   (subs pattern 0 i)
        tail   (subs pattern (inc i))]
    (and (str/starts-with? path prefix)
         (let [rel (subs path (count prefix))]
           (and (str/starts-with? rel head)
                (str/ends-with? rel tail)
                (>= (count rel) (+ (count head) (count tail))))))))

(def all-tools #{"ipset" "openvpn" "mullvad-exclude"})

(defn- harness
  "System over a recording shell. files (path -> text) back :read-fn and
   :glob-fn; writes and deletes land in that map and are recorded."
  ([] (harness {}))
  ([{:keys [respond files available settings]}]
   (let [recorder  (rec/make {:respond respond})
         shell     (which-shell recorder (or available all-tools))
         state     (atom (or files {}))
         writes    (atom [])
         deletes   (atom [])
         write-fn  (fn [p body]
                     (swap! writes conj [p body])
                     (swap! state assoc p body)
                     (r/ok {:path p}))
         delete-fn (fn [p]
                     (swap! deletes conj p)
                     (swap! state dissoc p)
                     (r/ok {:path p}))]
     {:system  {:shell     shell
                :read-fn   (fn [p] (get @state p))
                :write-fn  write-fn
                :delete-fn delete-fn
                :glob-fn   (fn [dir pattern] (filter #(glob-match? dir pattern %) (keys @state)))
                :ipset     (ipset/make shell)
                :iproute   (ipr/make shell)
                :systemd   (sd/make shell {:write-fn write-fn :delete-fn delete-fn})
                :dnsmasq   (dnsmasq/make shell {:write-fn write-fn :delete-fn delete-fn})
                :settings  (merge {:prog "vpn-kis"} settings)}
      :rec     recorder
      :files   state
      :writes  writes
      :deletes deletes})))

(defn- cmds [h] (rec/cmds (:rec h)))

(defn- quietly
  "Run f with stdout and stderr captured: [result output]."
  [f]
  (let [res (atom nil)
        out (with-out-str (binding [*err* *out*] (reset! res (f))))]
    [@res out]))

(def good-cfg
  {:name        "example"
   :domains     ["*.example.com"]
   :dev         "tun-example"
   :priority    5089
   :ovpn-config "/etc/openvpn/example.ovpn"})

(def unit-path "/etc/systemd/system/vpn-killswitch-split-example.service")

(def unit-text (s/systemd-unit-text (:value (s/validate good-cfg))))

(def mullvad-rules
  (str "0:\tfrom all lookup local\n"
       "5199:\tnot from all fwmark 0x6d6f6c65 lookup 1836018789\n"
       "32766:\tfrom all lookup main\n"))

(defn- install-respond
  "OUTPUT lacks the jump to the split chain (so it is added), PREROUTING
   has it; no earlier MARK rule or ip rule exists; `ip rule show` prints
   rules."
  ([] (install-respond ""))
  ([rules]
   (fn [cmd _opts]
     (cond
       (= cmd (s/jump-check-cmd "OUTPUT"))                             {:exit 1}
       (= (take 5 cmd) ["iptables" "-t" "mangle" "-D" "VPNKIS-SPLIT"]) {:exit 1}
       (= (take 3 cmd) ["ip" "rule" "del"])                            {:exit 2}
       (= cmd ["ip" "rule" "show"])                                    {:stdout rules}))))

(defn- once-then-fail
  "respond fn: each command in cmds succeeds on its first call only."
  [cmds]
  (let [seen (atom {})]
    (fn [cmd _opts]
      (when (contains? cmds cmd)
        (if (= 1 (get (swap! seen update cmd (fnil inc 0)) cmd))
          {:exit 0}
          {:exit 2})))))

;; ---------------------------------------------------------------- install

(deftest install-applies-now-and-persists
  (let [h         (harness {:respond (install-respond)})
        [res out] (quietly #(app/install! (:system h) good-cfg))
        unit      "vpn-killswitch-split-example.service"]
    (is (= {:installed "example" :set "vpnkis_split_example_dst" :unit unit :dev "tun-example"
            :table 142 :mark "0x42" :priority 5089 :started? true}
           (:ok res)))
    (testing "bash split_install order: checks, ipset, mangle, ip rule, dnsmasq, hooks, unit"
      (is (= [["test" "-d" "/etc/dnsmasq.d"]
              ["systemctl" "is-active" "--quiet" "systemd-resolved"]
              ["test" "-f" "/etc/NetworkManager/conf.d/dnsmasq.conf"]
              ["ipset" "create" "vpnkis_split_example_dst" "hash:ip" "family" "inet"
               "hashsize" "1024" "maxelem" "65536" "timeout" "3600" "-exist"]
              ["iptables" "-t" "mangle" "-N" "VPNKIS-SPLIT"]
              ["iptables" "-t" "mangle" "-C" "OUTPUT" "-j" "VPNKIS-SPLIT"]
              ["iptables" "-t" "mangle" "-A" "OUTPUT" "-j" "VPNKIS-SPLIT"]
              ["iptables" "-t" "mangle" "-C" "PREROUTING" "-j" "VPNKIS-SPLIT"]
              (s/mark-del-cmd "example" "0x42")
              (s/mark-add-cmd "example" "0x42")
              ["ip" "rule" "del" "priority" "5089"]
              ["ip" "rule" "add" "fwmark" "0x42" "lookup" "142" "priority" "5089"]
              ["systemctl" "is-active" "--quiet" "dnsmasq"]
              ["systemctl" "reload" "dnsmasq"]
              ["chmod" "755" "/etc/vpn-killswitch/split/example.up.sh"
               "/etc/vpn-killswitch/split/example.down.sh"]
              ["systemctl" "daemon-reload"]
              ["systemctl" "enable" unit]
              ["systemctl" "start" unit]]
             (cmds h))))
    (testing "drop-in, hooks and unit written"
      (is (= ["/etc/dnsmasq.d/vpn-kis-split-example.conf"
              "/etc/vpn-killswitch/split/example.up.sh"
              "/etc/vpn-killswitch/split/example.down.sh"
              unit-path]
             (mapv first @(:writes h))))
      (is (= unit-text (get @(:files h) unit-path))))
    (testing "bash info lines"
      (is (str/includes? out (str "[+] Installing split 'example': domains=[*.example.com]"
                                  " dev=tun-example table=142 mark=0x42 priority=5089")))
      (is (str/includes? out "[+] Split 'example' installed. Bring the tunnel up with:"))
      (is (str/includes? out "[+]   sudo vpn-kis split connect example")))))

(deftest install-auto-priority-slots-below-mullvad
  (let [h         (harness {:respond (install-respond mullvad-rules)})
        [res out] (quietly #(app/install! (:system h) (assoc good-cfg :priority :auto)))]
    (is (= 5188 (-> res :ok :priority)))
    (is (some #{["ip" "rule" "add" "fwmark" "0x42" "lookup" "142" "priority" "5188"]} (cmds h)))
    (is (str/includes? (get @(:files h) unit-path) "priority 5188"))
    (is (str/includes? out "Mullvad fwmark rule at priority 5199: split rule goes to priority 5188"))))

(deftest install-auto-priority-without-mullvad-falls-back
  (let [h         (harness {:respond (install-respond "0:\tfrom all lookup local\n")})
        [res out] (quietly #(app/install! (:system h) (assoc good-cfg :priority "auto")))]
    (is (= 5090 (-> res :ok :priority)))
    (is (str/includes? out "Mullvad fwmark rule not found: split rule at fallback priority 5090"))))

(deftest install-by-name-reads-the-conf
  (let [h       (harness {:respond (install-respond)
                          :files   {"/etc/vpn-killswitch/split/example.conf"
                                    "DOMAINS=\"*.example.com\"\nDEV=tun-example\nPRIORITY=5089\n"}})
        [res _] (quietly #(app/install! (:system h) "example"))]
    (is (r/ok? res))
    (is (= 5089 (-> res :ok :priority)))))

(deftest install-stops-before-any-change-without-dnsmasq-dir
  (let [h       (harness {:respond (fn [cmd _opts]
                                     (when (= cmd ["test" "-d" "/etc/dnsmasq.d"]) {:exit 1}))})
        [res _] (quietly #(app/install! (:system h) good-cfg))]
    (is (= :split/no-dnsmasq (:error res)))
    (is (= "split: /etc/dnsmasq.d missing (apt install dnsmasq, or enable NM dnsmasq plugin)"
           (:hint res)))
    (is (= [["test" "-d" "/etc/dnsmasq.d"]] (cmds h)))
    (is (empty? @(:writes h)))))

(deftest install-warns-when-no-dnsmasq-fronts-resolved
  (let [h         (harness {:respond (fn [cmd opts]
                                       (cond
                                         (= cmd ["test" "-f" "/etc/NetworkManager/conf.d/dnsmasq.conf"]) {:exit 1}
                                         (= cmd ["systemctl" "is-active" "--quiet" "dnsmasq"]) {:exit 3}
                                         :else ((install-respond) cmd opts)))})
        [res out] (quietly #(app/install! (:system h) good-cfg))]
    (is (r/ok? res))
    (is (str/includes? out (str "[!] split: systemd-resolved is the active resolver but no"
                                " dnsmasq instance was detected.")))
    (is (str/includes? out "[!] split: dnsmasq must front DNS for the ipset= directive to work. See README."))))

(deftest install-needs-ipset
  (let [h       (harness {:respond (install-respond) :available #{"openvpn"}})
        [res _] (quietly #(app/install! (:system h) good-cfg))]
    (is (= {:error :split/no-ipset :hint "ipset required"} res))))

(deftest install-stops-at-the-first-hard-failure
  (let [h       (harness {:respond (fn [cmd opts]
                                     (if (= cmd (s/mark-add-cmd "example" "0x42"))
                                       {:exit 2 :stderr "iptables: No chain/target/match by that name."}
                                       ((install-respond) cmd opts)))})
        [res _] (quietly #(app/install! (:system h) good-cfg))]
    (is (= :split/command-failed (:error res)))
    (is (str/includes? (:hint res) "iptables -t mangle -A VPNKIS-SPLIT"))
    (is (str/includes? (:hint res) "No chain/target/match"))
    (is (not-any? #(= ["ip" "rule" "add"] (take 3 %)) (cmds h)))
    (is (empty? @(:writes h)))))

(deftest install-start-failure-only-warns
  (let [h         (harness {:respond (fn [cmd opts]
                                       (if (= cmd ["systemctl" "start" "vpn-killswitch-split-example.service"])
                                         {:exit 1}
                                         ((install-respond) cmd opts)))})
        [res out] (quietly #(app/install! (:system h) good-cfg))]
    (is (r/ok? res))
    (is (false? (-> res :ok :started?)))
    (is (str/includes? out "[!] split: could not start vpn-killswitch-split-example.service"))))

(deftest install-invalid-config
  (let [h       (harness)
        [res _] (quietly #(app/install! (:system h) (dissoc good-cfg :dev)))]
    (is (= :split/invalid-config (:error res)))
    (is (= "split: DEV empty in /etc/vpn-killswitch/split/example.conf (must match openvpn --dev)"
           (:hint res)))
    (is (empty? (cmds h)))))

;; ---------------------------------------------------------------- remove

(deftest remove-reads-the-rule-from-the-unit-and-drains
  (let [rule-del  ["ip" "rule" "del" "priority" "5089"]
        mark-del  (s/mark-del-cmd "example" "0x42")
        h         (harness {:respond (once-then-fail #{rule-del mark-del})
                            :files   {unit-path unit-text}})
        [res out] (quietly #(app/remove! (:system h) "example"))]
    (is (= {:removed "example" :unit? true :priority "5089" :fwmark "0x42"} (:ok res)))
    (is (= [["systemctl" "disable" "--now" "vpn-killswitch-split-example.service"]
            ["systemctl" "daemon-reload"]
            rule-del rule-del
            mark-del mark-del
            ["ipset" "destroy" "vpnkis_split_example_dst"]
            ["systemctl" "is-active" "--quiet" "dnsmasq"]
            ["systemctl" "reload" "dnsmasq"]]
           (cmds h)))
    (is (= [unit-path
            "/etc/dnsmasq.d/vpn-kis-split-example.conf"
            "/etc/vpn-killswitch/split/example.up.sh"
            "/etc/vpn-killswitch/split/example.down.sh"]
           @(:deletes h)))
    (is (str/includes? out (str "[+] Split 'example' removed. Config left at"
                                " /etc/vpn-killswitch/split/example.conf"
                                " (delete manually if no longer needed).")))))

(deftest remove-without-a-unit-still-cleans-up
  (let [h       (harness)
        [res _] (quietly #(app/remove! (:system h) "example"))]
    (is (= {:removed "example" :unit? false :priority nil :fwmark nil} (:ok res)))
    (is (= [["ipset" "destroy" "vpnkis_split_example_dst"]
            ["systemctl" "is-active" "--quiet" "dnsmasq"]
            ["systemctl" "reload" "dnsmasq"]]
           (cmds h)))))

(deftest remove-rejects-a-bad-name
  (let [h (harness)]
    (is (= :split/invalid-name (:error (app/remove! (:system h) "../x"))))
    (is (empty? (cmds h)))))

(deftest remove-runs-every-step-then-reports-what-failed
  (let [h         (harness {:respond (fn [cmd _opts]
                                       (when (#{["systemctl" "reload" "dnsmasq"]
                                                ["systemctl" "restart" "dnsmasq"]} cmd)
                                         {:exit 1}))})
        [res out] (quietly #(app/remove! (:system h) "example"))]
    (is (= :split/remove-incomplete (:error res)))
    (is (= [:reload-dnsmasq] (mapv :step (:failures res))))
    (is (= 3 (count @(:deletes h))) "the file deletes still ran")
    (is (str/includes? out "only partly removed"))))

(deftest drains-stop-at-the-limit
  (let [h (harness {:files {unit-path unit-text}})
        _ (quietly #(app/remove! (:system h) "example"))]
    (is (= app/drain-limit
           (count (filter #{["ip" "rule" "del" "priority" "5089"]} (cmds h)))))))

(deftest remove-all-removes-each-config-then-the-chain
  (let [h         (harness {:files {"/etc/vpn-killswitch/split/a.conf"        "DEV=tun-a\n"
                                    "/etc/vpn-killswitch/split/b.edn"         "{:dev \"tun-b\"}"
                                    "/etc/vpn-killswitch/split/bad name.conf" "DEV=x\n"}})
        [res out] (quietly #(app/remove-all! (:system h)))]
    (is (= {:removed ["a" "b"] :failed [] :skipped ["bad name"]} (:ok res)))
    (is (some #{["ipset" "destroy" "vpnkis_split_a_dst"]} (cmds h)))
    (is (some #{["ipset" "destroy" "vpnkis_split_b_dst"]} (cmds h)))
    (is (= s/chain-teardown-cmds (vec (take-last 4 (cmds h)))))
    (is (str/includes? out "skipping config 'bad name'"))))

;; ---------------------------------------------------------------- list / status

(deftest list-shows-installed-and-configured
  (let [h         (harness {:files {"/etc/vpn-killswitch/split/a.conf"                   "DEV=tun-a\n"
                                    "/etc/vpn-killswitch/split/b.conf"                   "DEV=tun-b\n"
                                    "/etc/systemd/system/vpn-killswitch-split-a.service" unit-text}})
        [res out] (quietly #(app/list-installed (:system h)))]
    (is (= [{:name "a" :unit "vpn-killswitch-split-a.service" :installed? true}
            {:name "b" :unit "vpn-killswitch-split-b.service" :installed? false}]
           (-> res :ok :splits)))
    (is (str/includes? out (s/list-line {:name "a" :installed? true} "vpn-kis")))
    (is (str/includes? out (s/list-line {:name "b" :installed? false} "vpn-kis")))))

(deftest list-with-no-configs
  (let [[res out] (quietly #(app/list-installed (:system (harness))))]
    (is (= [] (-> res :ok :splits)))
    (is (str/includes? out (str "[+] No splits configured. Drop a config at"
                                " /etc/vpn-killswitch/split/<name>.conf (see README).")))))

(deftest status-without-a-name-lists
  (let [[res out] (quietly #(app/status (:system (harness)) nil))]
    (is (= [] (-> res :ok :splits)))
    (is (str/includes? out "No splits configured"))))

(deftest status-prints-the-config-and-the-live-state
  (let [h         (harness {:files   {"/etc/vpn-killswitch/split/example.conf"
                                      "DOMAINS=\"*.example.com\"\nDEV=tun-example\nPRIORITY=5089\n"}
                            :respond (fn [cmd _opts]
                                       (cond
                                         (= cmd ["ipset" "list" "vpnkis_split_example_dst"])
                                         {:exit 1}

                                         (= cmd ["ip" "rule" "show" "priority" "5089"])
                                         {:stdout "5089:\tfrom all fwmark 0x42 lookup 142\n"}

                                         (= cmd ["ip" "route" "show" "table" "142"])
                                         {:stdout "default dev tun-example scope link\n"}

                                         (= (take 2 cmd) ["systemctl" "is-enabled"])
                                         {:stdout "enabled\n"}

                                         (= (take 2 cmd) ["systemctl" "is-active"])
                                         {:exit 3 :stdout "inactive\n"}))})
        [res out] (quietly #(app/status (:system h) "example"))]
    (is (= {:ipset-present? false
            :ipset          []
            :rules          ["5089:\tfrom all fwmark 0x42 lookup 142"]
            :routes         ["default dev tun-example scope link"]
            :enabled        "enabled"
            :active         "inactive"}
           (dissoc (:ok res) :config)))
    (is (str/includes? out "[+] Split 'example':"))
    (is (str/includes? out "[+]   ovpn      : (unset)"))
    (is (str/includes? out "[!]   ipset vpnkis_split_example_dst not present"))
    (is (str/includes? out "  5089:\tfrom all fwmark 0x42 lookup 142"))
    (is (str/includes? out "  enabled: enabled"))
    (is (str/includes? out "  active : inactive"))))

(deftest status-of-a-missing-split
  (let [[res _] (quietly #(app/status (:system (harness)) "nope"))]
    (is (= :split/invalid-config (:error res)))
    (is (= "split: config not found: /etc/vpn-killswitch/split/nope.conf" (:hint res)))))

;; ---------------------------------------------------------------- connect

(def ovpn "/etc/openvpn/example.ovpn")

(defn- connect-harness [opts]
  (harness (merge {:files {ovpn "client\n"}} opts)))

(defn- spawned? [h]
  (some #(contains? #{"openvpn" "mullvad-exclude"} (first %)) (cmds h)))

(defn- mullvad-says [status]
  (fn [cmd _opts] (when (= cmd ["mullvad" "status"]) status)))

(deftest connect-plan-builds-the-bash-argv
  (let [h         (connect-harness {:respond (mullvad-says {:stdout "Connected to se-got-wg-001\n"})})
        [res out] (quietly #(app/connect-plan (:system h) good-cfg))]
    (is (= (into ["mullvad-exclude"] (s/openvpn-argv (:value (s/validate good-cfg))))
           (-> res :ok :argv)))
    (is (true? (-> res :ok :mullvad-exclude?)))
    (is (str/includes? out "[+] Mullvad active: wrapping with mullvad-exclude"))
    (is (str/includes? out (str "[+] Connecting split 'example' (dev=tun-example,"
                                " config=/etc/openvpn/example.ovpn)")))
    (is (str/includes? out (str "[+] Default route will NOT be hijacked (route-nopull)."
                                " Route table 142 handles split traffic.")))
    (is (not (spawned? h)) "never runs openvpn itself")))

(deftest connect-plan-mullvad-wrapping
  (testing "Disconnected matches too (bash grep -qi connected); lockdown still blocks"
    (let [h       (connect-harness {:respond (mullvad-says {:stdout "Disconnected\n"})})
          [res _] (quietly #(app/connect-plan (:system h) good-cfg))]
      (is (true? (-> res :ok :mullvad-exclude?)))))
  (testing "mullvad status failing: no wrapper"
    (let [h       (connect-harness {:respond (mullvad-says {:exit 1 :stdout "Connected"})})
          [res _] (quietly #(app/connect-plan (:system h) good-cfg))]
      (is (= "openvpn" (first (-> res :ok :argv))))))
  (testing "no mullvad-exclude: no wrapper, and mullvad is not asked"
    (let [h       (connect-harness {:available #{"openvpn"}})
          [res _] (quietly #(app/connect-plan (:system h) good-cfg))]
      (is (false? (-> res :ok :mullvad-exclude?)))
      (is (not-any? #(= ["mullvad" "status"] %) (cmds h))))))

(deftest connect-plan-errors
  (let [plan (fn [h cfg] (first (quietly #(app/connect-plan (:system h) cfg))))]
    (is (= {:error :split/no-ovpn-config
            :hint  "split connect: OVPN_CONFIG not set in /etc/vpn-killswitch/split/example.conf"}
           (plan (connect-harness {}) (dissoc good-cfg :ovpn-config))))
    (is (= {:error :split/ovpn-not-found
            :hint  "split connect: OVPN_CONFIG not found: /etc/openvpn/example.ovpn"}
           (plan (harness) good-cfg)))
    (is (= {:error :split/no-openvpn :hint "openvpn not installed"}
           (plan (connect-harness {:available #{"mullvad-exclude"}}) good-cfg)))
    (is (= :split/invalid-config
           (:error (plan (connect-harness {}) (assoc good-cfg :name "a b")))))))

(deftest connect-hands-the-argv-to-the-exec-file
  (let [h       (connect-harness {:settings {:exec-file "/run/vpn-kis/exec.sh"}})
        [res _] (quietly #(app/connect! (:system h) good-cfg))
        script  (get @(:files h) "/run/vpn-kis/exec.sh")]
    (is (= "/run/vpn-kis/exec.sh" (-> res :ok :via)))
    (is (str/includes? script "exec 'openvpn' '--config' '/etc/openvpn/example.ovpn'"))
    (is (not (spawned? h))))
  (testing "without the launcher's exec file"
    (let [[res _] (quietly #(app/connect! (:system (connect-harness {})) good-cfg))]
      (is (= :exec/no-launcher (:error res))))))

(deftest connect-cmd-pure
  (let [v (:value (s/validate good-cfg))]
    (is (= (s/openvpn-argv v) (app/connect-cmd v)))
    (is (= "mullvad-exclude" (first (app/connect-cmd v :mullvad-exclude? true))))))
