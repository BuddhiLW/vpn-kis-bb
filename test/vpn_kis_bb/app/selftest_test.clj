(ns vpn-kis-bb.app.selftest-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.app.selftest :as app]
            [vpn-kis-bb.domain.selftest :as st]))

;; ---------------------------------------------------------------- harness

(defn- lines [& ls] (str (str/join "\n" ls) "\n"))

(defn- table-shell
  "RecordingShell answering from `table` (full argv -> response). Any other
   command exits 127, like a binary that is not installed."
  [table]
  (rec/make {:respond (fn [cmd _] (get table cmd {:exit 127 :stdout ""}))}))

(defn- missing-binaries
  "Wrap `inner` so commands whose binary is in `missing` come back as an
   err Result, the way the JVM shell reports a program it cannot run."
  [inner missing]
  (reify proto/IShell
    (shell-exec! [_ cmd opts]
      (if (contains? missing (first cmd))
        (r/err :shell/exec-failed {:cmd cmd :message "Cannot run program"})
        (proto/shell-exec! inner cmd opts)))
    (shell-env [_] {})
    (shell-which [_ program] (r/err :shell/not-found {:program program}))))

(defn- system-of
  "Hand-built system: `files` are served by :read-fn (anything else reads
   as nil); settings default to a pinned wlan0."
  ([shell] (system-of shell {}))
  ([shell {:keys [files settings]}]
   {:shell    shell
    :read-fn  (fn [path] (get files path))
    :settings (merge {:physical-iface "wlan0"} settings)}))

(defn- quietly
  "Run f with the log lines (stderr) captured: [result log-text]."
  [f]
  (let [res (atom nil)
        log (with-out-str (binding [*err* *out*] (reset! res (f))))]
    [@res log]))

(defn- msgs [res] (mapv :msg (:results (:ok res))))
(defn- statuses [res] (mapv :status (:results (:ok res))))
(defn- counts [res] (select-keys (:ok res) [:passed :failed]))

;; ---------------------------------------------------------------- fixtures

(def vpn-ip "185.65.134.10")
(def isp-ip "203.0.113.7")

(def rules-strict
  (lines "-N ufw-before-output"
         "-A ufw-before-output -o lo -j ACCEPT"
         "-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
         "-A ufw-before-output -o wlan0 -p udp -m udp --dport 67 -j ACCEPT"
         "-A ufw-before-output -o wlan0 -m set --match-set vpn_endpoints dst -j ACCEPT"
         "-A ufw-before-output -o tun+ -j ACCEPT"
         "-A ufw-before-output -o wg+ -j ACCEPT"
         "-A ufw-before-output -o wlan0 -j DROP"))

(def rules-permissive
  (lines "-N ufw-before-output"
         "-A ufw-before-output -o lo -j ACCEPT"
         "-A ufw-before-output -o wlan0 -p udp -m udp --dport 53 -j ACCEPT"
         "-A ufw-before-output -o wlan0 -p tcp -m tcp --dport 53 -j ACCEPT"
         "-A ufw-before-output -o wlan0 -p tcp -m tcp --dport 443 -j ACCEPT"
         "-A ufw-before-output -o tun+ -j ACCEPT"
         "-A ufw-before-output -o wg+ -j ACCEPT"
         "-A ufw-before-output -o wlan0 -j DROP"))

(def link-up
  (lines "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00"
         "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000\\    link/ether 3c:22:fb:00:00:01 brd ff:ff:ff:ff:ff:ff"
         "5: wg0-mullvad: <POINTOPOINT,UP,LOWER_UP> mtu 1380 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/none "))

(def healthy
  "Command table of a healthy strict install with the VPN up."
  {["ufw" "status"]                        {:exit 0 :stdout "Status: active\n"}
   ["ufw" "status" "verbose"]              {:exit 0 :stdout (lines "Status: active"
                                                                   "Logging: on (low)"
                                                                   "Default: deny (incoming), deny (outgoing), disabled (routed)"
                                                                   "New profiles: skip")}
   ["iptables" "-S" "ufw-before-output"]   {:exit 0 :stdout rules-strict}
   ["ip6tables" "-S" "ufw6-before-output"] {:exit 0 :stdout (lines "-N ufw6-before-output"
                                                                   "-A ufw6-before-output -j DROP")}
   ["ipset" "list" "vpn_endpoints"]        {:exit 0 :stdout (lines "Name: vpn_endpoints" "Type: hash:ip"
                                                                   "Number of entries: 3" "Members:"
                                                                   vpn-ip "1.1.1.1" "8.8.8.8")}
   ["ip" "-o" "link" "show" "up"]          {:exit 0 :stdout link-up}
   ["curl" "--max-time" "5" "-s" "https://ifconfig.me"] {:exit 0 :stdout vpn-ip}})

(def ipv6-off {"/proc/sys/net/ipv6/conf/all/disable_ipv6" "1\n"})

(defn- passive-with [table & [opts]]
  (let [shell (table-shell table)
        [res _] (quietly #(app/passive (system-of shell (merge {:files ipv6-off} opts))))]
    [res shell]))

;; ---------------------------------------------------------------- passive

(deftest passive-all-pass
  (let [[res shell] (passive-with healthy)]
    (is (r/ok? res))
    (is (= {:passed 8 :failed 0} (counts res)))
    (is (= ["UFW active"
            "Default outgoing policy: deny"
            "Physical IF DROP rule present (wlan0)"
            "VPN interfaces ACCEPT: tun+ wg+"
            "IPv6 disabled"
            "IPv6 DROP rule present"
            "Strict mode active: ipset 'vpn_endpoints' with 3 IPs"
            "VPN up (wg0-mullvad), public IP: 185.65.134.10"]
           (msgs res)))
    (testing "bash order; a configured physical IF needs no route lookup"
      (is (= [["ufw" "status"]
              ["ufw" "status" "verbose"]
              ["iptables" "-S" "ufw-before-output"]
              ["ip6tables" "-S" "ufw6-before-output"]
              ["ipset" "list" "vpn_endpoints"]
              ["ip" "-o" "link" "show" "up"]
              ["curl" "--max-time" "5" "-s" "https://ifconfig.me"]]
             (rec/cmds shell))))
    (is (= ["[PASS] UFW active" "[PASS] Default outgoing policy: deny"]
           (take 2 (st/result-lines (:results (:ok res))))))))

(deftest passive-killswitch-missing
  (let [no-drop     (str/replace rules-strict "-A ufw-before-output -o wlan0 -j DROP\n" "")
        [res _]     (passive-with (assoc healthy ["iptables" "-S" "ufw-before-output"]
                                         {:exit 0 :stdout no-drop}))]
    (is (= {:passed 7 :failed 1} (counts res)))
    (is (= (st/fail "No DROP rule on wlan0 in ufw-before-output: killswitch will NOT fire")
           (nth (:results (:ok res)) 2)))))

(deftest passive-ufw-down
  (let [[res _] (passive-with (assoc healthy
                                     ["ufw" "status"] {:exit 0 :stdout "Status: inactive\n"}
                                     ["ufw" "status" "verbose"] {:exit 0 :stdout "Status: inactive\n"}))]
    (is (= [:fail :fail] (take 2 (statuses res))))
    (is (= "UFW not active: killswitch off" (first (msgs res))))))

(deftest passive-permissive-skips
  (let [[res shell] (passive-with (assoc healthy ["iptables" "-S" "ufw-before-output"]
                                         {:exit 0 :stdout rules-permissive}))]
    (is (= {:passed 7 :failed 0} (counts res)) "permissive mode is a SKIP, not a failure")
    (is (= (st/skip (str "Permissive mode (no ipset/no -d rules): pre-VPN HTTPS/DNS open, "
                         "full leak test will fail by design"))
           (nth (:results (:ok res)) 6)))
    (is (not-any? #{["ipset" "list" "vpn_endpoints"]} (rec/cmds shell))
        "the ipset is only listed when the rules reference it")))

(deftest passive-empty-ipset-fails
  (let [[res _] (passive-with (assoc healthy ["ipset" "list" "vpn_endpoints"]
                                     {:exit 1 :stdout ""}))]
    (is (= {:passed 7 :failed 1} (counts res)))
    (is (= [:fail :skip] (subvec (statuses res) 6 8)))))

(deftest passive-ipt-ro-falls-back-to-iptables-nft
  (let [[res shell] (passive-with
                     (-> healthy
                         (assoc ["iptables" "-S" "ufw-before-output"]
                                {:exit 1 :stdout ""
                                 :stderr "iptables v1.8.10 (legacy): chain `ufw-before-output' is incompatible, use 'nft' tool."})
                         (assoc ["iptables-nft" "-S" "ufw-before-output"]
                                {:exit 0 :stdout rules-strict})))]
    (is (= {:passed 8 :failed 0} (counts res)))
    (is (= [["iptables" "-S" "ufw-before-output"]
            ["iptables-nft" "-S" "ufw-before-output"]]
           (filterv #(str/starts-with? (first %) "iptables") (rec/cmds shell)))
        "iptables-legacy is never reached once iptables-nft answers")))

(deftest passive-without-any-iptables-backend
  (let [[res shell] (passive-with (dissoc healthy ["iptables" "-S" "ufw-before-output"]))]
    (is (= [["iptables" "-S" "ufw-before-output"]
            ["iptables-nft" "-S" "ufw-before-output"]
            ["iptables-legacy" "-S" "ufw-before-output"]]
           (filterv #(str/starts-with? (first %) "iptables") (rec/cmds shell))))
    (is (= [:pass :pass :fail :fail :pass :pass :skip :pass] (statuses res)))))

(deftest ipt-ro-order
  (testing "first exit-0 backend wins, even with empty output"
    (let [shell (table-shell {["iptables" "-S" "x"] {:exit 0 :stdout ""}})]
      (is (= "" (app/ipt-ro shell ["-S" "x"])))
      (is (= [["iptables" "-S" "x"]] (rec/cmds shell)))))
  (testing "an err Result (binary missing on the JVM shell) falls through"
    (let [inner (table-shell {["iptables-legacy" "-S" "x"] {:exit 0 :stdout "-N x\n"}})
          shell (missing-binaries inner #{"iptables" "iptables-nft"})]
      (is (= "-N x\n" (app/ipt-ro shell ["-S" "x"])))
      (is (= [["iptables-legacy" "-S" "x"]] (rec/cmds inner)))))
  (is (nil? (app/ipt-ro (table-shell {}) ["-S" "x"]))))

(deftest passive-vpn-iface-with-at-suffix
  (let [[res _] (passive-with (assoc healthy ["ip" "-o" "link" "show" "up"]
                                     {:exit 0 :stdout (lines "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536"
                                                             "7: wg0@if3: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420")}))]
    (is (= "VPN up (wg0), public IP: 185.65.134.10" (last (msgs res))))))

(deftest passive-without-vpn-iface
  (let [[res shell] (passive-with (assoc healthy ["ip" "-o" "link" "show" "up"]
                                         {:exit 0 :stdout (lines "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536"
                                                                 "2: wlan0: <BROADCAST,UP,LOWER_UP> mtu 1500")}))]
    (is (= (st/skip "No active VPN interface detected") (last (:results (:ok res)))))
    (is (not-any? #(= "curl" (first %)) (rec/cmds shell)))))

(deftest physical-iface-resolution
  (testing "the setting wins, nothing is read"
    (let [shell (table-shell {})]
      (is (= "eth9" (app/physical-iface (system-of shell {:settings {:physical-iface "eth9"}}))))
      (is (= [] (rec/cmds shell)))))
  (testing "else the IF pinned in before.rules, no route lookup"
    (let [shell (table-shell {})
          sys   (system-of shell {:settings {:physical-iface nil}
                                  :files {"/etc/ufw/before.rules"
                                          (lines "*filter" "-A ufw-before-output -o enp3s0 -j DROP" "COMMIT")}})]
      (is (= "enp3s0" (app/physical-iface sys)))
      (is (= [] (rec/cmds shell)))))
  (testing "else the first non-virtual default route"
    (let [shell (table-shell {["ip" "-4" "route" "ls"]
                              {:exit 0 :stdout (lines "default dev wg0-mullvad scope link"
                                                      "default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600")}})]
      (is (= "wlp2s0" (app/physical-iface (system-of shell {:settings {:physical-iface nil}}))))
      (is (= [["ip" "-4" "route" "ls"]] (rec/cmds shell)))))
  (testing "passive checks the DROP rule on the resolved IF"
    (let [[res _] (passive-with (assoc healthy ["ip" "-4" "route" "ls"]
                                       {:exit 0 :stdout "default via 10.0.0.1 dev eth0 metric 100\n"})
                                {:settings {:physical-iface nil}})]
      (is (= (st/fail "No DROP rule on eth0 in ufw-before-output: killswitch will NOT fire")
             (nth (:results (:ok res)) 2))))))

;; ---------------------------------------------------------------- active

(defn- active-shell
  "RecordingShell for `test active` on `iface`. The tunnel state flips on
   the down/up commands; with `leaky?` every probe gets through while it
   is down. `overrides` (argv -> response) are consulted first."
  ([iface leaky?] (active-shell iface leaky? {}))
  ([iface leaky? overrides]
   (let [up? (atom true)]
     (rec/make
      {:respond
       (fn [cmd _]
         (let [leak? (and leaky? (not @up?))]
           (or (get overrides cmd)
               (condp = cmd
                 ["wg-quick" "down" iface]        (do (reset! up? false) {:exit 0})
                 ["ip" "link" "set" iface "down"] (do (reset! up? false) {:exit 0})
                 ["wg-quick" "up" iface]          (do (reset! up? true) {:exit 0})
                 ["ip" "link" "set" iface "up"]   (do (reset! up? true) {:exit 0})
                 ["ip" "-o" "link" "show" "up"]
                 {:exit 0 :stdout (lines "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
                                         (str "5: " iface ": <POINTOPOINT,UP,LOWER_UP> mtu 1380"))}
                 ["curl" "--max-time" "5" "-s" "https://ifconfig.me"]
                 (cond @up? {:exit 0 :stdout vpn-ip}
                       leak? {:exit 0 :stdout isp-ip}
                       :else {:exit 28 :stdout ""})
                 ["curl" "--max-time" "10" "-s" "https://ifconfig.me"]
                 (if @up? {:exit 0 :stdout vpn-ip} {:exit 28 :stdout ""})
                 ["curl" "--max-time" "5" "-s" "https://1.1.1.1"]
                 (if leak? {:exit 0 :stdout "<html><head>"} {:exit 28 :stdout ""})
                 ["ping" "-c" "2" "-W" "2" "8.8.8.8"]
                 {:exit (if leak? 0 1)}
                 ["dig" "+time=3" "+tries=1" "google.com" "@8.8.8.8" "+short"]
                 {:exit (if leak? 0 9)}
                 ["iptables" "-S" "ufw-before-output"]
                 {:exit 0 :stdout rules-strict}
                 {:exit 127 :stdout ""}))))}))))

(defn- forced [shell] (system-of shell {:settings {:force? true}}))

(defn- active-run
  "Run the active test with no real sleeps: [result log sleeps]."
  [sys opts]
  (let [sleeps (atom [])
        [res log] (quietly #(app/active sys (merge {:sleep-fn (fn [ms] (swap! sleeps conj ms))} opts)))]
    [res log @sleeps]))

(deftest active-no-leak
  (let [shell (active-shell "wg0" false)
        [res log sleeps] (active-run (system-of shell) {:confirm-fn (constantly true)})]
    (is (r/ok? res))
    (is (= {:passed 5 :failed 0} (counts res)))
    (is (not (:aborted? (:ok res))))
    (is (= ["curl ifconfig.me timed out (no leak)"
            "curl 1.1.1.1 timed out (no leak)"
            "ping 8.8.8.8 blocked"
            "DNS @8.8.8.8 blocked"
            "VPN restored, public IP: 185.65.134.10"]
           (msgs res)))
    (is (= [["ip" "-o" "link" "show" "up"]
            ["curl" "--max-time" "5" "-s" "https://ifconfig.me"]
            ["wg-quick" "down" "wg0"]
            ["curl" "--max-time" "5" "-s" "https://ifconfig.me"]
            ["curl" "--max-time" "5" "-s" "https://1.1.1.1"]
            ["ping" "-c" "2" "-W" "2" "8.8.8.8"]
            ["dig" "+time=3" "+tries=1" "google.com" "@8.8.8.8" "+short"]
            ["wg-quick" "up" "wg0"]
            ["curl" "--max-time" "10" "-s" "https://ifconfig.me"]]
           (rec/cmds shell)))
    (is (= [2000 3000] sleeps))
    (is (str/includes? log "Baseline public IP (VPN up): 185.65.134.10"))
    (is (str/includes? log "Restoring VPN: wg-quick up wg0"))
    (is (str/includes? log "KILLSWITCH VERIFIED: no leak detected"))))

(deftest active-leak-detected
  (let [shell (active-shell "wg0" true)
        [res log _] (active-run (system-of shell) {:confirm-fn (constantly true)})]
    (is (= ["curl ifconfig.me returned: 203.0.113.7 (LEAK: killswitch failed)"
            "curl 1.1.1.1 returned data (LEAK)"
            "ping 8.8.8.8 succeeded (LEAK)"
            "DNS @8.8.8.8 resolved (LEAK: DNS rule shouldn't allow this)"
            "VPN restored, public IP: 185.65.134.10"
            "KILLSWITCH FAILED: 4 leak vector(s) detected"]
           (msgs res)))
    (is (= {:passed 1 :failed 5} (counts res)))
    (is (some #{["iptables" "-S" "ufw-before-output"]} (rec/cmds shell))
        "the rules are read to judge the DNS answer")
    (is (= ["wg-quick" "up" "wg0"] (nth (rec/cmds shell) 8)) "tunnel restored after the probes")
    (is (not (str/includes? log "KILLSWITCH VERIFIED")))))

(deftest active-dns-answer-excused-in-permissive-mode
  (let [shell (active-shell "wg0" false
                            {["dig" "+time=3" "+tries=1" "google.com" "@8.8.8.8" "+short"] {:exit 0 :stdout "142.250.79.46\n"}
                             ["iptables" "-S" "ufw-before-output"] {:exit 0 :stdout rules-permissive}})
        [res _ _] (active-run (forced shell) {})]
    (is (= (st/skip "DNS @8.8.8.8 reached (permissive mode allows DNS to any host)")
           (nth (:results (:ok res)) 3)))
    (is (= {:passed 4 :failed 0} (counts res)))))

(deftest active-aborts-when-not-confirmed
  (let [shell (active-shell "wg0" false)
        asked (atom 0)
        [res log sleeps] (active-run (system-of shell) {:confirm-fn (fn [] (swap! asked inc) false)})]
    (is (= 1 @asked))
    (is (= {:results [] :passed 0 :failed 0 :aborted? true :reason :declined} (:ok res)))
    (is (= [] (rec/cmds shell)) "nothing runs, nothing goes down")
    (is (= [] sleeps))
    (is (str/includes? log "Aborted."))))

(deftest active-force-skips-confirmation
  (let [shell (active-shell "wg0" false)
        [res _ _] (active-run (forced shell) {:confirm-fn (fn [] (throw (ex-info "must not ask" {})))})]
    (is (= {:passed 5 :failed 0} (counts res)))))

(deftest active-default-prompt-reads-stdin
  (let [shell (active-shell "wg0" false)
        [res log _] (with-in-str "n\n" (active-run (system-of shell) {}))]
    (is (= :declined (:reason (:ok res))))
    (is (str/includes? log "Continue? [y/N] "))))

(deftest active-aborts-before-touching-the-tunnel
  (testing "no VPN iface up"
    (let [shell (active-shell "wg0" false {["ip" "-o" "link" "show" "up"]
                                           {:exit 0 :stdout "2: wlan0: <BROADCAST,UP,LOWER_UP> mtu 1500\n"}})
          [res _ _] (active-run (forced shell) {})]
      (is (= :no-vpn-iface (:reason (:ok res))))
      (is (= [(st/fail "No VPN interface up: cannot test drop.")] (:results (:ok res))))
      (is (= 1 (:failed (:ok res))))
      (is (= [["ip" "-o" "link" "show" "up"]] (rec/cmds shell)))))
  (testing "no baseline IP with the VPN up"
    (let [shell (active-shell "wg0" false {["curl" "--max-time" "5" "-s" "https://ifconfig.me"]
                                           {:exit 28 :stdout ""}})
          [res log _] (active-run (forced shell) {})]
      (is (= :no-baseline (:reason (:ok res))))
      (is (= [(st/fail "No internet even with VPN up: aborting.")] (:results (:ok res))))
      (is (str/includes? log "Baseline public IP (VPN up): <unreachable>"))
      (is (= [["ip" "-o" "link" "show" "up"] ["curl" "--max-time" "5" "-s" "https://ifconfig.me"]]
             (rec/cmds shell)))))
  (testing "the iface cannot be brought down"
    (let [shell (active-shell "tun0" false {["ip" "link" "set" "tun0" "down"] {:exit 2 :stdout ""}})
          [res _ sleeps] (active-run (forced shell) {})]
      (is (= :down-failed (:reason (:ok res))))
      (is (= [(st/fail "Could not bring tun0 down: cannot test drop.")] (:results (:ok res))))
      (is (= ["ip" "link" "set" "tun0" "down"] (last (rec/cmds shell))) "no probe ran")
      (is (= [] sleeps)))))

(deftest active-down-and-restore-commands
  (testing "wg-quick down fails (app-managed wg0-mullvad): ip link fallback"
    (let [shell (active-shell "wg0-mullvad" false {["wg-quick" "down" "wg0-mullvad"] {:exit 1 :stdout ""}})
          [res log _] (active-run (forced shell) {})
          cmds (rec/cmds shell)]
      (is (= {:passed 5 :failed 0} (counts res)))
      (is (= [["wg-quick" "down" "wg0-mullvad"] ["ip" "link" "set" "wg0-mullvad" "down"]] (subvec cmds 2 4)))
      (is (= ["ip" "link" "set" "wg0-mullvad" "up"] (nth cmds 8)))
      (is (str/includes? log "Restoring VPN: ip link set wg0-mullvad up"))))
  (testing "non-WireGuard iface: ip link down, then up"
    (let [shell (active-shell "tun0" false)
          [res log _] (active-run (forced shell) {})
          cmds (rec/cmds shell)]
      (is (= {:passed 5 :failed 0} (counts res)))
      (is (= ["ip" "link" "set" "tun0" "down"] (nth cmds 2)))
      (is (= ["ip" "link" "set" "tun0" "up"] (nth cmds 7)))
      (is (not-any? #(= "wg-quick" (first %)) cmds))
      (is (str/includes? log "Restoring VPN: ip link set tun0 up (then reconnect via Eddie/openvpn client)"))))
  (testing "restore fails: warned, no restored PASS, not a failure"
    (let [shell (active-shell "wg0" false {["wg-quick" "up" "wg0"] {:exit 1 :stdout ""}})
          [res log _] (active-run (forced shell) {})]
      (is (= {:passed 4 :failed 0} (counts res)))
      (is (str/includes? log "Restore command failed: reconnect VPN manually"))
      (is (str/includes? log "VPN not restored automatically: reconnect via your VPN client")))))

(deftest active-drops-the-egress-tunnel-not-tailscale
  (let [shell (active-shell "wg0-mullvad" false
                            {["ip" "-o" "link" "show" "up"]
                             {:exit 0 :stdout (lines "2: enp46s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
                                                     "4: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280"
                                                     "5: wg0-mullvad: <POINTOPOINT,UP,LOWER_UP> mtu 1380")}})
        [res _ _] (active-run (forced shell) {})
        cmds (rec/cmds shell)]
    (is (= {:passed 5 :failed 0} (counts res)))
    (is (= ["wg-quick" "down" "wg0-mullvad"] (nth cmds 2)))
    (is (not-any? #(some #{"tailscale0"} %) cmds))))

(deftest active-restores-the-tunnel-when-probing-throws
  (let [shell  (active-shell "wg0" false)
        caught (atom nil)]
    (quietly #(try (app/active (forced shell) {:sleep-fn (fn [_] (throw (ex-info "interrupted" {})))})
                   (catch Exception e (reset! caught e))))
    (is (= "interrupted" (ex-message @caught)))
    (is (= ["wg-quick" "up" "wg0"] (last (rec/cmds shell))))))

;; ---------------------------------------------------------------- verify report

(def ufw-numbered
  (lines "Status: active" ""
         "     To                         Action      From"
         "     --                         ------      ----"
         "[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24"
         ""))

(def addr-show
  (lines "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000"
         "    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0"
         "       valid_lft 85000sec preferred_lft 85000sec"
         "5: wg0-mullvad: <POINTOPOINT,UP,LOWER_UP> mtu 1380 qdisc noqueue state UNKNOWN group default qlen 1000"
         "    inet 10.64.1.2/32 scope global wg0-mullvad"))

(def output-chain
  (lines "Chain OUTPUT (policy DROP 0 packets, 0 bytes)"
         " pkts bytes target     prot opt in     out     source               destination"
         " 9001  812K ufw-before-logging-output  0    --  *      *       0.0.0.0/0            0.0.0.0/0"
         " 9001  812K ufw-before-output  0    --  *      *       0.0.0.0/0            0.0.0.0/0"))

(def default-route "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n")

(deftest verify-report-lines
  (let [shell  (table-shell {["ufw" "status" "numbered"]            {:exit 0 :stdout ufw-numbered}
                             ["iptables" "-L" "OUTPUT" "-n" "-v"]   {:exit 0 :stdout output-chain}
                             ["iptables" "-S" "ufw-before-output"]  {:exit 0 :stdout rules-strict}
                             ["ip" "-4" "addr" "show"]              {:exit 0 :stdout addr-show}
                             ["ip" "route" "show" "default"]        {:exit 0 :stdout default-route}})
        res    (app/verify-report (system-of shell {:files ipv6-off}))
        report (:ok res)]
    (is (r/ok? res))
    (is (= [["ufw" "status" "numbered"]
            ["iptables" "-L" "OUTPUT" "-n" "-v"]
            ["iptables" "-S" "ufw-before-output"]
            ["ip" "-4" "addr" "show"]
            ["ip" "route" "show" "default"]]
           (rec/cmds shell)))
    (is (= (st/verify-lines {:ufw-numbered ufw-numbered :output-chain output-chain
                             :kill-rules rules-strict :disable-ipv6 "1\n"
                             :addr-show addr-show :default-route default-route})
           report))
    (is (some #{{:level :plain :text "Chain OUTPUT (policy DROP 0 packets, 0 bytes)"}} report))
    (is (some #{{:level :plain :text "-A ufw-before-output -o wlan0 -j DROP"}} report))
    (is (some #{{:level :info :text "IPv6: DISABLED (good)"}} report))
    (is (some #{{:level :plain :text "  wlan0: 192.168.1.5/24"}} report))
    (is (some #{{:level :plain :text "default via 192.168.1.1 dev wlan0 proto dhcp metric 600"}} report))
    (is (= st/leak-test-hint (filterv #(= :warn (:level %)) report))
        "a healthy install warns only with the leak-test hint")))

(deftest verify-report-fallbacks
  (let [shell  (table-shell {["nft" "list" "chain" "ip" "filter" "OUTPUT"]
                             {:exit 0 :stdout (lines "table ip filter {" "\tchain OUTPUT {" "\t}" "}")}})
        report (:ok (app/verify-report (system-of shell)))]
    (is (= [["ufw" "status" "numbered"]
            ["iptables" "-L" "OUTPUT" "-n" "-v"]
            ["iptables-nft" "-L" "OUTPUT" "-n" "-v"]
            ["iptables-legacy" "-L" "OUTPUT" "-n" "-v"]
            ["nft" "list" "chain" "ip" "filter" "OUTPUT"]
            ["iptables" "-S" "ufw-before-output"]
            ["iptables-nft" "-S" "ufw-before-output"]
            ["iptables-legacy" "-S" "ufw-before-output"]
            ["ip" "-4" "addr" "show"]
            ["ip" "route" "show" "default"]]
           (rec/cmds shell)))
    (is (some #{{:level :warn :text "No iptables backend can render filter/OUTPUT."}} report))
    (is (some #{{:level :plain :text "table ip filter {"}} report))
    (is (some #{{:level :warn :text "ufw-before-output unreadable or empty: KILL-SWITCH NOT CONFIRMED."}} report))
    (is (some #{{:level :info :text "IPv6: ABSENT, stack not loaded (best)"}} report))))
