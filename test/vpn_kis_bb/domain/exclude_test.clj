(ns vpn-kis-bb.domain.exclude-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.exclude :as d]))

(defn- text [& lines] (apply str (map #(str % "\n") lines)))

;; ---------------------------------------------------------------- fixtures

(def head-lines
  ["*filter"
   ":ufw-before-input - [0:0]"
   ":ufw-before-output - [0:0]"
   ":ufw-before-forward - [0:0]"
   ""
   "# --- Loopback ---"
   "-A ufw-before-input -i lo -j ACCEPT"
   "-A ufw-before-output -o lo -j ACCEPT"
   ""
   "# --- VPN interfaces: allow forwarded traffic (containers, VMs) ---"
   "-A ufw-before-forward -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
   "-A ufw-before-forward -o tun+ -j ACCEPT"])

(def ks-comment "# --- KILL-SWITCH: drop anything else on physical IF ---")
(def drop-out "-A ufw-before-output -o eth0 -j DROP")
(def drop-in "-A ufw-before-input  -i eth0 -j DROP")

(def block-lines
  [""
   "# --- BEGIN vpn-kis exclude (mark 0x51 via cgroup vpnkis-exclude) ---"
   "-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"
   "# --- END vpn-kis exclude ---"])

(def plain-rules
  "setup output with exclusion off"
  (apply text (concat head-lines ["" ks-comment drop-out drop-in "" "COMMIT"])))

(def setup-rules
  "setup output with exclusion on (block emitted before the KILL-SWITCH section)"
  (apply text (concat head-lines block-lines ["" ks-comment drop-out drop-in "" "COMMIT"])))

(def synced-rules
  "what the bash awk sync makes of plain-rules"
  (apply text (concat head-lines ["" ks-comment] block-lines [drop-out drop-in "" "COMMIT"])))

(def legacy-rules
  "an owner-based block written by an older version"
  (apply text (concat head-lines
                      [""
                       "# --- BEGIN vpn-kis exclude (owner-based: uid 1000 1001) ---"
                       "-A ufw-before-output -o eth0 -m owner --uid-owner 1000 -j ACCEPT"
                       "-A ufw-before-output -o eth0 -m owner --uid-owner 1001 -j ACCEPT"
                       "# --- END vpn-kis exclude (owner-based) ---"
                       "" ks-comment drop-out drop-in "" "COMMIT"])))

(def eth0-block (d/before-rules-block "eth0"))

;; ---------------------------------------------------------------- constants

(deftest constants
  (is (= "0x51" d/mark))
  (is (= 151 d/table))
  (is (= 5080 d/priority))
  (is (= "VPNKIS-EXCLUDE" d/mangle-chain))
  (is (= "VPNKIS-EXCLUDE-NAT" d/nat-chain))
  (is (= "vpn-killswitch-exclude.service" d/unit-name))
  (is (= "/etc/systemd/system/vpn-killswitch-exclude.service" d/unit-path))
  (is (= "/sys/fs/cgroup/vpnkis-exclude" d/cgroup))
  (is (= "vpnkis-exclude" d/cgroup-rel))
  (is (= (str d/cgroup "/cgroup.procs") d/cgroup-procs))
  (is (= "/etc/vpn-killswitch/exclude.users" d/legacy-users-file))
  (is (= ["127.0.0.0/8" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"
          "169.254.0.0/16" "224.0.0.0/4" "240.0.0.0/4"]
         d/skip-nets))
  (testing "markers and their stable prefixes"
    (is (= "# --- BEGIN vpn-kis exclude (mark 0x51 via cgroup vpnkis-exclude) ---" d/block-begin))
    (is (= "# --- END vpn-kis exclude ---" d/block-end))
    (is (str/starts-with? d/block-begin d/block-begin-prefix))
    (is (str/starts-with? d/block-end d/block-end-prefix))))

;; ---------------------------------------------------------------- before.rules

(deftest before-rules-block-text
  (is (= (apply text block-lines) eth0-block))
  (is (str/starts-with? eth0-block "\n")))

(deftest rewrite-inserts-before-drop
  (is (= synced-rules (d/rewrite-before-rules plain-rules "eth0" eth0-block))))

(deftest rewrite-is-idempotent
  (let [once (d/rewrite-before-rules plain-rules "eth0" eth0-block)]
    (is (= once (d/rewrite-before-rules once "eth0" eth0-block)))
    (is (= once (d/rewrite-before-rules (d/rewrite-before-rules once "eth0" eth0-block)
                                        "eth0" eth0-block)))))

(deftest rewrite-nil-strips-block
  (testing "synced file goes back to the plain setup output"
    (is (= plain-rules (d/rewrite-before-rules synced-rules "eth0" nil))))
  (testing "a block written by setup goes too"
    (is (= plain-rules (d/rewrite-before-rules setup-rules "eth0" nil))))
  (testing "no block present: unchanged"
    (is (= plain-rules (d/rewrite-before-rules plain-rules "eth0" nil))))
  (testing "a blank block string inserts nothing"
    (is (= plain-rules (d/rewrite-before-rules synced-rules "eth0" "\n\n")))))

(deftest rewrite-moves-setup-block-before-drop
  (is (= synced-rules (d/rewrite-before-rules setup-rules "eth0" eth0-block))))

(deftest rewrite-strips-legacy-owner-block
  (is (= synced-rules (d/rewrite-before-rules legacy-rules "eth0" eth0-block)))
  (is (= plain-rules (d/rewrite-before-rules legacy-rules "eth0" nil))))

(deftest rewrite-only-targets-phys-drop
  (let [two (text "-A ufw-before-output -o wlan0 -j DROP" drop-out "COMMIT")]
    (is (= (text "-A ufw-before-output -o wlan0 -j DROP"
                 "" d/block-begin "-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT" d/block-end
                 drop-out "COMMIT")
           (d/rewrite-before-rules two "eth0" eth0-block)))
    (testing "no DROP line for phys: block stripped, not inserted"
      (is (= plain-rules (d/rewrite-before-rules synced-rules "wlan0" (d/before-rules-block "wlan0")))))
    (testing "an eth0.5 DROP line is not eth0's"
      (let [t (text "-A ufw-before-output -o eth0.5 -j DROP")]
        (is (= t (d/rewrite-before-rules t "eth0" eth0-block)))))))

(deftest rewrite-unterminated-begin-keeps-the-drop
  (let [broken (apply text (concat head-lines
                                   ["# --- BEGIN vpn-kis exclude (half) ---"
                                    "-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"
                                    "" ks-comment drop-out drop-in "" "COMMIT"]))
        out    (d/rewrite-before-rules broken "eth0" nil)]
    (is (= (apply text (concat head-lines
                               ["-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"
                                "" ks-comment drop-out drop-in "" "COMMIT"]))
           out))
    (is (str/includes? out drop-out))
    (is (str/includes? out "COMMIT"))))

(deftest rewrite-line-handling
  (testing "empty text"
    (is (= "" (d/rewrite-before-rules "" "eth0" eth0-block)))
    (is (= "" (d/rewrite-before-rules nil "eth0" nil))))
  (testing "a missing final newline is added (awk prints every record with ORS)"
    (is (= (text "x" "y") (d/rewrite-before-rules "x\ny" "eth0" nil))))
  (testing "trailing blank lines survive"
    (is (= "x\n\n" (d/rewrite-before-rules "x\n\n" "eth0" nil))))
  (testing "a stray END line is kept"
    (let [t (text "x" d/block-end "y")]
      (is (= t (d/rewrite-before-rules t "eth0" nil))))))

(deftest pinned-phys-test
  (is (= "eth0" (d/pinned-phys plain-rules)))
  (is (= "eth0" (d/pinned-phys synced-rules)))
  (is (= "wlp0s20f3" (d/pinned-phys (text "-A ufw-before-output -o wlp0s20f3 -j DROP"))))
  (is (= "enp0s31f6.100" (d/pinned-phys (text "-A ufw-before-output -o enp0s31f6.100 -j DROP"))))
  (testing "first DROP wins"
    (is (= "wlan0" (d/pinned-phys (text "-A ufw-before-output -o wlan0 -j DROP" drop-out)))))
  (testing "no output DROP line"
    (is (nil? (d/pinned-phys (text drop-in "COMMIT"))))
    (is (nil? (d/pinned-phys "")))
    (is (nil? (d/pinned-phys nil)))))

(deftest accept-and-mark-lines
  (is (true? (d/accept-present? synced-rules)))
  (is (false? (d/accept-present? plain-rules)))
  (is (false? (d/accept-present? nil)))
  (is (= ["-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"]
         (d/mark-lines synced-rules)))
  (is (= [] (d/mark-lines nil))))

;; ---------------------------------------------------------------- unit

(deftest unit-text-exact
  (is (= (str "[Unit]\n"
              "Description=VPN Kill-Switch: cgroup-based VPN exclusion (mark + route excluded cgroup)\n"
              "After=network-online.target\n"
              "Wants=network-online.target\n"
              "\n"
              "[Service]\n"
              "Type=oneshot\n"
              "RemainAfterExit=yes\n"
              "ExecStart=/usr/local/bin/vpn-kis exclude _apply\n"
              "ExecStop=/usr/local/bin/vpn-kis exclude _teardown\n"
              "\n"
              "[Install]\n"
              "WantedBy=multi-user.target\n")
         (d/unit-text "/usr/local/bin/vpn-kis"))))

;; ---------------------------------------------------------------- exclude run args

(def users #{"bob" "alice"})

(deftest parse-run-args-grammar
  (let [p #(d/parse-run-args % users)]
    (testing "plain command after --"
      (is (= {:user nil :argv ["apt-get" "update"]} (p ["--" "apt-get" "update"]))))
    (testing "command without --"
      (is (= {:user nil :argv ["curl" "ifconfig.me"]} (p ["curl" "ifconfig.me"]))))
    (testing "--as USER and --as=USER"
      (is (= {:user "bob" :argv ["curl" "-s" "x"]} (p ["--as" "bob" "--" "curl" "-s" "x"])))
      (is (= {:user "bob" :argv ["curl"]} (p ["--as=bob" "--" "curl"])))
      (is (= {:user "bob" :argv ["curl"]} (p ["--as" "bob" "curl"]))))
    (testing "last --as wins; --as= clears"
      (is (= {:user "alice" :argv ["x"]} (p ["--as" "bob" "--as=alice" "--" "x"])))
      (is (= {:user nil :argv ["x"]} (p ["--as" "bob" "--as=" "--" "x"]))))
    (testing "legacy USER -- cmd"
      (is (= {:user "alice" :argv ["curl" "x"]} (p ["alice" "--" "curl" "x"])))
      (is (= {:user nil :argv ["nobody" "--" "curl"]} (p ["nobody" "--" "curl"])))
      (is (= {:user "alice" :argv ["x"]} (p ["--" "alice" "--" "x"]))
          "applies after an explicit -- too, like bash"))
    (testing "arguments after the command are untouched"
      (is (= {:user nil :argv ["sh" "-c" "echo --as"]} (p ["--" "sh" "-c" "echo --as"])))
      (is (= {:user nil :argv ["--as" "bob"]} (p ["--" "--as" "bob"])))
      (is (= {:user nil :argv ["-v" "--x"]} (p ["-v" "--x"]))))
    (testing "errors"
      (is (= {:error "exclude run: --as needs a username"} (p ["--as"])))
      (is (= {:error "exclude run: --as needs a username"} (p ["--as" "" "--" "x"])))
      (is (= {:error "exclude run: unknown flag '--bogus'"} (p ["--bogus" "--" "x"])))
      (is (= {:error "exclude run: unknown flag '--asx'"} (p ["--asx" "bob"])))
      (is (= {:error "exclude run: usage: sudo vpn-kis exclude run [--as USER] -- <command>"}
             (p [])))
      (is (:error (p ["--"])))
      (is (:error (p ["--as" "bob"])))
      (is (:error (p ["--as" "bob" "--"])))
      (is (= {:error "exclude run: user 'ghost' does not exist"} (p ["--as" "ghost" "--" "x"])))
      (is (= {:error "exclude run: user 'ghost' does not exist"} (p ["--as=ghost" "x"]))))
    (testing "usage names the program"
      (is (= {:error "exclude run: usage: sudo ./vpn-firewall-setup.sh exclude run [--as USER] -- <command>"}
             (d/parse-run-args ["--"] users "./vpn-firewall-setup.sh"))))))

(deftest parse-run-args-asks-about-users-only-when-needed
  (let [asked (atom [])
        pred  (fn [u] (swap! asked conj u) (contains? users u))]
    (d/parse-run-args ["--" "curl" "x"] pred)
    (d/parse-run-args ["curl" "x" "--" "y"] pred)
    (is (= [] @asked) "no probe unless the second word is --")
    (d/parse-run-args ["curl" "--" "y"] pred)
    (is (= ["curl"] @asked) "the legacy USER -- form probes")
    (reset! asked [])
    (d/parse-run-args ["--as" "bob" "--" "x"] pred)
    (is (= ["bob"] @asked))))

(deftest run-argv-test
  (is (= ["runuser" "-u" "bob" "--" "curl" "x"] (d/run-argv {:user "bob" :argv ["curl" "x"]})))
  (is (= ["apt-get" "update"] (d/run-argv {:user nil :argv ["apt-get" "update"]}))))

;; ---------------------------------------------------------------- plans

(def apply-cmds
  [["iptables" "-t" "mangle" "-N" "VPNKIS-EXCLUDE"]
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
   ["iptables" "-t" "mangle" "-A" "VPNKIS-EXCLUDE" "-m" "cgroup" "--path" "vpnkis-exclude"
    "-j" "MARK" "--set-mark" "0x51"]
   ["ip" "route" "replace" "default" "via" "192.168.1.1" "dev" "eth0" "table" "151"]
   ["ip" "rule" "del" "priority" "5080"]
   ["ip" "rule" "add" "fwmark" "0x51" "lookup" "151" "priority" "5080"]
   ["iptables" "-t" "nat" "-N" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-C" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-A" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-F" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-A" "VPNKIS-EXCLUDE-NAT" "-m" "mark" "--mark" "0x51" "-o" "eth0"
    "-j" "MASQUERADE"]])

(def teardown-cmds
  [["ip" "rule" "del" "priority" "5080"]
   ["ip" "route" "flush" "table" "151"]
   ["iptables" "-t" "mangle" "-F" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "mangle" "-D" "OUTPUT" "-j" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "mangle" "-X" "VPNKIS-EXCLUDE"]
   ["iptables" "-t" "nat" "-F" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-D" "POSTROUTING" "-j" "VPNKIS-EXCLUDE-NAT"]
   ["iptables" "-t" "nat" "-X" "VPNKIS-EXCLUDE-NAT"]])

(deftest apply-plan-commands
  (is (= apply-cmds (d/step-cmds (d/apply-steps "eth0" "192.168.1.1")))))

(deftest apply-plan-failure-policy
  (let [by-cmd (into {} (map (juxt :cmd identity) (d/apply-steps "eth0" "192.168.1.1")))]
    (testing "-N is best-effort, jumps are check-then-add"
      (is (= :ignore (:on-fail (by-cmd ["iptables" "-t" "mangle" "-N" "VPNKIS-EXCLUDE"]))))
      (is (= {:op :ensure
              :check ["iptables" "-t" "mangle" "-C" "OUTPUT" "-j" "VPNKIS-EXCLUDE"]
              :cmd ["iptables" "-t" "mangle" "-A" "OUTPUT" "-j" "VPNKIS-EXCLUDE"]}
             (by-cmd ["iptables" "-t" "mangle" "-A" "OUTPUT" "-j" "VPNKIS-EXCLUDE"]))))
    (testing "the cgroup MARK only warns"
      (let [s (by-cmd d/mark-cmd)]
        (is (= :warn (:on-fail s)))
        (is (= "exclude: cgroup mark rule failed (xt_cgroup missing, or cgroup absent)"
               (:warning s)))))
    (testing "ip rule del drains, the rest aborts"
      (is (= :drain (:op (by-cmd d/rule-del-cmd))))
      (is (= :abort (:on-fail (by-cmd d/rule-add-cmd))))
      (is (= :abort (:on-fail (by-cmd (d/masquerade-cmd "eth0"))))))))

(deftest teardown-plan
  (is (= teardown-cmds (d/step-cmds d/teardown-steps)))
  (is (= :drain (:op (first d/teardown-steps))))
  (is (every? #(= :ignore (:on-fail %)) (rest d/teardown-steps))))

;; ---------------------------------------------------------------- parsers

(deftest parse-gateway-test
  (is (= "192.168.1.1"
         (d/parse-gateway (text "default via 192.168.1.1 proto dhcp src 192.168.1.50 metric 600"
                                "192.168.1.0/24 proto kernel scope link src 192.168.1.50"))))
  (testing "falls back to the first ` via ` line"
    (is (= "10.1.1.254"
           (d/parse-gateway (text "192.168.1.0/24 proto kernel scope link"
                                  "10.0.0.0/8 via 10.1.1.254 proto static"
                                  "172.16.0.0/12 via 10.9.9.9")))))
  (testing "default via wins over an earlier via line"
    (is (= "192.168.1.1"
           (d/parse-gateway (text "10.0.0.0/8 via 10.1.1.254" "default via 192.168.1.1")))))
  (is (nil? (d/parse-gateway (text "192.168.1.0/24 proto kernel scope link"))))
  (is (nil? (d/parse-gateway "")))
  (is (nil? (d/parse-gateway nil))))

(deftest virtual-iface-test
  (doseq [v ["lo" "tun0" "wg0-mullvad" "tailscale0" "Eddie" "ppp0" "docker0" "veth1a2b"
             "virbr0" "br-1234" "zt0"]]
    (is (d/virtual-iface? v) v))
  (doseq [p ["eth0" "wlan0" "wlp0s20f3" "enp0s31f6" "eno1" "lo1" "Eddie2"]]
    (is (not (d/virtual-iface? p)) p))
  (is (false? (d/virtual-iface? nil))))

(deftest default-route-iface-test
  (is (= "wlp0s20f3"
         (d/default-route-iface
          (text "default dev wg0-mullvad scope link"
                "default via 10.8.0.1 dev tun0"
                "default via 192.168.1.1 dev wlp0s20f3 proto dhcp src 192.168.1.50 metric 600"
                "192.168.1.0/24 dev wlp0s20f3 proto kernel scope link"))))
  (is (= "eth0" (d/default-route-iface (text "default via 10.0.0.1 dev eth0"))))
  (is (nil? (d/default-route-iface (text "default dev tun0 scope link"
                                         "10.0.0.0/8 dev eth0"))))
  (is (nil? (d/default-route-iface nil))))

(deftest nonblank-lines-test
  (is (= ["123" "456"] (d/nonblank-lines "123\n\n456\n")))
  (is (= [] (d/nonblank-lines "")))
  (is (= [] (d/nonblank-lines nil))))

;; ---------------------------------------------------------------- status

(deftest status-lines-disabled
  (is (= ["exclude: disabled. Enable + run in one step: sudo vpn-kis exclude run -- <command>"]
         (d/status-lines {:enabled? false :prog "vpn-kis"}))))

(deftest status-lines-enabled
  (is (= ["exclude: ENABLED (cgroup /sys/fs/cgroup/vpnkis-exclude -> eth0, mark 0x51 table 151)"
          "  members (PIDs in cgroup):"
          "    4242"
          ""
          "ip rule (prio 5080):"
          "  5080:\tfrom all fwmark 0x51 lookup 151"
          "route table 151:"
          "  default via 192.168.1.1 dev eth0"
          "mangle chain:"
          "  -N VPNKIS-EXCLUDE"
          "nat chain:"
          "  -N VPNKIS-EXCLUDE-NAT"
          "before.rules ACCEPT:"
          "  -A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"
          "unit:"
          "  active : active"]
         (d/status-lines {:enabled? true
                          :phys "eth0"
                          :members ["4242"]
                          :ip-rules ["5080:\tfrom all fwmark 0x51 lookup 151"]
                          :routes ["default via 192.168.1.1 dev eth0"]
                          :mangle ["-N VPNKIS-EXCLUDE"]
                          :nat ["-N VPNKIS-EXCLUDE-NAT"]
                          :before-rules-accept ["-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"]
                          :unit-active "active"})))
  (testing "absent cgroup vs. empty cgroup"
    (let [absent (d/status-lines {:enabled? true :phys "eth0" :members nil :unit-active "active"})
          empty  (d/status-lines {:enabled? true :phys "eth0" :members [] :unit-active "active"})]
      (is (= "    (none / cgroup absent)" (nth absent 2)))
      (is (= "" (nth empty 2))))))

(deftest enabled-message-test
  (is (= "exclude: enabled. Run: sudo vpn-kis exclude run -- <command>  (add --as USER to drop root)"
         (d/enabled-message "vpn-kis"))))
