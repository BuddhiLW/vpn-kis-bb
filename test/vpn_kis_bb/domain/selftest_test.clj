(ns vpn-kis-bb.domain.selftest-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.selftest :as st]))

;; ---------------------------------------------------------------- fixtures

(defn- lines [& ls] (str (str/join "\n" ls) "\n"))

(def rules-strict
  "`iptables -S ufw-before-output` of an any-port strict install."
  (lines "-N ufw-before-output"
         "-A ufw-before-output -o lo -j ACCEPT"
         "-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
         "-A ufw-before-output -o wlan0 -p udp -m udp --dport 67 -j ACCEPT"
         "-A ufw-before-output -o wlan0 -p udp -m udp --dport 123 -j ACCEPT"
         "-A ufw-before-output -o wlan0 -m set --match-set vpn_endpoints dst -j ACCEPT"
         "-A ufw-before-output -o tun+ -j ACCEPT"
         "-A ufw-before-output -o wg+ -j ACCEPT"
         "-A ufw-before-output -o wlan0 -j DROP"))

(def rules-permissive-lan
  "A permissive install with a --lan exception (iptables prints -d before -o)."
  (lines "-N ufw-before-output"
         "-A ufw-before-output -o lo -j ACCEPT"
         "-A ufw-before-output -d 192.168.100.0/24 -o wlan0 -j ACCEPT"
         "-A ufw-before-output -o wlan0 -p udp -m udp --dport 53 -j ACCEPT"
         "-A ufw-before-output -o wlan0 -p tcp -m tcp --dport 443 -j ACCEPT"
         "-A ufw-before-output -o tun+ -j ACCEPT"
         "-A ufw-before-output -o wlan0 -j DROP"))

(def rules-host-locked
  "Pre-ipset strict mode: one -d rule per endpoint."
  (lines "-A ufw-before-output -d 185.65.134.10/32 -o wlan0 -p udp -m udp --dport 51820 -j ACCEPT"
         "-A ufw-before-output -d 185.65.134.11/32 -o wlan0 -p udp -m udp --dport 51820 -j ACCEPT"
         "-A ufw-before-output -o wg+ -j ACCEPT"
         "-A ufw-before-output -o wlan0 -j DROP"))

(def ipset-3 (lines "Name: vpn_endpoints" "Type: hash:ip" "References: 1"
                    "Number of entries: 3" "Members:" "185.65.134.10" "1.1.1.1" "8.8.8.8"))

(def link-up
  (lines "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00"
         "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000\\    link/ether 3c:22:fb:00:00:01 brd ff:ff:ff:ff:ff:ff"
         "4: veth1@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\\    link/ether 02:42:ac:00:00:02 brd ff:ff:ff:ff:ff:ff"
         "5: wg0-mullvad: <POINTOPOINT,UP,LOWER_UP> mtu 1380 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/none "))

;; ---------------------------------------------------------------- formatting

(deftest result-lines-and-summary
  (is (= ["[PASS] UFW active" "[FAIL] ping 8.8.8.8 succeeded (LEAK)" "[SKIP] No active VPN interface detected"]
         (st/result-lines [(st/pass "UFW active")
                           (st/fail "ping 8.8.8.8 succeeded (LEAK)")
                           (st/skip "No active VPN interface detected")])))
  (is (= "Test summary: 7 passed, 1 failed" (st/summary-line 7 1))))

(deftest tally-counts-pass-and-fail-only
  (let [t (st/tally [(st/pass "a") (st/skip "b") (st/fail "c") (st/pass "d")])]
    (is (= 2 (:passed t)))
    (is (= 1 (:failed t)))
    (is (= 4 (count (:results t)))))
  (is (= {:results [] :passed 0 :failed 0 :aborted? true :reason :declined}
         (st/aborted :declined []))))

;; ---------------------------------------------------------------- parsers

(deftest ufw-status-checks
  (is (= (st/pass "UFW active") (st/check-ufw-active "Status: active\n")))
  (is (= (st/fail "UFW not active: killswitch off") (st/check-ufw-active "Status: inactive\n")))
  (is (= :fail (:status (st/check-ufw-active nil)))))

(deftest outgoing-policy-reads-the-outgoing-word
  (let [verbose (fn [d] (lines "Status: active" "Logging: on (low)" (str "Default: " d) "New profiles: skip"))]
    (is (= "deny" (st/outgoing-policy (verbose "deny (incoming), deny (outgoing), disabled (routed)"))))
    (testing "incoming deny does not mask an outgoing allow"
      (is (= "allow" (st/outgoing-policy (verbose "deny (incoming), allow (outgoing), disabled (routed)"))))
      (is (= (st/fail "Default outgoing policy: allow (should be deny)")
             (st/check-default-outgoing (verbose "deny (incoming), allow (outgoing), disabled (routed)")))))
    (is (= (st/pass "Default outgoing policy: deny")
           (st/check-default-outgoing (verbose "allow (incoming), deny (outgoing), disabled (routed)"))))
    (is (= (st/fail "Default outgoing policy: unknown (should be deny)")
           (st/check-default-outgoing "Status: inactive\n")))))

(deftest vpn-iface-detection
  (is (= ["lo" "wlan0" "veth1" "wg0-mullvad"] (st/link-names link-up)))
  (is (= "wg0-mullvad" (st/first-vpn-iface link-up)))
  (testing "@ifX suffix stripped before matching"
    (is (= "wg0" (st/first-vpn-iface "7: wg0@if3: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420\n"))))
  (is (= "tun0" (st/first-vpn-iface "9: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500\n")))
  (is (= "Eddie" (st/first-vpn-iface "3: Eddie: <POINTOPOINT,UP,LOWER_UP> mtu 1500\n")))
  (testing "the tailscale overlay yields to an egress tunnel, but counts when alone"
    (is (= "wg0-mullvad"
           (st/first-vpn-iface (lines "4: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280"
                                      "5: wg0-mullvad: <POINTOPOINT,UP,LOWER_UP> mtu 1380"))))
    (is (= "tailscale0" (st/first-vpn-iface "6: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>\n"))))
  (testing "look-alikes are not tunnels"
    (is (nil? (st/first-vpn-iface "3: wgx: <UP>\n4: tunnel0: <UP>\n5: wg0mullvad: <UP>\n")))
    (is (nil? (st/first-vpn-iface "")))
    (is (nil? (st/first-vpn-iface nil)))))

(deftest physical-iface-sources
  (testing "pinned IF from before.rules, comments ignored"
    (is (= "enp3s0"
           (st/pinned-drop-iface (lines "# -A ufw-before-output -o wlan9 -j DROP"
                                        "-A ufw-before-output -o enp3s0 -j ACCEPT"
                                        "-A ufw-before-output -o enp3s0 -j DROP"
                                        "-A ufw-before-input  -i enp3s0 -j DROP"))))
    (is (nil? (st/pinned-drop-iface nil))))
  (testing "first non-virtual default route"
    (is (= "wlp2s0"
           (st/default-route-iface (lines "default dev wg0-mullvad scope link"
                                          "10.64.0.1 dev wg0-mullvad proto static"
                                          "default via 192.168.1.1 dev wlp2s0 proto dhcp metric 600"))))
    (is (nil? (st/default-route-iface "default dev tun0 scope link\n")))
    (is (nil? (st/default-route-iface nil))))
  (is (every? st/virtual-iface? ["lo" "tun0" "wg0-mullvad" "tailscale0" "Eddie" "ppp0"
                                 "docker0" "veth1" "virbr0" "br-1a2b" "zt0"]))
  (is (not-any? st/virtual-iface? ["wlan0" "enp3s0" "eth0"])))

;; ---------------------------------------------------------------- passive checks

(deftest physical-drop-check
  (is (= (st/pass "Physical IF DROP rule present (wlan0)") (st/check-physical-drop rules-strict "wlan0")))
  (is (= (st/fail "No DROP rule on eth0 in ufw-before-output: killswitch will NOT fire")
         (st/check-physical-drop rules-strict "eth0")))
  (is (= :fail (:status (st/check-physical-drop nil "wlan0"))))
  (is (= (st/fail "Physical IF not detected (set PHYSICAL_IF): DROP rule in ufw-before-output not confirmed")
         (st/check-physical-drop rules-strict nil)))
  (testing "matches with options between -o IF and -j DROP"
    (is (st/physical-drop-rule? "-A ufw-before-output -o wlan0 -m comment --comment ks -j DROP\n" "wlan0"))
    (is (not (st/physical-drop-rule? "-A ufw-before-output -o wlan0 -j ACCEPT\n" "wlan0")))))

(deftest vpn-accept-check
  (is (= (st/pass "VPN interfaces ACCEPT: tun+ wg+") (st/check-vpn-accept rules-strict)))
  (testing "a LAN -d CIDR exception does not list the physical IF"
    (is (= ["tun+"] (st/accept-ifaces rules-permissive-lan))))
  (testing "loopback alone is not a VPN allowance"
    (is (= (st/fail "No iface ACCEPT rules in ufw-before-output")
           (st/check-vpn-accept "-A ufw-before-output -o lo -j ACCEPT\n"))))
  (is (= :fail (:status (st/check-vpn-accept nil)))))

(deftest ipv6-checks
  (is (= (st/pass "IPv6 stack absent (module never loaded)") (st/check-ipv6-disabled nil)))
  (is (= (st/pass "IPv6 disabled") (st/check-ipv6-disabled "1\n")))
  (is (= (st/fail "IPv6 still enabled (reboot may be required)") (st/check-ipv6-disabled "0\n")))
  (is (= (st/pass "IPv6 DROP rule present")
         (st/check-ipv6-drop "-N ufw6-before-output\n-A ufw6-before-output -j DROP\n")))
  (is (= (st/skip "IPv6 DROP rule check (may be skipped if ip6tables unavailable)")
         (st/check-ipv6-drop ""))))

(def permissive-skip
  (st/skip "Permissive mode (no ipset/no -d rules): pre-VPN HTTPS/DNS open, full leak test will fail by design"))

(deftest strict-mode-check
  (is (= [(st/pass "Strict mode active: ipset 'vpn_endpoints' with 3 IPs")]
         (st/check-strict-mode rules-strict ipset-3)))
  (testing "ipset referenced but empty or missing: FAIL, and still permissive"
    (is (= [(st/fail "ipset referenced in rules but empty/missing: rules won't match") permissive-skip]
           (st/check-strict-mode rules-strict "Name: vpn_endpoints\nNumber of entries: 0\n")))
    (is (= [(st/fail "ipset referenced in rules but empty/missing: rules won't match") permissive-skip]
           (st/check-strict-mode rules-strict nil))))
  (is (= [(st/pass "Strict mode active: 2 IP-locked rules (-d form)")]
         (st/check-strict-mode rules-host-locked nil)))
  (testing "a --lan CIDR is not endpoint locking"
    (is (= 0 (st/ip-locked-rule-count rules-permissive-lan)))
    (is (= [permissive-skip] (st/check-strict-mode rules-permissive-lan nil))))
  (is (= [permissive-skip] (st/check-strict-mode nil nil))))

(deftest vpn-public-ip-check
  (is (= (st/pass "VPN up (wg0), public IP: 185.65.134.10") (st/check-vpn-public-ip "wg0" "185.65.134.10\n")))
  (is (= (st/fail "VPN iface wg0 up but no internet (rules too tight?)") (st/check-vpn-public-ip "wg0" "")))
  (is (= (st/skip "No active VPN interface detected") (st/check-vpn-public-ip nil nil))))

(deftest passive-results-in-bash-order
  (let [results (st/passive-results
                 {:ufw-status     "Status: active\n"
                  :ufw-verbose    "Default: deny (incoming), deny (outgoing), disabled (routed)\n"
                  :rules          rules-strict
                  :physical-iface "wlan0"
                  :disable-ipv6   nil
                  :ip6-rules      "-A ufw6-before-output -j DROP\n"
                  :ipset-list     ipset-3
                  :vpn-iface      "wg0-mullvad"
                  :public-ip      "185.65.134.10"})]
    (is (= ["[PASS] UFW active"
            "[PASS] Default outgoing policy: deny"
            "[PASS] Physical IF DROP rule present (wlan0)"
            "[PASS] VPN interfaces ACCEPT: tun+ wg+"
            "[PASS] IPv6 stack absent (module never loaded)"
            "[PASS] IPv6 DROP rule present"
            "[PASS] Strict mode active: ipset 'vpn_endpoints' with 3 IPs"
            "[PASS] VPN up (wg0-mullvad), public IP: 185.65.134.10"]
           (st/result-lines results)))))

;; ---------------------------------------------------------------- active test

(deftest leak-probes
  (is (= (st/fail "curl ifconfig.me returned: 203.0.113.7 (LEAK: killswitch failed)")
         (st/check-leak-ifconfig "203.0.113.7\n")))
  (is (= (st/pass "curl ifconfig.me timed out (no leak)") (st/check-leak-ifconfig "")))
  (is (= (st/fail "curl 1.1.1.1 returned data (LEAK)") (st/check-leak-cloudflare "<html>")))
  (is (= (st/pass "curl 1.1.1.1 timed out (no leak)") (st/check-leak-cloudflare nil)))
  (is (= (st/fail "ping 8.8.8.8 succeeded (LEAK)") (st/check-leak-ping 0)))
  (is (= (st/pass "ping 8.8.8.8 blocked") (st/check-leak-ping 1)))
  (testing "a DNS answer is only excused by a --dport 53 ACCEPT"
    (is (= (st/pass "DNS @8.8.8.8 blocked") (st/check-leak-dns 9 nil)))
    (is (= (st/skip "DNS @8.8.8.8 reached (permissive mode allows DNS to any host)")
           (st/check-leak-dns 0 rules-permissive-lan)))
    (is (= (st/fail "DNS @8.8.8.8 resolved (LEAK: DNS rule shouldn't allow this)")
           (st/check-leak-dns 0 rules-strict)))
    (is (not (st/dns-accept-rule? "-A ufw-before-output -o wlan0 -p udp -m udp --dport 5353 -j ACCEPT\n")))))

(deftest restore-and-verdict
  (is (= (st/pass "VPN restored, public IP: 185.65.134.10") (st/check-restored "185.65.134.10")))
  (is (nil? (st/check-restored "")))
  (is (= 2 (st/leak-count [(st/fail "a") (st/pass "b") (st/skip "c") (st/fail "d")])))
  (is (nil? (st/killswitch-verdict 0)))
  (is (= (st/fail "KILLSWITCH FAILED: 3 leak vector(s) detected") (st/killswitch-verdict 3))))

(deftest tunnel-commands
  (is (st/wireguard-iface? "wg0-mullvad"))
  (is (not (st/wireguard-iface? "tun0")))
  (is (= ["ip" "link" "set" "tun0" "down"] (st/link-cmd "tun0" "down")))
  (is (= ["wg-quick" "up" "wg0"] (st/wg-quick-cmd "up" "wg0")))
  (is (= "wg-quick up wg0" (st/restore-note "wg0" ["wg-quick" "up" "wg0"])))
  (is (= "ip link set wg0-mullvad up" (st/restore-note "wg0-mullvad" ["ip" "link" "set" "wg0-mullvad" "up"])))
  (is (= "ip link set tun0 up (then reconnect via Eddie/openvpn client)"
         (st/restore-note "tun0" ["ip" "link" "set" "tun0" "up"]))))

(deftest confirmation-answers
  (is (st/confirmed? "y"))
  (is (st/confirmed? " Y \n"))
  (is (not (st/confirmed? "yes")))
  (is (not (st/confirmed? "")))
  (is (not (st/confirmed? nil))))

;; ---------------------------------------------------------------- verify report

(def ufw-numbered
  (lines "Status: active" ""
         "     To                         Action      From"
         "     --                         ------      ----"
         "[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24"
         ""))

(def output-chain-25
  (apply lines "Chain OUTPUT (policy DROP 0 packets, 0 bytes)"
         " pkts bytes target     prot opt in     out     source               destination"
         (map #(str "    " % "   100 ufw-before-logging-output  0    --  *      *       0.0.0.0/0            0.0.0.0/0")
              (range 23))))

(def addr-show
  (lines "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000"
         "    inet 127.0.0.1/8 scope host lo"
         "       valid_lft forever preferred_lft forever"
         "2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000"
         "    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0"
         "       valid_lft 85000sec preferred_lft 85000sec"
         "5: wg0-mullvad: <POINTOPOINT,UP,LOWER_UP> mtu 1380 qdisc noqueue state UNKNOWN group default qlen 1000"
         "    inet 10.64.1.2/32 scope global wg0-mullvad"))

(defn- texts [ls] (mapv :text ls))

(defn- position
  "Index of the first x in coll, or nil."
  [coll x]
  (first (keep-indexed (fn [i v] (when (= v x) i)) coll)))

(deftest verify-lines-full-report
  (let [report (st/verify-lines {:ufw-numbered  ufw-numbered
                                 :output-chain  output-chain-25
                                 :kill-rules    rules-strict
                                 :disable-ipv6  "1\n"
                                 :addr-show     addr-show
                                 :default-route "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"})
        text   (texts report)
        index  (fn [t] (position text t))]
    (is (every? #{:info :warn :plain} (map :level report)))
    (is (= ["" "========== VERIFICATION ==========" "" "UFW status:" "Status: active" ""]
           (subvec text 0 6)))
    (testing "the OUTPUT chain is cut at 20 lines"
      (let [start (inc (index "iptables OUTPUT chain:"))]
        (is (= "Chain OUTPUT (policy DROP 0 packets, 0 bytes)" (nth text start)))
        (is (= "" (nth text (+ start 20))))
        (is (= "Physical IF kill-switch (should see DROP at end):" (nth text (+ start 21))))))
    (testing "last five DROP/ACCEPT rules"
      (let [start (inc (index "Physical IF kill-switch (should see DROP at end):"))]
        (is (= ["-A ufw-before-output -o wlan0 -p udp -m udp --dport 123 -j ACCEPT"
                "-A ufw-before-output -o wlan0 -m set --match-set vpn_endpoints dst -j ACCEPT"
                "-A ufw-before-output -o tun+ -j ACCEPT"
                "-A ufw-before-output -o wg+ -j ACCEPT"
                "-A ufw-before-output -o wlan0 -j DROP"]
               (subvec text start (+ start 5))))))
    (is (some #{{:level :info :text "IPv6: DISABLED (good)"}} report))
    (let [start (inc (index "Active interfaces:"))]
      (is (= ["  lo: 127.0.0.1/8" "  wlan0: 192.168.1.5/24" "  wg0-mullvad: 10.64.1.2/32"]
             (subvec text start (+ start 3)))))
    (is (= "default via 192.168.1.1 dev wlan0 proto dhcp metric 600"
           (nth text (inc (index "Default route:")))))
    (is (= st/leak-test-hint (subvec report (- (count report) 3))))
    (is (= {:level :warn :text "LEAK TEST: Disconnect VPN, then run:"}
           (first st/leak-test-hint)))))

(deftest verify-lines-fallbacks
  (let [report (st/verify-lines {:output-chain nil
                                 :nft-output   (lines "table ip filter {" "\tchain OUTPUT {" "\t}" "}")
                                 :kill-rules   nil
                                 :disable-ipv6 "0\n"})]
    (is (some #{{:level :warn :text "No iptables backend can render filter/OUTPUT."}} report))
    (is (some #{{:level :warn :text "Mixed legacy+nft tables, or a native nft ruleset owns the table."}} report))
    (is (some #{{:level :warn :text "Inspect with: nft list chain ip filter OUTPUT"}} report))
    (is (some #{{:level :plain :text "table ip filter {"}} report))
    (is (some #{{:level :warn :text "ufw-before-output unreadable or empty: KILL-SWITCH NOT CONFIRMED."}} report))
    (is (some #{{:level :warn :text "Inspect with: nft list chain ip filter ufw-before-output"}} report))
    (is (some #{{:level :warn :text "IPv6: still enabled, reboot required"}} report)))
  (is (= {:level :info :text "IPv6: ABSENT, stack not loaded (best)"}
         (st/ipv6-status-line nil))))
