(ns vpn-kis-bb.domain.selftest
  "Pure core of the kill-switch self-test, ported from the bash test
   suite (`ipt_ro`, `show_filter_chain`, `detect_vpn_iface`,
   `test_passive`, `test_active`, `summary` and `verify` in
   vpn-firewall-setup.sh).

   Every check is a function of captured command output, so the suite is
   testable without a shell: vpn-kis-bb.app.selftest runs the commands
   and feeds the captured strings in.

   A check result is {:status :pass|:fail|:skip :msg \"...\"}.
   A report line is  {:level :info|:warn|:plain :text \"...\"}."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.re :as rx]))

;; ---------------------------------------------------------------- constants

(def ipt-candidates
  "Read-only iptables backends in bash `ipt_ro` order: the first one that
   exits 0 renders the chain."
  ["iptables" "iptables-nft" "iptables-legacy"])

(def before-output-chain "ufw-before-output")
(def ip6-before-output-chain "ufw6-before-output")
(def endpoint-ipset "vpn_endpoints")
(def before-rules-path "/etc/ufw/before.rules")
(def ipv6-disable-path "/proc/sys/net/ipv6/conf/all/disable_ipv6")
(def ip-echo-url "https://ifconfig.me")

(def vpn-iface-re
  "bash `detect_vpn_iface`: tun0, wg0, wg0-mullvad, tailscale0, Eddie, ppp0."
  #"^(tun[0-9]+|wg[0-9]+([-_].+)?|tailscale[0-9]+|Eddie|ppp[0-9]+)$")

(def ^:private virtual-iface-re
  #"^(lo|tun.*|wg.*|tailscale.*|Eddie|ppp.*|docker.*|veth.*|virbr.*|br-.*|zt.*)$")

(def ^:private chain-listing-max-lines 20)
(def ^:private kill-rules-max-lines 5)

;; ---------------------------------------------------------------- results

(defn pass [msg] {:status :pass :msg msg})
(defn fail [msg] {:status :fail :msg msg})
(defn skip [msg] {:status :skip :msg msg})

(defn tally
  "results -> {:results [...] :passed N :failed M}, the bash PASS/FAIL
   counters (a skip counts as neither)."
  [results]
  (let [n (fn [status] (count (filter #(= status (:status %)) results)))]
    {:results (vec results) :passed (n :pass) :failed (n :fail)}))

(defn aborted
  "A run that stopped before testing: the tally plus :aborted? and a
   :reason keyword the CLI can branch on."
  [reason results]
  (assoc (tally results) :aborted? true :reason reason))

(def ^:private status-tag {:pass "[PASS]" :fail "[FAIL]" :skip "[SKIP]"})

(defn result-line
  "{:status :pass :msg \"UFW active\"} -> \"[PASS] UFW active\"."
  [{:keys [status msg]}]
  (str (status-tag status) " " msg))

(defn result-lines [results] (mapv result-line results))

(defn summary-line
  "bash `summary`."
  [passed failed]
  (str "Test summary: " passed " passed, " failed " failed"))

;; ---------------------------------------------------------------- text

(defn- rule-lines
  "Non-blank, trimmed lines of s ([] for nil)."
  [s]
  (->> (rx/split-lines* (or s "")) (map str/trim) (remove str/blank?) vec))

(defn output-lines
  "Lines of command output as a terminal shows them: inner blank lines
   kept, trailing ones dropped ([] for nil)."
  [s]
  (->> (rx/split-lines* (or s "")) reverse (drop-while str/blank?) reverse vec))

(defn echoed-ip
  "Trimmed body of a `curl -s https://ifconfig.me`, or nil when blank."
  [stdout]
  (when-not (str/blank? stdout) (str/trim stdout)))

;; ---------------------------------------------------------------- parsers

(defn ufw-active?
  "bash: `ufw status | grep -q \"Status: active\"`."
  [ufw-status]
  (str/includes? (or ufw-status "") "Status: active"))

(defn outgoing-policy
  "The default outgoing policy word (deny, allow, reject) from
   `ufw status verbose`, or nil. Reads the word right before \"(outgoing)\"."
  [ufw-verbose]
  (second (rx/re-find* #"(?m)^Default:.*\b([a-z]+) \(outgoing\)" (or ufw-verbose ""))))

(defn virtual-iface?
  "bash `is_virtual`: ifaces the kill-switch DROP is never pinned to."
  [iface]
  (boolean (rx/re-matches* virtual-iface-re (or iface ""))))

(defn pinned-drop-iface
  "The IF pinned by the kill-switch rule `-A ufw-before-output -o X -j DROP`
   in /etc/ufw/before.rules, or nil."
  [before-rules]
  (second (rx/re-find* #"(?m)^[ \t]*-A ufw-before-output -o (\S+) -j DROP[ \t]*$" (or before-rules ""))))

(defn default-route-iface
  "First non-virtual `dev` of a default route in `ip -4 route ls`, or nil."
  [route-ls]
  (->> (rule-lines route-ls)
       (filter #(str/starts-with? % "default"))
       (keep #(second (rx/re-find* #"\bdev\s+(\S+)" %)))
       (remove virtual-iface?)
       first))

(defn link-names
  "Names from `ip -o link show` lines (\"N: name: <FLAGS> ...\"), with the
   \"@ifX\" / \"@parent\" suffix stripped."
  [link-show]
  (->> (rule-lines link-show)
       (keep #(second (rx/split* % #": ")))
       (mapv #(first (rx/split* % #"@")))))

(defn first-vpn-iface
  "bash `detect_vpn_iface`: first up link named like a VPN tunnel, or nil.
   A tailscale overlay is only picked when no other tunnel is up: it is
   not the egress tunnel the kill-switch guards, and with Mullvad and
   Tailscale both up `ip` lists tailscale0 first."
  [link-show]
  (let [tunnels (filter (fn [n] (rx/re-matches* vpn-iface-re n)) (link-names link-show))]
    (or (first (remove #(str/starts-with? % "tailscale") tunnels))
        (first tunnels))))

(defn physical-drop-rule?
  "bash: `grep -qE -- \"-o $PHYSICAL_IF .*-j DROP\"` over the chain rules."
  [rules iface]
  (let [needle (str "-o " iface " ")]
    (boolean (some (fn [line]
                     (when-let [i (str/index-of line needle)]
                       (str/index-of line "-j DROP" i)))
                   (rule-lines rules)))))

(defn accept-ifaces
  "Sorted distinct X of the unconditional `-A <chain> -o X -j ACCEPT` rules,
   loopback excluded. A LAN exception (`-d CIDR -o wlan0 -j ACCEPT`) is
   not an interface allowance and is not listed."
  [rules]
  (->> (rule-lines rules)
       (keep #(second (rx/re-matches* #"-A \S+ -o (\S+) -j ACCEPT" %)))
       (remove #{"lo"})
       distinct
       sort
       vec))

(defn endpoint-ipset-referenced?
  "bash: `grep -q \"match-set vpn_endpoints\"`."
  [rules]
  (str/includes? (or rules "") (str "match-set " endpoint-ipset)))

(defn ipset-entry-count
  "\"Number of entries: N\" from `ipset list <set>`, or nil."
  [ipset-list]
  (some-> (rx/re-find* #"Number of entries:\s*(\d+)" (or ipset-list "")) second parse-long))

(defn ip-locked-rule-count
  "Rules that ACCEPT one destination host (`-d a.b.c.d[/32] ... ACCEPT`),
   the pre-ipset strict mode. A CIDR destination (a --lan exception) is
   not endpoint locking and does not count."
  [rules]
  (count (filter (fn [line] (rx/re-find* #"(?:^|\s)-d \d+\.\d+\.\d+\.\d+(?:/32)?\s.*ACCEPT" line)) (rule-lines rules))))

(defn dns-accept-rule?
  "bash: `grep -qE -- \"--dport 53.*ACCEPT\"`, port 53 exactly."
  [rules]
  (boolean (some (fn [line] (rx/re-find* #"--dport 53\b.*ACCEPT" line)) (rule-lines rules))))

(defn ipv6-state
  "Contents of /proc/sys/net/ipv6/conf/all/disable_ipv6, nil when the IPv6
   stack is absent -> :absent | :disabled | :enabled."
  [disable-ipv6]
  (cond (nil? disable-ipv6)                 :absent
        (= "1" (str/trim disable-ipv6))     :disabled
        :else                               :enabled))

(defn confirmed?
  "bash: `read -r ans; [[ $ans =~ ^[Yy]$ ]]` (read trims blanks)."
  [answer]
  (boolean (rx/re-matches* #"[Yy]" (str/trim (or answer "")))))

;; ---------------------------------------------------------------- passive checks

(defn check-ufw-active [ufw-status]
  (if (ufw-active? ufw-status)
    (pass "UFW active")
    (fail "UFW not active: killswitch off")))

(defn check-default-outgoing [ufw-verbose]
  (let [policy (outgoing-policy ufw-verbose)]
    (if (= "deny" policy)
      (pass "Default outgoing policy: deny")
      (fail (str "Default outgoing policy: " (or policy "unknown") " (should be deny)")))))

(defn check-physical-drop [rules iface]
  (cond
    (str/blank? iface)
    (fail "Physical IF not detected (set PHYSICAL_IF): DROP rule in ufw-before-output not confirmed")

    (physical-drop-rule? rules iface)
    (pass (str "Physical IF DROP rule present (" iface ")"))

    :else
    (fail (str "No DROP rule on " iface " in ufw-before-output: killswitch will NOT fire"))))

(defn check-vpn-accept [rules]
  (let [ifaces (accept-ifaces rules)]
    (if (seq ifaces)
      (pass (str "VPN interfaces ACCEPT: " (str/join " " ifaces)))
      (fail "No iface ACCEPT rules in ufw-before-output"))))

(defn check-ipv6-disabled [disable-ipv6]
  (case (ipv6-state disable-ipv6)
    :absent   (pass "IPv6 stack absent (module never loaded)")
    :disabled (pass "IPv6 disabled")
    :enabled  (fail "IPv6 still enabled (reboot may be required)")))

(defn check-ipv6-drop [ip6-rules]
  (if (str/includes? (or ip6-rules "") "-j DROP")
    (pass "IPv6 DROP rule present")
    (skip "IPv6 DROP rule check (may be skipped if ip6tables unavailable)")))

(defn check-strict-mode
  "bash check 7, one to two results. ipset-list is `ipset list vpn_endpoints`,
   only read when the rules reference the set."
  [rules ipset-list]
  (let [ipset?    (endpoint-ipset-referenced? rules)
        entries   (ipset-entry-count ipset-list)
        ipset-ok? (boolean (and ipset? entries (pos? entries)))
        locked    (ip-locked-rule-count rules)]
    (cond-> []
      ipset?
      (conj (if ipset-ok?
              (pass (str "Strict mode active: ipset '" endpoint-ipset "' with " entries " IPs"))
              (fail "ipset referenced in rules but empty/missing: rules won't match")))

      (pos? locked)
      (conj (pass (str "Strict mode active: " locked " IP-locked rules (-d form)")))

      (not (or ipset-ok? (pos? locked)))
      (conj (skip (str "Permissive mode (no ipset/no -d rules): pre-VPN HTTPS/DNS open, "
                       "full leak test will fail by design"))))))

(defn check-vpn-public-ip [vpn-iface public-ip]
  (cond
    (nil? vpn-iface)       (skip "No active VPN interface detected")
    (str/blank? public-ip) (fail (str "VPN iface " vpn-iface " up but no internet (rules too tight?)"))
    :else                  (pass (str "VPN up (" vpn-iface "), public IP: " (str/trim public-ip)))))

(defn passive-results
  "Every passive check, in bash order, over one captured snapshot:
   {:ufw-status :ufw-verbose :rules :physical-iface :disable-ipv6
    :ip6-rules :ipset-list :vpn-iface :public-ip}.
   :rules is `ipt_ro -S ufw-before-output` (nil when no backend renders it)."
  [{:keys [ufw-status ufw-verbose rules physical-iface disable-ipv6
           ip6-rules ipset-list vpn-iface public-ip]}]
  (-> [(check-ufw-active ufw-status)
       (check-default-outgoing ufw-verbose)
       (check-physical-drop rules physical-iface)
       (check-vpn-accept rules)
       (check-ipv6-disabled disable-ipv6)
       (check-ipv6-drop ip6-rules)]
      (into (check-strict-mode rules ipset-list))
      (conj (check-vpn-public-ip vpn-iface public-ip))))

;; ---------------------------------------------------------------- active test

(defn wireguard-iface? [iface] (str/starts-with? (or iface "") "wg"))

(defn link-cmd
  "`ip link set <iface> <up|down>`."
  [iface state]
  ["ip" "link" "set" iface state])

(defn wg-quick-cmd
  "`wg-quick <up|down> <iface>`."
  [action iface]
  ["wg-quick" action iface])

(defn restore-note
  "What bash prints after \"Restoring VPN: \" for this restore command."
  [iface restore-cmd]
  (str (str/join " " restore-cmd)
       (when-not (wireguard-iface? iface)
         " (then reconnect via Eddie/openvpn client)")))

(defn check-leak-ifconfig
  "`curl ifconfig.me` with the tunnel down: any answer is a leak."
  [stdout]
  (if-let [ip (echoed-ip stdout)]
    (fail (str "curl ifconfig.me returned: " ip " (LEAK: killswitch failed)"))
    (pass "curl ifconfig.me timed out (no leak)")))

(defn check-leak-cloudflare
  "`curl https://1.1.1.1` with the tunnel down: any data is a leak."
  [stdout]
  (if (str/blank? stdout)
    (pass "curl 1.1.1.1 timed out (no leak)")
    (fail "curl 1.1.1.1 returned data (LEAK)")))

(defn check-leak-ping
  "`ping -c 2 -W 2 8.8.8.8` with the tunnel down: exit 0 is a leak."
  [exit]
  (if (= 0 exit)
    (fail "ping 8.8.8.8 succeeded (LEAK)")
    (pass "ping 8.8.8.8 blocked")))

(defn check-leak-dns
  "`dig @8.8.8.8` with the tunnel down. An answer is only excused (SKIP)
   when the rules ACCEPT --dport 53 (permissive mode); rules are only
   needed when exit is 0."
  [exit rules]
  (cond
    (not= 0 exit)           (pass "DNS @8.8.8.8 blocked")
    (dns-accept-rule? rules) (skip "DNS @8.8.8.8 reached (permissive mode allows DNS to any host)")
    :else                   (fail "DNS @8.8.8.8 resolved (LEAK: DNS rule shouldn't allow this)")))

(defn leak-count
  "Leak vectors among the probe results (every probe FAIL is one)."
  [probe-results]
  (count (filter #(= :fail (:status %)) probe-results)))

(defn check-restored
  "PASS when the public IP answers again after the restore, else nil (the
   caller warns that the VPN must be reconnected by hand)."
  [restored-stdout]
  (when-let [ip (echoed-ip restored-stdout)]
    (pass (str "VPN restored, public IP: " ip))))

(defn killswitch-verdict
  "nil when nothing leaked (the caller reports KILLSWITCH VERIFIED), else
   the FAIL counting the leak vectors."
  [leaks]
  (when (pos? leaks)
    (fail (str "KILLSWITCH FAILED: " leaks " leak vector(s) detected"))))

;; ---------------------------------------------------------------- verify report

(defn- info-line  [text] {:level :info :text text})
(defn- warn-line  [text] {:level :warn :text text})
(defn- plain-line [text] {:level :plain :text text})
(def ^:private blank-line (plain-line ""))

(defn filter-chain-lines
  "bash `show_filter_chain`: up to 20 lines of `ipt_ro -L <chain> -n -v`
   (listing, nil when no backend could render it), or the fallback
   warnings plus up to 20 lines of `nft list chain ip filter <chain>`."
  [chain listing nft-listing]
  (if-not (str/blank? listing)
    (mapv plain-line (take chain-listing-max-lines (output-lines listing)))
    (into [(warn-line (str "No iptables backend can render filter/" chain "."))
           (warn-line "Mixed legacy+nft tables, or a native nft ruleset owns the table.")
           (warn-line (str "Inspect with: nft list chain ip filter " chain))]
          (map plain-line (take chain-listing-max-lines (output-lines nft-listing))))))

(defn kill-rule-lines
  "Last 5 DROP/ACCEPT rules of `-S ufw-before-output`, or the warning that
   the kill-switch could not be confirmed."
  [rules]
  (let [hits (->> (rule-lines rules)
                  (filter (fn [line] (rx/re-find* #"DROP|ACCEPT" line)))
                  (take-last kill-rules-max-lines))]
    (if (seq hits)
      (mapv plain-line hits)
      [(warn-line "ufw-before-output unreadable or empty: KILL-SWITCH NOT CONFIRMED.")
       (warn-line "Inspect with: nft list chain ip filter ufw-before-output")])))

(defn ipv6-status-line [disable-ipv6]
  (case (ipv6-state disable-ipv6)
    :absent   (info-line "IPv6: ABSENT, stack not loaded (best)")
    :disabled (info-line "IPv6: DISABLED (good)")
    :enabled  (warn-line "IPv6: still enabled, reboot required")))

(defn interface-lines
  "bash: `ip -4 addr show | grep 'inet ' | awk '{print \"  \" $NF \": \" $2}'`."
  [addr-show]
  (->> (rule-lines addr-show)
       (filter #(str/includes? % "inet "))
       (map (fn [line] (rx/split* line #"\s+")))
       (mapv (fn [fields] (plain-line (str "  " (last fields) ": " (second fields)))))))

(def leak-test-hint
  [(warn-line "LEAK TEST: Disconnect VPN, then run:")
   (warn-line "  curl --max-time 5 ifconfig.me")
   (warn-line "Must TIMEOUT. If it returns your real IP, the kill-switch failed.")])

(defn verify-lines
  "bash `verify`, as tagged lines, from captured output:
   {:ufw-numbered      `ufw status numbered`
    :output-chain      `ipt_ro -L OUTPUT -n -v` (nil: no backend)
    :nft-output        `nft list chain ip filter OUTPUT` (fallback only)
    :kill-rules        `ipt_ro -S ufw-before-output` (nil: no backend)
    :disable-ipv6      disable_ipv6 contents (nil: stack absent)
    :addr-show         `ip -4 addr show`
    :default-route     `ip route show default`}"
  [{:keys [ufw-numbered output-chain nft-output kill-rules
           disable-ipv6 addr-show default-route]}]
  (-> [blank-line (info-line "========== VERIFICATION ==========") blank-line
       (info-line "UFW status:")]
      (into (map plain-line (output-lines ufw-numbered)))
      (conj blank-line (info-line "iptables OUTPUT chain:"))
      (into (filter-chain-lines "OUTPUT" output-chain nft-output))
      (conj blank-line (info-line "Physical IF kill-switch (should see DROP at end):"))
      (into (kill-rule-lines kill-rules))
      (conj blank-line (info-line "IPv6 status:") (ipv6-status-line disable-ipv6))
      (conj blank-line (info-line "Active interfaces:"))
      (into (interface-lines addr-show))
      (conj blank-line (info-line "Default route:"))
      (into (map plain-line (output-lines default-route)))
      (conj blank-line (info-line "==================================") blank-line)
      (into leak-test-hint)))
