(ns vpn-kis-bb.app.setup-test
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.app.setup :as setup]
            [vpn-kis-bb.domain.rules :as rules]
            [vpn-kis-bb.domain.setup :as d]))

;; ---------------------------------------------------------------------------
;; fixtures

(def ^:private stamp "20260927-161149")
(def ^:private backup "/etc/ufw/backup-20260927-161149")
(def ^:private exclude-unit "/etc/systemd/system/vpn-killswitch-exclude.service")
(def ^:private verify-head ["ufw" "status" "numbered"])

(def ^:private routes
  (str "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
       "192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.20\n"))

(defn- probe-respond
  "Canned probe outputs: the default route, `date`, the live set count."
  [cmd _opts]
  (cond
    (= cmd ["ip" "-4" "route" "ls"])        {:stdout routes}
    (= cmd ["date" "+%Y%m%d-%H%M%S"])       {:stdout (str stamp "\n")}
    (= cmd ["ipset" "list" "vpn_endpoints"]) {:stdout "Name: vpn_endpoints\nNumber of entries: 2\nMembers:\n"}
    :else nil))

(defn- make-system
  "Hand-built system: a RecordingShell answering `respond` first, then
   probe-respond; in-memory files behind :read-fn and :write-fn; settings
   merged over test defaults; `extra` keys merged last."
  ([] (make-system {}))
  ([{:keys [respond files settings extra dir]}]
   (let [shell    (rec/make {:respond (fn [cmd opts]
                                        (or (when respond (respond cmd opts))
                                            (probe-respond cmd opts)))})
         files    (atom (or files {}))
         writes   (atom [])
         write-fn (fn [path body]
                    (swap! writes conj path)
                    (swap! files assoc path body)
                    (r/ok {:path path}))]
     {:system (merge {:shell         shell
                      :read-fn       (fn [path] (get @files path))
                      :write-fn      write-fn
                      :delete-fn     (fn [path] (swap! files dissoc path) (r/ok {:path path}))
                      :settings      (merge {:prog "vpn-kis" :dns-bootstrap []} settings)
                      :providers-dir (or dir "/nonexistent/vpn-kis-bb-test/providers")}
                     extra)
      :shell  shell
      :files  files
      :writes writes})))

(defn- quietly
  "Run f with log output (stdout and stderr) captured: [result log-text]."
  [f]
  (let [res (atom nil)
        out (with-out-str (binding [*err* *out*] (reset! res (f))))]
    [@res out]))

(defn- with-tmp [f]
  (let [d (fs/create-temp-dir {:prefix "vpn-kis-bb-setup-"})]
    (try (f (str d)) (finally (fs/delete-tree d)))))

(defn- index-of [coll x]
  (first (keep-indexed (fn [i y] (when (= x y) i)) coll)))

(defn- before-verify
  "Recorded commands up to the verification report."
  [shell]
  (let [c (rec/cmds shell)]
    (subvec c 0 (or (index-of c verify-head) (count c)))))

(defn- allow-out [port proto comment]
  ["ufw" "allow" "out" "on" "wlan0" "to" "any" "port" (str port) "proto" proto "comment" comment])

(defn- restore-cmd? [cmd]
  (and (= "sh" (first cmd)) (str/includes? (nth cmd 2 "") "ipset restore")))

;; Method params stay distinct: on cljw a record method written [_ _]
;; resolves its fields through the second `_`.
(defrecord NoIpsetShell [inner]
  proto/IShell
  (shell-exec! [_this cmd opts] (proto/shell-exec! inner cmd opts))
  (shell-env [_this] {})
  (shell-which [_this program]
    (if (= "ipset" program)
      (r/err :shell/not-found {:program program})
      (proto/shell-which inner program))))

;; ---------------------------------------------------------------------------
;; permissive

(deftest permissive-setup-runs-the-bash-sequence
  (let [{:keys [system shell files writes]} (make-system)
        [res log] (quietly #(setup/setup! system {:mode :permissive}))]
    (is (r/ok? res))
    (testing "every command, in bash order"
      (is (= (-> [["ip" "-4" "route" "ls"]
                  ["date" "+%Y%m%d-%H%M%S"]
                  ["mkdir" "-p" backup]]
                 (into (for [f ["/etc/ufw/user.rules" "/etc/ufw/user6.rules" "/etc/ufw/before.rules"
                                "/etc/ufw/before6.rules" "/etc/ufw/after.rules" "/etc/default/ufw"]]
                         ["cp" "-a" f (str backup "/")]))
                 (into [["sh" "-c" (str "ufw status verbose > '" backup "/ufw-status.txt' 2>/dev/null")]
                        ["sh" "-c" (str "iptables-save > '" backup "/iptables.v4' 2>/dev/null")]
                        ["sh" "-c" (str "ip6tables-save > '" backup "/iptables.v6' 2>/dev/null")]
                        ["sh" "-c" (str "for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do "
                                        "[ -w \"$f\" ] || continue; echo 1 > \"$f\" 2>/dev/null || true; done")]
                        ["sysctl" "--system"]
                        ["ufw" "--force" "reset"]
                        ["ufw" "default" "deny" "incoming"]
                        ["ufw" "default" "deny" "outgoing"]
                        ["ufw" "default" "deny" "routed"]
                        ["ufw" "allow" "in" "on" "lo"]
                        ["ufw" "allow" "out" "on" "lo"]
                        (allow-out 53 "udp" "DNS-UDP-pre-VPN")
                        (allow-out 53 "tcp" "DNS-TCP-pre-VPN")
                        (allow-out 67 "udp" "DHCP")
                        (allow-out 123 "udp" "NTP")
                        (allow-out 443 "tcp" "Eddie-HTTPS-auth")])
                 (into (for [p [1194 443 53 51820 1300 1301 1302 1637 41641 3478]]
                         (allow-out p "udp" (str "VPN-UDP-" p))))
                 (conj (allow-out 443 "tcp" "VPN-TCP-443"))
                 (into (mapcat (fn [v] [["ufw" "allow" "in" "on" v] ["ufw" "allow" "out" "on" v]])
                               ["tun+" "wg+" "Eddie" "ppp+" "tailscale0"]))
                 (into [["ufw" "--force" "enable"]
                        ["ufw" "reload"]
                        ["systemctl" "enable" "ufw"]
                        ["ufw" "reload"]]))
             (before-verify shell))))
    (testing "files written: the IPv6 drop-ins, then the rules"
      (is (= [d/sysctl-conf-path d/modprobe-conf-path "/etc/ufw/before.rules" "/etc/ufw/before6.rules"]
             @writes))
      (is (= (slurp "test/integration/golden/before-rules-permissive-wlan0.txt")
             (get @files "/etc/ufw/before.rules"))
          "byte-equal to the bash add_killswitch_before_rules output")
      (is (= rules/before6-rules-text (get @files "/etc/ufw/before6.rules"))))
    (testing "the result"
      (is (= {:mode :permissive :physical-iface "wlan0" :endpoint-count 0 :backup-dir backup
              :exclude? false :strict-ports? false :dry-run? false :lan-allow [] :dns-bootstrap []}
             (select-keys (:ok res) [:mode :physical-iface :endpoint-count :backup-dir :exclude?
                                     :strict-ports? :dry-run? :lan-allow :dns-bootstrap])))
      (is (nil? (-> res :ok :ipset-entries))))
    (testing "progress lines where bash prints them"
      (doseq [line ["[+] VPN Kill-Switch Firewall v3"
                    "[+] Mode: PERMISSIVE (DNS/443/VPN ports open pre-tunnel)"
                    "[+] Physical interface: wlan0"
                    (str "[+] Backing up current UFW config to " backup "...")
                    "[+] IPv6 disabled via sysctl + modprobe."
                    "[+] UFW enabled with VPN-only rules + DNS/Eddie pre-connect exceptions."
                    "[+] Kill-switch active in before.rules. Non-VPN traffic on wlan0 is DROP'd."
                    "[+] Tailscale bypass: not available in this build, skipped"
                    "[+] NetworkManager dispatcher: not available in this build, skipped"
                    "[+] Done. Reboot for full IPv6 disable."
                    "[+] Rollback: sudo vpn-kis unlock"]]
        (is (str/includes? log line) line))
      (is (< (str/index-of log "Physical interface") (str/index-of log "Backing up")
             (str/index-of log "Disabling IPv6") (str/index-of log "Configuring UFW")
             (str/index-of log "Hardening") (str/index-of log "UFW persistence")
             (str/index-of log "Done."))))))

;; ---------------------------------------------------------------------------
;; strict

(deftest strict-endpoints-build-both-sets-before-the-rules
  (let [{:keys [system shell files]}
        (make-system {:settings {:dns-bootstrap ["9.9.9.9" "1.1.1.1"]}})
        [res log] (quietly #(setup/setup! system {:mode      :strict
                                                   :endpoints ["5.6.7.8" "1.2.3.4" "bogus"]
                                                   :lan-allow ["192.168.100.0/24"]}))
        c (before-verify shell)]
    (is (r/ok? res))
    (testing "no pre-tunnel user rules in strict mode"
      (is (not-any? #(some #{"DNS-UDP-pre-VPN" "Eddie-HTTPS-auth" "VPN-UDP-51820"} %) c)))
    (testing "the sets are rebuilt after the UFW reset, then the rules reload"
      (let [enable (index-of c ["ufw" "--force" "enable"])
            load   (index-of c ["ipset" "destroy" "vpn_endpoints"])]
        (is (< enable load))
        (is (= [["ipset" "destroy" "vpn_endpoints"]
                ["sh" "-c" (str "printf '%s' 'create vpn_endpoints hash:ip family inet hashsize 2048 maxelem 65536 -exist\n"
                                "add vpn_endpoints 1.2.3.4\nadd vpn_endpoints 5.6.7.8\n' | ipset restore -exist")]
                ["ipset" "destroy" "vpn_dns_bootstrap"]
                ["sh" "-c" (str "printf '%s' 'create vpn_dns_bootstrap hash:ip family inet hashsize 2048 maxelem 65536 -exist\n"
                                "add vpn_dns_bootstrap 1.1.1.1\nadd vpn_dns_bootstrap 9.9.9.9\n' | ipset restore -exist")]
                ["sh" "-c" "{ ipset save vpn_endpoints && ipset save vpn_dns_bootstrap; } > /etc/ipset.conf"]
                ["chmod" "755" "/etc/ufw/before.init"]
                ["ipset" "list" "vpn_endpoints"]
                ["ufw" "reload"]
                ["systemctl" "enable" "ufw"]
                ["ufw" "reload"]]
               (subvec c load)))))
    (testing "before.rules: any port to the endpoints, port 53 to the bootstrap set, the LAN"
      (let [text (get @files "/etc/ufw/before.rules")]
        (is (= (rules/before-rules-text {:mode :strict :physical-iface "wlan0"
                                         :ipset-name "vpn_endpoints" :endpoint-count 2
                                         :lan-allow ["192.168.100.0/24"]
                                         :dns-ipset-name "vpn_dns_bootstrap" :dns-count 2})
               text))
        (is (str/includes? text "-A ufw-before-output -o wlan0 -m set --match-set vpn_endpoints dst -j ACCEPT\n"))
        (is (str/includes? text (str "-A ufw-before-output -o wlan0 -p udp --dport 53 -m set "
                                     "--match-set vpn_dns_bootstrap dst -j ACCEPT\n")))))
    (is (= d/before-init-text (get @files "/etc/ufw/before.init")))
    (testing "the result"
      (is (= {:mode :strict :endpoint-count 2 :source :endpoints :ipset-entries 2
              :dns-bootstrap ["1.1.1.1" "9.9.9.9"] :lan-allow ["192.168.100.0/24"]}
             (select-keys (:ok res) [:mode :endpoint-count :source :ipset-entries
                                     :dns-bootstrap :lan-allow]))))
    (testing "log"
      (doseq [line ["[+] Mode: STRICT (endpoint-locked, no DNS/443 pre-holes)"
                    "[+] Endpoints: 5.6.7.8 1.2.3.4 bogus"
                    "[+] VPN endpoints set: skipping DNS rules (strict mode, no DNS leak)."
                    "[+] Strict mode: endpoint rules live in before.rules via ipset (fast)"
                    "[+] Building ipset 'vpn_endpoints' with 3 IPs..."
                    "[!] Skipping non-IPv4 endpoint: bogus"
                    "[+] Building ipset 'vpn_dns_bootstrap' with 2 DNS bootstrap IPs (port 53 only)..."
                    "[+] ipset loaded: 2 entries. Persisted to /etc/ipset.conf + before.init hook."]]
        (is (str/includes? log line) line)))))

(deftest strict-providers-lock-to-the-cached-union
  (with-tmp
    (fn [dir]
      (spit (str dir "/mullvad.ips") "# mullvad server IPs\n1.1.1.2\n3.3.3.3\n")
      (spit (str dir "/tailscale.ips") "3.3.3.3\n4.4.4.4\n")
      (let [{:keys [system files]} (make-system {:dir dir})
            [res log] (quietly #(setup/setup! system {:mode      :strict
                                                       :providers [:mullvad "tailscale" :nope]}))]
        (is (r/ok? res))
        (is (= {:source :providers :providers ["mullvad" "tailscale" "nope"] :endpoint-count 3}
               (select-keys (:ok res) [:source :providers :endpoint-count])))
        (is (= "mullvad tailscale nope\n" (get @files "/etc/vpn-killswitch/providers.active"))
            "the refresh timer re-fetches these")
        (is (str/includes? (get @files "/etc/ufw/before.rules") "(ipset vpn_endpoints: 3 IPs;"))
        (doseq [line ["[+] Loading provider profiles: mullvad tailscale nope"
                      (str "[!] No cached list for 'nope' (" dir "/nope.ips). Run: vpn-kis fetch nope")
                      "[+] Locking to 3 endpoints from: mullvad tailscale nope"
                      "[+] Endpoints: 1.1.1.2 3.3.3.3 4.4.4.4"]]
          (is (str/includes? log line) line))
        (is (< (str/index-of log "Locking to") (str/index-of log "VPN Kill-Switch Firewall v3")))))))

(deftest explicit-endpoints-win-over-providers
  (let [{:keys [system files]} (make-system)
        [res _] (quietly #(setup/setup! system {:endpoints ["1.2.3.4"] :providers [:mullvad]}))]
    (is (= :strict (-> res :ok :mode)) "no :mode given: strict, since endpoints are")
    (is (= :endpoints (-> res :ok :source)))
    (is (nil? (get @files "/etc/vpn-killswitch/providers.active")))))

(deftest strict-without-ips-changes-nothing
  (testing "providers with no cached list"
    (let [{:keys [system shell writes]} (make-system)
          [res log] (quietly #(setup/setup! system {:mode :strict :providers [:mullvad :airvpn]}))]
      (is (= :setup/no-ips (:error res)))
      (is (= "No IPs loaded. Run: vpn-kis fetch mullvad airvpn" (:hint res)))
      (is (empty? (rec/cmds shell)))
      (is (empty? @writes))
      (is (str/includes? log "No cached list for 'mullvad'"))))
  (testing "explicit endpoints without a valid IPv4"
    (let [{:keys [system shell writes]} (make-system)
          [res _] (quietly #(setup/setup! system {:mode :strict :endpoints ["vpn.example.com" "::1"]}))]
      (is (= :setup/no-ips (:error res)))
      (is (str/includes? (:hint res) "no valid IPv4"))
      (is (empty? (rec/cmds shell)))
      (is (empty? @writes))))
  (testing "strict with no source at all"
    (let [{:keys [system shell]} (make-system)
          [res _] (quietly #(setup/setup! system {:mode :strict}))]
      (is (= :setup/no-endpoints (:error res)))
      (is (str/includes? (:hint res) "vpn-kis providers <names>"))
      (is (empty? (rec/cmds shell))))))

(deftest strict-ports-keeps-the-legacy-lock
  (let [{:keys [system files]} (make-system {:settings {:strict-ports? true}})
        [res _] (quietly #(setup/setup! system {:mode :strict :endpoints ["1.2.3.4"]}))]
    (is (true? (-> res :ok :strict-ports?)))
    (is (str/includes? (get @files "/etc/ufw/before.rules")
                       "-A ufw-before-output -o wlan0 -p udp --dport 51820 -m set --match-set vpn_endpoints dst -j ACCEPT")))
  (testing "opts override the setting"
    (let [{:keys [system files]} (make-system {:settings {:strict-ports? true}})
          [res _] (quietly #(setup/setup! system {:mode :strict :endpoints ["1.2.3.4"]
                                                   :strict-ports? false}))]
      (is (false? (-> res :ok :strict-ports?)))
      (is (not (str/includes? (get @files "/etc/ufw/before.rules") "--dport 51820 -m set"))))))

(deftest dns-bootstrap-off
  (let [{:keys [system shell files]} (make-system {:settings {:dns-bootstrap []}})
        [res log] (quietly #(setup/setup! system {:mode :strict :endpoints ["1.2.3.4"]}))]
    (is (r/ok? res))
    (is (not (str/includes? (get @files "/etc/ufw/before.rules") "vpn_dns_bootstrap"))
        "no port-53 path before the tunnel")
    (is (some #{["sh" "-c" (str "printf '%s' 'create vpn_dns_bootstrap hash:ip family inet "
                                "hashsize 2048 maxelem 65536 -exist\n' | ipset restore -exist")]}
              (rec/cmds shell))
        "the set still exists, empty, so refresh can always save and swap it")
    (is (str/includes? log "DNS bootstrap off"))
    (is (= [] (-> res :ok :dns-bootstrap)))))

(deftest exclusion-block-when-enabled
  (let [{:keys [system files]} (make-system {:files {exclude-unit "[Unit]\n"}})
        [res _] (quietly #(setup/setup! system {:mode :permissive}))]
    (is (true? (-> res :ok :exclude?)))
    (is (= (slurp "test/integration/golden/before-rules-permissive-exclude.txt")
           (get @files "/etc/ufw/before.rules")))))

(deftest lan-allow-from-settings-unless-given
  (let [{:keys [system files]} (make-system {:settings {:lan-allow ["10.5.0.0/24"]}})
        [res _] (quietly #(setup/setup! system {:mode :permissive}))]
    (is (= ["10.5.0.0/24"] (-> res :ok :lan-allow)))
    (is (str/includes? (get @files "/etc/ufw/before.rules")
                       "-A ufw-before-output -o wlan0 -d 10.5.0.0/24 -j ACCEPT")))
  (let [{:keys [system]} (make-system {:settings {:lan-allow ["10.5.0.0/24"]}})
        [res _] (quietly #(setup/setup! system {:mode :permissive :lan-allow []}))]
    (is (= [] (-> res :ok :lan-allow)) "an explicit empty list wins")))

;; ---------------------------------------------------------------------------
;; hooks, verification

(deftest hooks-run-in-bash-order
  (let [seen (atom {})
        hook (fn [k] (fn [sys opts]
                       (swap! seen assoc k {:at (count (rec/cmds (:shell sys))) :opts opts})
                       (r/ok {:installed k})))
        {:keys [system shell]} (make-system {:extra {:install-tailscale!     (hook :tailscale)
                                                     :install-nm-dispatcher! (hook :nm)}})
        [res _] (quietly #(setup/setup! system {:mode :permissive}))
        c (rec/cmds shell)]
    (is (r/ok? res))
    (is (= {:physical-iface "wlan0" :mode :permissive :dry-run? false
            :vpn-interfaces rules/default-vpn-interfaces}
           (-> @seen :tailscale :opts)))
    (testing "Tailscale bypass right after the kill-switch reload, before make_persistent"
      (is (= ["ufw" "reload"] (nth c (dec (-> @seen :tailscale :at)))))
      (is (= ["systemctl" "enable" "ufw"] (nth c (-> @seen :tailscale :at)))))
    (testing "NM dispatcher after make_persistent, before the verification report"
      (is (= ["ufw" "reload"] (nth c (dec (-> @seen :nm :at)))))
      (is (= verify-head (nth c (-> @seen :nm :at)))))
    (is (= {:tailscale {:installed :tailscale} :nm-dispatcher {:installed :nm}}
           (-> res :ok :hooks)))))

(deftest failing-hooks-only-warn
  (let [{:keys [system]}
        (make-system {:extra {:install-tailscale!     (fn [_sys _opts]
                                                        (r/err :tailscale/boom {:hint "tailscale: no table 52"}))
                              :install-nm-dispatcher! (fn [_sys _opts] (throw (ex-info "kaboom" {})))}})
        [res log] (quietly #(setup/setup! system {:mode :permissive}))]
    (is (r/ok? res) "setup still completes")
    (is (str/includes? log "[!] Tailscale bypass failed, continuing: tailscale: no table 52"))
    (is (str/includes? log "[!] NetworkManager dispatcher failed, continuing:"))
    (is (= :tailscale/boom (-> res :ok :hooks :tailscale :failed :error)))
    (is (str/includes? log "Done. Reboot for full IPv6 disable."))))

(deftest verification-report-printed-and-returned
  (let [{:keys [system]} (make-system {:respond (fn [cmd _]
                                                  (when (= cmd verify-head)
                                                    {:stdout "Status: active\n"}))})
        [res log] (quietly #(setup/setup! system {:mode :permissive}))
        lines (-> res :ok :verify)]
    (is (some #{{:level :info :text "========== VERIFICATION =========="}} lines))
    (is (some #{{:level :plain :text "Status: active"}} lines))
    (is (str/includes? log "[+] ========== VERIFICATION =========="))
    (is (str/includes? log "\nStatus: active\n") "command output goes to stdout, unprefixed")
    (is (< (str/index-of log "VERIFICATION") (str/index-of log "Done. Reboot")))))

;; ---------------------------------------------------------------------------
;; failures

(deftest a-failed-command-aborts-with-a-hint
  (let [{:keys [system shell writes]}
        (make-system {:respond (fn [cmd _]
                                 (when (= cmd ["ufw" "--force" "reset"])
                                   {:exit 1 :stderr "ERROR: Could not back up '/etc/ufw/user.rules'\n"}))})
        [res log] (quietly #(setup/setup! system {:mode :permissive}))]
    (is (= :setup/command-failed (:error res)))
    (is (= :ufw (:phase res)))
    (is (= 1 (:exit res)))
    (is (str/includes? (:hint res) "'ufw --force reset' failed (exit 1): ERROR: Could not back up"))
    (is (str/includes? (:hint res) "roll back with: sudo vpn-kis unlock"))
    (is (= ["ufw" "--force" "reset"] (last (rec/cmds shell))) "nothing runs after the failure")
    (is (not-any? #{"/etc/ufw/before.rules"} @writes))
    (is (not (str/includes? log "Done.")))))

(deftest a-failed-set-load-never-reloads-the-rules
  (let [{:keys [system shell files]}
        (make-system {:respond (fn [cmd _]
                                 (when (restore-cmd? cmd)
                                   {:exit 1 :stderr "ipset v7.19: Syntax error"}))})
        [res _] (quietly #(setup/setup! system {:mode :strict :endpoints ["1.2.3.4"]}))]
    (is (= :setup/command-failed (:error res)))
    (is (= :killswitch (:phase res)))
    (is (nil? (get @files "/etc/ufw/before.rules"))
        "before.rules never references a set that failed to load")
    (is (not-any? #{["ufw" "reload"]} (rec/cmds shell)))))

(deftest missing-ipset-is-installed-before-any-change
  (let [{:keys [system shell]} (make-system)
        system (assoc system :shell (->NoIpsetShell shell))
        [res log] (quietly #(setup/setup! system {:mode :strict :endpoints ["1.2.3.4"]}))
        c (rec/cmds shell)
        apt ["env" "DEBIAN_FRONTEND=noninteractive" "apt-get" "install" "-y" "ipset"]]
    (is (r/ok? res))
    (is (str/includes? log "[!] ipset not installed, installing..."))
    (is (some #{apt} c))
    (is (< (index-of c apt) (index-of c ["mkdir" "-p" backup])) "a pre-flight, before the backup"))
  (testing "a failed install stops setup with the firewall untouched"
    (let [{:keys [system shell writes]} (make-system {:respond (fn [cmd _]
                                                                 (when (= "env" (first cmd)) {:exit 100}))})
          system (assoc system :shell (->NoIpsetShell shell))
          [res _] (quietly #(setup/setup! system {:mode :strict :endpoints ["1.2.3.4"]}))]
      (is (= :setup/no-ipset (:error res)))
      (is (= :preflight (:phase res)))
      (is (= "Cannot install ipset. Run: sudo apt install ipset" (:hint res)))
      (is (= ["env" "DEBIAN_FRONTEND=noninteractive" "apt-get" "install" "-y" "ipset"]
             (last (rec/cmds shell))))
      (is (not-any? #(#{"ufw" "mkdir" "ipset" "sysctl"} (first %)) (rec/cmds shell)))
      (is (empty? @writes)))))

(deftest grub-gets-the-ipv6-flag-once
  (let [{:keys [system shell]} (make-system {:files {"/etc/default/grub" "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"\n"}})
        [_ log] (quietly #(setup/setup! system {:mode :permissive}))]
    (is (some #{["sed" "-i" "s/GRUB_CMDLINE_LINUX_DEFAULT=\"/\\0ipv6.disable=1 /" "/etc/default/grub"]}
              (rec/cmds shell)))
    (is (str/includes? log "[!] GRUB updated. Reboot to fully apply IPv6 disable.")))
  (let [{:keys [system shell]} (make-system {:files {"/etc/default/grub" "GRUB_CMDLINE_LINUX_DEFAULT=\"ipv6.disable=1 quiet\"\n"}})
        [_ log] (quietly #(setup/setup! system {:mode :permissive}))]
    (is (not-any? #(= "sed" (first %)) (rec/cmds shell)))
    (is (not (str/includes? log "GRUB updated")))))

(deftest backup-dir-falls-back-to-a-utc-stamp
  (let [{:keys [system]} (make-system {:respond (fn [cmd _]
                                                  (when (= cmd ["date" "+%Y%m%d-%H%M%S"]) {:exit 1}))})
        [res _] (quietly #(setup/setup! system {:mode :permissive}))]
    (is (re-matches #"/etc/ufw/backup-[0-9]{8}-[0-9]{6}" (-> res :ok :backup-dir)))))

;; ---------------------------------------------------------------------------
;; inputs

(deftest physical-interface-sources
  (testing "given: no probe"
    (let [{:keys [system shell]} (make-system)
          [res log] (quietly #(setup/setup! system {:mode :permissive :physical-iface "eth9"}))]
      (is (= "eth9" (-> res :ok :physical-iface)))
      (is (not-any? #{["ip" "-4" "route" "ls"]} (rec/cmds shell)))
      (is (str/includes? log "[+] Physical interface: eth9"))))
  (testing "settings :physical-iface (PHYSICAL_IF)"
    (let [{:keys [system]} (make-system {:settings {:physical-iface "enp0s31f6"}})
          [res _] (quietly #(setup/setup! system {:mode :permissive}))]
      (is (= "enp0s31f6" (-> res :ok :physical-iface)))))
  (testing "detected: a tunnel default route is skipped"
    (let [{:keys [system]} (make-system {:respond (fn [cmd _]
                                                    (when (= cmd ["ip" "-4" "route" "ls"])
                                                      {:stdout (str "default dev wg0-mullvad scope link\n"
                                                                    "default via 10.0.0.1 dev enp3s0\n")}))})]
      (is (= "enp3s0" (:ok (setup/detect-physical-iface system))))))
  (testing "no default route: the first real name under /sys/class/net"
    (let [{:keys [system]} (make-system {:respond (fn [cmd _]
                                                    (cond
                                                      (= cmd ["ip" "-4" "route" "ls"]) {:stdout ""}
                                                      (= cmd ["ls" "/sys/class/net"])
                                                      {:stdout "bonding_masters\ndocker0\neth0\nlo\n"}))})]
      (is (= "eth0" (:ok (setup/detect-physical-iface system))))))
  (testing "none at all: refused after the banner, before any change"
    (let [{:keys [system shell writes]} (make-system {:respond (fn [cmd _]
                                                                 (when (= cmd ["ip" "-4" "route" "ls"])
                                                                   {:stdout ""}))})
          [res log] (quietly #(setup/setup! system {:mode :permissive}))]
      (is (= :setup/no-physical-iface (:error res)))
      (is (str/includes? (:hint res) "Set PHYSICAL_IF manually"))
      (is (= [["ip" "-4" "route" "ls"] ["ls" "/sys/class/net"]] (rec/cmds shell)))
      (is (empty? @writes))
      (is (str/includes? log "VPN Kill-Switch Firewall v3")))))

(deftest invalid-input-is-refused-before-any-change
  (doseq [opts [{:mode :permissive :lan-allow ["192.168.1.0/33"]}
                {:mode :permissive :physical-iface "eth0 -j ACCEPT"}]]
    (let [{:keys [system shell writes]} (make-system)
          [res _] (quietly #(setup/setup! system opts))]
      (is (= :setup/invalid-input (:error res)) (pr-str opts))
      (is (string? (:hint res)))
      (is (empty? (rec/cmds shell)))
      (is (empty? @writes)))))

;; ---------------------------------------------------------------------------
;; dry run

(deftest dry-run
  (testing "refused on a :prod system"
    (let [{:keys [system shell writes]} (make-system {:extra {:profile :prod}})
          [res _] (quietly #(setup/setup! system {:mode :permissive :dry-run? true}))]
      (is (= :setup/dry-run-on-live-system (:error res)))
      (is (empty? (rec/cmds shell)))
      (is (empty? @writes))))
  (testing "a :dry-run system records the whole plan; probes read the live host"
    (let [live      (rec/make {:respond probe-respond})
          rec-shell (rec/make)
          {:keys [system files]} (make-system {:extra {:profile :dry-run :live-shell live}})
          system    (assoc system :shell rec-shell)
          [res log] (quietly #(setup/setup! system {:mode :strict :endpoints ["1.2.3.4"] :dry-run? true}))
          c         (rec/cmds rec-shell)]
      (is (r/ok? res))
      (is (true? (-> res :ok :dry-run?)))
      (is (= "wlan0" (-> res :ok :physical-iface)) "detected through :live-shell")
      (is (= backup (-> res :ok :backup-dir)))
      (is (= [["ip" "-4" "route" "ls"] ["date" "+%Y%m%d-%H%M%S"]] (rec/cmds live))
          "only reads go to the live shell")
      (is (some #{["ufw" "--force" "reset"]} c))
      (is (some #{["ipset" "destroy" "vpn_endpoints"]} c))
      (is (not-any? #{verify-head} c) "a plan is not verified")
      (is (str/includes? log "dry-run: nothing applied, VERIFICATION skipped"))
      (is (= 1 (-> res :ok :ipset-entries)) "planned count: the recording shell has no live set")
      (is (str/includes? (-> res :ok :before-rules) "--match-set vpn_endpoints dst -j ACCEPT"))
      (is (= (-> res :ok :before-rules) (get @files "/etc/ufw/before.rules"))))))
