(ns vpn-kis-bb.app.panic-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.app.panic :as panic]))

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

(def all-tools #{"ufw" "ipset" "tailscale"})

(def split-unit "/etc/systemd/system/vpn-killswitch-split-foo.service")
(def split-drop-in "/etc/dnsmasq.d/vpn-kis-split-foo.conf")
(def cidrs-file "/etc/vpn-killswitch/tailnet.cidrs")

(def base-files
  {split-unit                                  "[Unit]\n"
   split-drop-in                               "ipset=/a.com/vpnkis_split_foo_dst\n"
   "/proc/sys/net/ipv6/conf/all/disable_ipv6"  "1\n"
   "/proc/sys/net/ipv6/conf/eth0/disable_ipv6" "1\n"
   cidrs-file                                  "100.64.0.0/10\n"})

(defn- normal-respond
  "A healthy host: one split set among others, a regular resolv.conf, no
   exclude ip rule left, a readable OUTPUT chain."
  [cmd _opts]
  (cond
    (= cmd ["ipset" "list" "-name"])
    {:stdout "vpn_endpoints\nvpnkis_split_foo_dst\ntailscale\n"}

    (= cmd ["test" "-L" "/etc/resolv.conf"])
    {:exit 1}

    (= (take 3 cmd) ["ip" "rule" "del"])
    {:exit 2}

    (= cmd ["iptables" "-L" "OUTPUT" "-n"])
    {:stdout (str "Chain OUTPUT (policy ACCEPT)\n"
                  "target     prot opt source               destination\n"
                  "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0\n"
                  "LINE-FOUR\n")}))

(defn- harness
  "System over a recording shell. files (path -> text) back :read-fn and
   :glob-fn; writes and deletes land in :events, in order."
  [{:keys [respond files available shell write-fn delete-fn]}]
  (let [recorder  (rec/make {:respond respond})
        shell     (or shell (which-shell recorder (or available all-tools)))
        state     (atom (or files base-files))
        events    (atom [])
        write-fn  (or write-fn
                      (fn [p body]
                        (swap! events conj [:write p body])
                        (swap! state assoc p body)
                        (r/ok {:path p})))
        delete-fn (or delete-fn
                      (fn [p]
                        (swap! events conj [:delete p])
                        (swap! state dissoc p)
                        (r/ok {:path p})))]
    {:system {:shell     shell
              :read-fn   (fn [p] (get @state p))
              :write-fn  write-fn
              :delete-fn delete-fn
              :glob-fn   (fn [dir pattern] (filter #(glob-match? dir pattern %) (keys @state)))
              :systemd   (sd/make shell {:write-fn write-fn :delete-fn delete-fn})
              :settings  {:prog "vpn-kis"}
              :env       {}
              :self-path "/opt/vpn-kis/bin/vpn-kis"}
     :rec    recorder
     :files  state
     :events events}))

(defn- cmds [h] (rec/cmds (:rec h)))

(defn- index-of [coll x]
  (first (keep-indexed (fn [i y] (when (= x y) i)) coll)))

(defn- quietly
  "Run f with stdout and stderr captured: [result output]."
  [f]
  (let [res (atom nil)
        out (with-out-str (binding [*err* *out*] (reset! res (f))))]
    [@res out]))

;; ---------------------------------------------------------------- tests

(deftest dry-run-prints-the-plan-and-runs-nothing
  (let [h         (harness {})
        [res out] (quietly #(panic/panic! (:system h) {:dry-run? true}))]
    (is (true? (-> res :ok :dry-run?)))
    (is (= panic/dry-run-steps (-> res :ok :steps)))
    (is (some #(str/includes? % "ufw --force disable") (-> res :ok :steps)))
    (is (some #(str/includes? % "KEEP the Tailscale bypass") (-> res :ok :steps)))
    (is (str/includes? out "[dry-run] panic: "))
    (is (empty? (cmds h)))
    (is (empty? @(:events h)))))

(deftest panic-runs-every-step-in-bash-order
  (let [h         (harness {:respond normal-respond})
        [res out] (quietly #(panic/panic! (:system h) {}))
        cs        (cmds h)
        evs       @(:events h)
        idx       #(index-of cs %)]
    (is (r/ok? res))
    (is (= [] (-> res :ok :failed)))
    (testing "firewall dropped"
      (is (some #{["ufw" "--force" "disable"]} cs))
      (is (some #{["systemctl" "stop" "ufw"]} cs))
      (is (some #{["iptables" "-t" "filter" "-F"]} cs))
      (is (some #{["ip6tables" "-t" "filter" "-F"]} cs))
      (is (some #{["iptables" "-P" "OUTPUT" "ACCEPT"]} cs)))
    (testing "kill-switch and vpn-kis ipsets destroyed, others left"
      (doseq [s ["vpn_endpoints" "vpn_endpoints_new" "vpn_dns_bootstrap"
                 "vpn_dns_bootstrap_new" "vpnkis_split_foo_dst"]]
        (is (some #{["ipset" "destroy" s]} cs) s))
      (is (some #{["ipset" "flush"]} cs))
      (is (not-any? #{["ipset" "destroy" "tailscale"]} cs)))
    (testing "split units and drop-ins, exclusion and refresh timer removed"
      (is (some #{["systemctl" "disable" "--now" "vpn-killswitch-split-foo.service"]} cs))
      (is (some #{[:delete split-unit]} evs))
      (is (some #{[:delete split-drop-in]} evs))
      (is (some #{["ip" "rule" "del" "priority" "5080"]} cs))
      (is (some #{["systemctl" "disable" "--now" "vpn-killswitch-refresh.timer"]} cs)))
    (testing "hooks removed, IPv6 on, DNS reset, network restarted"
      (is (some #{[:delete "/etc/NetworkManager/dispatcher.d/90-vpn-killswitch"]} evs))
      (is (some #{[:delete "/etc/ufw/before.init"]} evs))
      (is (some #{[:write "/proc/sys/net/ipv6/conf/all/disable_ipv6" "0\n"]} evs))
      (is (some #{[:write "/proc/sys/net/ipv6/conf/eth0/disable_ipv6" "0\n"]} evs))
      (is (some #{[:write "/etc/resolv.conf" panic/resolv-text]} evs))
      (is (not-any? #{[:delete "/etc/resolv.conf"]} evs) "a regular file is overwritten in place")
      (is (some #{["chmod" "644" "/etc/resolv.conf"]} cs))
      (is (some #{["systemctl" "restart" "systemd-resolved"]} cs))
      (is (some #{["systemctl" "restart" "NetworkManager"]} cs))
      (is (= 1 (count (filter #{["systemctl" "restart" "tailscaled"]} cs)))))
    (testing "probes"
      (is (some #(= "ping" (first %)) cs))
      (is (some #{["getent" "ahosts" "cloudflare.com"]} cs))
      (is (= {:ping? true :dns? true} (-> res :ok :probe))))
    (testing "bash order"
      (is (< (idx ["ufw" "--force" "disable"])
             (idx ["iptables" "-t" "filter" "-F"])
             (idx ["ipset" "destroy" "vpn_endpoints"])
             (idx ["systemctl" "disable" "--now" "vpn-killswitch-split-foo.service"])
             (idx ["systemctl" "disable" "--now" "vpn-killswitch-refresh.timer"])
             (idx ["systemctl" "restart" "NetworkManager"])
             (idx ["systemctl" "restart" "tailscaled"])
             (idx ["getent" "ahosts" "cloudflare.com"]))))
    (testing "output"
      (is (str/includes? out "=== VPN-KILLSWITCH PANIC RECOVERY ==="))
      (is (str/includes? out "[*] Keeping Tailscale bypass (remove with: vpn-kis tailscale-routes remove)"))
      (is (str/includes? out "    [OK] ICMP to 1.1.1.1 succeeded"))
      (is (str/includes? out "    [OK] DNS resolution working"))
      (is (str/includes? out "Chain OUTPUT (policy ACCEPT)"))
      (is (not (str/includes? out "LINE-FOUR")) "only the first 3 lines of the OUTPUT chain")
      (is (str/includes? out "=== RECOVERY DONE ==="))
      (is (str/includes? out "    Remove with: sudo vpn-kis tailscale-routes remove"))
      (is (str/includes? out "  sudo vpn-kis unlock"))
      (is (str/includes? out "All recovery steps succeeded.")))))

(deftest panic-keeps-the-tailnet-bypass
  (let [h       (harness {:respond normal-respond})
        [res _] (quietly #(panic/panic! (:system h) {}))
        cs      (cmds h)]
    (is (not-any? #(some #{"vpn-killswitch-tailscale"} %) cs) "nft table untouched")
    (is (not-any? #{[:delete cidrs-file]} @(:events h)))
    (is (contains? @(:files h) cidrs-file))
    (is (not-any? #(some #{"vpn-killswitch-tailscale-routes.service"} %) cs))
    (is (= ["nft table inet vpn-killswitch-tailscale" cidrs-file] (-> res :ok :kept)))
    (is (not-any? #{["ip" "rule" "del" "priority" "5200"]} cs)
        "no blanket priority-5200 rule removal")))

(deftest panic-completes-when-everything-fails
  (let [fail-fs   (fn [& _args] (r/err :fs/write-failed {:cause "read-only file system"}))
        h         (harness {:respond   (fn [_cmd _opts] {:exit 1 :stderr "boom"})
                            :write-fn  fail-fs
                            :delete-fn fail-fs})
        [res out] (quietly #(panic/panic! (:system h) {}))
        failed    (set (map :step (-> res :ok :failed)))]
    (is (r/ok? res))
    (is (str/includes? out "=== RECOVERY DONE ==="))
    (is (str/includes? out "Steps that FAILED"))
    (is (str/includes? out "    [FAIL] No reply from 1.1.1.1: check physical link / wifi"))
    (is (str/includes? out "    [FAIL] DNS still broken; try: sudo systemctl restart NetworkManager"))
    (is (str/includes? out "    (iptables unreadable)"))
    (doseq [s ["ufw --force disable"
               "iptables -t filter -F"
               "iptables -P INPUT ACCEPT"
               "rm -f /etc/NetworkManager/dispatcher.d/90-vpn-killswitch"
               "systemctl disable --now vpn-killswitch-split-foo.service"
               "write /etc/resolv.conf"
               "systemctl restart NetworkManager"
               "systemctl restart tailscaled"]]
      (is (contains? failed s) s))
    (testing "normal failures are recorded, not reported"
      (is (not (contains? failed "ip6tables -t filter -F")))
      (is (not (contains? failed "ipset destroy vpn_endpoints")))
      (is (some #(= {:step "ip6tables -t filter -F" :ok? false :report? false}
                    (select-keys % [:step :ok? :report?]))
                (-> res :ok :steps))))
    (is (= 1 (count (filter #{["systemctl" "restart" "tailscaled"]} (cmds h))))
        "tailscaled is still restarted")))

(deftest panic-survives-a-throwing-shell
  (let [boom      (reify proto/IShell
                    (shell-exec! [_this _cmd _opts] (throw (ex-info "spawn failed" {})))
                    (shell-env [_this] {})
                    (shell-which [_this program] (r/ok {:path (str "/usr/bin/" program)})))
        h         (harness {:shell boom})
        [res out] (quietly #(panic/panic! (:system h) {}))]
    (is (r/ok? res))
    (is (str/includes? out "=== RECOVERY DONE ==="))
    (is (seq (-> res :ok :failed)))
    (is (some #{[:write "/etc/resolv.conf" panic/resolv-text]} @(:events h))
        "file steps still run")))

(deftest panic-skips-tools-that-are-not-installed
  (let [h         (harness {:respond normal-respond :available #{}})
        [res out] (quietly #(panic/panic! (:system h) {}))
        cs        (cmds h)]
    (is (r/ok? res))
    (is (not-any? #(= "ufw" (first %)) cs))
    (is (not-any? #(= "ipset" (first %)) cs))
    (is (not-any? #{["systemctl" "restart" "tailscaled"]} cs))
    (is (not (str/includes? out "[*] Restarting tailscaled...")))
    (is (some #{["iptables" "-t" "filter" "-F"]} cs) "iptables is flushed regardless")))

(deftest panic-replaces-a-symlinked-resolv-conf
  ;; `rm -f` through the shell (as bash) also drops a dangling link.
  (let [events (atom [])
        h      (harness {:respond   (fn [cmd opts]
                                      (cond
                                        (= cmd ["test" "-L" "/etc/resolv.conf"])
                                        {:exit 0}

                                        (= cmd ["rm" "-f" "/etc/resolv.conf"])
                                        (do (swap! events conj [:rm "/etc/resolv.conf"]) {:exit 0})

                                        :else (normal-respond cmd opts)))
                          :write-fn (fn [p body]
                                      (swap! events conj [:write p body])
                                      (r/ok {:path p}))})
        _      (quietly #(panic/panic! (:system h) {}))
        evs    (filterv #(= "/etc/resolv.conf" (second %)) @events)]
    (is (= [[:rm "/etc/resolv.conf"] [:write "/etc/resolv.conf" panic/resolv-text]] evs))))

(deftest panic-reports-tailscale-web-left-behind
  (let [h       (harness {:respond normal-respond
                          :files   (assoc base-files "/etc/vpn-killswitch/tailscale-web.enabled" "")})
        [res _] (quietly #(panic/panic! (:system h) {}))]
    (is (some #{"tailscale-web remove"} (map :step (-> res :ok :failed))))
    (is (some #{[:delete "/etc/vpn-killswitch/tailscale-web.enabled"]} @(:events h)))))
