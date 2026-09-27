(ns vpn-kis-bb.app.panic
  "Emergency recovery (bash panic_recover): drop the kill-switch and bring
   the network back, from a local TTY when locked out.

   Every step is best-effort: a failing command, a throwing adapter or a
   missing tool never stops the run. Failures that matter are warned about
   as they happen and listed after the closing note; failures that are
   normal (a chain or set already gone, ip6tables on a host booted with
   IPv6 disabled) are recorded but not reported.

   The tailnet bypass (nft table inet vpn-killswitch-tailscale,
   /etc/vpn-killswitch/tailnet.cidrs, its boot unit and the tailscaled
   drop-in) is KEPT, so the tailnet and the k8s cluster behind it stay
   reachable; `<prog> tailscale-routes remove` drops it.

   System keys: :shell :systemd :read-fn :write-fn :delete-fn :settings
   (:prog), optional :glob-fn (see vpn-kis-bb.app.split/glob), plus what
   vpn-kis-bb.app.exclude/remove-all!, vpn-kis-bb.app.refresh/remove-timer!
   and vpn-kis-bb.app.tailscale-web/run! read (:env :self-path)."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.nm-dispatcher :as nm]
            [vpn-kis-bb.app.exclude :as exclude]
            [vpn-kis-bb.app.refresh :as refresh]
            [vpn-kis-bb.app.selftest :as selftest]
            [vpn-kis-bb.app.split :as split-app]
            [vpn-kis-bb.app.tailscale-web :as web]
            [vpn-kis-bb.domain.re :as rx]
            [vpn-kis-bb.domain.split :as split]
            [vpn-kis-bb.domain.tailscale :as ts]
            [vpn-kis-bb.log :as log]
            [vpn-kis-bb.ports.systemd :as sd-port]))

;; ---------------------------------------------------------------- constants

(def resolv-path "/etc/resolv.conf")
(def before-init-path "/etc/ufw/before.init")
(def ipv6-conf-dir "/proc/sys/net/ipv6/conf")

(def resolv-text
  "The emergency /etc/resolv.conf: public resolvers."
  (str "# Emergency DNS: restored by vpn-kis panic\n"
       "nameserver 1.1.1.1\n"
       "nameserver 8.8.8.8\n"
       "nameserver 9.9.9.9\n"
       "options timeout:2 attempts:2\n"))

(def fixed-sets
  "Kill-switch ipsets destroyed by name: the strict-mode endpoint and DNS
   bootstrap sets and the temporaries refresh swaps in."
  ["vpn_endpoints" "vpn_endpoints_new" "vpn_dns_bootstrap" "vpn_dns_bootstrap_new"])

(def owned-set-prefix
  "Every ipset whose name starts with this is vpn-kis state (the split sets)."
  "vpnkis_")

(def kept
  "What panic leaves in place on purpose: the tailnet bypass."
  [(str "nft table inet " ts/nft-table) ts/cidrs-file])

(def dry-run-steps
  "What panic! does, in order; a dry run prints and returns these."
  ["ufw --force disable; systemctl stop ufw (when ufw is installed)"
   (str "iptables and ip6tables: -F and -X in filter, nat, mangle and raw;"
        " INPUT, OUTPUT and FORWARD policies ACCEPT")
   (str "ipset destroy " (str/join " " fixed-sets) "; ipset flush (when ipset is installed)")
   (str "rm -f " nm/dispatcher-path " " before-init-path)
   "tailscale-web remove (OpenClaw client exception)"
   (str "KEEP the Tailscale bypass (" (str/join ", " kept) ")")
   (str "systemctl disable --now and rm every " split/unit-dir "/" split/unit-glob
        "; ipset destroy every " owned-set-prefix "* set; remove the " split/mangle-chain
        " chain; rm " split/dnsmasq-dir "/" split/dnsmasq-glob)
   "exclude teardown (routing, unit, cgroup)"
   "refresh timer: disable --now, remove its units"
   (str "echo 0 > " ipv6-conf-dir "/*/disable_ipv6")
   (str "reset " resolv-path " to 1.1.1.1 8.8.8.8 9.9.9.9 (a symlink is replaced by a file)")
   "systemctl restart systemd-resolved NetworkManager"
   "systemctl restart tailscaled (when tailscale is installed)"
   "probe: ping 1.1.1.1, getent ahosts cloudflare.com; show the iptables OUTPUT chain"])

(defn note-lines
  "The closing note (bash panic_recover's NOTE), with prog for the script
   path."
  [prog]
  [""
   "=== RECOVERY DONE ==="
   ""
   "What was reverted (runtime only):"
   "  - UFW disabled"
   "  - iptables/ip6tables flushed, default ACCEPT"
   "  - ipset 'vpn_endpoints' destroyed"
   "  - NetworkManager dispatcher hook removed"
   "  - IPv6 re-enabled in /proc"
   "  - /etc/resolv.conf reset to public resolvers"
   "  - NetworkManager + systemd-resolved restarted"
   "  - tailscaled restarted (if present)"
   ""
   "What is NOT reverted (persists across reboot):"
   "  - /etc/sysctl.d/99-disable-ipv6.conf  (IPv6 will disable again on boot)"
   "  - /etc/modprobe.d/disable-ipv6.conf"
   "  - /etc/default/grub  (ipv6.disable=1 kernel arg)"
   "  - UFW rule files in /etc/ufw/  (UFW disabled but rules remain)"
   "  - Tailscale bypass past Mullvad (nft table inet vpn-killswitch-tailscale,"
   "    boot unit, tailscaled drop-in) so the tailnet stays reachable."
   (str "    Remove with: sudo " prog " tailscale-routes remove")
   ""
   "To fully revert IPv6 disable:"
   "  sudo rm /etc/sysctl.d/99-disable-ipv6.conf /etc/modprobe.d/disable-ipv6.conf"
   "  sudo sed -i 's/ipv6.disable=1 //' /etc/default/grub"
   "  sudo update-grub"
   "  sudo reboot"
   ""
   "To restore UFW from snapshot backup (less invasive than panic):"
   (str "  sudo " prog " unlock")
   ""])

;; ---------------------------------------------------------------- steps

(defn- attempt
  "Call thunk f; a throw becomes an error Result."
  [f]
  (try (f)
       (catch Throwable t
         (r/err :panic/threw {:hint (str t)}))))

(defn- first-line [s]
  (let [s (str/trim (str s))
        i (str/index-of s "\n")]
    (if i (subs s 0 i) s)))

(defn- reason
  "Short text saying why an err Result failed."
  [res]
  (let [e (first-line (:stderr res))]
    (cond
      (some? (:exit res)) (str "exit " (:exit res) (when-not (str/blank? e) (str ": " e)))
      (:hint res)         (str (:hint res))
      (:message res)      (str (:message res))
      (:cause res)        (str (:cause res))
      :else               (str (:error res)))))

(defn- step
  "Run thunk f (-> Result) as one best-effort step named desc. Never
   throws; returns {:step desc :ok? bool :report? bool :reason s}.
   report? false marks a step whose failure is normal: recorded, not
   warned about or listed."
  ([desc f] (step desc f true))
  ([desc f report?]
   (let [res (attempt f)]
     (if (r/ok? res)
       {:step desc :ok? true}
       (let [why (reason (if (map? res) res {:error res}))]
         (when report?
           (log/warn "panic: " desc " failed (" why ")"))
         {:step desc :ok? false :report? report? :reason why})))))

(defn- run
  "Result of argv: ok on exit 0, else err :panic/command-failed with
   :exit and :stderr."
  ([system argv] (run system argv {}))
  ([system argv opts]
   (let [res (proto/shell-exec! (:shell system) argv opts)]
     (cond
       (r/err? res)             res
       (= 0 (-> res :ok :exit)) res
       :else                    (r/err :panic/command-failed
                                       {:cmd    argv
                                        :exit   (-> res :ok :exit)
                                        :stderr (-> res :ok :stderr)})))))

(defn- cmd-step
  "step running argv."
  ([system argv] (cmd-step system argv true))
  ([system argv report?]
   (step (str/join " " argv) #(run system argv) report?)))

(defn- ok-run? [system argv opts]
  (r/ok? (attempt #(run system argv opts))))

(defn- has?
  "True when program is on the PATH (bash `command -v`)."
  [system program]
  (try (r/ok? (proto/shell-which (:shell system) program))
       (catch Throwable _lookup-failed-means-absent false)))

(defn- prog [system] (or (get-in system [:settings :prog]) "vpn-kis"))

;; ---------------------------------------------------------------- phases

(defn- disable-ufw
  "bash step 1, when ufw is installed."
  [system]
  (when (has? system "ufw")
    (log/say "[*] Disabling UFW...")
    [(cmd-step system ["ufw" "--force" "disable"])
     (cmd-step system ["systemctl" "stop" "ufw"])]))

(defn- flush-iptables
  "bash step 2: -F and -X in every table, v4 and v6, then ACCEPT policies.
   Reported: the v4 flushes of filter, nat and mangle and the v4 policies.
   raw, -X and every ip6tables call (they fail on a host booted with IPv6
   disabled) are only recorded."
  [system]
  (log/say "[*] Flushing iptables (filter/nat/mangle/raw)...")
  (let [flushes  (mapv (fn [t]
                         [(cmd-step system ["iptables" "-t" t "-F"] (not= "raw" t))
                          (cmd-step system ["iptables" "-t" t "-X"] false)
                          (cmd-step system ["ip6tables" "-t" t "-F"] false)
                          (cmd-step system ["ip6tables" "-t" t "-X"] false)])
                       ["filter" "nat" "mangle" "raw"])
        policies (mapv (fn [c]
                         [(cmd-step system ["iptables" "-P" c "ACCEPT"])
                          (cmd-step system ["ip6tables" "-P" c "ACCEPT"] false)])
                       ["INPUT" "OUTPUT" "FORWARD"])]
    (vec (mapcat identity (concat flushes policies)))))

(defn- destroy-ipsets
  "bash step 3, when ipset is installed: the fixed kill-switch sets, then
   `ipset flush`. A set that does not exist is normal: recorded only."
  [system]
  (when (has? system "ipset")
    (log/say "[*] Destroying ipsets...")
    (conj (mapv (fn [s] (cmd-step system ["ipset" "destroy" s] false)) fixed-sets)
          (cmd-step system ["ipset" "flush"] false))))

(defn- remove-hooks
  "bash step 4: the NetworkManager dispatcher hook and UFW's before.init."
  [system]
  (log/say "[*] Removing NetworkManager dispatcher hook...")
  [(step (str "rm -f " nm/dispatcher-path)
         #(let [res (nm/remove! system)]
            (if (-> res :ok :removed?)
              res
              (r/err :panic/delete-failed {:hint (str "could not delete " nm/dispatcher-path)}))))
   (step (str "rm -f " before-init-path) #((:delete-fn system) before-init-path))])

(defn- remove-tailscale-web
  "bash remove_tailscale_web (vpn-kis-bb.app.tailscale-web). Its own
   warnings print either way; the step counts as failed only when
   tailscale-web was enabled (its marker existed) and the helper could not
   remove it."
  [system]
  (let [enabled? (some? (try ((:read-fn system) ts/web-enabled-file)
                             (catch Throwable _unreadable-means-disabled nil)))]
    [(step "tailscale-web remove"
           #(let [res (web/run! system "remove")]
              (if (or (not enabled?) (-> res :ok :helper-ok?))
                res
                (r/err :panic/tailscale-web
                       {:hint "OpenClaw client exception not fully removed"}))))]))

(defn- keep-tailscale-bypass
  "bash 4b: the tailnet bypass stays; say so."
  [system]
  (log/say "[*] Keeping Tailscale bypass (remove with: " (prog system)
           " tailscale-routes remove)")
  nil)

(defn- remove-splits
  "bash 4c: every split unit (config or not), every vpn-kis ipset (the
   split sets), the shared mangle chain (normally gone after the flush:
   recorded only), every split dnsmasq drop-in. dnsmasq is not reloaded;
   the NetworkManager restart restarts its own."
  [system]
  (log/say "[*] Removing split-tunnel rules...")
  (let [sd       (:systemd system)
        unit-rm  (mapv (fn [path]
                         (let [unit (split/basename path)]
                           [(step (str "systemctl disable --now " unit) #(sd-port/-disable! sd unit))
                            (step (str "rm -f " path) #((:delete-fn system) path))]))
                       (split-app/glob system split/unit-dir split/unit-glob))
        reload   (step "systemctl daemon-reload" #(sd-port/-daemon-reload! sd))
        listed   (when (has? system "ipset")
                   (attempt #(run system ["ipset" "list" "-name"])))
        sets     (when (r/ok? listed)
                   (->> (rx/split-lines* (str (-> listed :ok :stdout)))
                        (map str/trim)
                        (filterv #(str/starts-with? % owned-set-prefix))))
        set-rm   (mapv (fn [s] (cmd-step system ["ipset" "destroy" s])) sets)
        chain-rm (mapv (fn [cmd] (cmd-step system cmd false)) split/chain-teardown-cmds)
        drop-rm  (mapv (fn [path] (step (str "rm -f " path) #((:delete-fn system) path)))
                       (split-app/glob system split/dnsmasq-dir split/dnsmasq-glob))]
    (-> (vec (mapcat identity unit-rm))
        (conj reload)
        (into set-rm)
        (into chain-rm)
        (into drop-rm))))

(defn- remove-exclude
  "bash 4c-bis: cgroup exclusion routing, unit and cgroup
   (vpn-kis-bb.app.exclude/remove-all!, which never fails)."
  [system]
  (log/say "[*] Removing VPN-exclude rules...")
  [(step "exclude teardown (routing, unit, cgroup)" #(exclude/remove-all! system))])

(defn- remove-refresh-timer
  "bash 4d (vpn-kis-bb.app.refresh/remove-timer!). Its disable step fails
   whenever no timer is installed, so only its other steps count."
  [system]
  (log/say "[*] Removing endpoint-refresh timer...")
  [(step "refresh timer removal"
         #(let [res  (refresh/remove-timer! system)
                real (remove (fn [f] (= :disable (:step f))) (-> res :ok :failures))]
            (cond
              (r/err? res) res
              (seq real)   (r/err :panic/refresh-timer
                                  {:hint (str/join "; " (map (fn [f] (str (name (:step f)) ": " (reason f)))
                                                             real))})
              :else        res)))])

(defn- reenable-ipv6
  "bash step 5: 0 into every /proc/sys/net/ipv6/conf/*/disable_ipv6
   (runtime only)."
  [system]
  (log/say "[*] Re-enabling IPv6 (runtime only)...")
  (mapv (fn [f] (step (str "echo 0 > " f) #((:write-fn system) f "0\n")))
        (split-app/glob system ipv6-conf-dir "*/disable_ipv6")))

(defn- reset-dns
  "bash step 6: a symlinked /etc/resolv.conf (systemd-resolved) is removed
   first with `rm -f`, which also drops a dangling link, then the
   public-resolver file is written, mode 644."
  [system]
  (log/say "[*] Restoring DNS resolvers...")
  (let [link? (ok-run? system ["test" "-L" resolv-path] {})]
    (-> (if link? [(cmd-step system ["rm" "-f" resolv-path])] [])
        (conj (step (str "write " resolv-path) #((:write-fn system) resolv-path resolv-text)))
        (conj (cmd-step system ["chmod" "644" resolv-path])))))

(defn- restart-network
  "bash step 7."
  [system]
  (log/say "[*] Restarting systemd-resolved + NetworkManager...")
  [(cmd-step system ["systemctl" "restart" "systemd-resolved"])
   (cmd-step system ["systemctl" "restart" "NetworkManager"])])

(defn- restart-tailscaled
  "bash step 8, when tailscale is installed."
  [system]
  (when (has? system "tailscale")
    (log/say "[*] Restarting tailscaled...")
    [(cmd-step system ["systemctl" "restart" "tailscaled"])]))

(def ^:private phases
  "The recovery steps in bash order, as [id phase-fn]."
  [[:ufw disable-ufw]
   [:iptables flush-iptables]
   [:ipsets destroy-ipsets]
   [:hooks remove-hooks]
   [:tailscale-web remove-tailscale-web]
   [:keep-tailnet keep-tailscale-bypass]
   [:splits remove-splits]
   [:exclude remove-exclude]
   [:refresh-timer remove-refresh-timer]
   [:ipv6 reenable-ipv6]
   [:dns reset-dns]
   [:network restart-network]
   [:tailscaled restart-tailscaled]])

;; ---------------------------------------------------------------- report

(defn- probe
  "bash step 9: ICMP to 1.1.1.1 and a DNS lookup, each printed OK or FAIL."
  [system]
  (log/say "")
  (log/say "[*] Connectivity probe...")
  (let [ping? (ok-run? system ["ping" "-c" "1" "-W" "3" "1.1.1.1"] {:timeout-ms 15000})
        _     (log/say (if ping?
                         "    [OK] ICMP to 1.1.1.1 succeeded"
                         "    [FAIL] No reply from 1.1.1.1: check physical link / wifi"))
        dns?  (ok-run? system ["getent" "ahosts" "cloudflare.com"] {:timeout-ms 15000})]
    (log/say (if dns?
               "    [OK] DNS resolution working"
               "    [FAIL] DNS still broken; try: sudo systemctl restart NetworkManager"))
    {:ping? ping? :dns? dns?}))

(defn- show-output-chain
  "bash step 10: the first 3 lines of `iptables -L OUTPUT -n` from the
   first iptables backend that can render it."
  [system]
  (log/say "")
  (log/say "[*] Current iptables OUTPUT policy:")
  (let [out (try (selftest/ipt-ro (:shell system) ["-L" "OUTPUT" "-n"])
                 (catch Throwable _unreadable nil))]
    (if (nil? out)
      (log/say "    (iptables unreadable)")
      (doseq [line (take 3 (rx/split-lines* out))]
        (log/say line)))))

(defn- print-summary
  "The failed-steps list printed after the note."
  [failed]
  (if (empty? failed)
    (log/say "All recovery steps succeeded.")
    (do (log/say "Steps that FAILED (" (count failed) "), check them by hand:")
        (doseq [f failed]
          (log/say "  - " (:step f) ": " (:reason f))))))

(defn panic!
  "Emergency recovery (bash panic_recover). Never stops early: every step
   runs; failures that matter are warned about as they happen and listed
   after the closing note. Keeps the tailnet bypass.

   opts {:dry-run? true}: print the plan and return it; nothing runs.

   Result<{:failed [{:step s :reason s} ..] :steps [{:step :ok? ..} ..]
           :probe {:ping? bool :dns? bool} :kept [..]}>, always ok.
   Dry run: Result<{:dry-run? true :steps [s ..] :failed [] :kept [..]}>."
  [system {:keys [dry-run?]}]
  (if dry-run?
    (do (doseq [s dry-run-steps]
          (log/say "[dry-run] panic: " s))
        (r/ok {:dry-run? true :steps dry-run-steps :failed [] :kept kept}))
    (do (log/say "")
        (log/say "=== VPN-KILLSWITCH PANIC RECOVERY ===")
        (log/say "")
        (let [steps  (reduce (fn [acc [id phase]]
                               (into acc (try (phase system)
                                              (catch Throwable t
                                                [{:step    (str "panic phase " (name id))
                                                  :ok?     false
                                                  :report? true
                                                  :reason  (str t)}]))))
                             []
                             phases)
              probes (try (probe system)
                          (catch Throwable _probe-threw {:ping? false :dns? false}))
              _      (try (show-output-chain system)
                          (catch Throwable _display-only nil))
              failed (into []
                           (comp (filter #(and (not (:ok? %)) (:report? %)))
                                 (map #(select-keys % [:step :reason])))
                           steps)]
          (doseq [line (note-lines (prog system))]
            (log/say line))
          (print-summary failed)
          (r/ok {:failed failed :steps steps :probe probes :kept kept})))))
