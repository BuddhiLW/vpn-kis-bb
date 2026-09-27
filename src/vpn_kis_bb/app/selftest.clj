(ns vpn-kis-bb.app.selftest
  "Kill-switch self-test and the post-setup verification printout: bash
   `test passive`, `test active` and `verify` (vpn-firewall-setup.sh,
   \"Test suite\" section).

   Effects only. Every command goes through (:shell system) and every
   verdict comes from the pure vpn-kis-bb.domain.selftest. Progress lines
   go to stderr via vpn-kis-bb.log while the checks run; the results come
   back as data for the caller to print (domain.selftest/result-lines and
   summary-line), so nothing here prints a [PASS]/[FAIL] line itself.

   system keys used: :shell (IShell), :read-fn (path -> string or nil),
   :settings {:physical-iface :force?}."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.domain.selftest :as st]
            [vpn-kis-bb.log :as log]))

;; ---------------------------------------------------------------- shell

(defn- run
  "Run argv, always yielding {:exit N :stdout S}. A shell err Result (how
   the JVM shell reports a missing binary; the cljw shell exits 127
   instead) becomes exit -1 with no output."
  [shell argv]
  (let [res (proto/shell-exec! shell argv {})]
    (if (r/ok? res)
      {:exit   (or (:exit (:ok res)) -1)
       :stdout (or (:stdout (:ok res)) "")}
      {:exit -1 :stdout ""})))

(defn- ok-exit? [res] (= 0 (:exit res)))

(defn- stdout-of [shell argv] (:stdout (run shell argv)))

(defn- read-fn-of [system]
  (or (:read-fn system)
      (fn [path] (try (slurp path) (catch Throwable _ nil)))))

(defn ipt-ro
  "bash `ipt_ro`: `<backend> args` for iptables, iptables-nft and
   iptables-legacy in turn; the stdout of the first that exits 0, or nil
   when none can render the request. Read only: rule writes keep using
   plain `iptables`, the backend UFW restores into."
  [shell args]
  (some (fn [backend]
          (let [res (run shell (into [backend] args))]
            (when (ok-exit? res) (:stdout res))))
        st/ipt-candidates))

(defn detect-vpn-iface
  "bash `detect_vpn_iface`: the up VPN tunnel link (the tailscale overlay
   only when no other tunnel is up), or nil."
  [shell]
  (st/first-vpn-iface (stdout-of shell ["ip" "-o" "link" "show" "up"])))

(defn physical-iface
  "The IF the kill-switch DROP should sit on: the :physical-iface setting,
   else the IF pinned in /etc/ufw/before.rules, else the first non-virtual
   default route of `ip -4 route ls`. nil when none is found."
  [system]
  (or (not-empty (:physical-iface (:settings system)))
      (st/pinned-drop-iface ((read-fn-of system) st/before-rules-path))
      (st/default-route-iface (stdout-of (:shell system) ["ip" "-4" "route" "ls"]))))

(defn- public-ip-out
  "Raw stdout of `curl --max-time N -s https://ifconfig.me`."
  [shell max-time-secs]
  (stdout-of shell ["curl" "--max-time" (str max-time-secs) "-s" st/ip-echo-url]))

;; ---------------------------------------------------------------- passive

(defn- passive-snapshot
  "Capture everything the passive checks read, in bash order."
  [system]
  (let [shell  (:shell system)
        status (stdout-of shell ["ufw" "status"])
        policy (stdout-of shell ["ufw" "status" "verbose"])
        phys   (physical-iface system)
        rules  (ipt-ro shell ["-S" st/before-output-chain])
        ipv6   ((read-fn-of system) st/ipv6-disable-path)
        rules6 (stdout-of shell ["ip6tables" "-S" st/ip6-before-output-chain])
        ipset  (when (st/endpoint-ipset-referenced? rules)
                 (stdout-of shell ["ipset" "list" st/endpoint-ipset]))
        vpn-if (detect-vpn-iface shell)]
    {:ufw-status     status
     :ufw-verbose    policy
     :physical-iface phys
     :rules          rules
     :disable-ipv6   ipv6
     :ip6-rules      rules6
     :ipset-list     ipset
     :vpn-iface      vpn-if
     :public-ip      (when vpn-if (public-ip-out shell 5))}))

(defn passive
  "bash `test passive`: the eight non-disruptive checks.
   Returns Result<{:results [{:status :msg} ...] :passed N :failed M}>."
  [system]
  (log/info "========== PASSIVE TESTS (non-disruptive) ==========")
  (r/ok (st/tally (st/passive-results (passive-snapshot system)))))

;; ---------------------------------------------------------------- active

(defn- confirm-prompt
  "bash: `read -rp \"Continue? [y/N] \" ans` (prompt on stderr)."
  []
  (binding [*out* *err*]
    (print "Continue? [y/N] ")
    (flush))
  (st/confirmed? (read-line)))

(defn- sleep-ms [ms] (Thread/sleep (long ms)))

(defn- bring-down!
  "wg* ifaces: `wg-quick down`, falling back to `ip link set X down`;
   anything else: `ip link set X down`. Returns the command that brings
   the tunnel back, or nil when it could not be brought down."
  [shell iface]
  (cond
    (and (st/wireguard-iface? iface) (ok-exit? (run shell (st/wg-quick-cmd "down" iface))))
    (st/wg-quick-cmd "up" iface)

    (ok-exit? (run shell (st/link-cmd iface "down")))
    (st/link-cmd iface "up")

    :else nil))

(defn- probe-leaks!
  "The four leak probes, run with the tunnel down."
  [shell]
  (let [ifconfig (run shell ["curl" "--max-time" "5" "-s" st/ip-echo-url])
        cf       (run shell ["curl" "--max-time" "5" "-s" "https://1.1.1.1"])
        ping     (run shell ["ping" "-c" "2" "-W" "2" "8.8.8.8"])
        dig      (run shell ["dig" "+time=3" "+tries=1" "google.com" "@8.8.8.8" "+short"])]
    [(st/check-leak-ifconfig (:stdout ifconfig))
     (st/check-leak-cloudflare (:stdout cf))
     (st/check-leak-ping (:exit ping))
     (st/check-leak-dns (:exit dig)
                        (when (ok-exit? dig) (ipt-ro shell ["-S" st/before-output-chain])))]))

(defn- probe-while-down!
  "Wait for the drop, then probe. On an unexpected throw the tunnel is
   brought back before the error propagates, so it is never left down."
  [shell sleep-fn restore-cmd]
  (try
    (sleep-fn 2000)
    (log/info "Testing leak with VPN DOWN...")
    (probe-leaks! shell)
    (catch Throwable t
      (run shell restore-cmd)
      (throw t))))

(defn- restore!
  "Bring the tunnel back; the restored-IP PASS, or nil after warning."
  [shell sleep-fn iface restore-cmd]
  (log/info "Restoring VPN: " (st/restore-note iface restore-cmd))
  (when-not (ok-exit? (run shell restore-cmd))
    (log/warn "Restore command failed: reconnect VPN manually"))
  (sleep-fn 3000)
  (let [restored (st/check-restored (public-ip-out shell 10))]
    (when-not restored
      (log/warn "VPN not restored automatically: reconnect via your VPN client"))
    restored))

(defn- leak-test!
  "Tunnel up with a baseline IP: drop it, probe, restore, verdict."
  [shell sleep-fn iface]
  (log/info "Dropping VPN interface: " iface)
  (if-let [restore-cmd (bring-down! shell iface)]
    (let [probes   (probe-while-down! shell sleep-fn restore-cmd)
          restored (restore! shell sleep-fn iface restore-cmd)
          verdict  (st/killswitch-verdict (st/leak-count probes))]
      (when-not verdict
        (log/info "KILLSWITCH VERIFIED: no leak detected"))
      (r/ok (st/tally (cond-> probes
                        restored (conj restored)
                        verdict  (conj verdict)))))
    (r/ok (st/aborted :down-failed
                      [(st/fail (str "Could not bring " iface " down: cannot test drop."))]))))

(defn- run-active [shell sleep-fn]
  (if-let [iface (detect-vpn-iface shell)]
    (let [baseline (st/echoed-ip (public-ip-out shell 5))]
      (log/info "Baseline public IP (VPN up): " (or baseline "<unreachable>"))
      (if baseline
        (leak-test! shell sleep-fn iface)
        (r/ok (st/aborted :no-baseline
                          [(st/fail "No internet even with VPN up: aborting.")]))))
    (r/ok (st/aborted :no-vpn-iface
                      [(st/fail "No VPN interface up: cannot test drop.")]))))

(defn active
  "bash `test active` (disruptive): bring the VPN iface down, probe for
   leaks, bring it back.

   opts: {:confirm-fn (fn [] boolean)  asked unless (:force? settings);
                                       default prompts \"Continue? [y/N] \"
          :sleep-fn   (fn [ms])        default Thread/sleep}

   Returns Result<{:results [...] :passed N :failed M}>. A run that
   stops early also carries :aborted? true and :reason: :declined (no
   results, like bash's exit 0), or :no-vpn-iface, :no-baseline,
   :down-failed (one FAIL each, like bash's exit 1). Nothing is brought
   down in any aborted run."
  ([system] (active system {}))
  ([system {:keys [confirm-fn sleep-fn]}]
   (let [confirm-fn (or confirm-fn confirm-prompt)
         sleep-fn   (or sleep-fn sleep-ms)]
     (log/info "========== ACTIVE LEAK TEST (disruptive) ==========")
     (log/warn "This will DROP your VPN connection to test the killswitch.")
     (log/warn "Any active downloads/SSH/streams will be interrupted.")
     (if (or (:force? (:settings system)) (confirm-fn))
       (run-active (:shell system) sleep-fn)
       (do (log/info "Aborted.")
           (r/ok (st/aborted :declined [])))))))

;; ---------------------------------------------------------------- verify

(defn verify-report
  "bash `verify`: the VERIFICATION printout after setup. Never fails:
   unreadable pieces turn into :warn lines.
   Returns Result<[{:level :info|:warn|:plain :text \"...\"} ...]>."
  [system]
  (let [shell   (:shell system)
        ufw     (stdout-of shell ["ufw" "status" "numbered"])
        listing (ipt-ro shell ["-L" "OUTPUT" "-n" "-v"])
        nft     (when (str/blank? listing)
                  (stdout-of shell ["nft" "list" "chain" "ip" "filter" "OUTPUT"]))
        rules   (ipt-ro shell ["-S" st/before-output-chain])
        ipv6    ((read-fn-of system) st/ipv6-disable-path)
        addrs   (stdout-of shell ["ip" "-4" "addr" "show"])
        route   (stdout-of shell ["ip" "route" "show" "default"])]
    (r/ok (st/verify-lines {:ufw-numbered  ufw
                            :output-chain  listing
                            :nft-output    nft
                            :kill-rules    rules
                            :disable-ipv6  ipv6
                            :addr-show     addrs
                            :default-route route}))))
