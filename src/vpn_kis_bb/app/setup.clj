(ns vpn-kis-bb.app.setup
  "`setup`: install the kill-switch (bash main() tail: banner,
   detect_physical_if, backup_existing, disable_ipv6, setup_ufw,
   add_killswitch_before_rules, the Tailscale bypass, make_persistent, the
   NetworkManager dispatcher, verify, closing lines).

     permissive  DNS, 443 and the VPN ports open pre-tunnel to any host.
     strict      pre-tunnel traffic on the physical IF only to members of
                 the ipset vpn_endpoints, on any port (STRICT_PORTS=1: on
                 the VPN ports only), plus port 53 to the separate
                 vpn_dns_bootstrap set.

   Plans come from the pure vpn-kis-bb.domain.setup and domain.rules; this
   namespace runs them against the system map and logs progress through
   vpn-kis-bb.log where the bash prints it.

   System keys used:
     :shell                  IShell for every command (a RecordingShell in dry runs)
     :live-shell             optional IShell for read-only probes (ip route, date)
     :read-fn                (fn [path] -> string | nil)
     :write-fn               (fn [path body] -> Result)
     :settings               {:prog :lan-allow :vpn-interfaces :dns-bootstrap
                              :strict-ports? :physical-iface}
     :providers-dir          optional .ips cache dir (default app.fetch/providers-dir)
     :install-tailscale!     optional (fn [system opts] -> Result)
     :install-nm-dispatcher! optional (fn [system opts] -> Result)
     :profile                a :dry-run? call on a :prod system is refused"
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.app.exclude :as exclude]
            [vpn-kis-bb.app.fetch :as fetch]
            [vpn-kis-bb.app.providers :as providers]
            [vpn-kis-bb.app.selftest :as selftest]
            [vpn-kis-bb.domain.refresh :as refresh]
            [vpn-kis-bb.domain.rules :as rules]
            [vpn-kis-bb.domain.setup :as d]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.log :as log]))

;; ---------------------------------------------------------------- helpers

(defn- prog
  "Name shown in hints (bash `$0`)."
  [system]
  (or (get-in system [:settings :prog]) "vpn-kis"))

(defn- providers-dir [system]
  (or (:providers-dir system) fetch/providers-dir))

(defn- ips-path [system pname]
  (str (providers-dir system) "/" pname ".ips"))

(defn- attempt
  "Call thunk f; a throw becomes an error Result instead of escaping."
  [f]
  (try (f)
       (catch Throwable t
         (r/err :setup/threw {:cause (str t)
                              :hint  (str "setup: unexpected failure: " t)}))))

(defn- brief
  "argv with long words (an inline ipset restore payload) cut."
  [cmd]
  (mapv #(let [s (str %)] (if (> (count s) 160) (str (subs s 0 160) "...") s)) cmd))

(defn- probe
  "stdout of a read-only argv (on :live-shell when present, else :shell),
   or nil when it fails."
  [system argv]
  (let [shell (or (:live-shell system) (:shell system))
        res   (attempt #(proto/shell-exec! shell argv {}))]
    (when (and (r/ok? res) (= 0 (-> res :ok :exit)))
      (-> res :ok :stdout))))

(defn- emit!
  "Print one {:level :text} line: :info and :warn to stderr, else stdout."
  [{:keys [level text]}]
  (case level
    :info (log/info text)
    :warn (log/warn text)
    (log/say text)))

;; ---------------------------------------------------------------- step interpreter

(defn- command-failed [system cmd res]
  (let [{:keys [exit stderr]} (:ok res)
        stderr (str/trim (str (or stderr "")))]
    (r/err :setup/command-failed
           {:cmd    (brief cmd)
            :exit   exit
            :stderr stderr
            :cause  (when (r/err? res) res)
            :hint   (str "setup: '" (str/join " " (brief cmd)) "' failed"
                         (when exit (str " (exit " exit ")"))
                         (when-not (str/blank? stderr) (str ": " stderr))
                         ". The firewall may be half-configured; roll back with: sudo "
                         (prog system) " unlock")})))

(defn- run-step!
  "Interpret one domain.setup step against the system. Result: an error
   only for a failed write or a failed :abort command."
  [system {:keys [op cmd on-fail warning path body timeout-ms] :as step}]
  (case op
    :log   (do (emit! step) (r/ok nil))
    :write (let [w (attempt #((:write-fn system) path body))]
             (if (r/err? w)
               (r/err :setup/write-failed
                      {:path  path
                       :cause w
                       :hint  (str "setup: cannot write " path ". Roll back with: sudo "
                                   (prog system) " unlock")})
               (r/ok nil)))
    :run   (let [res (attempt #(proto/shell-exec! (:shell system) cmd
                                                  {:timeout-ms (or timeout-ms d/default-timeout-ms)}))]
             (cond
               (and (r/ok? res) (= 0 (-> res :ok :exit))) (r/ok nil)
               (= :ignore on-fail)                        (r/ok nil)
               (= :warn on-fail)                          (do (log/warn warning) (r/ok nil))
               :else                                      (command-failed system cmd res)))))

(defn- run-plan!
  "Run steps in order, stopping at the first error Result."
  [system steps]
  (reduce (fn [acc step]
            (let [res (run-step! system step)]
              (if (r/err? res) (reduced res) acc)))
          (r/ok nil)
          steps))

(defn- run-phases
  "Run [k thunk] pairs in order, stopping at the first error Result (tagged
   with :phase k). Result<{k ok-value}>."
  [phases]
  (reduce (fn [acc [k f]]
            (let [res (attempt f)]
              (if (r/err? res)
                (reduced (assoc res :phase k))
                (r/ok (assoc (:ok acc) k (:ok res))))))
          (r/ok {})
          phases))

;; ---------------------------------------------------------------- physical IF

(defn detect-physical-iface
  "bash detect_physical_if: the first non-virtual default-route interface
   of `ip -4 route ls`, else the first non-virtual name in
   /sys/class/net. Probes use :live-shell when present, else :shell.
   Result<iface>; err :setup/no-physical-iface (with :hint) when none."
  [system]
  (if-let [phys (or (d/iface-from-routes (probe system d/routes-cmd))
                    (d/iface-from-links (probe system d/links-cmd)))]
    (r/ok phys)
    (r/err :setup/no-physical-iface
           {:hint "Cannot detect physical interface. Set PHYSICAL_IF manually (or pass --physical-iface)."})))

(defn- physical-iface!
  "The configured interface, else the detected one; logged like bash."
  [system ctx]
  (let [res (if-let [given (:physical-iface ctx)]
              (r/ok given)
              (detect-physical-iface system))]
    (when (r/ok? res)
      (log/info "Physical interface: " (:ok res)))
    res))

;; ---------------------------------------------------------------- endpoints

(defn- load-providers!
  "bash `providers`: the union of the cached lists (a warning per missing
   one), refused when empty; the names become the refresh timer's active
   set. Result<{:mode :strict :endpoints [ip ...] :source :providers
   :providers [name ...]}>."
  [system names]
  (log/info "Loading provider profiles: " (str/join " " names))
  (let [union-r (attempt #(providers/load-union names {:dir (providers-dir system)}))]
    (if (r/err? union-r)
      union-r
      (let [{:keys [union missing]} (:ok union-r)]
        (doseq [n missing]
          (log/warn "No cached list for '" n "' (" (ips-path system n) "). Run: "
                    (prog system) " fetch " n))
        (if (empty? union)
          (r/err :setup/no-ips
                 {:providers names
                  :missing   missing
                  :hint      (str "No IPs loaded. Run: " (prog system) " fetch "
                                  (str/join " " names))})
          (do (log/info "Locking to " (count union) " endpoints from: " (str/join " " names))
              (let [w (attempt #((:write-fn system) refresh/active-file
                                                    (refresh/active-text names)))]
                (if (r/err? w)
                  w
                  (r/ok {:mode      :strict
                         :endpoints (vec union)
                         :source    :providers
                         :providers names})))))))))

(defn- endpoint-source!
  "Mode and strict-mode endpoints: explicit :endpoints first, else the
   :providers union. A nil :mode means strict when either is given.
   Result<{:mode :endpoints [..] :source :endpoints|:providers ..}>."
  [system {:keys [mode endpoints providers]}]
  (let [explicit (d/words endpoints)
        names    (refresh/normalize-names providers)
        mode     (or mode (if (or (seq explicit) (seq names)) :strict :permissive))]
    (cond
      (= :permissive mode)
      (r/ok {:mode :permissive :endpoints []})

      (not= :strict mode)
      (r/err :setup/bad-mode {:mode mode :hint "setup: :mode must be :permissive or :strict"})

      (seq explicit)
      (if (some u/ipv4? explicit)
        (r/ok {:mode :strict :endpoints explicit :source :endpoints})
        (r/err :setup/no-ips
               {:endpoints explicit
                :hint      (str "No IPs loaded: no valid IPv4 endpoint in '"
                                (str/join " " explicit) "'")}))

      (seq names)
      (load-providers! system names)

      :else
      (r/err :setup/no-endpoints
             {:hint (str "strict mode needs endpoints: set VPN_ENDPOINTS, or run '"
                         (prog system) " auto' or '" (prog system) " providers <names>'")}))))

;; ---------------------------------------------------------------- context

(defn- context
  "Setup inputs: opts first, then the system settings, then defaults."
  [system opts]
  (let [settings (:settings system)]
    {:dry-run?       (boolean (:dry-run? opts))
     :lan-allow      (d/words (if (some? (:lan-allow opts))
                                (:lan-allow opts)
                                (:lan-allow settings)))
     :vpn-interfaces (or (not-empty (d/words (:vpn-interfaces settings)))
                         rules/default-vpn-interfaces)
     :dns-bootstrap  (d/words (:dns-bootstrap settings))
     :strict-ports?  (boolean (if (contains? opts :strict-ports?)
                                (:strict-ports? opts)
                                (:strict-ports? settings)))
     :physical-iface (or (not-empty (:physical-iface opts))
                         (not-empty (:physical-iface settings)))}))

(defn- refusal
  "An error Result when setup must not start, else nil."
  [system ctx]
  (let [errors (d/input-errors ctx)]
    (cond
      (and (:dry-run? ctx) (= :prod (:profile system)))
      (r/err :setup/dry-run-on-live-system
             {:hint "setup: a dry run needs the :dry-run system profile; refusing to touch the live system"})

      (seq errors)
      (r/err :setup/invalid-input {:errors errors :hint (str "setup: " (str/join "; " errors))})

      :else nil)))

;; ---------------------------------------------------------------- phases

(defn- backup-dir
  "/etc/ufw/backup-<local time from `date`>, a UTC stamp when that fails."
  [system]
  (d/backup-dir (or (d/date-stamp (probe system d/date-cmd))
                    (d/iso-stamp (u/now-iso)))))

(defn- ensure-ipset!
  "setup_endpoint_ipset preamble, run as a pre-flight before any change:
   install ipset when it is missing. Result; err :setup/no-ipset."
  [system]
  (if (r/ok? (attempt #(proto/shell-which (:shell system) "ipset")))
    (r/ok nil)
    (do (log/warn "ipset not installed, installing...")
        (let [res (run-step! system d/install-ipset-step)]
          (if (r/err? res)
            (r/err :setup/no-ipset {:cause res :hint "Cannot install ipset. Run: sudo apt install ipset"})
            res)))))

(defn- load-sets!
  "Strict mode: build vpn_endpoints and vpn_dns_bootstrap, persist them,
   log the live entry count. Result<{:ipset-entries n}>."
  [system ctx]
  (let [res (run-plan! system (d/ipset-steps ctx))]
    (if (r/err? res)
      res
      (let [out (attempt #(proto/shell-exec! (:shell system) (refresh/list-command) {}))
            n   (or (when (r/ok? out) (refresh/entry-count (-> out :ok :stdout)))
                    (count (refresh/valid-ips (:endpoints ctx))))]
        (log/info "ipset loaded: " n " entries. Persisted to " refresh/ipset-conf
                  " + before.init hook.")
        (r/ok {:ipset-entries n})))))

(defn- killswitch!
  "add_killswitch_before_rules: the ipsets (strict), before.rules,
   before6.rules, ufw reload."
  [system ctx before-text]
  (log/info "Hardening: adding iptables kill-switch to UFW before.rules...")
  (let [sets (if (= :strict (:mode ctx)) (load-sets! system ctx) (r/ok {}))]
    (if (r/err? sets)
      sets
      (let [res (run-plan! system (d/killswitch-steps (:physical-iface ctx) before-text))]
        (if (r/err? res) res sets)))))

(defn- hook!
  "Run the optional system hook k as (f system opts). Absent: skipped with
   a log line. An error Result or a throw: warned, setup continues.
   Result<hook value | {:skipped? true} | {:failed err}>."
  [system k label opts]
  (if-let [f (get system k)]
    (let [res (attempt #(f system opts))]
      (if (r/err? res)
        (do (log/warn label " failed, continuing: "
                      (or (:hint res) (:message res) (:error res)))
            (r/ok {:failed res}))
        (r/ok (if (r/ok? res) (:ok res) res))))
    (do (log/info label ": not available in this build, skipped")
        (r/ok {:skipped? true}))))

(defn- verify!
  "bash verify: app.selftest/verify-report, printed and returned.
   Skipped in a dry run, where nothing was applied."
  [system dry-run?]
  (if dry-run?
    (do (log/info "dry-run: nothing applied, VERIFICATION skipped")
        (r/ok nil))
    (let [res (attempt #(selftest/verify-report system))]
      (if (r/ok? res)
        (do (run! emit! (:ok res))
            res)
        (do (log/warn "VERIFICATION could not run: " (or (:hint res) (:error res)))
            (r/ok nil))))))

(defn- report
  "The ok value of setup!."
  [ctx dir exclude? before-text done]
  (let [strict? (= :strict (:mode ctx))]
    {:mode           (:mode ctx)
     :physical-iface (:physical-iface ctx)
     :endpoint-count (if strict? (count (refresh/valid-ips (:endpoints ctx))) 0)
     :source         (:source ctx)
     :providers      (:providers ctx)
     :dns-bootstrap  (if strict? (vec (refresh/valid-ips (:dns-bootstrap ctx))) [])
     :lan-allow      (:lan-allow ctx)
     :strict-ports?  (boolean (and strict? (:strict-ports? ctx)))
     :exclude?       exclude?
     :backup-dir     dir
     :before-rules   before-text
     :ipset-entries  (get-in done [:killswitch :ipset-entries])
     :hooks          {:tailscale     (:tailscale done)
                      :nm-dispatcher (:nm-dispatcher done)}
     :verify         (:verify done)
     :dry-run?       (:dry-run? ctx)}))

(defn- install!
  "Everything after the physical IF is known, in bash order, after a
   strict-mode pre-flight (ipset present) that changes nothing on failure.
   Hooks get opts {:physical-iface :mode :vpn-interfaces :dry-run?}."
  [system ctx]
  (let [dir      (backup-dir system)
        exclude? (boolean (exclude/enabled? system))
        before-r (attempt #(r/ok (rules/before-rules-text (d/rules-plan ctx exclude?))))]
    (if (r/err? before-r)
      before-r
      (let [before    (:ok before-r)
            strict?   (= :strict (:mode ctx))
            hook-opts {:physical-iface (:physical-iface ctx)
                       :mode           (:mode ctx)
                       :vpn-interfaces (:vpn-interfaces ctx)
                       :dry-run?       (:dry-run? ctx)}
            res       (run-phases
                       [[:preflight     #(if strict? (ensure-ipset! system) (r/ok nil))]
                        [:backup        #(run-plan! system (d/backup-steps dir))]
                        [:ipv6          #(run-plan! system (d/ipv6-steps ((:read-fn system) d/grub-path)))]
                        [:ufw           #(run-plan! system (d/ufw-steps ctx))]
                        [:killswitch    #(killswitch! system ctx before)]
                        [:tailscale     #(hook! system :install-tailscale! "Tailscale bypass" hook-opts)]
                        [:persist       #(run-plan! system d/persist-steps)]
                        [:nm-dispatcher #(hook! system :install-nm-dispatcher!
                                                "NetworkManager dispatcher" hook-opts)]
                        [:verify        #(verify! system (:dry-run? ctx))]])]
        (if (r/err? res)
          res
          (do (run-plan! system (d/done-steps (prog system)))
              (r/ok (report ctx dir exclude? before (:ok res)))))))))

(defn- setup* [system opts]
  (let [ctx (context system opts)]
    (or (refusal system ctx)
        (let [src (endpoint-source! system opts)]
          (if (r/err? src)
            src
            (let [ctx (merge ctx (:ok src))]
              (run-plan! system (d/banner-steps ctx))
              (let [phys (physical-iface! system ctx)]
                (if (r/err? phys)
                  phys
                  (install! system (assoc ctx :physical-iface (:ok phys)))))))))))

;; ---------------------------------------------------------------- API

(defn setup!
  "Install the kill-switch: bash `setup`, `providers` and `auto` from the
   endpoint lookup on (banner, physical IF, backup, IPv6 off, UFW, ipsets,
   before.rules, Tailscale bypass hook, persistence, NM dispatcher hook,
   verification report, closing lines).

   opts: {:mode           :permissive | :strict (nil: strict when endpoints
                          or providers are given)
          :endpoints      [ip ...]   strict: explicit list (VPN_ENDPOINTS, auto)
          :providers      [name ...] strict, used when :endpoints is empty: the
                          union of the cached lists; the names are written
                          to the refresh timer's active file
          :lan-allow      [cidr ...] nil: settings :lan-allow
          :physical-iface s          nil: settings :physical-iface, else detected
          :strict-ports?  bool       absent: settings :strict-ports?
          :dry-run?       bool       plan against a :dry-run system (recording
                          shell); refused on a :prod system}

   Strict mode without a valid endpoint IP, invalid input, and an
   undetectable physical IF are refused before anything changes.
   Result<{:mode :physical-iface :endpoint-count :source :providers
           :dns-bootstrap :lan-allow :strict-ports? :exclude? :backup-dir
           :before-rules :ipset-entries :hooks :verify :dry-run?}>.
   Errors carry :hint, plus :phase once changes have started."
  [system opts]
  (attempt #(setup* system opts)))
