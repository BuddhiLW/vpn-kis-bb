(ns vpn-kis-bb.cli.main
  "CLI entry: bash `main` of vpn-firewall-setup.sh, command for command.

   `run` parses argv, builds the system (--dry-run records commands instead
   of running them), checks root where the bash did and dispatches. Every
   handler takes a context {:system :opts :prog} plus the command's
   arguments and returns the exit code; -main only adds the process exit."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.exec :as exec]
            [vpn-kis-bb.app.detect :as detect]
            [vpn-kis-bb.app.exclude :as exclude]
            [vpn-kis-bb.app.fetch :as fetch]
            [vpn-kis-bb.app.nm-dispatch :as nm-dispatch]
            [vpn-kis-bb.app.panic :as panic]
            [vpn-kis-bb.app.refresh :as refresh]
            [vpn-kis-bb.app.selftest :as selftest]
            [vpn-kis-bb.app.setup :as setup]
            [vpn-kis-bb.app.split :as split]
            [vpn-kis-bb.app.tailscale :as tailscale]
            [vpn-kis-bb.app.tailscale-web :as tailscale-web]
            [vpn-kis-bb.app.unlock :as unlock]
            [vpn-kis-bb.cli.args :as args]
            [vpn-kis-bb.cli.system :as system]
            [vpn-kis-bb.cli.usage :as usage]
            [vpn-kis-bb.domain.exclude :as exclude-d]
            [vpn-kis-bb.domain.refresh :as refresh-d]
            [vpn-kis-bb.domain.selftest :as selftest-d]
            [vpn-kis-bb.log :as log]))

;; ---------------------------------------------------------------- output

(defn- reason
  "Printable cause of an error Result."
  [res]
  (or (:hint res) (:message res) (some-> (:error res) str) (pr-str res)))

(defn- fail
  "Print an error Result as bash `error` does (the whole value too when
   VPN_KIS_DEBUG=1). Exit code 1."
  [ctx res]
  (log/error (reason res))
  (when (= "1" (get-in ctx [:system :env "VPN_KIS_DEBUG"]))
    (log/error (pr-str res)))
  1)

(defn- usage-error [ctx msg]
  (fail ctx (r/err :cli/usage {:hint msg})))

(defn- done
  "Exit code of a workflow Result: 0 when ok, else printed and 1."
  [ctx res]
  (if (r/ok? res) 0 (fail ctx res)))

(defn- print-lines
  "Report lines: strings go to stdout, {:level :text} maps by level."
  [lines]
  (doseq [l lines]
    (if (map? l)
      (case (:level l)
        :info  (log/info (:text l))
        :warn  (log/warn (:text l))
        :error (log/error (:text l))
        (log/say (:text l)))
      (log/say (str l)))))

;; ---------------------------------------------------------------- context

(defn- dry-run? [ctx] (boolean (get-in ctx [:opts :dry-run?])))

(defn- live
  "The system with its live shell: for read-only probes, which a dry run
   must still see (detect, auto)."
  [system]
  (assoc system :shell (:live-shell system)))

(defn euid-zero?
  "True when the process runs as root (`id -u` through the live shell)."
  [system]
  (let [res (proto/shell-exec! (:live-shell system) ["id" "-u"] {})]
    (and (r/ok? res) (= "0" (str/trim (str (-> res :ok :stdout)))))))

(defn- root? [ctx]
  (if (contains? ctx :root?) (:root? ctx) (euid-zero? (:system ctx))))

(defn- as-root
  "bash require_root: run f, or refuse unless root (a dry run never needs it)."
  [ctx f]
  (if (or (dry-run? ctx) (root? ctx))
    (f)
    (fail ctx (r/err :cli/not-root {:hint "Run as root or with sudo"}))))

(defn context
  "Handler context: the wired system (profile from --dry-run; --lan and
   --physical-iface override the env settings) and the parsed opts."
  [opts env]
  (let [sys       (system/make-system {:profile (if (:dry-run? opts) :dry-run :prod)
                                       :env     env})
        overrides (cond-> {}
                    (seq (:lan opts))      (assoc :lan-allow (vec (:lan opts)))
                    (:physical-iface opts) (assoc :physical-iface (:physical-iface opts)))]
    {:system (update sys :settings merge overrides)
     :opts   opts
     :prog   (get-in sys [:settings :prog])}))

;; ---------------------------------------------------------------- setup family

(defn- setup-opts
  "setup! options shared by setup, auto and providers. LAN CIDRs come from
   the settings (LAN_ALLOW_CIDRS, overridden by --lan in `context`)."
  [{:keys [system] :as ctx} mode-opts]
  (merge {:physical-iface (get-in system [:settings :physical-iface])
          :dry-run?       (dry-run? ctx)}
         mode-opts))

(defn- run-setup [ctx mode-opts]
  (done ctx (setup/setup! (:system ctx) (setup-opts ctx mode-opts))))

(defn cmd-setup
  "bash `setup` (the default): strict when VPN_ENDPOINTS is set."
  [ctx _args]
  (let [eps (get-in ctx [:system :settings :endpoints])]
    (run-setup ctx (if (seq eps)
                     {:mode :strict :endpoints (vec eps)}
                     {:mode :permissive}))))

(defn cmd-auto
  "bash `auto`: strict-lock to the live VPN peers."
  [{:keys [system] :as ctx} _args]
  (log/info "Auto-detecting VPN endpoints...")
  (let [ips (sort (:ok (detect/detect-endpoints (live system))))]
    (if (empty? ips)
      (usage-error ctx (str "No active VPN detected. Connect VPN first, then rerun with 'auto'."
                            " Or use 'setup' for permissive mode, or set VPN_ENDPOINTS=... manually."))
      (do (log/info "Locking to endpoints: " (str/join " " ips))
          (run-setup ctx {:mode :strict :endpoints (vec ips)})))))

(defn- known-providers [system]
  (str/join " " (sort (map name (keys (:fetchers system))))))

(defn cmd-providers
  "bash `providers`: strict-lock to the union of the cached provider lists.
   setup! loads them, warns about missing ones, writes providers.active
   for `refresh` and refuses when no IP is loaded."
  [{:keys [system] :as ctx} names]
  (if (empty? names)
    (usage-error ctx (str "providers: specify at least one provider name. Known: "
                          (known-providers system)))
    (run-setup ctx {:mode :strict :providers (vec names)})))

;; ---------------------------------------------------------------- endpoints

(defn cmd-fetch
  "bash `fetch`: refresh each named provider list (default: the built-in
   ones). Exit code = number of failures, as in the bash."
  [{:keys [system]} names]
  (let [targets (if (seq names) names (map name fetch/builtin-providers))
        failed  (count (filter r/err? (mapv #(fetch/fetch-provider! system %) targets)))]
    (when (pos? failed)
      (log/warn failed " provider(s) failed"))
    (min failed 255)))

(defn cmd-refresh
  "bash `refresh`: rebuild the endpoint sets, or install/remove the timer."
  [{:keys [system] :as ctx} args]
  (let [{:keys [op interval names]} (refresh-d/parse-command args)]
    (done ctx (case op
                :install (refresh/install-timer! system interval)
                :remove  (refresh/remove-timer! system)
                (refresh/refresh! system names)))))

(defn cmd-detect
  "bash `detect`."
  [{:keys [system]} _args]
  (let [ips (sort (:ok (detect/detect-endpoints (live system))))]
    (if (empty? ips)
      (do (log/warn "No active VPN endpoints detected. Connect VPN first.") 1)
      (do (log/info "Detected VPN endpoints: " (str/join " " ips)) 0))))

;; ---------------------------------------------------------------- recovery

(defn cmd-unlock [ctx _args]
  (done ctx (unlock/unlock! (:system ctx) {:dry-run? (dry-run? ctx)})))

(defn cmd-panic [ctx _args]
  (done ctx (panic/panic! (:system ctx) {:dry-run? (dry-run? ctx)})))

;; ---------------------------------------------------------------- tailscale

(defn cmd-tailscale-routes
  "bash `tailscale-routes [apply|install|remove]`."
  [{:keys [system] :as ctx} [sub]]
  (case (or sub "apply")
    ("apply" "_apply") (done ctx (tailscale/apply! system {}))
    "install"          (done ctx (tailscale/install! system {}))
    ("remove" "rm")    (done ctx (tailscale/remove! system {}))
    (usage-error ctx (str "tailscale-routes: unknown subcommand '" sub
                          "'. Try: apply|install|remove"))))

(defn cmd-tailscale-web
  "bash `tailscale-web [apply|remove]`."
  [{:keys [system] :as ctx} [sub]]
  (done ctx (tailscale-web/run! system (or sub "apply"))))

(defn cmd-nm-dispatch
  "NetworkManager hook entry (the hook execs `<self> nm-dispatch IF ACTION`).
   Always exits 0: a failing hook must not disturb NetworkManager."
  [{:keys [system]} [iface action]]
  (let [res (nm-dispatch/handle! system iface action)]
    (when (r/err? res)
      (log/warn "nm-dispatch " iface " " action ": " (reason res)))
    0))

;; ---------------------------------------------------------------- split

(defn cmd-split
  "bash `split add|rm|list|status|connect`. The workflows print their own
   reports; connect hands openvpn the terminal through the launcher."
  [{:keys [system] :as ctx} [sub name]]
  (let [sub   (or sub "list")
        named (fn [f]
                (if (str/blank? name)
                  (usage-error ctx (str "split " sub ": name required"))
                  (f)))]
    (case sub
      ("add" "install")
      (as-root ctx #(named (fn [] (done ctx (split/install! system name)))))

      ("rm" "remove" "del" "delete")
      (as-root ctx #(named (fn [] (done ctx (split/remove! system name)))))

      ("ls" "list")
      (done ctx (split/list-installed system))

      "status"
      (done ctx (split/status system name))

      ("connect" "up")
      (as-root ctx #(named (fn []
                             (let [plan (split/connect-plan system name)]
                               (if (r/err? plan)
                                 (fail ctx plan)
                                 (done ctx (exec/exec! system (-> plan :ok :argv) {})))))))

      (usage-error ctx (str "split: unknown subcommand '" sub
                            "'. Try: add|rm|list|status|connect")))))

;; ---------------------------------------------------------------- exclude

(defn- exclude-run [{:keys [system] :as ctx} args]
  (let [prep (exclude/prepare-run! system args)]
    (if (r/err? prep)
      (fail ctx prep)
      (let [{:keys [argv cgroup-procs]} (:ok prep)]
        (done ctx (exec/exec! system argv {:cgroup-procs cgroup-procs}))))))

(defn cmd-exclude
  "bash `exclude run|on|off|status`."
  [{:keys [system prog] :as ctx} [sub & more]]
  (case (or sub "status")
    ("run" "exec")
    (as-root ctx #(exclude-run ctx more))

    ("on" "enable" "add" "install")
    (as-root ctx #(let [res (exclude/enable! system)]
                    (if (r/ok? res)
                      (do (log/info (exclude-d/enabled-message prog)) 0)
                      (fail ctx res))))

    ("off" "disable" "rm" "remove" "del" "delete")
    (as-root ctx #(done ctx (exclude/disable! system)))

    ("status" "ls" "list" "show")
    (let [res (exclude/status system)]
      (if (r/ok? res)
        (do (print-lines (exclude-d/status-lines (:ok res))) 0)
        (fail ctx res)))

    "_apply"
    (as-root ctx #(done ctx (exclude/apply-routing! system)))

    "_teardown"
    (as-root ctx #(done ctx (exclude/teardown-routing! system)))

    (usage-error ctx (str "exclude: unknown subcommand '" sub "'. Try: run|on|off|status"))))

;; ---------------------------------------------------------------- test

(defn- report-tests
  "Print self-test results and the bash `summary`; exit 1 on any FAIL."
  [ctx res]
  (if (r/err? res)
    (fail ctx res)
    (let [{:keys [results passed failed reason]} (:ok res)]
      (print-lines (selftest-d/result-lines results))
      (if (= :declined reason)
        0
        (do (log/say "")
            (log/info (selftest-d/summary-line passed failed))
            (if (zero? failed) 0 1))))))

(defn cmd-test
  "bash `test [passive|active]`."
  [{:keys [system] :as ctx} [mode]]
  (case (or mode "passive")
    "passive" (report-tests ctx (selftest/passive system))
    "active"  (report-tests ctx (selftest/active system))
    (usage-error ctx "test mode must be 'passive' or 'active'")))

(defn cmd-help [ctx _args]
  (log/say (usage/text (:prog ctx)))
  0)

;; ---------------------------------------------------------------- dispatch

(def commands
  "Command word -> {:run handler :root? bool}: the arms of bash `main`.
   split and exclude check root per subcommand, as the bash does."
  {"help"             {:run cmd-help}
   "-h"               {:run cmd-help}
   "--help"           {:run cmd-help}
   "setup"            {:run cmd-setup :root? true}
   "auto"             {:run cmd-auto :root? true}
   "providers"        {:run cmd-providers :root? true}
   "fetch"            {:run cmd-fetch :root? true}
   "refresh"          {:run cmd-refresh :root? true}
   "detect"           {:run cmd-detect :root? true}
   "unlock"           {:run cmd-unlock :root? true}
   "panic"            {:run cmd-panic :root? true}
   "rescue"           {:run cmd-panic :root? true}
   "emergency"        {:run cmd-panic :root? true}
   "tailscale-routes" {:run cmd-tailscale-routes :root? true}
   "tailscale-web"    {:run cmd-tailscale-web :root? true}
   "test"             {:run cmd-test :root? true}
   "nm-dispatch"      {:run cmd-nm-dispatch :root? true}
   "split"            {:run cmd-split}
   "exclude"          {:run cmd-exclude}})

(defn dispatch
  "Run command `cmd` with `args` in context `ctx`; returns the exit code."
  [ctx cmd args]
  (if-let [{:keys [run root?]} (get commands cmd)]
    (if root?
      (as-root ctx #(run ctx args))
      (run ctx args))
    (do (log/say (usage/text (:prog ctx)))
        (log/error "Unknown command: " cmd)
        1)))

(defn run
  "argv + environment map -> exit code."
  [argv env]
  (let [{:keys [error cmd args opts]} (args/parse argv)]
    (if error
      (do (log/error error) 1)
      (dispatch (context opts env) cmd args))))

(defn -main [& argv]
  (let [code (try
               (run argv (into {} (System/getenv)))
               (catch Throwable t
                 (log/error "vpn-kis: " (or (ex-message t) (str t)))
                 70))]
    (flush)
    (System/exit code)))
