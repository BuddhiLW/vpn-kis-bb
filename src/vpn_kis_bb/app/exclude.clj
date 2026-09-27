(ns vpn-kis-bb.app.exclude
  "Workflows for the cgroup-based VPN exclusion (bash: exclude_enable,
   exclude_disable, exclude_apply_routing, exclude_teardown_routing,
   exclude_sync_before_rules, exclude_status, exclude_remove_all, and
   exclude_run up to, not including, its exec).

   Every public fn takes the `system` map and returns a hive-dsl Result,
   except `enabled?` (boolean). Keys used: :shell (IShell), :systemd
   (ISystemdUnit), :read-fn, :write-fn, :delete-fn, :self-path, and
   :settings (:physical-iface :prog :self-path). Errors carry :message.

   Command failures follow the bash script under `set -e`: `|| true`
   steps are ignored, `|| warn` steps log and continue, any other failure
   stops the workflow with an err. Root is not checked here.

   Known limitation (Mullvad 2026.x reorders its catch-all ip rule on
   every reconnect): see vpn-kis-bb.domain.exclude."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.domain.exclude :as d]
            [vpn-kis-bb.log :as log]
            [vpn-kis-bb.ports.systemd :as sd-port]))

;; ---------------------------------------------------------------- helpers

(defn- sh!
  "Run cmd. Returns {:cmd :exit :stdout :stderr}; a shell-level err
   (spawn failure, timeout) reads as exit -1."
  [system cmd]
  (let [res (proto/shell-exec! (:shell system) cmd {})]
    (if (r/ok? res)
      (let [{:keys [exit stdout stderr]} (:ok res)]
        {:cmd cmd :exit exit :stdout (or stdout "") :stderr (or stderr "")})
      {:cmd cmd :exit -1 :stdout "" :stderr (str (:error res))})))

(defn- ok-exit? [x] (= 0 (:exit x)))

(defn- prog [system]
  (or (:prog (:settings system)) d/default-prog))

(defn- self-path [system]
  (or (:self-path system) (:self-path (:settings system)) d/default-prog))

(defn- read-rules [system]
  ((:read-fn system) d/before-rules-path))

(defn- detect-phys
  "First non-virtual default-route interface from `ip -4 route ls`."
  [system]
  (d/default-route-iface (:stdout (sh! system d/default-routes-cmd))))

(defn- resolve-phys
  "Physical IF: the before.rules DROP pin, else settings :physical-iface,
   else detected from the default routes. nil when all three fail."
  [system rules-text]
  (or (d/pinned-phys rules-text)
      (:physical-iface (:settings system))
      (detect-phys system)))

(defn- no-phys-err []
  (r/err :exclude/no-physical-iface
         {:message "exclude: cannot determine the physical interface (set PHYSICAL_IF)"}))

;; ---------------------------------------------------------------- step interpreter

(defn- failed [x]
  (r/err :exclude/command-failed
         {:message (str "exclude: command failed (exit " (:exit x) "): "
                        (str/join " " (:cmd x)))
          :cmd     (:cmd x)
          :exit    (:exit x)
          :stderr  (str/trim (:stderr x))}))

(defn- drain!
  "Run cmd until it fails, at most d/drain-limit times. Returns the number
   of successful runs."
  [system cmd]
  (loop [n 0]
    (cond
      (>= n d/drain-limit)
      (do (log/warn "exclude: '" (str/join " " cmd) "' still succeeding after "
                    n " runs, stopped")
          n)

      (ok-exit? (sh! system cmd)) (recur (inc n))
      :else n)))

(defn- run-step!
  "Interpret one domain step. Returns Result<{:deleted n}|{:warning s}|{}>."
  [system {:keys [op cmd check on-fail warning]}]
  (case op
    :drain  (r/ok {:deleted (drain! system cmd)})
    :ensure (if (ok-exit? (sh! system check))
              (r/ok {})
              (let [x (sh! system cmd)]
                (if (ok-exit? x) (r/ok {}) (failed x))))
    :run    (let [x (sh! system cmd)]
              (cond
                (ok-exit? x)        (r/ok {})
                (= :ignore on-fail) (r/ok {})
                (= :warn on-fail)   (do (log/warn warning) (r/ok {:warning warning}))
                :else               (failed x)))))

(defn- run-steps!
  "Interpret a plan in order, stopping at the first failing :abort step.
   Returns Result<{:rules-deleted n :warnings [...]}>."
  [system steps]
  (reduce (fn [acc step]
            (let [res (run-step! system step)]
              (if (r/err? res)
                (reduced res)
                (let [{:keys [deleted warning]} (:ok res)]
                  (r/ok (cond-> (:ok acc)
                          deleted (update :rules-deleted + deleted)
                          warning (update :warnings conj warning)))))))
          (r/ok {:rules-deleted 0 :warnings []})
          steps))

;; ---------------------------------------------------------------- state

(defn enabled?
  "True when the exclude unit file exists (the persistent 'enabled' marker)."
  [system]
  (some? ((:read-fn system) d/unit-path)))

(defn- ensure-cgroup!
  "cgroup v2 check, then `mkdir -p` of the exclude cgroup."
  [system]
  (if (nil? ((:read-fn system) d/cgroup-controllers))
    (do (log/warn "exclude: /sys/fs/cgroup is not cgroup v2, cgroup exclusion unavailable")
        (r/err :exclude/no-cgroup-v2
               {:message "exclude: /sys/fs/cgroup is not cgroup v2, cgroup exclusion unavailable"}))
    (let [x (sh! system d/mkdir-cgroup-cmd)]
      (if (ok-exit? x)
        (r/ok {:cgroup d/cgroup})
        (do (log/warn "exclude: cannot create cgroup " d/cgroup)
            (r/err :exclude/cgroup-create-failed
                   {:message (str "exclude: cannot create cgroup " d/cgroup)
                    :stderr  (str/trim (:stderr x))}))))))

;; ---------------------------------------------------------------- routing

(defn- apply-routing*
  "exclude_apply_routing without the enabled? gate."
  [system]
  (let [cg (ensure-cgroup! system)]
    (if (r/err? cg)
      cg
      (let [phys (resolve-phys system (read-rules system))
            gw   (when phys
                   (d/parse-gateway (:stdout (sh! system (d/gateway-query-cmd phys)))))]
        (cond
          (nil? phys)
          (do (log/warn "exclude: cannot determine the physical interface, routing not applied")
              (no-phys-err))

          (nil? gw)
          (do (log/warn "exclude: cannot determine physical gateway on " phys
                        ", routing not applied")
              (r/err :exclude/no-gateway
                     {:message (str "exclude: cannot determine physical gateway on " phys)
                      :phys    phys}))

          :else
          (let [res (run-steps! system (d/apply-steps phys gw))]
            (if (r/err? res)
              res
              (do (log/info "exclude: active (cgroup " d/cgroup-rel " -> " phys " via " gw
                            ", mark " d/mark " table " d/table ", SNAT -> " phys ")")
                  (r/ok (assoc (:ok res) :applied? true :phys phys :gateway gw))))))))))

(defn teardown-routing!
  "Remove the ip rule, table 151 routes and both chains. Best-effort:
   always ok. Result<{:rules-deleted n ...}>."
  [system]
  (let [res (run-steps! system d/teardown-steps)]
    (if (r/err? res) res (r/ok (assoc (:ok res) :torn-down? true)))))

(defn apply-routing!
  "Mark + policy routing + SNAT for the exclude cgroup; idempotent (chains
   flushed and rebuilt). When exclusion is not enabled, tears routing down
   instead. Result<{:applied? bool ...}>."
  [system]
  (if (enabled? system)
    (apply-routing* system)
    (let [td (teardown-routing! system)]
      (if (r/err? td) td (r/ok (assoc (:ok td) :applied? false))))))

;; ---------------------------------------------------------------- before.rules

(defn- sync-before-rules*
  "exclude_sync_before_rules with the enabled state given as on?."
  [system on?]
  (let [text (read-rules system)]
    (if (nil? text)
      (r/err :exclude/no-before-rules
             {:message (str "no " d/before-rules-path ": install the killswitch first (sudo "
                            (prog system) " setup ...)")
              :path    d/before-rules-path})
      (let [phys (resolve-phys system text)]
        (if (and on? (nil? phys))
          (no-phys-err)
          (let [block    (when on? (d/before-rules-block phys))
                new-text (d/rewrite-before-rules text phys block)
                accept?  (boolean (and on? (str/includes? new-text (d/accept-rule phys))))
                _        (when (and on? (not accept?))
                           (log/warn "exclude: no '" (d/drop-rule phys) "' line in "
                                     d/before-rules-path ", mark ACCEPT not inserted"))
                w        ((:write-fn system) d/before-rules-path new-text)]
            (if (r/err? w)
              w
              (let [reloaded? (ok-exit? (sh! system d/ufw-reload-cmd))]
                (when-not reloaded?
                  (log/warn "ufw reload failed, check 'ufw status'"))
                (r/ok {:path      d/before-rules-path
                       :phys      phys
                       :accept?   accept?
                       :changed?  (not= text new-text)
                       :reloaded? reloaded?})))))))))

(defn sync-before-rules!
  "Rewrite /etc/ufw/before.rules so it holds the mark ACCEPT block exactly
   when exclusion is enabled (before the physical-IF DROP), write it via
   :write-fn, then `ufw reload` (a failed reload only warns)."
  [system]
  (sync-before-rules* system (enabled? system)))

;; ---------------------------------------------------------------- unit

(defn- install-unit! [system]
  (let [sd (:systemd system)
        w  (sd-port/-write! sd d/unit-name (d/unit-text (self-path system)))]
    (if (r/err? w)
      w
      (let [dr (sd-port/-daemon-reload! sd)]
        (if (r/err? dr)
          (r/err :exclude/daemon-reload-failed
                 {:message "exclude: systemctl daemon-reload failed" :cause dr})
          (do (sd-port/-enable! sd d/unit-name)
              (r/ok {:unit d/unit-path})))))))

(defn- remove-unit!
  "systemctl disable --now (ignored), delete the unit file, daemon-reload
   (ignored)."
  [system]
  (let [sd (:systemd system)]
    (sd-port/-disable! sd d/unit-name)
    (let [rm (sd-port/-remove! sd d/unit-name)]
      (if (r/err? rm)
        rm
        (do (sd-port/-daemon-reload! sd)
            (r/ok {:unit d/unit-path}))))))

;; ---------------------------------------------------------------- enable / disable

(defn enable!
  "Persistent exclusion: drop the legacy users file, ensure the cgroup,
   install + enable the unit, apply routing, sync before.rules.
   Idempotent. Result<{:enabled? true :routing .. :before-rules ..}>."
  [system]
  ((:delete-fn system) d/legacy-users-file)
  (let [cg (ensure-cgroup! system)]
    (if (r/err? cg)
      (r/err :exclude/cgroup-unavailable
             {:message "exclude: cgroup v2 unavailable, cannot enable" :cause cg})
      (let [u (install-unit! system)]
        (if (r/err? u)
          u
          (let [ap (apply-routing* system)]
            (if (r/err? ap)
              ap
              (let [sy (sync-before-rules* system true)]
                (if (r/err? sy)
                  sy
                  (r/ok {:enabled?     true
                         :unit         d/unit-path
                         :routing      (:ok ap)
                         :before-rules (:ok sy)}))))))))))

(defn disable!
  "Remove the unit (clearing the enabled marker), tear routing down,
   rmdir the cgroup, strip the before.rules ACCEPT.
   Result<{:enabled? false ...}>."
  [system]
  (let [u (remove-unit! system)]
    (if (r/err? u)
      u
      (let [td (teardown-routing! system)
            rm (sh! system d/rmdir-cgroup-cmd)
            sy (sync-before-rules* system false)]
        (if (r/err? sy)
          sy
          (do (log/info "exclude: disabled (routing, unit, cgroup and before.rules ACCEPT removed).")
              (r/ok {:enabled?        false
                     :routing         (:ok td)
                     :cgroup-removed? (ok-exit? rm)
                     :before-rules    (:ok sy)})))))))

(defn remove-all!
  "Full best-effort teardown for unlock/panic: legacy users file, routing,
   unit, cgroup. Never fails; before.rules is left alone.
   Result<{:routing .. :unit-removed? bool :cgroup-removed? bool ...}>."
  [system]
  (let [legacy ((:delete-fn system) d/legacy-users-file)
        td     (teardown-routing! system)
        unit   (remove-unit! system)
        rm     (sh! system d/rmdir-cgroup-cmd)]
    (r/ok {:legacy-removed? (r/ok? legacy)
           :routing         (:ok td)
           :unit-removed?   (r/ok? unit)
           :cgroup-removed? (ok-exit? rm)})))

;; ---------------------------------------------------------------- status

(defn status
  "Live exclusion state. Disabled: Result<{:enabled? false :prog ..}>.
   Enabled: also :phys :members (PIDs, nil when the cgroup is absent)
   :ip-rules :routes :mangle :nat :before-rules-accept (line vectors) and
   :unit-active. Render with vpn-kis-bb.domain.exclude/status-lines."
  [system]
  (if-not (enabled? system)
    (r/ok {:enabled? false :prog (prog system)})
    (let [lines    (fn [cmd] (d/nonblank-lines (:stdout (sh! system cmd))))
          rules    (read-rules system)
          phys     (resolve-phys system rules)
          procs    ((:read-fn system) d/cgroup-procs)
          ip-rules (lines d/rule-show-cmd)
          routes   (lines d/table-show-cmd)
          mangle   (lines (d/chain-list-cmd "mangle" d/mangle-chain))
          nat      (lines (d/chain-list-cmd "nat" d/nat-chain))
          active   (sh! system d/unit-active-cmd)
          state    (str/trim (:stdout active))]
      (r/ok {:enabled?            true
             :prog                (prog system)
             :phys                phys
             :cgroup              d/cgroup
             :mark                d/mark
             :table               d/table
             :priority            d/priority
             :members             (when procs (d/nonblank-lines procs))
             :ip-rules            ip-rules
             :routes              routes
             :mangle              mangle
             :nat                 nat
             :before-rules-accept (d/mark-lines rules)
             :unit-active         (if (str/blank? state) (str/trim (:stderr active)) state)}))))

;; ---------------------------------------------------------------- run

(defn prepare-run!
  "Everything `exclude run` does before its exec: parse args (bash
   grammar), check the --as user and `runuser`, enable on first use,
   re-apply routing, and re-sync before.rules when an already-enabled
   install lacks the mark ACCEPT. Never execs.
   Result<{:argv [...] :cgroup-procs path :user u-or-nil}>, argv already
   wrapped in `runuser -u USER --` for --as; hand it to
   vpn-kis-bb.adapters.exec/exec! with {:cgroup-procs ..}."
  [system args]
  (let [user-exists? (fn [u] (ok-exit? (sh! system (d/user-check-cmd u))))
        parsed       (d/parse-run-args args user-exists? (prog system))]
    (cond
      (:error parsed)
      (r/err :exclude/usage {:message (:error parsed)})

      (and (:user parsed) (r/err? (proto/shell-which (:shell system) "runuser")))
      (r/err :exclude/no-runuser
             {:message "exclude run: 'runuser' (util-linux) needed for --as"})

      :else
      (let [was-on? (enabled? system)
            en      (if was-on?
                      (r/ok nil)
                      (do (log/info "exclude: enabling on first use...")
                          (enable! system)))]
        (if (r/err? en)
          en
          (let [ap (apply-routing* system)]
            (if (r/err? ap)
              (r/err :exclude/apply-failed
                     {:message "exclude run: could not apply exclusion rules" :cause ap})
              (let [heal (if (and was-on? (not (d/accept-present? (read-rules system))))
                           (sync-before-rules* system true)
                           (r/ok nil))]
                (if (r/err? heal)
                  heal
                  (r/ok {:argv         (d/run-argv parsed)
                         :cgroup-procs d/cgroup-procs
                         :user         (:user parsed)}))))))))))
