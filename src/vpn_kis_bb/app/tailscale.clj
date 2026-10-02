(ns vpn-kis-bb.app.tailscale
  "Tailnet bypass workflows (bash: apply_tailscale_route_rules,
   install_tailscale_route_rules + install_nm_dispatcher,
   remove_tailscale_route_rules).

     apply!    load the nft bypass (nothing happens when it is current),
               then retire the legacy `to X lookup 52` ip rules, exclude
               tailscaled from Mullvad, and run the tailscale-web helper
               when enabled and its nft table is missing. Safe to repeat
               (boot unit, NM hook, by hand).
     install!  tailscale-web marker, tailscaled drop-in, boot unit
               (restarted, which runs apply), NetworkManager hook.
     remove!   best-effort teardown of all of it except the NM hook.

   Tailnet traffic bypasses Mullvad by Mullvad's own marks, never by ip
   rule priority (see vpn-kis-bb.domain.tailscale).

   System keys: :shell :systemd :read-fn :write-fn :delete-fn :self-path
   :env, :settings (:vpn-interfaces :self-path). Every public fn returns a
   Result; progress goes to stderr through vpn-kis-bb.log."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.nm-dispatcher :as nm]
            [vpn-kis-bb.app.tailscale-web :as web]
            [vpn-kis-bb.domain.refresh :as refresh]
            [vpn-kis-bb.domain.rules :as rules]
            [vpn-kis-bb.domain.tailscale :as d]
            [vpn-kis-bb.log :as log]
            [vpn-kis-bb.ports.systemd :as sd-port]))

(def restart-timeout-ms
  "Budget for `systemctl restart` of the oneshot unit, which waits for
   apply (and possibly the tailscale-web helper) to finish."
  120000)

;; ---------------------------------------------------------------- helpers

(defn- attempt
  "Call thunk f; a throw becomes an error Result instead of escaping."
  [f]
  (try (f)
       (catch Throwable t
         (r/err :tailscale/threw {:hint (str "tailscale: " t)}))))

(defn- sh!
  "Run cmd. Returns {:cmd :exit :stdout :stderr}; a shell-level err (spawn
   failure, timeout) or a throw reads as exit -1."
  ([system cmd] (sh! system cmd {}))
  ([system cmd opts]
   (let [res (try (proto/shell-exec! (:shell system) cmd opts)
                  (catch Throwable t (r/err :shell/threw {:message (str t)})))]
     (if (r/ok? res)
       (let [{:keys [exit stdout stderr]} (:ok res)]
         {:cmd cmd :exit exit :stdout (or stdout "") :stderr (or stderr "")})
       {:cmd cmd :exit -1 :stdout "" :stderr (str (or (:message res) (:error res)))}))))

(def netmap-wait-s
  "How long apply waits, one probe a second, for tailscaled to get its
   netmap when it is running without one. The first nft load is what lets
   an excluded tailscaled reach its control plane (restore_ctmark), so the
   subnet routes only show up in table 52 after it."
  30)

(def sleep-cmd ["sleep" "1"])

(defn- ok-exit? [x] (= 0 (:exit x)))

(defn- has?
  "True when `program` is on the PATH (bash `command -v`)."
  [system program]
  (try (r/ok? (proto/shell-which (:shell system) program))
       (catch Throwable _ false)))

(defn- run-steps
  "Call each thunk in order, stopping at the first error Result."
  [thunks]
  (reduce (fn [_ f]
            (let [res (attempt f)]
              (if (r/err? res) (reduced res) res)))
          (r/ok nil)
          thunks))

(defn- self-path [system]
  (or (:self-path system) (get-in system [:settings :self-path])))

(defn- drain!
  "Run cmd until it fails, at most d/drain-limit times; the number of
   successful runs."
  [system cmd]
  (loop [n 0]
    (if (and (< n d/drain-limit) (ok-exit? (sh! system cmd)))
      (recur (inc n))
      n)))

(defn- delete-legacy-rules!
  "bash remove_tailscale_policy_rules: delete every `to X lookup 52` ip
   rule. Returns {:cidrs [...] :deleted n}."
  [system]
  (let [cidrs (d/legacy-rule-cidrs (:stdout (sh! system d/rule-show-cmd)))]
    {:cidrs   cidrs
     :deleted (reduce + 0 (map #(drain! system (d/rule-del-cmd %)) cidrs))}))

;; ---------------------------------------------------------------- apply

(defn- apply-nft!
  "bash apply_tailscale_nft. Result<{:status :applied|:current|:no-nft
   :dests [..] :dropped [..] :source ..}>; err when nft rejects the batch
   or the stored set cannot be written."
  [system]
  (if-not (has? system "nft")
    (do (log/warn "nft not found, Mullvad will capture tailnet traffic")
        (r/ok {:status :no-nft}))
    (let [stored ((:read-fn system) d/cidrs-file)
          {:keys [dests dropped source]}
          (d/destinations (:stdout (sh! system d/table-routes-cmd)) stored)
          live   (let [x (sh! system d/nft-list-cmd)] (if (ok-exit? x) (:stdout x) ""))
          info   {:dests dests :dropped dropped :source source}]
      (doseq [c dropped]
        (log/warn "Tailnet route " c " contains Mullvad's in-tunnel DNS ("
                  (str/join " " d/protected-ips) "), left out of the bypass"))
      (if (d/bypass-current? live stored dests)
        (r/ok (assoc info :status :current))
        (let [x (sh! system (d/nft-load-cmd (d/render-nft dests)))]
          (if-not (ok-exit? x)
            (r/err :tailscale/nft-failed
                   (assoc info
                          :hint (str "nft rejected the tailnet bypass (table inet " d/nft-table
                                     "): " (str/trim (:stderr x)))
                          :exit (:exit x)))
            (let [w ((:write-fn system) d/cidrs-file (d/cidrs-text dests))]
              (if (r/err? w)
                (r/err :tailscale/cidrs-write-failed
                       {:hint  (str "tailnet bypass loaded, but " d/cidrs-file
                                    " could not be written")
                        :cause w})
                (do (log/info "Tailnet bypasses Mullvad by mark (nft table inet " d/nft-table "): "
                              (str/join " " dests))
                    (r/ok (assoc info :status :applied)))))))))))

(defn- retire-legacy-rules!
  "Remove the priority rules older versions installed, once the marks are
   live. The number of rules deleted."
  [system]
  (let [{:keys [cidrs deleted]} (delete-legacy-rules! system)]
    (when (seq cidrs)
      (log/info "Removed legacy Tailscale ip rules (replaced by the mark-based bypass)"))
    deleted))

(defn- exclude-tailscaled!
  "bash exclude_tailscaled_from_mullvad: add tailscaled's MainPID to
   Mullvad's split tunnel unless it is listed. Never fails; returns
   {:status :no-mullvad|:not-running|:listed|:excluded|:failed :pid ..}."
  [system]
  (if-not (has? system "mullvad")
    {:status :no-mullvad}
    (let [pid (d/main-pid (:stdout (sh! system d/main-pid-cmd)))]
      (cond
        (nil? pid)
        {:status :not-running}

        (d/pid-listed? (:stdout (sh! system d/split-list-cmd)) pid)
        {:status :listed :pid pid}

        (ok-exit? (sh! system (d/split-add-cmd pid)))
        (do (log/info "tailscaled (pid " pid ") excluded from Mullvad")
            {:status :excluded :pid pid})

        :else
        (do (log/warn "Could not exclude tailscaled (pid " pid
                      ") from Mullvad, Tailscale login will fail")
            {:status :failed :pid pid})))))

(defn- await-netmap!
  "When tailscaled runs but table 52 has no netmap yet, probe once a second
   for up to `seconds`. Returns :loaded (it arrived while waiting),
   :timeout, or :skipped (nothing to wait for)."
  [system ts seconds]
  (let [loaded? #(d/netmap-loaded? (:stdout (sh! system d/table-routes-cmd)))]
    (if (or (nil? (:pid ts)) (not (pos? seconds)) (loaded?))
      :skipped
      (do (log/info "Waiting up to " seconds "s for tailscaled to log in...")
          (loop [left seconds]
            (cond
              (not (pos? left)) (do (log/warn "tailscaled has no netmap yet; rerun"
                                              " tailscale-routes apply once it is logged in")
                                    :timeout)
              (do (sh! system sleep-cmd) (loaded?)) :loaded
              :else (recur (dec left))))))))

(defn- web-if-enabled!
  "Run the tailscale-web helper when its marker exists and its nft table
   is missing. Never fails; returns {:status :disabled|:present|:applied|:failed}."
  [system]
  (cond
    (nil? ((:read-fn system) d/web-enabled-file))
    {:status :disabled}

    (ok-exit? (sh! system d/openclaw-list-cmd))
    {:status :present}

    :else
    (let [res (web/run! system "apply")]
      (if (r/ok? res)
        {:status :applied}
        (do (log/warn (:hint res))
            (log/warn "OpenClaw client check failed; inspect output and rerun"
                      " tailscale-routes apply when Tailscale is ready.")
            {:status :failed :error (:error res)})))))

(defn apply!
  "Bring the tailnet bypass up to date (bash apply_tailscale_route_rules).
   Changes nothing when the live table carries the current tag and set.
   Legacy `to X lookup 52` rules are removed only once the marks are live
   (applied or current). When tailscaled is running without a netmap, waits
   for it (opts :netmap-wait-s, default netmap-wait-s, 0 to skip) and loads
   the set again with the routes that arrived; :nft is then that second
   load and :netmap says how the wait ended.

   Result<{:nft {:status :applied|:current|:no-nft :dests [..] :dropped [..]
                 :source :table|:stored}
           :legacy-rules-removed n
           :tailscaled {:status .. :pid ..}
           :netmap :skipped|:loaded|:timeout
           :web {:status ..}}>;
   err :tailscale/nft-failed or :tailscale/cidrs-write-failed (the rest is
   then skipped)."
  [system opts]
  (attempt
   (fn []
     (let [nft (apply-nft! system)]
       (if (r/err? nft)
         nft
         (let [live?   (contains? #{:applied :current} (-> nft :ok :status))
               retired (if live? (retire-legacy-rules! system) 0)
               ts      (exclude-tailscaled! system)
               netmap  (if live?
                         (await-netmap! system ts (or (:netmap-wait-s opts) netmap-wait-s))
                         :skipped)
               nft     (if (= :loaded netmap) (apply-nft! system) nft)]
           (if (r/err? nft)
             nft
             (r/ok {:nft                  (:ok nft)
                    :legacy-rules-removed retired
                    :tailscaled           ts
                    :netmap               netmap
                    :web                  (web-if-enabled! system)}))))))))

;; ---------------------------------------------------------------- install

(defn- sync-web-marker!
  "The tailscale-web step of install_tailscale_route_rules: touch the
   marker when providers.active names mullvad and tailscale, else remove
   tailscale-web when the marker exists."
  [system]
  (cond
    (d/web-profile? ((:read-fn system) refresh/active-file))
    (let [w ((:write-fn system) d/web-enabled-file "")]
      (if (r/err? w) w (r/ok :enabled)))

    (some? ((:read-fn system) d/web-enabled-file))
    (do (web/run! system "remove")
        (r/ok :removed))

    :else (r/ok :disabled)))

(defn- install-dropin!
  "bash install_tailscaled_dropin (only when mullvad is installed)."
  [system]
  (if-not (has? system "mullvad")
    (r/ok :no-mullvad)
    (let [w ((:write-fn system) d/dropin-path d/dropin-text)]
      (if (r/err? w)
        w
        (let [dr (sd-port/-daemon-reload! (:systemd system))]
          (if (r/err? dr)
            (r/err :tailscale/daemon-reload-failed
                   {:hint "systemctl daemon-reload failed" :cause dr})
            (do (log/info "tailscaled drop-in installed: " d/dropin-path)
                (r/ok d/dropin-path))))))))

(defn- restart-unit!
  [system]
  (let [x (sh! system d/unit-restart-cmd {:timeout-ms restart-timeout-ms})]
    (if (ok-exit? x)
      (r/ok nil)
      (r/err :tailscale/unit-restart-failed
             {:hint   (str "systemctl restart " d/unit-name " failed (see: journalctl -u "
                           d/unit-name ")")
              :exit   (:exit x)
              :stderr (str/trim (:stderr x))}))))

(defn- install-unit!
  "Write, enable (failure ignored) and restart the boot unit."
  [system self]
  (let [sd  (:systemd system)
        res (run-steps
             [#(sd-port/-write! sd d/unit-name (d/unit-text self))
              #(sd-port/-daemon-reload! sd)
              #(do (sd-port/-enable! sd d/unit-name) (r/ok nil))
              #(restart-unit! system)])]
    (if (r/err? res)
      res
      (do (log/info "Boot-persisted via " d/unit-path)
          (r/ok d/unit-path)))))

(defn- install-routes!
  "bash install_tailscale_route_rules once the profile includes tailscale."
  [system]
  (let [self (self-path system)]
    (if (str/blank? self)
      (r/err :tailscale/no-self-path
             {:hint "system has no :self-path: the command the boot unit runs"})
      (let [web (attempt #(sync-web-marker! system))]
        (if (r/err? web)
          web
          (let [dropin (attempt #(install-dropin! system))]
            (if (r/err? dropin)
              dropin
              (let [unit (attempt #(install-unit! system self))]
                (if (r/err? unit)
                  unit
                  (r/ok {:web    (:ok web)
                         :dropin (:ok dropin)
                         :unit   (:ok unit)}))))))))))

(defn install!
  "Install the tailnet bypass and the NetworkManager hook (bash
   `tailscale-routes install`: install_tailscale_route_rules, then
   install_nm_dispatcher). The routes part is skipped when the VPN
   interface list does not mention tailscale; the hook is always
   installed unless opts :nm-dispatcher? is false.

   opts: {:vpn-interfaces [..]  overrides (:settings :vpn-interfaces)
          :nm-dispatcher? bool  default true}

   Result<{:routes {:web :enabled|:removed|:disabled
                    :dropin path|:no-mullvad
                    :unit path}
                   | {:skipped :no-tailscale-interface}
           :nm-dispatcher <adapters.nm-dispatcher/install! value>
                          | {:skipped :by-option}}>;
   the first failing step's err otherwise."
  [system opts]
  (let [ifaces (or (:vpn-interfaces opts)
                   (get-in system [:settings :vpn-interfaces])
                   rules/default-vpn-interfaces)
        routes (if (d/tailscale-profile? ifaces)
                 (install-routes! system)
                 (r/ok {:skipped :no-tailscale-interface}))]
    (if (r/err? routes)
      routes
      (let [hook (if (false? (:nm-dispatcher? opts))
                   (r/ok {:skipped :by-option})
                   (attempt #(nm/install! system)))]
        (if (r/err? hook)
          hook
          (r/ok {:routes (:ok routes) :nm-dispatcher (:ok hook)}))))))

;; ---------------------------------------------------------------- remove

(defn- remove-unit!
  "Disable --now, delete and daemon-reload the boot unit when its file
   exists. True when it existed."
  [system]
  (let [sd (:systemd system)]
    (if (nil? ((:read-fn system) d/unit-path))
      false
      (do (sd-port/-disable! sd d/unit-name)
          (sd-port/-remove! sd d/unit-name)
          (sd-port/-daemon-reload! sd)
          true))))

(defn- remove-nft!
  "Delete the nft table (when nft exists). True when a table was deleted."
  [system]
  (and (has? system "nft")
       (ok-exit? (sh! system d/nft-delete-cmd))))

(defn- remove-dropin!
  "bash remove_tailscaled_dropin. True when the drop-in existed."
  [system]
  (if (nil? ((:read-fn system) d/dropin-path))
    false
    (do ((:delete-fn system) d/dropin-path)
        (sh! system d/dropin-rmdir-cmd)
        (sd-port/-daemon-reload! (:systemd system))
        true)))

(defn remove!
  "Tear the tailnet bypass down (bash remove_tailscale_route_rules):
   tailscale-web (marker + helper remove), boot unit, legacy ip rules, nft
   table, stored set, tailscaled drop-in. The NM hook stays. Every step is
   best-effort; a throwing step is reported under :failures.
   opts: currently unused.

   Result<{:web .. :unit-removed? bool :legacy-rules-removed n
           :nft-removed? bool :cidrs-removed? bool :dropin-removed? bool
           :failures [err ..]}>."
  [system _opts]
  (let [steps    [[:web                  #(r/ok (:ok (web/run! system "remove")))]
                  [:unit-removed?        #(r/ok (remove-unit! system))]
                  [:legacy-rules-removed #(r/ok (:deleted (delete-legacy-rules! system)))]
                  [:nft-removed?         #(r/ok (remove-nft! system))]
                  [:cidrs-removed?       #(r/ok (r/ok? ((:delete-fn system) d/cidrs-file)))]
                  [:dropin-removed?      #(r/ok (remove-dropin! system))]]
        results  (mapv (fn [[k f]] [k (attempt f)]) steps)
        failures (into [] (keep (fn [[k res]] (when (r/err? res) (assoc res :step k)))) results)]
    (r/ok (into {:failures failures}
                (keep (fn [[k res]] (when (r/ok? res) [k (:ok res)])))
                results))))
