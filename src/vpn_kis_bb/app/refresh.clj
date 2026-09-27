(ns vpn-kis-bb.app.refresh
  "Endpoint auto-refresh workflows (bash: refresh_endpoints,
   install_refresh_timer, remove_refresh_timer).

     refresh!        re-fetch provider lists and atomically rebuild the
                     vpn_endpoints ipset (provider IPs only) and the
                     vpn_dns_bootstrap ipset WITHOUT touching UFW rules.
                     Each new set is built aside and swapped in with one
                     kernel op, so the killswitch never has an empty
                     whitelist. Safe to run from the timer while connected.
     install-timer!  systemd service + timer running `<self> refresh`.
     remove-timer!   best-effort teardown of both units.

   System keys consumed:
     :shell          IShell (ipset, systemctl enable --now)
     :read-fn        (fn [path] -> string | nil)
     :write-fn       (fn [path body] -> Result)
     :fetchers       {provider-kw IProviderFetcher}
     :settings       {:dns-bootstrap [ip ...] :prog \"vpn-kis\" :self-path ..}
     :self-path      command the service unit invokes
     :systemd        ISystemdUnit
     :providers-dir  optional: .ips cache dir (default app.fetch/providers-dir)

   Every function returns a Result. Progress goes to stderr through
   vpn-kis-bb.log, as in the bash original."
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.app.fetch :as fetch]
            [vpn-kis-bb.app.providers :as providers]
            [vpn-kis-bb.domain.refresh :as refresh]
            [vpn-kis-bb.log :as log]
            [vpn-kis-bb.ports.systemd :as sd-port]))

;; ---------------------------------------------------------------------------
;; helpers

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
         (r/err :refresh/threw {:cause (str t)}))))

(defn- brief
  "cmd with long words (an inline restore payload) cut, for error data."
  [cmd]
  (mapv #(if (> (count %) 160) (str (subs % 0 160) "...") %) cmd))

(defn- exec!
  "Run argv through the shell. A non-zero exit (or a shell that throws)
   becomes :refresh/command-failed."
  [shell cmd]
  (let [resp (attempt #(proto/shell-exec! shell cmd {}))]
    (cond
      (r/err? resp)
      (r/err :refresh/command-failed {:cmd (brief cmd) :cause resp})

      (= 0 (-> resp :ok :exit))
      resp

      :else
      (r/err :refresh/command-failed {:cmd    (brief cmd)
                                      :exit   (-> resp :ok :exit)
                                      :stderr (-> resp :ok :stderr)}))))

(defn- run-steps
  "Call each thunk in order, stopping at the first error Result."
  [thunks]
  (reduce (fn [_ f]
            (let [res (attempt f)]
              (if (r/err? res) (reduced res) res)))
          (r/ok nil)
          thunks))

;; ---------------------------------------------------------------------------
;; refresh

(defn- read-active
  "Result<[name ...]> from the active file."
  [system]
  (let [text ((:read-fn system) refresh/active-file)
        names (refresh/parse-active text)]
    (cond
      (nil? text)
      (r/err :refresh/no-active
             {:path refresh/active-file
              :hint (str "refresh: no providers given and " refresh/active-file
                         " missing. Run '" (prog system)
                         " refresh <names>' once to seed it.")})

      (empty? names)
      (r/err :refresh/empty-list
             {:path refresh/active-file
              :hint "refresh: empty provider list"})

      :else (r/ok names))))

(defn- resolve-names
  "Explicit names become the new active set (the timer picks them up);
   no names means: read the active file."
  [system names]
  (let [given (refresh/normalize-names names)]
    (if (empty? given)
      (read-active system)
      (let [w ((:write-fn system) refresh/active-file (refresh/active-text given))]
        (if (r/err? w) w (r/ok given))))))

(defn- fetch-provider!
  "bash fetch_provider, as the refresh loop uses it: never aborts.
   Returns :fetched, :failed (cached list kept), :static (no fetcher, a
   hand-made .ips exists) or :unknown (no fetcher, no list)."
  [system pname]
  (if (contains? (:fetchers system) (keyword pname))
    (do (log/info "Fetching " pname " server IPs...")
        (let [res (attempt #(fetch/fetch-one! system (keyword pname)))]
          (if (r/ok? res)
            (do (log/info "Wrote " (-> res :ok :count) " IPs to " (-> res :ok :path))
                :fetched)
            (do (log/warn "refresh: fetch failed for " pname
                          ", keeping cached list (" (:error res) ")")
                :failed))))
    (let [path (ips-path system pname)]
      (if (fs/exists? path)
        (do (log/warn pname ": no fetcher, keeping static " path)
            :static)
        (do (log/warn "refresh: unknown provider '" pname "' (known: "
                      (str/join " " (sort (map name (keys (:fetchers system)))))
                      ") and no cached list. Custom: drop IPs into " path
                      ". Skipping it.")
            :unknown)))))

(defn- live-count
  "Entries in the live set per `ipset list`, else `fallback`."
  [shell fallback]
  (let [res (exec! shell (refresh/list-command))]
    (or (when (r/ok? res) (refresh/entry-count (-> res :ok :stdout)))
        fallback)))

(defn- swap-in!
  "Rebuild the live endpoint set from `union` (provider IPs only) and the
   DNS bootstrap set from settings :dns-bootstrap, each atomically, then
   persist both for boot."
  [system names fetched union]
  (let [shell (:shell system)
        dns   (get-in system [:settings :dns-bootstrap])
        plan  (attempt #(let [ips     (refresh/valid-ips union)
                              dns-ips (refresh/valid-ips dns)]
                          (r/ok {:ips     ips
                                 :dns-ips dns-ips
                                 :cmds    (refresh/swap-commands ips {:dns-ips dns-ips})})))]
    (if (r/err? plan)
      plan
      (let [{:keys [ips dns-ips cmds]} (:ok plan)
            res (run-steps (map (fn [cmd] #(exec! shell cmd)) cmds))]
        (if (r/err? res)
          res
          (let [n (live-count shell (count ips))]
            (log/info "refresh: " refresh/set-name " now has " n
                      " IPs (providers: " (str/join " " names) ")")
            (r/ok {:providers     names
                   :count         n
                   :fetch         fetched
                   :dns-bootstrap (vec dns-ips)})))))))

(defn refresh!
  "Re-fetch provider IP lists and atomically rebuild the vpn_endpoints
   ipset from them, and the vpn_dns_bootstrap ipset from settings
   :dns-bootstrap. UFW rules are not touched.

   names: provider names (strings or keywords). Given, they become the new
   active set; empty, the active file supplies them.

   A failed fetch keeps that provider's cached list; a name with no
   fetcher keeps its hand-made .ips (or is skipped with a warning). The
   swaps only run when the providers' union holds at least one IPv4, so a
   typo or a wiped cache can never empty the whitelist: both live sets
   are left untouched instead.

   Result<{:providers [name ...] :count N :fetch {name status}
           :dns-bootstrap [ip ...]}>."
  [system names]
  (let [names-r (resolve-names system names)]
    (if (r/err? names-r)
      names-r
      (let [names   (:ok names-r)
            fetched (into {} (map (fn [n] [n (fetch-provider! system n)])) names)
            union-r (attempt #(providers/load-union names {:dir (providers-dir system)}))]
        (if (r/err? union-r)
          union-r
          (let [{:keys [union missing]} (:ok union-r)]
            (doseq [n missing
                    :when (not= :unknown (get fetched n))]
              (log/warn "No cached list for '" n "' (" (ips-path system n)
                        "). Run: " (prog system) " fetch " n))
            (if (empty? union)
              (r/err :refresh/no-ips
                     {:providers names
                      :missing   missing
                      :hint      (str "refresh: no provider IPs to load, aborting"
                                      " (current ipset left untouched)")})
              (swap-in! system names fetched union))))))))

;; ---------------------------------------------------------------------------
;; timer

(defn- self-path [system]
  (or (:self-path system) (get-in system [:settings :self-path])))

(defn install-timer!
  "Write the refresh service + timer, daemon-reload, then
   `systemctl enable --now` the timer. interval: systemd time span, nil or
   blank -> 15min. Warns when the active file does not exist yet (the timer
   would fail until it does).

   Result<{:timer .. :service .. :interval .. :self-path ..}>."
  [system interval]
  (let [interval (if (str/blank? interval) refresh/default-interval (str/trim interval))
        self     (self-path system)
        sd       (:systemd system)]
    (cond
      (not (refresh/valid-interval? interval))
      (r/err :refresh/bad-interval
             {:interval interval
              :hint     "interval must be a systemd time span such as 15min or 1h"})

      (str/blank? self)
      (r/err :refresh/no-self-path
             {:hint "system has no :self-path: the command the service unit runs"})

      :else
      (do
        (when-not ((:read-fn system) refresh/active-file)
          (log/warn "No " refresh/active-file " yet: timer will fail until you run '"
                    (prog system) " providers <names>' (or 'refresh <names>') once."))
        (let [res (run-steps
                   [#(sd-port/-write! sd refresh/service-name (refresh/service-unit-text self))
                    #(sd-port/-write! sd refresh/timer-name (refresh/timer-unit-text interval))
                    #(sd-port/-daemon-reload! sd)
                    #(exec! (:shell system) ["systemctl" "enable" "--now" refresh/timer-name])])]
          (if (r/err? res)
            res
            (do (log/info "Refresh timer active: every " interval " (" refresh/timer-name ")")
                (log/info "Provider list read from " refresh/active-file
                          " (set by 'providers <names>').")
                (r/ok {:timer     refresh/timer-name
                       :service   refresh/service-name
                       :interval  interval
                       :self-path self}))))))))

(defn remove-timer!
  "Disable --now the timer, remove both unit files, daemon-reload. Every
   step is best-effort (bash `|| true`), so this always returns ok; step
   errors are reported under :failures.

   Result<{:removed [timer service] :failures [err ...]}>."
  [system]
  (let [sd       (:systemd system)
        steps    [[:disable        #(sd-port/-disable! sd refresh/timer-name)]
                  [:remove-timer   #(sd-port/-remove! sd refresh/timer-name)]
                  [:remove-service #(sd-port/-remove! sd refresh/service-name)]
                  [:daemon-reload  #(sd-port/-daemon-reload! sd)]]
        failures (into []
                       (keep (fn [[step f]]
                               (let [res (attempt f)]
                                 (when (r/err? res) (assoc res :step step)))))
                       steps)]
    (log/info "Refresh timer removed.")
    (r/ok {:removed  [refresh/timer-name refresh/service-name]
           :failures failures})))
