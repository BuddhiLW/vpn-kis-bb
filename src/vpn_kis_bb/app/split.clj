(ns vpn-kis-bb.app.split
  "Split-tunnel workflows (bash: split_install, split_remove,
   split_remove_all, split_list, split_status, split_connect).

     install!        ipset, mangle MARK rule and fwmark ip rule live now;
                     dnsmasq drop-in (reloaded); openvpn up/down hooks;
                     boot unit written, enabled and started.
     remove!         one split down; its config stays.
     remove-all!     every configured split, then the shared chain (unlock).
     list-installed  status   printed reports, also returned as data.
     connect-plan    the argv `split connect` execs; nothing runs.
     connect!        connect-plan handed to vpn-kis-bb.adapters.exec.

   A conf is a map (vpn-kis-bb.domain.config/read-split-conf's :value) or
   a split name, read through :read-fn from domain.split/conf-dir.

   System keys: :shell :read-fn :write-fn :delete-fn :ipset :iproute
   :systemd :dnsmasq :settings (:prog; :exec-file for connect!), optional
   :glob-fn (fn [dir pattern] -> paths; default babashka.fs/glob).

   Every public fn returns a hive-dsl Result; errors carry :hint. Progress
   and reports print through vpn-kis-bb.log where the bash prints. Root is
   not checked here."
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.exec :as exec]
            [vpn-kis-bb.domain.config :as config]
            [vpn-kis-bb.domain.priority :as priority]
            [vpn-kis-bb.domain.re :as rx]
            [vpn-kis-bb.domain.split :as split]
            [vpn-kis-bb.log :as log]
            [vpn-kis-bb.ports.dnsmasq :as dns-port]
            [vpn-kis-bb.ports.iproute :as ipr-port]
            [vpn-kis-bb.ports.ipset :as ipset-port]
            [vpn-kis-bb.ports.systemd :as sd-port]))

;; ---------------------------------------------------------------- helpers

(def drain-limit
  "Upper bound on repetitions of a delete-until-it-fails loop (the bash
   `while cmd; do :; done`)."
  16)

(defn- attempt
  "Call thunk f; a throw becomes an error Result."
  [f]
  (try (f)
       (catch Throwable t
         (r/err :split/threw {:hint (str "split: " t)}))))

(defn- sh!
  "Run cmd: {:cmd :exit :stdout :stderr}; a shell err or a throw reads as
   exit -1."
  ([system cmd] (sh! system cmd {}))
  ([system cmd opts]
   (let [res (try (proto/shell-exec! (:shell system) cmd opts)
                  (catch Throwable t (r/err :shell/threw {:message (str t)})))]
     (if (r/ok? res)
       (let [{:keys [exit stdout stderr]} (:ok res)]
         {:cmd    cmd
          :exit   (if (some? exit) exit -1)
          :stdout (or stdout "")
          :stderr (or stderr "")})
       {:cmd cmd :exit -1 :stdout "" :stderr (str (or (:message res) (:error res)))}))))

(defn- ok-exit? [x] (= 0 (:exit x)))

(defn- has?
  "True when program is on the PATH (bash `command -v`)."
  [system program]
  (try (r/ok? (proto/shell-which (:shell system) program))
       (catch Throwable _lookup-failed-means-absent false)))

(defn- prog [system] (or (get-in system [:settings :prog]) "vpn-kis"))

(defn- read-quietly
  "(:read-fn system) of path; nil when it throws."
  [system path]
  (try ((:read-fn system) path)
       (catch Throwable _unreadable-means-absent nil)))

(defn- failed
  "err for a command bash runs under set -e."
  [x]
  (let [e (str/trim (:stderr x))]
    (r/err :split/command-failed
           {:hint (str "split: command failed (exit " (:exit x) "): " (str/join " " (:cmd x))
                       (when-not (str/blank? e) (str ": " e)))
            :cmd  (:cmd x)
            :exit (:exit x)})))

(defn- must!
  "Run cmd; err when it fails."
  [system cmd]
  (let [x (sh! system cmd)]
    (if (ok-exit? x) (r/ok x) (failed x))))

(defn- ensure!
  "bash `check || cmd`: run cmd only when check fails; err when cmd fails."
  [system check cmd]
  (if (ok-exit? (sh! system check))
    (r/ok nil)
    (must! system cmd)))

(defn- drain!
  "Call (step) until it returns false, at most drain-limit times; the
   number of successful calls."
  [step]
  (loop [n 0]
    (if (and (< n drain-limit) (step))
      (recur (inc n))
      n)))

(defn- run-steps
  "Call each thunk in order, stopping at the first error Result."
  [thunks]
  (reduce (fn [_ f]
            (let [res (attempt f)]
              (if (r/err? res) (reduced res) res)))
          (r/ok nil)
          thunks))

(defn- emit!
  "Print [[level line] ..]: :info and :warn through vpn-kis-bb.log, :say
   to stdout."
  [report]
  (doseq [[level line] report]
    (case level
      :info (log/info line)
      :warn (log/warn line)
      (log/say line))))

(defn glob
  "Paths in dir matching glob pattern, sorted: (:glob-fn system) (fn [dir
   pattern] -> seq of paths) when present, else babashka.fs/glob. [] when
   dir is missing or the listing throws."
  [system dir pattern]
  (try
    (->> (if-let [g (:glob-fn system)]
           (g dir pattern)
           (when (fs/directory? dir) (fs/glob dir pattern)))
         (map str)
         sort
         vec)
    (catch Throwable _unlistable-means-empty [])))

(defn- configured-names
  "Split names with a config in domain.split/conf-dir."
  [system]
  (split/conf-names (concat (glob system split/conf-dir "*.conf")
                            (glob system split/conf-dir "*.edn"))))

;; ---------------------------------------------------------------- config

(defn- validated
  "Result<validated cfg> for conf: a map (domain.config/read-split-conf's
   :value) or a split name read through :read-fn from domain.split/conf-dir."
  [system conf]
  (let [loaded (if (string? conf)
                 (let [c (config/read-split-conf split/conf-dir conf (:read-fn system))]
                   (if (:ok? c)
                     (r/ok [(:value c) (:path c)])
                     (r/err :split/invalid-config {:hint (:error c)})))
                 (r/ok [conf nil]))]
    (if (r/err? loaded)
      loaded
      (let [[m source] (:ok loaded)
            v          (split/validate m source)]
        (if (:ok? v)
          (r/ok (:value v))
          (r/err :split/invalid-config {:hint (:error v)}))))))

(defn- resolve-priority
  "cfg with PRIORITY=auto resolved from the live `ip rule show` (bash
   split_load_conf), logging where the rule goes. An unreadable rule list
   counts as no Mullvad rule, as in bash."
  [system cfg]
  (if (not= :auto (:priority cfg))
    cfg
    (let [shown (attempt #(ipr-port/-rule-show (:iproute system)))
          rules (if (r/ok? shown) (:ok shown) [])
          mp    (priority/mullvad-priority rules)
          p     (priority/choose-split-priority rules)]
      (if mp
        (log/info "Mullvad fwmark rule at priority " mp ": split rule goes to priority " p)
        (log/info "Mullvad fwmark rule not found: split rule at fallback priority " p))
      (assoc cfg :priority p))))

(defn- prepare
  "Result<cfg>: validated, priority resolved."
  [system conf]
  (let [v (validated system conf)]
    (if (r/err? v)
      v
      (r/ok (resolve-priority system (:ok v))))))

;; ---------------------------------------------------------------- install

(defn- check-dnsmasq!
  "bash split_require_dnsmasq, run before anything changes: err without
   /etc/dnsmasq.d, warnings when no dnsmasq fronts systemd-resolved."
  [system]
  (let [pf (attempt #(dns-port/-preflight (:dnsmasq system)))]
    (cond
      (r/err? pf)
      pf

      (not (-> pf :ok :drop-in-dir?))
      (r/err :split/no-dnsmasq
             {:hint (str "split: " split/dnsmasq-dir
                         " missing (apt install dnsmasq, or enable NM dnsmasq plugin)")})

      :else
      (do (when-not (-> pf :ok :fronted?)
            (log/warn "split: systemd-resolved is the active resolver but no dnsmasq instance was detected.")
            (log/warn "split: dnsmasq must front DNS for the ipset= directive to work. See README."))
          pf))))

(defn- install-ipset!
  "bash split_install_ipset."
  [system {:keys [name]}]
  (if-not (has? system "ipset")
    (r/err :split/no-ipset {:hint "ipset required"})
    (let [res (ipset-port/-create! (:ipset system) (split/ipset-name name) split/ipset-opts)]
      (if (r/err? res)
        (r/err :split/ipset-failed
               {:hint  (str "split: ipset create " (split/ipset-name name) " failed")
                :cause res})
        res))))

(defn- install-mangle!
  "bash split_install_mangle: the shared chain, its OUTPUT and PREROUTING
   jumps, then this split's MARK rule (drained first, so never doubled)."
  [system {:keys [name mark]}]
  (sh! system split/chain-new-cmd)
  (run-steps
   [#(ensure! system (split/jump-check-cmd "OUTPUT") (split/jump-add-cmd "OUTPUT"))
    #(ensure! system (split/jump-check-cmd "PREROUTING") (split/jump-add-cmd "PREROUTING"))
    #(r/ok (drain! (fn [] (ok-exit? (sh! system (split/mark-del-cmd name mark))))))
    #(must! system (split/mark-add-cmd name mark))]))

(defn- rule-deleted?
  "One `ip rule del priority p`; true when it deleted a rule."
  [system p]
  (let [res (attempt #(ipr-port/-rule-del! (:iproute system) p))]
    (and (r/ok? res) (= 0 (-> res :ok :exit)))))

(defn- install-rule!
  "bash split_install_iprule: drop whatever sits at the priority, then add
   the fwmark rule."
  [system {:keys [mark table priority]}]
  (drain! #(rule-deleted? system priority))
  (let [res (attempt #(ipr-port/-rule-add! (:iproute system)
                                           {:fwmark mark :lookup table :priority priority}))]
    (if (r/err? res)
      (r/err :split/rule-failed
             {:hint  (str "split: ip rule add fwmark " mark " lookup " table
                          " priority " priority " failed")
              :cause res})
      res)))

(defn- install-dnsmasq!
  "Drop-in written, dnsmasq reloaded (bash split_install_dnsmasq)."
  [system {:keys [name] :as cfg}]
  (let [dns (:dnsmasq system)
        w   (dns-port/-write-drop-in! dns (split/dnsmasq-name name)
                                      (split/dnsmasq-drop-in-text cfg))]
    (if (r/err? w) w (dns-port/-reload! dns))))

(defn- write-hooks!
  "The openvpn up/down scripts, mode 755."
  [system {:keys [name] :as cfg}]
  (let [up   (split/up-script-path name)
        down (split/down-script-path name)]
    (run-steps
     [#((:write-fn system) up (split/openvpn-up-script-text cfg))
      #((:write-fn system) down (split/openvpn-down-script-text cfg))
      #(must! system ["chmod" "755" up down])])))

(defn- install-unit!
  "Write the boot unit, daemon-reload, enable (a failure ignored, as in
   bash), start. The rules are live already, so a failed start only warns.
   Result<{:started? bool}>."
  [system {:keys [name] :as cfg}]
  (let [sd   (:systemd system)
        unit (split/unit-name name)]
    (run-steps
     [#(sd-port/-write! sd unit (split/systemd-unit-text cfg))
      #(let [dr (sd-port/-daemon-reload! sd)]
         (if (r/err? dr)
           (r/err :split/daemon-reload-failed
                  {:hint "split: systemctl daemon-reload failed" :cause dr})
           dr))
      #(do (sd-port/-enable! sd unit) (r/ok nil))
      #(let [st (sd-port/-start! sd unit)]
         (when (r/err? st)
           (log/warn "split: could not start " unit
                     "; the rules are live now and the unit applies them at boot"))
         (r/ok {:started? (r/ok? st)}))])))

(defn install!
  "Install a split tunnel (bash split_install): ipset, mangle MARK rule and
   fwmark ip rule applied now; dnsmasq drop-in written and dnsmasq
   reloaded; openvpn up/down hooks written; boot unit written, enabled and
   started. The dnsmasq directory check runs before anything changes; the
   first hard failure stops the install (bash set -e).

   conf: a map (domain.config/read-split-conf :value) or a split name.
   Result<{:installed name :set :unit :dev :table :mark :priority
           :started? bool}>; err :split/invalid-config, :split/no-dnsmasq,
   :split/no-ipset, :split/ipset-failed, :split/command-failed,
   :split/rule-failed, :split/daemon-reload-failed, :dnsmasq/reload-failed
   or a :write-fn err, each with :hint."
  [system conf]
  (let [prep (prepare system conf)]
    (if (r/err? prep)
      prep
      (let [{:keys [name patterns dev table mark priority] :as cfg} (:ok prep)
            _   (log/info "Installing split '" name "': domains=[" (str/join " " patterns)
                          "] dev=" dev " table=" table " mark=" mark " priority=" priority)
            res (run-steps [#(check-dnsmasq! system)
                            #(install-ipset! system cfg)
                            #(install-mangle! system cfg)
                            #(install-rule! system cfg)
                            #(install-dnsmasq! system cfg)
                            #(write-hooks! system cfg)
                            #(install-unit! system cfg)])]
        (if (r/err? res)
          res
          (do (log/info "Split '" name "' installed. Bring the tunnel up with:")
              (log/info "  sudo " (prog system) " split connect " name)
              (r/ok {:installed name
                     :set       (split/ipset-name name)
                     :unit      (split/unit-name name)
                     :dev       dev
                     :table     table
                     :mark      mark
                     :priority  priority
                     :started?  (boolean (-> res :ok :started?))})))))))

;; ---------------------------------------------------------------- remove

(defn remove!
  "Tear one split down (bash split_remove): when its unit file exists, read
   the rule's priority and fwmark from it, disable --now and delete the
   unit; drain that ip rule and that MARK rule; destroy the ipset; delete
   the dnsmasq drop-in and the up/down hooks; reload dnsmasq. The config
   stays. Every step runs; failures of the ones bash would stop on (file
   deletes, the dnsmasq reload) are collected.

   Result<{:removed name :unit? bool :priority s :fwmark s}>; err
   :split/invalid-name, or :split/remove-incomplete {:hint :failures [err
   with :step ..]} after every step ran."
  [system split-name]
  (if-not (split/valid-name? split-name)
    (r/err :split/invalid-name {:hint "split: invalid name" :name split-name})
    (let [sd       (:systemd system)
          unit     (split/unit-name split-name)
          unit-txt (read-quietly system (split/unit-path split-name))
          {:keys [priority fwmark]} (split/unit-rule-params unit-txt)
          mark-del (split/mark-del-cmd split-name fwmark)
          steps    (concat
                    (when unit-txt
                      [[:disable-unit #(sd-port/-disable! sd unit) false]
                       [:remove-unit #(sd-port/-remove! sd unit) true]
                       [:daemon-reload #(sd-port/-daemon-reload! sd) false]])
                    (when priority
                      [[:ip-rule #(r/ok (drain! (fn [] (rule-deleted? system priority)))) false]])
                    (when fwmark
                      [[:mark-rule #(r/ok (drain! (fn [] (ok-exit? (sh! system mark-del))))) false]])
                    [[:destroy-ipset
                      #(ipset-port/-destroy! (:ipset system) (split/ipset-name split-name)) false]
                     [:remove-drop-in
                      #(dns-port/-remove-drop-in! (:dnsmasq system) (split/dnsmasq-name split-name)) true]
                     [:remove-up #((:delete-fn system) (split/up-script-path split-name)) true]
                     [:remove-down #((:delete-fn system) (split/down-script-path split-name)) true]
                     [:reload-dnsmasq #(dns-port/-reload! (:dnsmasq system)) true]])
          failures (into []
                         (keep (fn [[step f report?]]
                                 (let [res (attempt f)]
                                   (when (and report? (not (r/ok? res)))
                                     (assoc (if (map? res) res {:error res}) :step step)))))
                         steps)
          conf     (if (read-quietly system (split/edn-path split-name))
                     (split/edn-path split-name)
                     (split/conf-path split-name))]
      (if (seq failures)
        (let [what (str/join ", " (map #(name (:step %)) failures))]
          (log/warn "Split '" split-name "' only partly removed (" what " failed).")
          (r/err :split/remove-incomplete
                 {:hint     (str "split: '" split-name "' only partly removed: " what " failed")
                  :name     split-name
                  :failures failures}))
        (do (log/info "Split '" split-name "' removed. Config left at " conf
                      " (delete manually if no longer needed).")
            (r/ok {:removed  split-name
                   :unit?    (some? unit-txt)
                   :priority priority
                   :fwmark   fwmark}))))))

(defn remove-all!
  "bash split_remove_all, for unlock: remove! every split configured in
   domain.split/conf-dir, then tear the shared mangle chain down (bash
   skips that while configs remain, leaving an empty chain behind). A
   config whose name is not a valid split name is skipped with a warning
   (bash exits there). Best-effort: always
   Result<{:removed [name ..] :failed [name ..] :skipped [name ..]}>."
  [system]
  (let [names   (configured-names system)
        valid   (filterv split/valid-name? names)
        invalid (filterv (complement split/valid-name?) names)
        results (mapv (fn [n] [n (attempt #(remove! system n))]) valid)]
    (doseq [n invalid]
      (log/warn "split: skipping config '" n "': not a valid split name"))
    (doseq [cmd split/chain-teardown-cmds]
      (sh! system cmd))
    (r/ok {:removed (mapv first (filter #(r/ok? (second %)) results))
           :failed  (mapv first (remove #(r/ok? (second %)) results))
           :skipped invalid})))

;; ---------------------------------------------------------------- list / status

(defn list-installed
  "bash split_list: print each split configured in domain.split/conf-dir
   (<name>.conf or <name>.edn) as installed (its unit file exists) or
   configured, or a hint when there is none.
   Result<{:conf-dir dir :splits [{:name :installed? :unit} ..]}>."
  [system]
  (let [splits (mapv (fn [n]
                       {:name       n
                        :unit       (split/unit-name n)
                        :installed? (some? (read-quietly system (split/unit-path n)))})
                     (configured-names system))]
    (if (empty? splits)
      (log/info "No splits configured. Drop a config at " split/conf-dir
                "/<name>.conf (see README).")
      (doseq [s splits]
        (log/say (split/list-line s (prog system)))))
    (r/ok {:conf-dir split/conf-dir :splits splits})))

(defn status
  "bash split_status. A nil or blank name runs list-installed. Otherwise
   load the split (PRIORITY=auto resolved live, as bash does) and print its
   settings and the live ipset, ip rule, route table and unit state.
   Result<{:config cfg :ipset-present? bool :ipset [line ..] :rules [..]
           :routes [..] :enabled s :active s}>; err :split/invalid-config
   when the split cannot be loaded."
  [system split-name]
  (if (str/blank? split-name)
    (list-installed system)
    (let [prep (prepare system split-name)]
      (if (r/err? prep)
        prep
        (let [{:keys [name table priority] :as cfg} (:ok prep)
              unit    (split/unit-name name)
              ipset   (sh! system ["ipset" "list" (split/ipset-name name)])
              rules   (sh! system (split/rule-show-cmd priority))
              routes  (sh! system (split/route-show-cmd table))
              enabled (sh! system ["systemctl" "is-enabled" unit])
              active  (sh! system ["systemctl" "is-active" unit])
              both    (fn [x] (str/join "\n" (remove str/blank? [(str/trimr (:stdout x))
                                                                 (str/trimr (:stderr x))])))
              lines   (fn [s] (vec (remove str/blank? (rx/split-lines* (or s "")))))
              live    {:ipset-ok? (ok-exit? ipset)
                       :ipset     (:stdout ipset)
                       :rules     (:stdout rules)
                       :routes    (:stdout routes)
                       :enabled   (both enabled)
                       :active    (both active)}]
          (emit! (split/status-report cfg live))
          (r/ok {:config         cfg
                 :ipset-present? (:ipset-ok? live)
                 :ipset          (lines (:stdout ipset))
                 :rules          (lines (:stdout rules))
                 :routes         (lines (:stdout routes))
                 :enabled        (:enabled live)
                 :active         (:active live)}))))))

;; ---------------------------------------------------------------- connect

(defn- mullvad-up?
  "bash split_connect's test: mullvad-exclude is installed and `mullvad
   status` succeeds with output containing \"connected\" in any case, so
   Disconnected counts too (Mullvad's lockdown still blocks traffic that
   is not excluded)."
  [system]
  (and (has? system "mullvad-exclude")
       (let [x (sh! system ["mullvad" "status"] {:timeout-ms 10000})]
         (and (ok-exit? x)
              (str/includes? (str/lower-case (:stdout x)) "connected")))))

(defn connect-cmd
  "Pure: the command `split connect` runs for a validated config, the
   openvpn line (domain.split/openvpn-argv) wrapped in mullvad-exclude
   when :mullvad-exclude? is true."
  [cfg & {:keys [mullvad-exclude?]}]
  (let [base (split/openvpn-argv cfg)]
    (if mullvad-exclude?
      (into ["mullvad-exclude"] base)
      base)))

(defn connect-plan
  "bash split_connect up to its exec: validate the split, check that
   OVPN_CONFIG is set and readable (through :read-fn) and that openvpn is
   installed, decide on the mullvad-exclude wrapper, print the bash info
   lines. Runs and spawns nothing: hand :argv to
   vpn-kis-bb.adapters.exec/exec! so openvpn replaces the launcher.

   conf: a map (domain.config/read-split-conf :value) or a split name.
   Result<{:argv [..] :name :dev :table :ovpn-config :mullvad-exclude? bool}>;
   err :split/invalid-config, :split/no-ovpn-config, :split/ovpn-not-found
   or :split/no-openvpn, each with :hint."
  [system conf]
  (let [v (validated system conf)]
    (if (r/err? v)
      v
      (let [{:keys [name dev table ovpn-config source] :as cfg} (:ok v)]
        (cond
          (nil? ovpn-config)
          (r/err :split/no-ovpn-config
                 {:hint (str "split connect: OVPN_CONFIG not set in " source)})

          (nil? (read-quietly system ovpn-config))
          (r/err :split/ovpn-not-found
                 {:hint (str "split connect: OVPN_CONFIG not found: " ovpn-config)})

          (not (has? system "openvpn"))
          (r/err :split/no-openvpn {:hint "openvpn not installed"})

          :else
          (let [wrap? (mullvad-up? system)]
            (when wrap?
              (log/info "Mullvad active: wrapping with mullvad-exclude"))
            (log/info "Connecting split '" name "' (dev=" dev ", config=" ovpn-config ")")
            (log/info "Default route will NOT be hijacked (route-nopull). Route table "
                      table " handles split traffic.")
            (r/ok {:argv             (connect-cmd cfg :mullvad-exclude? wrap?)
                   :name             name
                   :dev              dev
                   :table            table
                   :ovpn-config      ovpn-config
                   :mullvad-exclude? wrap?})))))))

(defn connect!
  "connect-plan, then vpn-kis-bb.adapters.exec/exec! with its argv, so
   openvpn replaces the launcher process and is never a child of this one.
   Result of exec! ({:exec argv :via file}, or err :exec/no-launcher), or
   connect-plan's err."
  [system conf]
  (let [plan (connect-plan system conf)]
    (if (r/err? plan)
      plan
      (exec/exec! system (-> plan :ok :argv) {}))))



