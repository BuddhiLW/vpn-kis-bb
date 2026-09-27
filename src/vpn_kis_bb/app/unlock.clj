(ns vpn-kis-bb.app.unlock
  "Roll the kill-switch back from the latest UFW snapshot (bash
   unlock_firewall): restore the rules files and /etc/default/ufw from the
   newest /etc/ufw/backup-*/ (by modification time, as `ls -1dt`); then,
   best-effort and in bash order, remove the NetworkManager hook,
   before.init and /etc/ipset.conf, the tailnet bypass, the refresh timer,
   every split tunnel and the cgroup exclusion; reload UFW; destroy the
   vpn_endpoints and vpn_dns_bootstrap sets. Less invasive than panic:
   iptables policies and DNS are left to the restored UFW config.

   System keys: :shell (changes), :live-shell (read-only lookups of the
   backup, falling back to :shell), :ipset, :systemd, :read-fn, :write-fn,
   :delete-fn, :settings (:prog), plus what vpn-kis-bb.app.tailscale/remove!,
   vpn-kis-bb.app.refresh/remove-timer!, vpn-kis-bb.app.split/remove-all!
   and vpn-kis-bb.app.exclude/remove-all! read."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.nm-dispatcher :as nm]
            [vpn-kis-bb.app.exclude :as exclude]
            [vpn-kis-bb.app.refresh :as refresh]
            [vpn-kis-bb.app.split :as split-app]
            [vpn-kis-bb.app.tailscale :as tailscale]
            [vpn-kis-bb.log :as log]
            [vpn-kis-bb.ports.ipset :as ipset-port]))

;; ---------------------------------------------------------------- constants

(def restore-files
  "Rules files a backup may hold, restored into /etc/ufw/."
  ["user.rules" "user6.rules" "before.rules" "before6.rules" "after.rules"])

(def default-ufw-path "/etc/default/ufw")

(def removed-files
  "Deleted after the restore (bash rm -f), next to the NetworkManager hook."
  ["/etc/ufw/before.init" "/etc/ipset.conf"])

(def destroyed-sets
  "ipsets destroyed after `ufw reload`, once no rule references them."
  ["vpn_endpoints" "vpn_dns_bootstrap"])

(def latest-backup-cmd
  "bash: `ls -1dt /etc/ufw/backup-*/ | head -1`, the newest backup
   directory by modification time, printed with a trailing slash."
  ["sh" "-c" "ls -1dt /etc/ufw/backup-*/ 2>/dev/null | head -1"])

;; ---------------------------------------------------------------- helpers

(defn- attempt
  "Call thunk f; a throw becomes an error Result."
  [f]
  (try (f)
       (catch Throwable t
         (r/err :unlock/threw {:hint (str "unlock: " t)}))))

(defn- sh!
  "Run cmd through shell: {:cmd :exit :stdout :stderr}; a shell err or a
   throw reads as exit -1."
  [shell cmd]
  (let [res (try (proto/shell-exec! shell cmd {})
                 (catch Throwable t (r/err :shell/threw {:message (str t)})))]
    (if (r/ok? res)
      (let [{:keys [exit stdout stderr]} (:ok res)]
        {:cmd    cmd
         :exit   (if (some? exit) exit -1)
         :stdout (or stdout "")
         :stderr (or stderr "")})
      {:cmd cmd :exit -1 :stdout "" :stderr (str (or (:message res) (:error res)))})))

(defn- reader
  "Shell for read-only lookups: :live-shell (the real system even in a
   dry-run profile), else :shell."
  [system]
  (or (:live-shell system) (:shell system)))

(defn- failure
  "nil when res is an ok Result, else {:step desc :reason s}, warned about."
  [desc res]
  (when-not (r/ok? res)
    (let [why (str (or (:hint res) (:message res) (:error res) "failed"))]
      (log/warn "unlock: " desc " failed (" why ")")
      {:step desc :reason why})))

;; ---------------------------------------------------------------- backup

(defn latest-backup
  "The newest /etc/ufw/backup-*/ directory as ls prints it (trailing slash
   kept), or nil. Read-only: runs through :live-shell when present."
  [system]
  (let [x    (sh! (reader system) latest-backup-cmd)
        line (str/trim (:stdout x))]
    (when (and (= 0 (:exit x)) (not (str/blank? line)))
      (let [i (str/index-of line "\n")]
        (if i (subs line 0 i) line)))))

(defn- file?
  "True when path is a regular file (read-only `test -f`)."
  [system path]
  (= 0 (:exit (sh! (reader system) ["test" "-f" path]))))

(defn restore-plan
  "[[src dst] ..] for the files backup holds, in bash order: the rules
   files into /etc/ufw/, then <backup>/ufw into /etc/default/ufw."
  [system backup]
  (let [dir (if (str/ends-with? backup "/") (subs backup 0 (dec (count backup))) backup)]
    (filterv (fn [[src _dst]] (file? system src))
             (conj (mapv (fn [f] [(str dir "/" f) (str "/etc/ufw/" f)]) restore-files)
                   [(str dir "/ufw") default-ufw-path]))))

(defn- copy!
  "cp -a src dst; err :unlock/restore-failed when it fails (bash set -e)."
  [system [src dst]]
  (let [x (sh! (:shell system) ["cp" "-a" src dst])]
    (if (= 0 (:exit x))
      (r/ok dst)
      (r/err :unlock/restore-failed
             {:hint (str "unlock: could not restore " dst " from " src
                         (let [e (str/trim (:stderr x))]
                           (when-not (str/blank? e) (str ": " e))))
              :exit (:exit x)}))))

;; ---------------------------------------------------------------- teardown

(defn- step-failures
  "Text for a list of step errors ({:step kw :hint ..})."
  [errs]
  (str/join "; " (map #(str (name (:step %)) ": " (or (:hint %) (:error %))) errs)))

(defn- teardown!
  "Everything unlock_firewall does after the copies, in bash order, each
   step best-effort. {:failed [{:step :reason} ..] :hook-removed? ..
   :tailscale .. :refresh-timer .. :splits .. :exclude .. :ufw-reloaded? ..}."
  [system]
  (let [hook     (attempt #(nm/remove! system))
        f-hook   (failure (str "rm -f " nm/dispatcher-path)
                          (if (-> hook :ok :removed?)
                            hook
                            (r/err :unlock/delete-failed {:hint "delete failed"})))
        f-files  (mapv (fn [p] (failure (str "rm -f " p) (attempt #((:delete-fn system) p))))
                       removed-files)
        ts       (attempt #(tailscale/remove! system {}))
        f-ts     (failure "tailscale-routes remove"
                          (if (seq (-> ts :ok :failures))
                            (r/err :unlock/tailscale {:hint (step-failures (-> ts :ok :failures))})
                            ts))
        timer    (attempt #(refresh/remove-timer! system))
        real     (remove #(= :disable (:step %)) (-> timer :ok :failures))
        f-timer  (failure "refresh timer removal"
                          (if (seq real)
                            (r/err :unlock/refresh-timer {:hint (step-failures real)})
                            timer))
        splits   (attempt #(split-app/remove-all! system))
        f-splits (failure "split remove-all"
                          (if (seq (-> splits :ok :failed))
                            (r/err :unlock/splits
                                   {:hint (str "not fully removed: "
                                               (str/join ", " (-> splits :ok :failed)))})
                            splits))
        excl     (attempt #(exclude/remove-all! system))
        f-excl   (failure "exclude teardown" excl)
        reload   (sh! (:shell system) ["ufw" "reload"])
        f-reload (when-not (= 0 (:exit reload))
                   (log/warn "ufw reload failed")
                   {:step "ufw reload" :reason (str "exit " (:exit reload))})]
    (doseq [s destroyed-sets]
      (attempt #(ipset-port/-destroy! (:ipset system) s)))
    {:failed        (vec (remove nil? (concat [f-hook] f-files
                                              [f-ts f-timer f-splits f-excl f-reload])))
     :hook-removed? (boolean (-> hook :ok :removed?))
     :tailscale     (:ok ts)
     :refresh-timer (:ok timer)
     :splits        (:ok splits)
     :exclude       (:ok excl)
     :ufw-reloaded? (= 0 (:exit reload))}))

;; ---------------------------------------------------------------- unlock

(defn- dry-run
  "Print and return the plan; nothing changes."
  [latest plan]
  (doseq [[src dst] plan]
    (log/say "[dry-run] unlock: cp -a " src " " dst))
  (log/say "[dry-run] unlock: rm -f " (str/join " " (cons nm/dispatcher-path removed-files)))
  (log/say "[dry-run] unlock: tailscale-routes remove, refresh timer removal,"
           " split remove-all, exclude teardown")
  (log/say "[dry-run] unlock: ufw reload; ipset destroy " (str/join " " destroyed-sets))
  (r/ok {:dry-run?     true
         :backup       latest
         :will-restore (mapv first plan)
         :restores     plan
         :will-remove  (vec (cons nm/dispatcher-path removed-files))}))

(defn unlock!
  "Roll back to the latest UFW snapshot (bash unlock_firewall). The file
   copies must succeed (bash set -e); every later step is best-effort and
   its failures are collected and warned about.

   opts {:dry-run? true}: print and return the plan; nothing changes.

   Result<{:restored backup :files [dst ..] :failed [{:step :reason} ..]
           :ufw-reloaded? bool :hook-removed? bool :tailscale ..
           :refresh-timer .. :splits .. :exclude ..}>;
   dry run: Result<{:dry-run? true :backup :will-restore [src ..]
                    :restores [[src dst] ..] :will-remove [..]}>;
   err :unlock/no-backup (no /etc/ufw/backup-*/) or :unlock/restore-failed
   (a copy failed; nothing after it ran), each with :hint."
  [system {:keys [dry-run?]}]
  (log/info "Rolling back VPN kill-switch...")
  (let [latest (latest-backup system)]
    (if (nil? latest)
      (r/err :unlock/no-backup
             {:hint "No backup found in /etc/ufw/backup-*. Manual recovery needed."})
      (let [plan (restore-plan system latest)]
        (log/info "Restoring from: " latest)
        (if dry-run?
          (dry-run latest plan)
          (let [copied (reduce (fn [_ pair]
                                 (let [c (copy! system pair)]
                                   (if (r/err? c) (reduced c) c)))
                               (r/ok nil)
                               plan)]
            (if (r/err? copied)
              copied
              (let [td (teardown! system)]
                (log/info "Firewall restored from " latest ".")
                (log/info "IPv6 disable (sysctl/modprobe/GRUB) NOT reverted; remove manually if desired:")
                (log/info "  rm /etc/sysctl.d/99-disable-ipv6.conf /etc/modprobe.d/disable-ipv6.conf")
                (log/info "  edit /etc/default/grub to drop ipv6.disable=1, then update-grub")
                (when (seq (:failed td))
                  (log/warn "unlock: " (count (:failed td)) " step(s) failed: "
                            (str/join ", " (map :step (:failed td)))))
                (r/ok (assoc td
                             :restored latest
                             :files    (mapv second plan)))))))))))
