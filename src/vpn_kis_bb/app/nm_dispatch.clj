(ns vpn-kis-bb.app.nm-dispatch
  "NetworkManager dispatcher logic (bash: the body of the
   /etc/NetworkManager/dispatcher.d/90-vpn-killswitch hook). The installed
   hook (vpn-kis-bb.adapters.nm-dispatcher) execs
   `<self> nm-dispatch IFACE ACTION`, which calls handle!.

   Relevant actions: up, down, vpn-up, vpn-down, connectivity-change.
     tailscale* interface  restart the tailnet bypass unit when it is
                           enabled
     other virtual IFs     ignored: a tunnel is never the physical link
     anything else         single-flight retarget: pin the kill-switch
                           DROP rule of /etc/ufw/before.rules on the
                           current physical IF (nothing happens when it is
                           already pinned there), ufw reload, restart the
                           cgroup-exclusion unit when exclusion is enabled,
                           refresh the tailnet bypass
   Diagnostics go to syslog through `logger -t vpn-killswitch`.

   System keys: :shell :systemd :read-fn :write-fn."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.app.exclude :as exclude]
            [vpn-kis-bb.domain.exclude :as ex]
            [vpn-kis-bb.domain.nm-dispatch :as d]
            [vpn-kis-bb.domain.tailscale :as ts]
            [vpn-kis-bb.ports.systemd :as sd-port]))

(def restart-timeout-ms
  "Budget for `systemctl restart` of the oneshot units, which wait for
   their ExecStart to finish."
  120000)

;; ---------------------------------------------------------------- helpers

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

(defn- ok-exit? [x] (= 0 (:exit x)))

(defn- syslog!
  "Send the message to syslog (`logger -t vpn-killswitch`)."
  [system & parts]
  (sh! system (d/logger-cmd (apply str parts)))
  nil)

(defn- skip
  "Log msg; the ok Result of an event the hook leaves alone."
  [system reason msg]
  (syslog! system msg)
  (r/ok {:action :skipped :reason reason :message msg}))

;; ---------------------------------------------------------------- tailnet

(defn- refresh-tailnet!
  "bash refresh_tailscale_routes: restart the tailnet bypass unit when it
   is enabled. True when it was restarted."
  [system]
  (let [en (sd-port/-enabled? (:systemd system) ts/unit-name)]
    (cond
      (not (true? (:ok en))) false

      (ok-exit? (sh! system ts/unit-restart-cmd {:timeout-ms restart-timeout-ms})) true

      :else (do (syslog! system "failed to refresh Tailscale bypass")
                false))))

;; ---------------------------------------------------------------- lock

(defn- lock!
  "Take the single-flight lock (an atomic mkdir). A lock directory older
   than lock-stale-minutes is removed and taken once. True when held."
  [system]
  (boolean
   (or (ok-exit? (sh! system d/lock-cmd))
       (when-not (str/blank? (:stdout (sh! system d/stale-lock-cmd)))
         (syslog! system "stale lock " d/lock-dir " removed")
         (sh! system d/unlock-cmd)
         (ok-exit? (sh! system d/lock-cmd))))))

;; ---------------------------------------------------------------- retarget

(defn- candidate
  "Physical IF to pin: the first non-virtual default-route device, else
   the first non-virtual interface holding IPv4; nil when none."
  [system]
  (or (ex/default-route-iface (:stdout (sh! system ex/default-routes-cmd)))
      (d/fallback-iface (:stdout (sh! system d/addrs-cmd)))))

(defn- restore!
  "Write the original before.rules text back. True on success."
  [system text]
  (r/ok? ((:write-fn system) ex/before-rules-path text)))

(defn- follow-up!
  "After a live retarget: restart the exclusion unit (when enabled) so its
   routing follows the new IF, then refresh the tailnet bypass."
  [system cur new-if]
  (syslog! system "killswitch retargeted: " cur " -> " new-if)
  (let [excl? (and (exclude/enabled? system)
                   (ok-exit? (sh! system d/exclude-restart-cmd {:timeout-ms restart-timeout-ms})))
        ts?   (refresh-tailnet! system)]
    (r/ok {:action             :retargeted
           :from               cur
           :to                 new-if
           :exclude-restarted? excl?
           :tailnet-refreshed? ts?})))

(defn- reload-failed!
  "ufw reload failed on the new rules: restore the original text and
   reload again."
  [system text cur new-if]
  (syslog! system "ufw reload failed, restoring backup")
  (let [restored? (restore! system text)
        again?    (ok-exit? (sh! system ex/ufw-reload-cmd))]
    (when-not again?
      (syslog! system "restore reload also failed, MANUAL INTERVENTION NEEDED"))
    (r/err :nm-dispatch/reload-failed
           {:hint      (if again?
                         (str "ufw reload failed after retargeting " cur " -> " new-if
                              "; before.rules restored")
                         "ufw reload failed and so did the restore reload, MANUAL INTERVENTION NEEDED")
            :from      cur
            :to        new-if
            :restored? restored?
            :reloaded? again?})))

(defn- rewrite!
  "Move the pin from cur to new-if: check the rewritten text, back the
   file up (cp -a), write, ufw reload; a failed write or reload restores
   the original text."
  [system text cur new-if]
  (syslog! system "physical IF changed: " cur " -> " new-if ", reapplying")
  (let [new-text (d/retarget-rules text cur new-if)
        fail     (fn [kw msg extra]
                   (syslog! system msg)
                   (r/err kw (merge {:hint msg :from cur :to new-if} extra)))]
    (cond
      (not (d/retarget-valid? new-text new-if))
      (fail :nm-dispatch/validation-failed
            (str "rewrite validation failed (no DROP rule for " new-if
                 "), before.rules left unchanged")
            {})

      (not (ok-exit? (sh! system d/backup-cmd)))
      (fail :nm-dispatch/backup-failed "backup failed, abort" {})

      (r/err? ((:write-fn system) ex/before-rules-path new-text))
      (let [res (fail :nm-dispatch/write-failed "before.rules write failed, restoring backup" {})]
        (assoc res :restored? (restore! system text)))

      (not (ok-exit? (sh! system ex/ufw-reload-cmd)))
      (reload-failed! system text cur new-if)

      :else
      (follow-up! system cur new-if))))

(defn- retarget!
  "The locked part of the hook: find the physical IF and the pinned one,
   and move the pin when they differ."
  [system]
  (let [new-if (candidate system)]
    (if (nil? new-if)
      (skip system :no-candidate "no physical IF candidate, skip")
      (let [text ((:read-fn system) ex/before-rules-path)
            cur  (ex/pinned-phys text)]
        (cond
          (nil? cur)
          (skip system :unparsable-rules
                (str "cannot parse current IF from " ex/before-rules-path
                     ", skip (manual fix needed)"))

          (ex/virtual-iface? cur)
          (skip system :virtual-current
                (str "current IF '" cur "' looks virtual/VPN, refusing rewrite"
                     " (rules may be corrupted)"))

          (ex/virtual-iface? new-if)
          (skip system :virtual-candidate
                (str "candidate '" new-if "' is virtual/VPN, refusing rewrite"))

          (= new-if cur)
          (r/ok {:action :unchanged :iface cur})

          :else
          (rewrite! system text cur new-if))))))

;; ---------------------------------------------------------------- public

(defn handle!
  "Handle one NetworkManager dispatcher event: `iface` and `action` are
   the hook's two arguments (iface may be nil or blank).

   Result<{:action :ignored :iface .. :event ..}>       irrelevant event
   Result<{:action :tailnet-refresh :iface .. :refreshed? bool}>
   Result<{:action :skipped :reason kw :message s}>     lock held, no
       candidate IF, before.rules unparsable, or a virtual pin / candidate
   Result<{:action :unchanged :iface s}>                pin already right
   Result<{:action :retargeted :from s :to s :exclude-restarted? bool
           :tailnet-refreshed? bool}>
   or err :nm-dispatch/validation-failed | backup-failed | write-failed |
   reload-failed | threw, whose :hint is the message sent to syslog."
  [system iface action]
  (try
    (case (d/event-kind iface action)
      :ignore
      (r/ok {:action :ignored :iface iface :event action})

      :tailnet-refresh
      (r/ok {:action :tailnet-refresh :iface iface :refreshed? (refresh-tailnet! system)})

      :retarget
      (if (lock! system)
        (try (retarget! system)
             (finally (sh! system d/unlock-cmd)))
        (skip system :lock-held "lock held, skip")))
    (catch Throwable t
      (r/err :nm-dispatch/threw {:hint (str "nm-dispatch failed: " t)}))))
