(ns vpn-kis-bb.adapters.nm-dispatcher
  "Install / remove the NetworkManager dispatcher hook
   /etc/NetworkManager/dispatcher.d/90-vpn-killswitch (bash:
   install_nm_dispatcher). The hook is a POSIX sh script that execs
   `<self-path> nm-dispatch IFACE ACTION`; the logic lives in
   vpn-kis-bb.app.nm-dispatch/handle!.

   System keys: :shell (directory test, chmod), :write-fn, :delete-fn,
   :self-path (or :settings :self-path)."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.exec :as exec]
            [vpn-kis-bb.log :as log]))

(def dispatcher-dir "/etc/NetworkManager/dispatcher.d")

(def dispatcher-path (str dispatcher-dir "/90-vpn-killswitch"))

(defn hook-text
  "Pure: the hook script for launcher `self-path`."
  [self-path]
  (str "#!/bin/sh\n"
       "# Managed by vpn-kis: NetworkManager dispatcher hook. Retargets the\n"
       "# kill-switch DROP rule when the physical interface changes and\n"
       "# refreshes the tailnet bypass on tailscale events.\n"
       "exec " (exec/sh-quote self-path) " nm-dispatch \"$1\" \"$2\"\n"))

(defn- nm-present?
  "True when NetworkManager's dispatcher.d directory exists."
  [shell]
  (let [res (proto/shell-exec! shell ["test" "-d" dispatcher-dir] {})]
    (and (r/ok? res) (= 0 (-> res :ok :exit)))))

(defn install!
  "Write the hook (mode 755) when NetworkManager's dispatcher.d exists;
   otherwise warn and skip.

   Result<{:path .. :bytes .. :self-path ..}>, or
   Result<{:skipped :no-network-manager}>; err :nm-dispatcher/no-self-path
   (no launcher path), the :write-fn err, or :nm-dispatcher/chmod-failed."
  [system]
  (let [self  (or (:self-path system) (get-in system [:settings :self-path]))
        shell (:shell system)]
    (cond
      (str/blank? self)
      (r/err :nm-dispatcher/no-self-path
             {:hint "system has no :self-path: the command the dispatcher hook runs"})

      (not (nm-present? shell))
      (do (log/warn "NetworkManager not present, skipping IF-change hook.")
          (r/ok {:skipped :no-network-manager}))

      :else
      (let [_    (log/info "Installing NetworkManager dispatcher hook...")
            body (hook-text self)
            w    ((:write-fn system) dispatcher-path body)]
        (if (r/err? w)
          w
          (let [c (proto/shell-exec! shell ["chmod" "755" dispatcher-path] {})]
            (if (and (r/ok? c) (= 0 (-> c :ok :exit)))
              (do (log/info "Hook installed: " dispatcher-path)
                  (r/ok {:path dispatcher-path :bytes (count body) :self-path self}))
              (r/err :nm-dispatcher/chmod-failed
                     {:hint (str "chmod 755 " dispatcher-path " failed")
                      :cause c}))))))))

(defn remove!
  "Delete the hook, best-effort (bash `rm -f ... || true`): always
   Result<{:path .. :removed? bool}>, :removed? false when the delete
   failed."
  [system]
  (let [d ((:delete-fn system) dispatcher-path)]
    (r/ok {:path dispatcher-path :removed? (r/ok? d)})))
