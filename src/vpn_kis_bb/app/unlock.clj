(ns vpn-kis-bb.app.unlock
  "Non-destructive rollback. Restores UFW config from the latest
   /etc/ufw/backup-* snapshot, removes the NetworkManager dispatcher
   hook, drops the vpn_endpoints ipset, and reloads UFW.

   Bash equivalent: `unlock_firewall` (vpn-firewall-setup.sh ~line 445)."
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.ports.ipset :as ipset-port]))

(def backup-glob "/etc/ufw/backup-*")
(def restore-files
  ["user.rules" "user6.rules" "before.rules" "before6.rules" "after.rules"])

(defn latest-backup
  "Pure-ish (filesystem only): find the most recent /etc/ufw/backup-*
   directory by name (timestamp-suffixed). Returns the path or nil."
  []
  (->> (fs/glob "/etc/ufw" "backup-*")
       (filter fs/directory?)
       (map str)
       sort
       last))

(defn- run [shell cmd]
  (let [resp (proto/shell-exec! shell cmd {})]
    (if (r/err? resp) resp (r/ok (:ok resp)))))

(defn unlock!
  "Restore UFW from the latest snapshot.

   system: requires :shell :ipset :write-fn :delete-fn.
   opts:   {:dry-run? bool}"
  [system {:keys [dry-run?] :as _opts}]
  (let [backup (latest-backup)]
    (cond
      (nil? backup)
      (r/err :unlock/no-backup
             {:hint "No /etc/ufw/backup-* found. Use 'panic' for hard reset."})

      dry-run?
      (r/ok {:dry-run? true
             :backup backup
             :will-restore (mapv #(str backup "/" %) restore-files)
             :will-remove ["/etc/NetworkManager/dispatcher.d/90-vpn-killswitch"
                           "/etc/ufw/before.init"
                           "/etc/ipset.conf"]})

      :else
      (let [{:keys [shell ipset write-fn delete-fn]} system]
        (doseq [f restore-files
                :let [src (str backup "/" f)]
                :when (fs/exists? src)]
          (write-fn (str "/etc/ufw/" f) (slurp src)))
        (delete-fn "/etc/NetworkManager/dispatcher.d/90-vpn-killswitch")
        (delete-fn "/etc/ufw/before.init")
        (delete-fn "/etc/ipset.conf")
        (ipset-port/-destroy! ipset "vpn_endpoints")
        (run shell ["ufw" "reload"])
        (r/ok {:restored backup})))))
