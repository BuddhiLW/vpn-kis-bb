(ns vpn-kis-bb.adapters.nm-dispatcher
  "Install / remove the NetworkManager dispatcher hook that retargets the
   kill-switch DROP rule when the physical interface changes (dock/undock,
   wifi<->ethernet).

   The hook script body lives in resources/ — bash, not Clojure — so the
   logic can be audited under `bash -x` exactly like the original."
  (:require [clojure.java.io :as io]
            [hive-dsl.result :as r]))

(def dispatcher-path "/etc/NetworkManager/dispatcher.d/90-vpn-killswitch")
(def hook-resource   "nm-dispatcher-90-vpn-killswitch.sh")

(defn hook-body
  "Pure: read the bundled hook script as a string."
  []
  (when-let [u (io/resource hook-resource)]
    (slurp u)))

(defn install!
  "Write the dispatcher hook + chmod 755. Uses the system's :write-fn
   for the file write and the :shell for chmod."
  [{:keys [write-fn shell]}]
  (if-let [body (hook-body)]
    (let [w (write-fn dispatcher-path body)]
      (if (r/err? w)
        w
        (do ((requiring-resolve 'hive-system.protocols/shell-exec!)
             shell ["chmod" "755" dispatcher-path] {})
            (r/ok {:path dispatcher-path :bytes (count body)}))))
    (r/err :nm-dispatcher/missing-resource {})))

(defn remove! [{:keys [delete-fn]}]
  (delete-fn dispatcher-path))
