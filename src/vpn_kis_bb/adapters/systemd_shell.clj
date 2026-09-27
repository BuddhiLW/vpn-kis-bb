(ns vpn-kis-bb.adapters.systemd-shell
  "ShellSystemdUnit: ISystemdUnit over systemctl and unit-file writes.

   Unit files go through the :write-fn / :delete-fn the caller supplies
   (tests record them), else a plain spit / delete fallback. Privileged
   write paths land under /etc/systemd/system/."
  (:require [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.ports.systemd :as port]))

(def unit-dir "/etc/systemd/system")

(defn- run [shell cmd]
  (let [resp (proto/shell-exec! shell cmd {})]
    (cond
      (r/err? resp)              resp
      (zero? (-> resp :ok :exit)) (r/ok (:ok resp))
      :else                      (r/err :systemd/non-zero-exit (:ok resp)))))

(defn- run-exit
  "Run and return Result<bool> based on exit==0."
  [shell cmd]
  (let [resp (proto/shell-exec! shell cmd {})]
    (if (r/err? resp) resp (r/ok (zero? (-> resp :ok :exit))))))

(defrecord ShellSystemdUnit [shell write-fn delete-fn]
  port/ISystemdUnit
  (-write! [_this unit-name body]
    (write-fn (str unit-dir "/" unit-name) body))

  (-remove! [_this unit-name]
    (delete-fn (str unit-dir "/" unit-name)))

  (-enable! [_this unit-name]
    (run shell ["systemctl" "enable" unit-name]))

  (-start! [_this unit-name]
    (run shell ["systemctl" "start" unit-name]))

  (-disable! [_this unit-name]
    (run shell ["systemctl" "disable" "--now" unit-name]))

  (-daemon-reload! [_this]
    (run shell ["systemctl" "daemon-reload"]))

  (-active? [_this unit-name]
    (run-exit shell ["systemctl" "is-active" "--quiet" unit-name]))

  (-enabled? [_this unit-name]
    (run-exit shell ["systemctl" "is-enabled" "--quiet" unit-name])))

(defn- default-write [path body]
  (try
    (fs/create-dirs (fs/parent path))
    (spit path body)
    (r/ok {:path path :bytes (count body)})
    (catch Throwable t
      (r/err :systemd/write-failed {:path path :cause (str t)}))))

(defn- default-delete [path]
  (try
    (fs/delete-if-exists path)
    (r/ok {:path path})
    (catch Throwable t
      (r/err :systemd/delete-failed {:path path :cause (str t)}))))

(defn make
  "Build a systemd adapter. Optional :write-fn / :delete-fn let tests
   substitute the side effects."
  ([shell] (make shell {}))
  ([shell {:keys [write-fn delete-fn]
           :or   {write-fn default-write
                  delete-fn default-delete}}]
   (->ShellSystemdUnit shell write-fn delete-fn)))
