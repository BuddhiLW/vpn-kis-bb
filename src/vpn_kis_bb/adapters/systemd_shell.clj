(ns vpn-kis-bb.adapters.systemd-shell
  "ShellSystemdUnit — ISystemdUnit impl via systemctl + filesystem writes.

   File ops go through hive-system's IFilesystem when the caller supplies
   one (so tests can use an in-memory FS); else a plain spit/rm fallback
   is used. Privileged write paths land under /etc/systemd/system/."
  (:require [clojure.string :as str]
            [babashka.fs :as fs]
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
  (-write! [_ unit-name body]
    (write-fn (str unit-dir "/" unit-name) body))

  (-remove! [_ unit-name]
    (delete-fn (str unit-dir "/" unit-name)))

  (-enable! [_ unit-name]
    (run shell ["systemctl" "enable" unit-name]))

  (-disable! [_ unit-name]
    (run shell ["systemctl" "disable" "--now" unit-name]))

  (-daemon-reload! [_]
    (run shell ["systemctl" "daemon-reload"]))

  (-active? [_ unit-name]
    (run-exit shell ["systemctl" "is-active" "--quiet" unit-name]))

  (-enabled? [_ unit-name]
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
