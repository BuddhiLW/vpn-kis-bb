(ns vpn-kis-bb.adapters.dnsmasq-shell
  "ShellDnsmasq — IDnsmasq impl via filesystem writes + systemctl/SIGHUP.

   Reload strategy:
     1. If `dnsmasq.service` is active, `systemctl reload dnsmasq`.
     2. Else if a `dnsmasq` process is running (e.g. NM-spawned),
        `pkill -HUP -x dnsmasq`.
     3. Else: nothing to reload — return ok with a hint."
  (:require [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.ports.dnsmasq :as port]))

(def drop-in-dir "/etc/dnsmasq.d")

(defn- run [shell cmd]
  (let [resp (proto/shell-exec! shell cmd {})]
    (if (r/err? resp) resp (r/ok (:ok resp)))))

(defn- exit0? [shell cmd]
  (let [resp (proto/shell-exec! shell cmd {})]
    (and (r/ok? resp) (zero? (-> resp :ok :exit)))))

(defrecord ShellDnsmasq [shell write-fn delete-fn]
  port/IDnsmasq
  (-write-drop-in! [_ drop-in-name body]
    (write-fn (str drop-in-dir "/" drop-in-name) body))

  (-remove-drop-in! [_ drop-in-name]
    (delete-fn (str drop-in-dir "/" drop-in-name)))

  (-reload! [_]
    (cond
      (exit0? shell ["systemctl" "is-active" "--quiet" "dnsmasq"])
      (run shell ["systemctl" "reload" "dnsmasq"])

      (exit0? shell ["pgrep" "-x" "dnsmasq"])
      (run shell ["pkill" "-HUP" "-x" "dnsmasq"])

      :else
      (r/ok {:reloaded? false
             :hint "no dnsmasq process detected — drop-in written; install dnsmasq or enable NM dnsmasq plugin"}))))

(defn- default-write [path body]
  (try
    (fs/create-dirs (fs/parent path))
    (spit path body)
    (r/ok {:path path :bytes (count body)})
    (catch Throwable t
      (r/err :dnsmasq/write-failed {:path path :cause (str t)}))))

(defn- default-delete [path]
  (try
    (fs/delete-if-exists path)
    (r/ok {:path path})
    (catch Throwable t
      (r/err :dnsmasq/delete-failed {:path path :cause (str t)}))))

(defn make
  ([shell] (make shell {}))
  ([shell {:keys [write-fn delete-fn]
           :or   {write-fn default-write
                  delete-fn default-delete}}]
   (->ShellDnsmasq shell write-fn delete-fn)))
