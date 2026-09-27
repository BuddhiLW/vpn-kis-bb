(ns vpn-kis-bb.adapters.dnsmasq-shell
  "ShellDnsmasq: IDnsmasq over the filesystem (drop-ins through :write-fn /
   :delete-fn) and systemctl, pgrep, pkill and test through an IShell.

   Reload: reload (else restart) an active dnsmasq unit; else SIGHUP a
   dnsmasq process (NetworkManager's); else nothing to reload (ok, with a
   hint). Preflight: bash split_require_dnsmasq's checks."
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.ports.dnsmasq :as port]))

(def drop-in-dir "/etc/dnsmasq.d")

(def nm-plugin-conf
  "NetworkManager's dnsmasq plugin switch; when present, NM runs a dnsmasq."
  "/etc/NetworkManager/conf.d/dnsmasq.conf")

(defn- sh!
  "Run cmd: {:cmd :exit :stderr}; a shell err or a throw reads as exit -1."
  [shell cmd]
  (let [res (try (proto/shell-exec! shell cmd {})
                 (catch Throwable t (r/err :shell/threw {:message (str t)})))]
    (if (r/ok? res)
      {:cmd cmd :exit (let [e (-> res :ok :exit)] (if (some? e) e -1))
       :stderr (or (-> res :ok :stderr) "")}
      {:cmd cmd :exit -1 :stderr (str (or (:message res) (:error res)))})))

(defn- exit0? [shell cmd] (= 0 (:exit (sh! shell cmd))))

(defn- reload
  "bash: reload (else restart) an active dnsmasq unit, else SIGHUP a
   dnsmasq process, else nothing."
  [shell]
  (cond
    (exit0? shell ["systemctl" "is-active" "--quiet" "dnsmasq"])
    (if (exit0? shell ["systemctl" "reload" "dnsmasq"])
      (r/ok {:reloaded? true :via :systemctl-reload})
      (let [x (sh! shell ["systemctl" "restart" "dnsmasq"])]
        (if (= 0 (:exit x))
          (r/ok {:reloaded? true :via :systemctl-restart})
          (r/err :dnsmasq/reload-failed
                 {:hint   "dnsmasq: systemctl reload and restart both failed (see: journalctl -u dnsmasq)"
                  :exit   (:exit x)
                  :stderr (str/trim (:stderr x))}))))

    (exit0? shell ["pgrep" "-x" "dnsmasq"])
    (do (sh! shell ["pkill" "-HUP" "-x" "dnsmasq"])
        (r/ok {:reloaded? true :via :sighup}))

    :else
    (r/ok {:reloaded? false
           :hint      (str "no dnsmasq process detected: drop-in written; install dnsmasq"
                           " or enable the NetworkManager dnsmasq plugin")})))

(defn- preflight
  "bash split_require_dnsmasq's two checks, in its order."
  [shell]
  (let [dir? (exit0? shell ["test" "-d" drop-in-dir])]
    (r/ok {:drop-in-dir? dir?
           :fronted?     (when dir?
                           (not (and (exit0? shell ["systemctl" "is-active" "--quiet" "systemd-resolved"])
                                     (not (exit0? shell ["test" "-f" nm-plugin-conf]))
                                     (not (exit0? shell ["systemctl" "is-active" "--quiet" "dnsmasq"])))))})))

(defrecord ShellDnsmasq [shell write-fn delete-fn]
  port/IDnsmasq
  (-write-drop-in! [_this drop-in-name body]
    (write-fn (str drop-in-dir "/" drop-in-name) body))

  (-remove-drop-in! [_this drop-in-name]
    (delete-fn (str drop-in-dir "/" drop-in-name)))

  (-reload! [_this]
    (reload shell))

  (-preflight [_this]
    (preflight shell)))

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
