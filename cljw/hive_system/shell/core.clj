(ns hive-system.shell.core
  "cljw stand-in for hive-system.shell.core: IShell over clojure.java.shell.

   Same contract as the ProcessBuilder original:
     - a string cmd runs under `sh -c`, a vector runs as argv
     - opts :dir, :env (merged OVER the current environment), :timeout-ms
       (default 30s)
     - returns (ok {:exit :stdout :stderr :duration-ms :cmd}); a non-zero
       exit is still ok, callers inspect :exit
     - a timeout is (err :shell/timeout {...})
   Extension: opts :in feeds the string to stdin (cljw's sh supports it).

   The timeout is enforced with coreutils `timeout`, so a hung command is
   actually killed rather than abandoned in a background future. A missing
   binary surfaces as exit 127 from `timeout` instead of an exception."
  (:require [clojure.java.shell :as sh]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]))

(def ^:private default-timeout-ms 30000)
(def ^:private kill-grace-secs "5")

(defn- argv-of [cmd]
  (if (string? cmd) ["sh" "-c" cmd] (mapv str cmd)))

(defn- env-of [extra]
  (when (seq extra)
    (into (into {} (System/getenv))
          (map (fn [[k v]] [(str k) (str v)]))
          extra)))

(defn- timeout-secs [ms]
  (str (max 1 (quot (+ (long ms) 999) 1000))))

(defn- run-argv
  "Run argv under `timeout`; returns the clojure.java.shell result map."
  [argv {:keys [dir env in timeout-ms]}]
  (let [wrapped (into ["timeout" "-k" kill-grace-secs
                       (timeout-secs (or timeout-ms default-timeout-ms))]
                      argv)
        kw-opts (cond-> []
                  dir         (into [:dir (str dir)])
                  (some? in)  (into [:in (str in)])
                  (env-of env) (into [:env (env-of env)]))]
    (apply sh/sh (concat wrapped kw-opts))))

(defrecord Shell [default-opts]
  proto/IShell
  (shell-exec! [_ cmd opts]
    (let [opts  (merge default-opts opts)
          start (System/nanoTime)]
      (try
        (let [{:keys [exit out err]} (run-argv (argv-of cmd) opts)
              duration-ms (/ (- (System/nanoTime) start) 1e6)]
          (if (= 124 exit)
            (r/err :shell/timeout {:cmd cmd
                                   :timeout-ms (or (:timeout-ms opts) default-timeout-ms)
                                   :duration-ms duration-ms})
            (r/ok {:exit        exit
                   :stdout      (or out "")
                   :stderr      (or err "")
                   :duration-ms duration-ms
                   :cmd         cmd})))
        (catch Throwable t
          (r/err :shell/exec-failed {:cmd cmd :message (ex-message t)})))))

  (shell-env [_]
    (into {} (System/getenv)))

  (shell-which [_ program]
    (let [{:keys [exit out]} (sh/sh "sh" "-c" "command -v \"$1\"" "sh" (str program))
          path (str/trim (or out ""))]
      (if (and (zero? exit) (seq path))
        (r/ok {:path path})
        (r/err :shell/not-found {:program program})))))

(defn make-shell
  "Create a Shell instance with optional default opts (:dir :env :timeout-ms)."
  ([] (make-shell {}))
  ([opts] (->Shell opts)))

(def ^:private default-shell (delay (make-shell)))

(defn exec!
  "Execute a shell command with the default shell. Returns Result."
  ([cmd] (exec! cmd {}))
  ([cmd opts] (proto/shell-exec! @default-shell cmd opts)))

(defn exec-ok!
  "Like exec! but returns (err :shell/non-zero-exit ...) on a non-zero exit."
  ([cmd] (exec-ok! cmd {}))
  ([cmd opts]
   (let [result (exec! cmd opts)]
     (if (r/err? result)
       result
       (let [{:keys [exit] :as v} (:ok result)]
         (if (zero? exit)
           (r/ok v)
           (r/err :shell/non-zero-exit v)))))))
