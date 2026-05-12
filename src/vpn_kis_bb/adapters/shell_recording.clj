(ns vpn-kis-bb.adapters.shell-recording
  "RecordingShell — IShell impl that captures every invocation into an
   atom instead of actually executing it. Two use cases:

   1. Unit tests: assert the exact shell sequence an adapter emits.
   2. `--dry-run` mode: print the plan to stdout before running anything
      privileged.

   Optional :responses map: keyed by the first arg (the command string or
   the first element of a vector). Values are the maps returned. Anything
   not in the map gets a default 0-exit ok response."
  (:require [hive-dsl.result :as r]
            [hive-system.protocols :as proto]))

(defn- key-of-cmd [cmd]
  (if (vector? cmd)
    (first cmd)
    (-> (str cmd) (clojure.string/split #"\s+") first)))

(defrecord RecordingShell [calls responses]
  proto/IShell
  (shell-exec! [_ cmd opts]
    (swap! calls conj {:cmd cmd :opts opts})
    (let [k (key-of-cmd cmd)
          override (get responses k)]
      (r/ok (merge {:exit 0 :stdout "" :stderr "" :duration-ms 0 :cmd cmd}
                   (or override {})))))
  (shell-env [_] (into {} (System/getenv)))
  (shell-which [_ program]
    (r/ok {:path (str "/usr/bin/" program)})))

(defn make
  "Construct a RecordingShell.

   opts: {:responses {<cmd-key-str> {:exit N :stdout S :stderr S}}}
   The :calls atom is exposed on the returned record so tests can read it."
  ([]              (make {}))
  ([{:keys [responses]}] (->RecordingShell (atom []) (or responses {}))))

(defn calls
  "Read recorded invocations from a RecordingShell."
  [shell]
  @(:calls shell))

(defn reset! [shell]
  (clojure.core/reset! (:calls shell) []))
