(ns vpn-kis-bb.adapters.exec
  "Hand the terminal to another program (bash `exec`), portably.

   Neither cljw nor a captured IShell can replace the current process, so
   the launcher (bin/vpn-kis) passes VPN_KIS_EXEC_FILE: we write a tiny
   shell script there and exit; the launcher sources it, which runs the
   optional cgroup join and then `exec`s the command in the launcher's own
   process. The PID is kept, so a cgroup joined by `echo $$` holds for
   the exec'd command (what `exclude run` relies on)."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]))

(defn sh-quote
  "Pure: single-quote s for POSIX sh."
  [s]
  (str "'" (str/replace (str s) "'" "'\\''") "'"))

(defn exec-script
  "Pure: the script the launcher sources.
   opts: {:cgroup-procs \"/sys/fs/cgroup/x/cgroup.procs\"} joins that
   cgroup first (fails closed: the command never runs outside it)."
  [argv {:keys [cgroup-procs]}]
  (str "rm -f \"$VPN_KIS_EXEC_FILE\"\n"
       (when cgroup-procs
         (str "echo $$ > " (sh-quote cgroup-procs)
              " || { echo 'vpn-kis: cannot join cgroup " cgroup-procs "' >&2; exit 1; }\n"))
       "exec " (str/join " " (map sh-quote argv)) "\n"))

(defn exec!
  "Arrange for argv to replace the launcher process. Returns Result;
   (err :exec/no-launcher) when not started through bin/vpn-kis."
  [{:keys [settings write-fn]} argv opts]
  (if-let [f (:exec-file settings)]
    (let [w (write-fn f (exec-script argv opts))]
      (if (r/err? w) w (r/ok {:exec argv :via f})))
    (r/err :exec/no-launcher
           {:hint "run through bin/vpn-kis (or vpn-firewall-setup.sh) so the command can take over the terminal"
            :argv argv})))
