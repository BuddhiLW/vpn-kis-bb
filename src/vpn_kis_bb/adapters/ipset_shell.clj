(ns vpn-kis-bb.adapters.ipset-shell
  "ShellIpset — IIpset impl via the `ipset` CLI.

   All operations are idempotent: create uses -exist, add uses -exist,
   destroy is best-effort. Bulk-load goes through stdin to `ipset restore`
   so loading thousands of IPs is a single syscall batch."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.ports.ipset :as port]
            [vpn-kis-bb.domain.re :as rx]))

(defn- run [shell cmd]
  (let [resp (proto/shell-exec! shell cmd {})]
    (cond
      (r/err? resp)              resp
      (zero? (-> resp :ok :exit)) (r/ok (:ok resp))
      :else                      (r/err :ipset/non-zero-exit (:ok resp)))))

(defn- run-stdin [shell cmd stdin]
  ;; ProcessBuilder route doesn't expose stdin cleanly; use sh -c with
  ;; heredoc-equivalent via printf piping. This works in both real bb and
  ;; under recording (recording shell just captures the cmd string).
  (let [encoded (clojure.string/escape stdin {\' "'\\''"})
        sh-cmd  (str "printf '%s' '" encoded "' | " (if (vector? cmd) (str/join " " cmd) cmd))]
    (run shell ["sh" "-c" sh-cmd])))

(defrecord ShellIpset [shell]
  port/IIpset
  (-create! [_ set-name {:keys [family hashsize maxelem timeout]
                          :or {family "inet" hashsize 2048 maxelem 65536}}]
    (let [args ["ipset" "create" set-name
                "hash:ip" "family" family
                "hashsize" (str hashsize)
                "maxelem" (str maxelem)]
          args (if timeout (conj args "timeout" (str timeout)) args)
          args (conj args "-exist")]
      (run shell args)))

  (-add! [_ set-name ip]
    (run shell ["ipset" "add" set-name ip "-exist"]))

  (-add-bulk! [_ set-name ips]
    (when (seq ips)
      (let [lines (concat
                   [(str "create " set-name " hash:ip family inet hashsize 2048 maxelem 65536 -exist")]
                   (for [ip ips] (str "add " set-name " " ip " -exist"))
                   [""])
            payload (str/join "\n" lines)]
        (run-stdin shell ["ipset" "restore" "-exist"] payload))))

  (-list [_ set-name]
    (let [resp (run shell ["ipset" "list" set-name])]
      (if (r/err? resp)
        resp
        (let [out (-> resp :ok :stdout)
              ips (->> (rx/split-lines* out)
                       (drop-while #(not (str/starts-with? % "Members:")))
                       (drop 1)
                       (map str/trim)
                       (remove str/blank?)
                       (into #{}))]
          (r/ok ips)))))

  (-destroy! [_ set-name]
    ;; Best-effort: ipset destroy returns non-zero if the set doesn't exist;
    ;; we don't treat that as an error so callers can use this idempotently.
    (let [resp (proto/shell-exec! shell ["ipset" "destroy" set-name] {})]
      (r/ok (:ok resp))))

  (-save [_ set-name out-path]
    (run shell ["sh" "-c"
                (str "ipset save " set-name " > " out-path)]))

  (-restore! [_ in-path]
    (run shell ["sh" "-c"
                (str "ipset restore -exist < " in-path)])))

(defn make
  ([shell] (->ShellIpset shell)))
