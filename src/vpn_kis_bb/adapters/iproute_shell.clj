(ns vpn-kis-bb.adapters.iproute-shell
  "ShellIpRoute — IIpRoute impl via `ip rule` / `ip route` CLI.

   The parser for `ip rule show` lives in domain.priority; this adapter
   just wires the shell capture into that pure function."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.domain.priority :as priority]
            [vpn-kis-bb.ports.iproute :as port]))

(defn- run [shell cmd]
  (let [resp (proto/shell-exec! shell cmd {})]
    (cond
      (r/err? resp)              resp
      (zero? (-> resp :ok :exit)) (r/ok (:ok resp))
      :else                      (r/err :iproute/non-zero-exit (:ok resp)))))

(defn- run-soft
  "Like run but does NOT raise on non-zero exit. Used for idempotent
   teardowns where 'no such rule' is a success state, not an error."
  [shell cmd]
  (let [resp (proto/shell-exec! shell cmd {})]
    (if (r/err? resp) resp (r/ok (:ok resp)))))

(defrecord ShellIpRoute [shell]
  port/IIpRoute
  (-rule-show [_]
    (let [resp (run shell ["ip" "rule" "show"])]
      (if (r/err? resp)
        resp
        (r/ok (priority/parse-ip-rule-output (-> resp :ok :stdout))))))

  (-rule-add! [_ {:keys [fwmark to lookup priority]}]
    (let [args (cond-> ["ip" "rule" "add"]
                 fwmark   (into ["fwmark" (str fwmark)])
                 to       (into ["to" (str to)])
                 lookup   (into ["lookup" (str lookup)])
                 priority (into ["priority" (str priority)]))]
      (run shell args)))

  (-rule-del! [_ priority]
    ;; idempotent — best-effort drop
    (run-soft shell ["ip" "rule" "del" "priority" (str priority)]))

  (-route-add! [_ {:keys [dst dev table]}]
    (run shell ["ip" "route" "add" (str dst) "dev" (str dev) "table" (str table)]))

  (-route-replace-default! [_ {:keys [dev table]}]
    (run shell ["ip" "route" "replace" "default" "dev" (str dev) "table" (str table)]))

  (-table-flush! [_ table]
    (run-soft shell ["ip" "route" "flush" "table" (str table)])))

(defn make
  ([shell] (->ShellIpRoute shell)))
