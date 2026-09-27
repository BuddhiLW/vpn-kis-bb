(ns hive-weave.safe
  "cljw stand-in for hive-weave.safe: safe-future-call only."
  (:require [hive-dsl.result :as r]))

(defn safe-future-call
  "Execute f in a future with timeout. Returns Result:
   (ok value), (err :weave/timeout {...}) or (err :weave/exception {...})."
  [{:keys [timeout-ms name] :or {name "anonymous"}} f]
  (let [fut    (future
                 (try
                   (f)
                   (catch Throwable t
                     {::exception t})))
        result (deref fut timeout-ms ::timed-out)]
    (cond
      (= result ::timed-out)
      (do (future-cancel fut)
          (r/err :weave/timeout {:name name :timeout-ms timeout-ms}))

      (and (map? result) (::exception result))
      (r/err :weave/exception {:name    name
                               :message (ex-message (::exception result))})

      :else
      (r/ok result))))
