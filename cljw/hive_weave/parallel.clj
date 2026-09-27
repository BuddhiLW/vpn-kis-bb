(ns hive-weave.parallel
  "cljw stand-in for hive-weave.parallel: bounded-pmap only.

   Same contract as the Semaphore-based original: at most :concurrency
   items in flight, each bounded by :timeout-ms, and a timed-out or
   failed item yields :fallback. Results keep input order.")

(defn- run-item [f timeout-ms fallback item]
  (future
    (let [inner  (future (try (f item) (catch Throwable _ ::failed)))
          result (deref inner timeout-ms ::timed-out)]
      (cond
        (= result ::timed-out) (do (future-cancel inner) fallback)
        (= result ::failed)    fallback
        :else                  result))))

(defn bounded-pmap
  [{:keys [concurrency timeout-ms fallback]
    :or   {concurrency 4 timeout-ms 10000 fallback nil}}
   f coll]
  (if (empty? coll)
    []
    (->> (partition-all (max 1 concurrency) coll)
         (mapcat (fn [batch]
                   (mapv deref (mapv #(run-item f timeout-ms fallback %) batch))))
         vec)))
