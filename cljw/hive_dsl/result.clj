(ns hive-dsl.result
  "cljw stand-in for hive-dsl.result (v0.5.1): the Result shape only.

   ok  results: {:ok value}
   err results: {:error category ...extra-data}")

(defn ok
  "Wrap a value in a success Result."
  [value]
  {:ok value})

(defn err
  "Create an error Result with category keyword and optional data map."
  ([category]
   {:error category})
  ([category data]
   (merge {:error category} data)))

(defn ok?
  "True if result is a success."
  [r]
  (and (map? r) (contains? r :ok)))

(defn err?
  "True if result is an error."
  [r]
  (and (map? r) (contains? r :error)))

(defn bind
  "Monadic bind: apply f to the unwrapped value of an ok result."
  [result f]
  (if (ok? result)
    (f (:ok result))
    result))
