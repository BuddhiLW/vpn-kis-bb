(ns test-runner
  "Babashka-native test runner. Discovers and runs all `*-test` namespaces
   under test/ via classpath scanning. Used by `bb test`."
  (:require [clojure.test :as t]
            [babashka.classpath :as cp]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(defn- discover-test-ns-files []
  (let [roots (->> (cp/split-classpath (cp/get-classpath))
                   (map io/file)
                   (filter #(.isDirectory ^java.io.File %)))]
    (for [^java.io.File root roots
          ^java.io.File f (file-seq root)
          :let [path (.getPath f)]
          :when (and (.isFile f)
                     (str/ends-with? path "_test.clj"))
          :let [rel (.relativize (.toPath root) (.toPath f))
                ns-sym (-> (str rel)
                           (str/replace #"\.clj$" "")
                           (str/replace "/" ".")
                           (str/replace "_" "-")
                           symbol)]]
      ns-sym)))

(defn -main [& _]
  (let [nss (vec (sort (set (discover-test-ns-files))))]
    (when (seq nss)
      (apply require nss))
    (let [r (apply t/run-tests nss)]
      (System/exit (if (and (zero? (:fail r)) (zero? (:error r))) 0 1)))))
