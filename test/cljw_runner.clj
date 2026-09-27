(ns cljw-runner
  "ClojureWasm test runner: the same `*_test.clj` suite `bb test` runs,
   executed on cljw with the compat layer mounted:

     cljw -cp cljw:src:test -m cljw-runner [ns-substring ...]

   Namespaces that exercise JVM-only adapters are skipped here (they
   still run under bb)."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :as t]))

(def jvm-only
  "Test namespaces for adapters that need java.net / java.net.http."
  #{'vpn-kis-bb.adapters.http-test
    'vpn-kis-bb.adapters.dns-test})

(defn- test-files [^java.io.File dir]
  (when (.isDirectory dir)
    (mapcat (fn [^java.io.File f]
              (cond
                (.isDirectory f) (test-files f)
                (str/ends-with? (.getName f) "_test.clj") [f]
                :else nil))
            (.listFiles dir))))

(defn- file->ns [root ^java.io.File f]
  (-> (subs (.getPath f) (inc (count root)))
      (str/replace #"\.clj$" "")
      (str/replace "/" ".")
      (str/replace "_" "-")
      symbol))

(defn discover [root]
  (->> (test-files (io/file root))
       (map #(file->ns root %))
       (remove jvm-only)
       sort
       vec))

(defn -main [& filters]
  (let [nss (cond->> (discover "test")
              (seq filters) (filter (fn [ns-sym]
                                      (some #(str/includes? (str ns-sym) %) filters))))]
    (doseq [n nss] (require n))
    (let [{:keys [fail error] :as summary} (apply t/run-tests nss)]
      (println (str "cljw: " (:test summary) " tests, "
                    (:pass summary) " passed, " fail " failed, " error " errors"))
      (System/exit (if (and (zero? fail) (zero? error)) 0 1)))))
