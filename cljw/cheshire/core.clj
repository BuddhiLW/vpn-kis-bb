(ns cheshire.core
  "cljw stand-in for cheshire.core over clojure.data.json (bundled in cljw).
   Covers parse-string (with the key-fn / keywordize flag) and
   generate-string."
  (:require [clojure.data.json :as json]))

(defn parse-string
  "JSON string -> data. key-fn: true keywordizes, a fn maps each key."
  ([s] (parse-string s nil))
  ([s key-fn]
   (when s
     (cond
       (true? key-fn) (json/read-str s :key-fn keyword)
       (fn? key-fn)   (json/read-str s :key-fn key-fn)
       :else          (json/read-str s)))))

(defn generate-string
  "Data -> JSON string (keyword keys become their names)."
  ([data] (json/write-str data))
  ([data _opts] (json/write-str data)))
