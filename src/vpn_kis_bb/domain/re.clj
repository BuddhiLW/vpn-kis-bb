(ns vpn-kis-bb.domain.re
  "Regex operations that are stable on ClojureWasm 1.14.11, whose regex
   results are intermittently corrupted: capture groups, and also plain
   splits once different regexes interleave (hive memory
   20260927161240-0a22ae62). Each wrapper repeats the operation until two
   answers agree."
  (:require [clojure.string :as str]))

(def ^:private max-attempts 8)

(defn- stable [f]
  (loop [prev (f) n 1]
    (let [cur (f)]
      (if (or (= prev cur) (>= n max-attempts))
        cur
        (recur cur (inc n))))))

(defn re-find*
  "re-find, stable against cljw's capture-group corruption."
  [re s]
  (stable #(re-find re s)))

(defn re-matches*
  "re-matches, stable against cljw's capture-group corruption."
  [re s]
  (stable #(re-matches re s)))

(defn group
  "Capture group n of (re-find* re s), or nil when there is no match."
  [re s n]
  (let [m (re-find* re s)]
    (when (vector? m) (nth m n nil))))

(defn split*
  "clojure.string/split, stable against cljw's regex corruption."
  ([s re] (stable #(str/split s re)))
  ([s re limit] (stable #(str/split s re limit))))

(defn re-seq*
  "re-seq realized to a vector, stable against cljw's regex corruption."
  [re s]
  (stable #(vec (re-seq re s))))

(defn replace*
  "clojure.string/replace, stable against cljw's regex corruption."
  [s match replacement]
  (stable #(str/replace s match replacement)))

(defn split-lines*
  "clojure.string/split-lines, stable against cljw's regex corruption."
  [s]
  (stable #(str/split-lines s)))
