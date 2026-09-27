(ns vpn-kis-bb.domain.util
  "Pure helpers: IPv4 validation, normalization, set merge."
  (:require [clojure.string :as str]))

(def ipv4-re #"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$")

(defn ipv4?
  "True if s parses as a dotted-quad with each octet in [0,255]."
  [s]
  (when (string? s)
    (when-let [m (re-matches ipv4-re s)]
      (every? #(<= 0 (Long/parseLong %) 255) (rest m)))))

(defn normalize-ips
  "Coerce a collection of strings (possibly with whitespace/comments) into a
   sorted set of unique valid IPv4 addresses. Drops blanks, comments, and
   anything that doesn't match `ipv4?`."
  [coll]
  (into (sorted-set)
        ;; `str` first so non-string inputs (e.g. a numeric IP field from a
        ;; provider's JSON) coerce to a string and get rejected by ipv4?
        ;; rather than throwing ClassCastException inside str/trim.
        (comp (map #(some-> % str str/trim))
              (remove (some-fn nil? str/blank? #(str/starts-with? % "#")))
              (filter ipv4?))
        coll))

(defn merge-ip-sets
  "Union of any number of IP collections, normalized."
  [& colls]
  (normalize-ips (apply concat colls)))
