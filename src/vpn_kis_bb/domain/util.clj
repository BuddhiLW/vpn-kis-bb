(ns vpn-kis-bb.domain.util
  "Pure helpers: IPv4 validation, normalization, set merge."
  (:require [clojure.string :as str]))

(defn split-on
  "s split at every occurrence of the string sep, empty parts kept (like
   str/split with limit -1). Regex-free: cljw corrupts regex split results
   intermittently."
  [s sep]
  (loop [start 0 acc []]
    (if-let [i (str/index-of s sep start)]
      (recur (+ i (count sep)) (conj acc (subs s start i)))
      (conj acc (subs s start)))))

(defn- octet?
  "1 to 3 ASCII digits with a value in [0,255]."
  [p]
  (and (<= 1 (count p) 3)
       (every? #(<= 48 (int %) 57) p)
       (<= (parse-long p) 255)))

(defn ipv4?
  "True if s is a dotted quad with each octet in [0,255]. Regex-free: this
   runs once per endpoint IP and cljw corrupts regex results intermittently."
  [s]
  (boolean
   (and (string? s)
        (let [parts (split-on s ".")]
          (and (= 4 (count parts))
               (every? octet? parts))))))

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

;; ---------------------------------------------------------------- time
;; Portable (bb + cljw) UTC timestamps. cljw has no java.time, so civil
;; date conversion is done by hand (Howard Hinnant's days->civil).

(defn- floor-div [a b]
  (let [q (quot a b)]
    (if (and (not (zero? (rem a b))) (neg? (* (compare a 0) (compare b 0))))
      (dec q)
      q)))

(defn- pad [n width]
  (let [s (str n)]
    (str (apply str (repeat (- width (count s)) "0")) s)))

(defn epoch-ms->iso8601
  "Pure: epoch milliseconds -> \"YYYY-MM-DDTHH:MM:SSZ\" (UTC)."
  [ms]
  (let [secs (floor-div ms 1000)
        days (floor-div secs 86400)
        sod  (- secs (* days 86400))
        z    (+ days 719468)
        era  (floor-div z 146097)
        doe  (- z (* era 146097))
        yoe  (quot (- doe (quot doe 1460) (- (quot doe 36524)) (quot doe 146096)) 365)
        doy  (- doe (+ (* 365 yoe) (quot yoe 4) (- (quot yoe 100))))
        mp   (quot (+ (* 5 doy) 2) 153)
        d    (inc (- doy (quot (+ (* 153 mp) 2) 5)))
        m    (if (< mp 10) (+ mp 3) (- mp 9))
        y    (+ yoe (* era 400) (if (<= m 2) 1 0))]
    (str (pad y 4) "-" (pad m 2) "-" (pad d 2) "T"
         (pad (quot sod 3600) 2) ":" (pad (quot (rem sod 3600) 60) 2) ":" (pad (rem sod 60) 2)
         "Z")))

(defn now-iso
  "Current time as an ISO-8601 UTC string."
  []
  (epoch-ms->iso8601 (System/currentTimeMillis)))
