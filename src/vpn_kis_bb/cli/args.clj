(ns vpn-kis-bb.cli.args
  "Pure: command-line parsing with the bash grammar of vpn-firewall-setup.sh.

   Global flags are taken from anywhere before a `--` token:
     --lan CIDRS          --lan=CIDRS          (alias --lan-allow)
     --physical-iface IF  --physical-iface=IF
     --dry-run
   A --lan value may hold several space-separated CIDRs; repeated --lan
   flags add up. The first remaining word is the command (default
   \"setup\"); the rest are its arguments, with `--` and everything after
   it passed through untouched (exclude run needs them verbatim)."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.re :as rx]))

(def ^:private value-flags
  {"--lan"            :lan
   "--lan-allow"      :lan
   "--physical-iface" :physical-iface})

(def ^:private switch-flags
  {"--dry-run" :dry-run?})

(def default-command "setup")

(defn- words [s]
  (if (str/blank? s) [] (rx/split* (str/trim s) #"\s+")))

(defn- split-eq
  "\"--k=v\" -> [\"--k\" \"v\"], or nil without an `=`."
  [arg]
  (when-let [i (str/index-of arg "=")]
    [(subs arg 0 i) (subs arg (inc i))]))

(defn- add-value [opts k v]
  (if (= k :lan)
    (update opts :lan (fnil into []) (words v))
    (assoc opts k v)))

(defn- missing-value [flag]
  (if (= :lan (value-flags flag))
    (str flag " requires a CIDR (or quoted, space-separated CIDRs)")
    (str flag " requires a value")))

(defn parse
  "argv -> {:cmd s :args [s ...] :opts {:lan [cidr ...] :physical-iface s
   :dry-run? true}} (absent opts are left out), or {:error msg}."
  [argv]
  (loop [in (vec argv) out [] opts {}]
    (if (empty? in)
      {:cmd  (or (first out) default-command)
       :args (vec (rest out))
       :opts opts}
      (let [a    (first in)
            more (subvec in 1)
            [ek ev] (split-eq a)]
        (cond
          (= "--" a)
          (recur [] (into (conj out a) more) opts)

          (contains? switch-flags a)
          (recur more out (assoc opts (switch-flags a) true))

          (contains? value-flags a)
          (if (empty? more)
            {:error (missing-value a)}
            (recur (subvec more 1) out (add-value opts (value-flags a) (first more))))

          (contains? value-flags ek)
          (recur more out (add-value opts (value-flags ek) ev))

          :else
          (recur more (conj out a) opts))))))
