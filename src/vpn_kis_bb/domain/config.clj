(ns vpn-kis-bb.domain.config
  "Config parsing for vpn-kis-bb.

   1. Project-wide  /etc/vpn-killswitch/config.edn (default-project-config).
   2. Split tunnels /etc/vpn-killswitch/split/<name>.conf in the bash
      KEY=VALUE format, read exactly as split_load_conf reads it (never
      sourced), or <name>.edn (a vpn-kis-bb extension, tried first).
      Validation lives in vpn-kis-bb.domain.split/validate.

   KEY=VALUE parsing uses index-of and string prefixes, no regex
   (ClojureWasm 1.14.11 corrupts some regex results)."
  (:require [babashka.fs :as fs]
            [clojure.edn :as edn]
            [clojure.string :as str]
            [vpn-kis-bb.domain.re :as rx]
            [vpn-kis-bb.domain.split :as split]))

(def default-project-config
  {:lan-allow      []
   :vpn-ports      {:udp [1194 443 53 51820 1300 1301 1302 1637 41641 3478]
                    :tcp [443]}
   :physical-iface nil})

(def split-keys
  "KEY=VALUE keys split_load_conf reads (case-sensitive), and their
   keywords; other keys are ignored."
  {"DOMAINS"     :domains
   "DEV"         :dev
   "TABLE"       :table
   "MARK"        :mark
   "PRIORITY"    :priority
   "OVPN_CONFIG" :ovpn-config})

(defn- strip-prefix [s x] (if (str/starts-with? s x) (subs s (count x)) s))

(defn- strip-suffix [s x] (if (str/ends-with? s x) (subs s 0 (- (count s) (count x))) s))

(defn unquote-value
  "bash split_load_conf's quote strip: one trailing then one leading double
   quote, then one trailing then one leading single quote."
  [v]
  (-> v
      (strip-suffix "\"")
      (strip-prefix "\"")
      (strip-suffix "'")
      (strip-prefix "'")))

(defn parse-key-value-line
  "[KEY value] for one line of a split conf as split_load_conf reads it:
   leading blanks allowed, `#` comment lines skipped, KEY one of split-keys
   written right before the first `=`, the value trimmed and unquoted.
   nil for any other line."
  [raw]
  (let [line (str/triml (or raw ""))
        i    (str/index-of line "=")]
    (when (and i (not (str/starts-with? line "#")))
      (let [k (subs line 0 i)]
        (when (contains? split-keys k)
          [k (unquote-value (str/trim (subs line (inc i))))])))))

(defn parse-key-value
  "The split keys (split-keys) of a KEY=VALUE text as a keyword map of
   strings; a later line wins, other keys are ignored."
  [s]
  (into {}
        (keep (fn [line]
                (when-let [[k v] (parse-key-value-line line)]
                  [(get split-keys k) v])))
        (rx/split-lines* (or s ""))))

(defn legacy->split-edn
  "The parsed KEY=VALUE map in the shape vpn-kis-bb.domain.split/validate
   takes: DOMAINS split on whitespace, TABLE and PRIORITY as longs when
   they are digits (PRIORITY \"auto\" as :auto). Blank values are dropped
   so the defaults apply (bash ${VAR:-default}); anything else is kept as
   written for validate to judge."
  [{:keys [name domains dev table mark priority ovpn-config]}]
  (let [present (fn [s] (when-not (str/blank? s) (str/trim s)))
        number  (fn [s] (if (split/digits? s) (or (parse-long s) s) s))]
    (cond-> {:name (or name "unnamed")}
      (present domains)     (assoc :domains (split/words domains))
      (present dev)         (assoc :dev (present dev))
      (present table)       (assoc :table (number (present table)))
      (present mark)        (assoc :mark (present mark))
      (present priority)    (assoc :priority (let [p (present priority)]
                                               (if (= "auto" p) :auto (number p))))
      (present ovpn-config) (assoc :ovpn-config (present ovpn-config)))))

(defn- read-file
  "File text, or nil when missing or unreadable."
  [path]
  (try
    (when (fs/exists? path) (slurp (str path)))
    (catch Throwable _unreadable-means-absent nil)))

(defn read-split-conf
  "Read split `name` from conf-dir: <name>.edn when it exists (an EDN map),
   else <name>.conf (KEY=VALUE, parse-key-value + legacy->split-edn).
   read-fn (path -> text or nil; default: the filesystem) is the seam
   tests stub.

   {:ok? true :value <map for domain.split/validate, :name set> :path p}
   or {:ok? false :error msg} with the bash messages: split: name
   required, split: name must match [a-zA-Z0-9_-]+, split: config not
   found: <conf-dir>/<name>.conf."
  ([conf-dir name] (read-split-conf conf-dir name read-file))
  ([conf-dir name read-fn]
   (cond
     (str/blank? (str name))
     {:ok? false :error "split: name required"}

     (not (split/valid-name? name))
     {:ok? false :error "split: name must match [a-zA-Z0-9_-]+"}

     :else
     (let [edn-path  (str conf-dir "/" name ".edn")
           conf-path (str conf-dir "/" name ".conf")
           edn-text  (read-fn edn-path)]
       (if (some? edn-text)
         (try
           (let [v (edn/read-string edn-text)]
             (if (or (nil? v) (map? v))
               {:ok? true :value (assoc v :name name) :path edn-path}
               {:ok? false :error (str "split: " edn-path " must hold an EDN map")}))
           (catch Throwable t
             {:ok? false :error (str "split: EDN parse error in " edn-path ": " (ex-message t))}))
         (if-let [text (read-fn conf-path)]
           {:ok?   true
            :value (legacy->split-edn (assoc (parse-key-value text) :name name))
            :path  conf-path}
           {:ok? false :error (str "split: config not found: " conf-path)}))))))
