(ns babashka.fs
  "cljw stand-in for the subset of babashka.fs that vpn-kis-bb uses,
   built on java.io.File (the host class cljw ships).

   Paths are returned as strings (babashka.fs returns java.nio Paths);
   every caller in vpn-kis-bb either `str`s them or hands them back to
   this namespace / slurp / spit, which accept strings.

   Covered: exists? directory? sym-link? file path parent file-name
            create-dirs delete-if-exists delete-tree create-temp-dir
            create-temp-file glob"
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.java.shell :as sh]))

(defn- ->file ^java.io.File [p]
  (if (instance? java.io.File p) p (io/file (str p))))

(defn file
  "java.io.File for the joined path parts."
  [p & more]
  (apply io/file (str p) (map str more)))

(defn path
  "Joined path as a string."
  [p & more]
  (str (apply file p more)))

(defn exists? [p] (.exists (->file p)))

(defn directory? [p] (.isDirectory (->file p)))

(defn sym-link?
  "True when the last path component is a symlink (the canonical path
   differs from the canonical parent joined with the name)."
  [p]
  (let [f      (.getAbsoluteFile (->file p))
        parent (.getParentFile f)]
    (and (some? parent)
         (not= (.getCanonicalPath f)
               (str (.getCanonicalPath parent) "/" (.getName f))))))

(defn parent [p] (.getParent (->file p)))

(defn file-name [p] (.getName (->file p)))

(defn create-dirs [p]
  (.mkdirs (->file p))
  (str p))

(defn delete-if-exists
  "Delete p, a symlink itself rather than its target; true when something
   was deleted. `.exists` would follow a dangling link and skip it."
  [p]
  (.delete (->file p)))

(defn delete-tree [p]
  (let [f (->file p)]
    (when (.exists f)
      (when (.isDirectory f)
        (doseq [child (.listFiles f)]
          (delete-tree child)))
      (.delete f))
    nil))

(defn move
  "Rename source to target with `mv -f` (an atomic rename(2) within one
   filesystem; an existing target is replaced). opts are accepted for
   babashka.fs compatibility. Returns target; throws when mv fails."
  ([source target] (move source target {}))
  ([source target _opts]
   (let [{:keys [exit err]} (sh/sh "mv" "-f" (str source) (str target))]
     (when-not (zero? exit)
       (throw (ex-info (str "move failed: " err) {:source source :target target})))
     (str target))))

(defn create-temp-file
  ([] (create-temp-file {}))
  ([{:keys [prefix suffix] :or {prefix "tmp" suffix ".tmp"}}]
   (str (java.io.File/createTempFile prefix suffix))))

(defn create-temp-dir
  ([] (create-temp-dir {}))
  ([{:keys [prefix] :or {prefix "tmp"}}]
   (let [f (java.io.File/createTempFile prefix "")]
     (.delete f)
     (.mkdirs f)
     (str f))))

;; ---------------------------------------------------------------- glob

(defn- split-on
  "s split at every occurrence of sep, empty parts kept. Regex-free: cljw
   corrupts regex split results intermittently."
  [s sep]
  (loop [start 0 acc []]
    (if-let [i (str/index-of s sep start)]
      (recur (+ i (count sep)) (conj acc (subs s start i)))
      (conj acc (subs s start)))))

(defn- expand-braces
  "Brace expansion: \"a{b,c}d\" -> [\"abd\" \"acd\"]. Expands the innermost
   pair closing first, then recurses on each alternative."
  [pattern]
  (let [close (str/index-of pattern "}")
        open  (when close (str/last-index-of (subs pattern 0 close) "{"))]
    (if open
      (let [pre   (subs pattern 0 open)
            inner (subs pattern (inc open) close)
            post  (subs pattern (inc close))]
        (mapcat #(expand-braces (str pre % post)) (split-on inner ",")))
      [pattern])))

(defn- wildcard-match?
  "True when name matches the glob segment pat: * is any run of
   characters, ? exactly one, anything else itself."
  [pat name]
  (let [pn (count pat)
        sn (count name)]
    (loop [p 0 i 0 star -1 mark 0]
      (if (< i sn)
        (let [pc (when (< p pn) (nth pat p))]
          (cond
            (and pc (or (= pc \?) (= pc (nth name i)))) (recur (inc p) (inc i) star mark)
            (= pc \*)                                   (recur (inc p) i p i)
            (not= star -1)                              (recur (inc star) (inc mark) star (inc mark))
            :else                                       false))
        (every? #(= % \*) (subs pat p))))))

(defn- children [^java.io.File dir]
  (sort-by #(.getName ^java.io.File %) (or (seq (.listFiles dir)) [])))

(defn- match-segments [^java.io.File dir segments]
  (if (empty? segments)
    [dir]
    (let [[seg & more] segments
          hidden?      (str/starts-with? seg ".")]
      (->> (children dir)
           (filter #(let [n (.getName ^java.io.File %)]
                      (and (wildcard-match? seg n)
                           (or hidden? (not (str/starts-with? n "."))))))
           (mapcat #(if (seq more)
                      (when (.isDirectory ^java.io.File %) (match-segments % more))
                      [%]))))))

(defn glob
  "Paths under root matching a glob pattern (* ? {a,b}; per-segment,
   hidden files skipped unless the segment starts with a dot)."
  [root pattern]
  (let [root-f (->file root)]
    (if-not (.isDirectory root-f)
      []
      (->> (expand-braces pattern)
           (mapcat #(match-segments root-f (vec (remove empty? (split-on % "/")))))
           (map str)
           distinct
           vec))))
