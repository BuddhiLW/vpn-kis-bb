(ns vpn-kis-bb.domain.config
  "EDN config schema for vpn-kis-bb.

   Two config kinds:

   1. Project-wide  /etc/vpn-killswitch/config.edn
        {:lan-allow [\"192.168.100.0/24\"]
         :vpn-ports {:udp [1194 443 53 51820]
                     :tcp [443]}
         :physical-iface nil}        ; auto-detect when nil

   2. Split-tunnel   /etc/vpn-killswitch/split/<name>.conf  (legacy KEY=VALUE)
      or            /etc/vpn-killswitch/split/<name>.edn   (preferred)
      see domain.split/validate for the keys.

   We also tolerate the bash KEY=VALUE format for migration — a parser
   below normalizes it into the EDN shape."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [babashka.fs :as fs]))

(def default-project-config
  {:lan-allow      []
   :vpn-ports      {:udp [1194 443 53 51820 1300 1301 1302 1637 41641 3478]
                    :tcp [443]}
   :physical-iface nil})

(defn parse-key-value
  "Parse the bash-flavored KEY=VALUE format used by the legacy split confs.
   Returns a keyword-keyed map. Surrounding quotes are stripped."
  [s]
  (->> (str/split-lines (or s ""))
       (keep (fn [raw]
               (let [line (str/trim raw)]
                 (when (and (seq line)
                            (not (str/starts-with? line "#")))
                   (when-let [m (re-matches #"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$" line)]
                     (let [k (-> m (nth 1) str/lower-case (str/replace "_" "-") keyword)
                           v (-> m (nth 2) str/trim)
                           v (str/replace v #"^[\"']|[\"']$" "")]
                       [k v]))))))
       (into {})))

(defn legacy->split-edn
  "Convert the parsed legacy KEY=VALUE map into our split-config EDN shape."
  [{:keys [domains dev table mark priority ovpn-config name] :as legacy}]
  (cond-> (assoc {} :name (or name "unnamed"))
    domains     (assoc :domains (vec (str/split (str domains) #"\s+")))
    dev         (assoc :dev dev)
    table       (assoc :table (parse-long table))
    mark        (assoc :mark mark)
    priority    (assoc :priority (if (= priority "auto") :auto (parse-long priority)))
    ovpn-config (assoc :ovpn-config ovpn-config)))

(defn read-split-conf
  "Read /etc/vpn-killswitch/split/<name>.{edn,conf}.

   Tries .edn first, falls back to .conf (legacy KEY=VALUE). Returns
   {:ok? true :value <map>} or {:ok? false :error <msg>}."
  [conf-dir name]
  (let [edn-path  (fs/path conf-dir (str name ".edn"))
        conf-path (fs/path conf-dir (str name ".conf"))]
    (cond
      (fs/exists? edn-path)
      (try
        {:ok? true :value (-> edn-path fs/file slurp edn/read-string
                              (assoc :name name))}
        (catch Throwable t
          {:ok? false :error (str "edn parse error: " (.getMessage t))}))

      (fs/exists? conf-path)
      (let [parsed (-> conf-path fs/file slurp parse-key-value)]
        {:ok? true :value (legacy->split-edn (assoc parsed :name name))})

      :else
      {:ok? false :error (str "no config at " edn-path " or " conf-path)})))
