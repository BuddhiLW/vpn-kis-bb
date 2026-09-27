(ns vpn-kis-bb.app.providers
  "Provider IP-union loader.

   `providers` subcommand in the bash version reads the union of
   /etc/vpn-killswitch/providers/<name>.ips for each requested provider
   and hands the result to the firewall as the strict-mode allowlist.

   Pure-ish: only reads files + does set math. No shelling."
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.app.fetch :as fetch]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.domain.re :as rx]))

(defn- read-ips-file [path]
  (when (fs/exists? path)
    (->> (rx/split-lines* (slurp (fs/file path)))
         u/normalize-ips)))

(defn load-union
  "Return Result<#{ip ...}> = union of cached .ips files for each
   requested provider. Missing files are surfaced as warnings, not errors,
   so a partial union still yields a usable allowlist.

   opts: {:dir <path>} override providers dir (default from app.fetch)."
  ([providers]      (load-union providers {}))
  ([providers {:keys [dir] :or {dir fetch/providers-dir}}]
   (let [results (for [p providers
                       :let [pname (name p)
                             path  (str dir "/" pname ".ips")
                             ips   (read-ips-file path)]]
                   {:provider pname
                    :path     path
                    :ips      (or ips #{})
                    :missing? (nil? ips)})]
     (r/ok {:union   (apply u/merge-ip-sets (map :ips results))
            :sources results
            :missing (->> results (filter :missing?) (map :provider) vec)}))))
