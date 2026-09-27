(ns vpn-kis-bb.app.fetch
  "Provider-fetch workflows.

   `fetch-one!` runs a single fetcher and writes the IPs to
   /etc/vpn-killswitch/providers/<name>.ips. `fetch-many!` fans out
   in parallel via hive-weave's bounded-pmap (3 providers, ~5s budget).

   The output format matches the bash version byte-for-byte modulo
   comment ordering, so the two can co-exist on the same host during
   migration."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-weave.parallel :as weave]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.fetcher :as port]
            [vpn-kis-bb.adapters.fetcher.ovpn-file :as ovpn]
            [vpn-kis-bb.ports.dns :as dns]
            [vpn-kis-bb.log :as log]
            [vpn-kis-bb.domain.re :as rx]))

(def providers-dir "/etc/vpn-killswitch/providers")

(defn ips-file-text
  "Render IPs to the canonical .ips file format: header comments +
   one IP per line, sorted, deduped."
  [provider-name ips]
  (let [hdr (str "# " (name provider-name) " server IPs\n"
                 "# Fetched: " (str (u/now-iso)) "\n")
        body (str/join "\n" (sort ips))]
    (str hdr body "\n")))

(defn fetch-one!
  "Run the fetcher for one provider and write its IPs file.

   system: requires :fetchers (map provider-name → IProviderFetcher)
           and :write-fn (fn [path body] → Result).
   provider: keyword/string identifying the provider.
   opts: forwarded to (-fetch-ips fetcher opts)."
  ([system provider]       (fetch-one! system provider {}))
  ([system provider opts]
   (let [pname (keyword provider)
         fetch (get-in system [:fetchers pname])]
     (cond
       (nil? fetch)
       (r/err :fetch/unknown-provider {:provider pname
                                       :known (vec (keys (:fetchers system)))})

       :else
       (let [res ((requiring-resolve 'vpn-kis-bb.ports.fetcher/-fetch-ips)
                  fetch opts)]
         (if (r/err? res)
           res
           (let [ips  (-> res :ok :ips)
                 path (str providers-dir "/" (name pname) ".ips")
                 wf   (:write-fn system)
                 w    (wf path (ips-file-text pname ips))]
             (if (r/err? w)
               w
               (r/ok {:provider pname :ips ips :path path
                      :count    (count ips)})))))))))

(defn fetch-many!
  "Parallel fan-out across providers. Returns Result<{provider Result}>."
  ([system providers] (fetch-many! system providers {}))
  ([system providers {:keys [concurrency timeout-ms]
                      :or {concurrency 3 timeout-ms 30000}}]
   (let [pmapped (weave/bounded-pmap
                  {:concurrency concurrency :timeout-ms timeout-ms}
                  (fn [p] [p (fetch-one! system p)])
                  providers)]
     (r/ok (into {} pmapped)))))

;; ---------------------------------------------------------------- fetch command
;; bash fetch_provider / fetch_split_remotes: the `fetch` command's per-name
;; chain, custom providers included.

(def builtin-providers
  "Providers with a network fetcher: the default `fetch` targets."
  [:mullvad :airvpn :tailscale])

(def split-conf-dir "/etc/vpn-killswitch/split")

(defn ips-path
  "Cache file of provider `pname` under the system's providers dir."
  [system pname]
  (str (or (:providers-dir system) providers-dir) "/" (name pname) ".ips"))

(defn split-conf-candidates
  "Split configs that may name the .ovpn of provider `pname`, in bash
   fetch_split_remotes order."
  [pname]
  (mapv #(str split-conf-dir "/" %)
        [(str pname ".conf") (str pname "-vpn.conf") (str "vpn-" pname ".conf")]))

(defn ovpn-config-value
  "OVPN_CONFIG value of a split conf body, blanks and quotes trimmed, or nil."
  [conf-text]
  (some (fn [line]
          (when-let [i (str/index-of line "=")]
            (when (= "OVPN_CONFIG" (str/trim (subs line 0 i)))
              (not-empty (str/replace (subs line (inc i)) #"^[\s\"']+|[\s\"']+$" "")))))
        (rx/split-lines* (or conf-text ""))))

(defn- resolve-hosts
  "IPv4 set of `hosts`: dotted quads as given, names through the system's
   IDnsResolver (a name that does not resolve adds nothing)."
  [system hosts]
  (u/merge-ip-sets
   (filter u/ipv4? hosts)
   (mapcat (fn [h]
             (let [res (dns/-resolve-a (:dns system) h)]
               (if (r/ok? res) (:ok res) [])))
           (remove u/ipv4? hosts))))

(defn split-remote-ips
  "bash fetch_split_remotes: the `remote` hosts of the .ovpn a split config
   names, resolved and merged with the provider's previous list.
   Result<#{ip}>; :fetch/no-split-conf when no config exists."
  [system pname]
  (let [read-fn          (:read-fn system)
        [conf-path text] (some (fn [p] (when-let [t (read-fn p)] [p t]))
                               (split-conf-candidates pname))
        ovpn             (when text (ovpn-config-value text))
        ovpn-text        (when ovpn (read-fn ovpn))
        hosts            (when ovpn-text (ovpn/parse-remote-lines ovpn-text))]
    (cond
      (nil? text)
      (r/err :fetch/no-split-conf {:provider pname})

      (nil? ovpn-text)
      (r/err :fetch/no-ovpn {:provider pname
                             :hint     (str conf-path ": no readable OVPN_CONFIG")})

      (empty? hosts)
      (r/err :fetch/no-remotes {:provider pname
                                :hint     (str "no 'remote' directives in " ovpn)})

      :else
      (r/ok (u/merge-ip-sets (resolve-hosts system hosts)
                             (rx/split-lines* (or (read-fn (ips-path system pname)) "")))))))

(defn- reason
  "Printable cause of an error Result."
  [res]
  (or (:hint res) (:message res) (some-> (:error res) str)))

(defn- write-ips!
  "Write the provider's .ips cache (bash fetch_provider tail)."
  [system pname ips]
  (let [path (ips-path system pname)
        w    ((:write-fn system) path (ips-file-text pname ips))]
    (if (r/err? w)
      w
      (do (log/info "Wrote " (count ips) " IPs to " path)
          (r/ok {:provider (keyword pname) :ips ips :path path :count (count ips)})))))

(defn- unknown-provider [system pname]
  (r/err :fetch/unknown-provider
         {:provider pname
          :hint     (str "Unknown provider: " pname ". Known: "
                         (str/join " " (sort (map name (keys (:fetchers system)))))
                         ". Custom: drop IPs into " (ips-path system pname)
                         ", or create a split config with OVPN_CONFIG.")}))

(defn fetch-provider!
  "bash fetch_provider: refresh one provider's .ips cache, logging as the
   bash does. Sources in order: the registered fetcher, then the remotes of
   a split config's .ovpn, else a hand-made .ips is kept as is.
   Result<{:provider :ips :path :count}>, Result<{:provider :kept path}>
   for a kept static list, or an err with a :hint."
  [system provider]
  (let [pname   (name provider)
        fetcher (get-in system [:fetchers (keyword pname)])
        _       (log/info "Fetching " pname " server IPs...")
        res     (if fetcher
                  (r/bind (port/-fetch-ips fetcher {}) #(r/ok (:ips %)))
                  (split-remote-ips system pname))]
    (cond
      (and (r/ok? res) (seq (:ok res)))
      (do (when-not fetcher (log/info pname ": resolved from split config remotes"))
          (write-ips! system pname (:ok res)))

      (r/ok? res)
      (do (log/warn "No IPs returned for " pname)
          (r/err :fetch/no-ips {:provider pname :hint (str "No IPs returned for " pname)}))

      fetcher
      (do (log/warn "Fetch failed for " pname ": " (reason res))
          res)

      :else
      (do (when (:hint res) (log/warn (:hint res)))
          (if ((:read-fn system) (ips-path system pname))
            (do (log/warn pname ": no fetcher and no split config, keeping static "
                          (ips-path system pname))
                (r/ok {:provider (keyword pname) :kept (ips-path system pname)}))
            (let [e (unknown-provider system pname)]
              (log/error (:hint e))
              e))))))
