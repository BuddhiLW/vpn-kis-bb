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
            [vpn-kis-bb.ports.fetcher :as port]))

(def providers-dir "/etc/vpn-killswitch/providers")

(defn ips-file-text
  "Render IPs to the canonical .ips file format: header comments +
   one IP per line, sorted, deduped."
  [provider-name ips]
  (let [hdr (str "# " (name provider-name) " server IPs\n"
                 "# Fetched: " (str (java.time.Instant/now)) "\n")
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
