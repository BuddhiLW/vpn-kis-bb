(ns vpn-kis-bb.adapters.fetcher.airvpn
  "AirvpnFetcher — discover AirVPN entry IPs, composed from substitutable
   IEndpointSource strategies tried in order:

     1. AirvpnApiSource  — the COMPLETE entry-IP list from the public status
                           API (airvpn.org/api/status), plus the API host's
                           own IP (so a strict-mode refresh can reach :443 to
                           it pre-tunnel). This is the primary source.
     2. OvpnScanSource   — OFFLINE FALLBACK: scan Eddie / OpenVPN / WireGuard
                           configs for `remote`/`Endpoint` hosts and
                           DNS-resolve them. Used when the API is unreachable.

   Why the API beats config scanning: AirVPN ships round-robin DNS cluster
   hostnames (e.g. earth3.vpn.airdns.org) that rotate over a large server pool
   and hand out ~one A-record per query, so scanning + resolving can only
   sample a sliver. In strict mode the freshly rotated entry IP the client
   picks is then often absent from the allowlist and its handshake is DROP'd.
   The API enumerates every server's entry IPs at once — the same model
   MullvadFetcher uses for its relay list.

   The fetcher itself only orchestrates the fallback chain; each source owns
   exactly one acquisition strategy and depends only on the ports it needs."
  (:require [babashka.fs :as fs]
            [cheshire.core :as json]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.dns :as dns]
            [vpn-kis-bb.ports.endpoint-source :as src]
            [vpn-kis-bb.ports.fetcher :as port]
            [vpn-kis-bb.ports.http :as http]
            [vpn-kis-bb.domain.re :as rx]))

;; ---------------------------------------------------------------------------
;; Source 1 — the public status API (primary)
;; ---------------------------------------------------------------------------

(def api-url "https://airvpn.org/api/status/")
(def api-host "airvpn.org")

;; Up to four IPv4 entry addresses per server in the status JSON.
(def ^:private entry-ip-keys [:ip_v4_in1 :ip_v4_in2 :ip_v4_in3 :ip_v4_in4])

(defn parse-status-json
  "Pure: extract every IPv4 entry address from the parsed AirVPN status JSON.
   Each `:servers` entry carries up to four entry IPs (ip_v4_in1..4); nils,
   blanks and non-IPv4 values are dropped by normalize-ips."
  [json-data]
  (u/normalize-ips
   (mapcat (apply juxt entry-ip-keys) (:servers json-data))))

(defrecord AirvpnApiSource [fetcher resolver]
  src/IEndpointSource
  (-source-id [_] api-url)
  (-endpoints [_ {:keys [timeout-ms] :or {timeout-ms 30000}}]
    (let [resp (http/-fetch fetcher api-url
                            {:timeout-ms timeout-ms
                             :headers {"Accept" "application/json"}})]
      (if-not (r/ok? resp)
        (r/err :fetcher/airvpn-http-failed {:cause resp})
        (try
          (let [entries (parse-status-json
                         (json/parse-string (-> resp :ok :body) keyword))]
            ;; Empty entries → return an empty (but ok) set so the fetcher
            ;; chain falls through to the scan fallback. Only when we have real
            ;; server IPs do we add the API host's own IP (bootstrap: lets a
            ;; strict-mode refresh re-hit :443 to it after the killswitch
            ;; locks). Merging the host IP onto an empty set would mask the
            ;; emptiness and pin the allowlist to a lone CDN edge.
            (if (empty? entries)
              (r/ok #{})
              (let [api-r   (dns/-resolve-a resolver api-host)
                    api-ips (if (r/ok? api-r) (:ok api-r) #{})]
                (r/ok (u/merge-ip-sets entries api-ips)))))
          (catch Throwable t
            (let [body (-> resp :ok :body)]
              (r/err :fetcher/airvpn-parse-failed
                     {:cause (str t)
                      :body-prefix (when (string? body)
                                     (subs body 0 (min 200 (count body))))}))))))))

;; ---------------------------------------------------------------------------
;; Source 2 — local config scan (offline fallback)
;; ---------------------------------------------------------------------------

(def default-scan-dirs
  ["/etc/openvpn"
   "/etc/openvpn/airvpn"
   "/etc/AirVPN"
   "/etc/eddie"
   "/opt/AirVPN"])

(defn user-scan-dirs
  "Per-user candidate dirs. Reads $HOME so an injected env can override."
  [home]
  (when home
    [home
     (str home "/Downloads")
     (str home "/.airvpn")
     (str home "/AirVPN")]))

(defn parse-ovpn-remotes
  "Extract hostnames from `remote <host>` lines in an OpenVPN .ovpn/.conf."
  [content]
  (->> (rx/split-lines* (or content ""))
       (keep #(some-> (rx/re-find* #"^\s*remote\s+(\S+)" %) second))))

(defn parse-wg-endpoints
  "Extract hostnames from `Endpoint = <host>:<port>` lines (WireGuard)."
  [content]
  (->> (rx/split-lines* (or content ""))
       (keep (fn [line]
               (when-let [m (rx/re-find* #"^\s*Endpoint\s*=\s*([^:\s]+)" line)]
                 (second m))))))

(defn collect-hosts
  "Walk dirs, find *.ovpn / *.conf, return distinct hostnames."
  [dirs]
  (->> dirs
       (filter #(and % (fs/exists? %) (fs/directory? %)))
       (mapcat #(fs/glob % "{*.ovpn,*.conf,*/*.ovpn,*/*.conf}"))
       (mapcat (fn [path]
                 (let [content (slurp (fs/file path))]
                   (concat (parse-ovpn-remotes content)
                           (parse-wg-endpoints content)))))
       distinct
       vec))

(defn resolve-many
  [resolver hosts]
  (reduce (fn [acc h]
            (if (u/ipv4? h)
              (conj acc h)
              (let [res (dns/-resolve-a resolver h)]
                (if (r/ok? res)
                  (into acc (:ok res))
                  acc))))
          #{}
          hosts))

(defrecord OvpnScanSource [resolver dirs home]
  src/IEndpointSource
  (-source-id [_] "scanned ovpn/wg configs")
  (-endpoints [_ _opts]
    (let [all-dirs (concat dirs (user-scan-dirs home))
          hosts    (collect-hosts all-dirs)]
      (if (empty? hosts)
        (r/err :fetcher/airvpn-no-configs
               {:scanned-dirs all-dirs
                :hint "API unreachable and no local AirVPN configs found. Drop .ovpn files in ~/Downloads or /etc/openvpn/."})
        (r/ok (resolve-many resolver hosts))))))

;; ---------------------------------------------------------------------------
;; Fetcher — compose the sources into a fallback chain
;; ---------------------------------------------------------------------------

(defn first-populated
  "Try each IEndpointSource in order; return Result<{:ips :source}> for the
   first that yields a non-empty set. If none do, return the last error
   encountered (most actionable — typically the terminal fallback's), or a
   generic :airvpn-no-endpoints when every source was merely empty."
  [sources opts]
  (loop [[s & more] sources
         last-err   nil]
    (if (nil? s)
      (or last-err (r/err :fetcher/airvpn-no-endpoints {}))
      (let [res (src/-endpoints s opts)]
        (cond
          (and (r/ok? res) (seq (:ok res)))
          (r/ok {:ips (:ok res) :source (src/-source-id s)})

          (r/ok? res)            (recur more last-err) ; ok but empty
          :else                  (recur more res)))))) ; err — remember it

(defrecord AirvpnFetcher [sources]
  port/IProviderFetcher
  (-provider-id [_] :airvpn)
  (-supports? [_ pname] (= "airvpn" (name pname)))
  (-fetch-ips [_ opts]
    (let [res (first-populated sources opts)]
      (if (r/ok? res)
        (r/ok {:provider   :airvpn
               :ips        (-> res :ok :ips)
               :source     (-> res :ok :source)
               :fetched-at (u/now-iso)})
        res))))

(defn make
  "Build an AirVPN fetcher. Primary source is the status API; falls back to
   scanning local configs. `fetcher` is an IWebFetcher, `resolver` an
   IDnsResolver. Add a source by conj-ing another IEndpointSource here."
  ([fetcher resolver]
   (make fetcher resolver default-scan-dirs (System/getenv "HOME")))
  ([fetcher resolver dirs home]
   (->AirvpnFetcher [(->AirvpnApiSource fetcher resolver)
                     (->OvpnScanSource resolver dirs home)])))
