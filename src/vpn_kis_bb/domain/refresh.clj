(ns vpn-kis-bb.domain.refresh
  "Pure: endpoint auto-refresh.

   Bash equivalent: the `Endpoint auto-refresh` section of
   vpn-firewall-setup.sh (refresh_endpoints, install_refresh_timer,
   remove_refresh_timer) plus the `refresh` branch of `main`.

   This namespace only produces data: paths and names, the active-file
   format, the systemd unit bodies and the ipset command plan that
   rebuilds the live endpoint set, and next to it the DNS bootstrap set,
   without an empty window. The workflows in app.refresh run it."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.domain.re :as rx]))

(def active-file
  "Provider names from the last `providers` / `refresh <names>` run. The
   timer's `refresh` (no names) re-fetches these."
  "/etc/vpn-killswitch/providers.active")

(def set-name     "vpn_endpoints")
(def tmp-set-name "vpn_endpoints_new")
(def ipset-conf   "/etc/ipset.conf")

(def dns-set-name
  "DNS bootstrap resolvers (settings :dns-bootstrap). Kept out of
   vpn_endpoints: strict rules open that set on every port, this one on
   port 53 only."
  "vpn_dns_bootstrap")

(def dns-tmp-set-name "vpn_dns_bootstrap_new")

(def service-name     "vpn-killswitch-refresh.service")
(def timer-name       "vpn-killswitch-refresh.timer")
(def default-interval "15min")

(def restore-chunk-size
  "Max IPs per `ipset restore` payload. A payload travels inside a single
   `sh -c` argument and Linux caps one argv string at 128 KiB
   (MAX_ARG_STRLEN); 2000 add lines stay near 76 KB."
  2000)

(def ^:private create-opts
  ["hash:ip" "family" "inet" "hashsize" "2048" "maxelem" "65536" "-exist"])

;; ---------------------------------------------------------------------------
;; Provider names and the active file

(defn normalize-names
  "Provider names as strings, in order: keywords are named, an entry
   holding whitespace splits into words, blanks and repeats are dropped."
  [names]
  (->> names
       (map #(if (keyword? %) (name %) (str %)))
       (mapcat (fn [w] (rx/split* (str/trim w) #"\s+")))
       (remove str/blank?)
       distinct
       vec))

(defn parse-active
  "Provider names stored in the active file. Like bash `read -ra`, only the
   first line counts and its words are the names. nil/blank -> []."
  [text]
  (normalize-names [(first (rx/split-lines* (or text "")))]))

(defn active-text
  "Active file body for `names`: one space-separated line, as bash
   `echo \"${names[*]}\"` writes it."
  [names]
  (str (str/join " " (normalize-names names)) "\n"))

;; ---------------------------------------------------------------------------
;; systemd units (bash heredocs in install_refresh_timer)

(defn service-unit-text
  "Oneshot the timer fires: `<self-path> refresh`, which re-reads the
   active file."
  [self-path]
  (str "[Unit]\n"
       "Description=VPN Kill-Switch: refresh endpoint ipset from provider lists\n"
       "Wants=network-online.target\n"
       "After=network-online.target\n"
       "\n"
       "[Service]\n"
       "Type=oneshot\n"
       "ExecStart=" self-path " refresh\n"))

(defn timer-unit-text
  "Periodic trigger for the refresh service. nil interval -> default."
  [interval]
  (str "[Unit]\n"
       "Description=VPN Kill-Switch: periodic endpoint refresh\n"
       "\n"
       "[Timer]\n"
       "OnBootSec=2min\n"
       "OnUnitActiveSec=" (or interval default-interval) "\n"
       "RandomizedDelaySec=30\n"
       "Persistent=true\n"
       "\n"
       "[Install]\n"
       "WantedBy=timers.target\n"))

(defn valid-interval?
  "True for a plausible systemd time span (\"15min\", \"1h 30min\", \"90\").
   Keeps stray characters, newlines above all, out of the timer unit."
  [s]
  (boolean (and (string? s) (rx/re-matches* #"[0-9][0-9A-Za-z. ]*" s))))

;; ---------------------------------------------------------------------------
;; ipset: atomic rebuild of the live endpoint set

(defn valid-ips
  "Sorted set of the IPv4 addresses in `ips` (each trimmed). Anything that
   is not a dotted quad (hostnames, IPv6, comments, blanks) is dropped."
  [ips]
  (into (sorted-set)
        (comp (map #(str/trim (str %)))
              (filter u/ipv4?))
        ips))

(defn- payload-text
  "restore-payload body for addresses already validated."
  [target-set valid]
  (str/join "\n"
            (concat [(str "create " target-set " " (str/join " " create-opts))]
                    (map #(str "add " target-set " " %) valid)
                    [""])))

(defn restore-payload
  "`ipset restore` input that fills `target-set` (the TEMP set) with the
   valid IPv4 addresses in `ips`: a `create ... -exist` line, then one
   `add` line per address, newline terminated."
  [target-set ips]
  (payload-text target-set (valid-ips ips)))

(defn sh-quote
  "`s` as one single-quoted sh word (embedded quotes closed, escaped and
   reopened), for command strings handed to `sh -c`."
  [s]
  (str "'" (str/escape (str s) {\' "'\\''"}) "'"))

(defn restore-command
  "argv loading `payload` through `ipset restore -exist`. The real shell
   adapter has no stdin, so the payload rides in the command line, the
   same route as adapters.ipset-shell."
  [payload]
  ["sh" "-c" (str "printf '%s' " (sh-quote payload) " | ipset restore -exist")])

(defn save-command
  "argv persisting both sets to ipset-conf, the file the UFW before.init
   hook restores at boot. A failure of either save fails the command."
  []
  ["sh" "-c" (str "{ ipset save " set-name " && ipset save " dns-set-name "; } > " ipset-conf)])

(defn- set-swap-commands
  "Create `live` and `tmp` (-exist), flush `tmp`, load the already
   validated `ips` into it chunk by chunk, swap, drop `tmp`."
  [live tmp ips chunk-size]
  (concat
   [(into ["ipset" "create" live] create-opts)
    (into ["ipset" "create" tmp] create-opts)
    ["ipset" "flush" tmp]]
   (for [chunk (partition-all chunk-size ips)]
     (restore-command (payload-text tmp chunk)))
   [["ipset" "swap" tmp live]
    ["ipset" "destroy" tmp]]))

(defn swap-commands
  "Commands, in order, that rebuild the live endpoint set from `ips`, then
   the DNS bootstrap set from opts :dns-ips, each with no window where it
   is empty: fill a temp set aside, swap it in (one kernel op), drop the
   temp set. Last, both sets are persisted for boot (save-command). A list
   longer than :chunk-size (default restore-chunk-size) loads in several
   payloads, all before its swap.

   No valid IPv4 in `ips` -> [] : an empty endpoint whitelist is never
   swapped in (the DNS set is left alone too). An empty :dns-ips is fine:
   the DNS set is swapped to empty, so it always exists for the rules."
  ([ips] (swap-commands ips {}))
  ([ips {:keys [dns-ips chunk-size] :or {chunk-size restore-chunk-size}}]
   (let [ips (valid-ips ips)]
     (if (empty? ips)
       []
       (vec
        (concat
         (set-swap-commands set-name tmp-set-name ips chunk-size)
         (set-swap-commands dns-set-name dns-tmp-set-name (valid-ips dns-ips) chunk-size)
         [(save-command)]))))))

(defn list-command
  "argv whose output carries the live set's `Number of entries:`."
  []
  ["ipset" "list" set-name])

(defn entry-count
  "N from the `Number of entries: N` line of `ipset list` output, or nil.
   Last word of that line, like the bash `awk '{print $NF}'`; no regex
   capture groups, which cljw's engine can hand back corrupted."
  [list-output]
  (when (string? list-output)
    (some (fn [line]
            (let [line (str/trim line)]
              (when (str/starts-with? line "Number of entries:")
                (parse-long (last (rx/split* line #"\s+"))))))
          (rx/split-lines* list-output))))

;; ---------------------------------------------------------------------------
;; CLI dispatch (bash `main`, case refresh)

(defn parse-command
  "Arguments after `refresh`, dispatched like bash `main`:
     install|timer [interval] -> {:op :install :interval i}  (default 15min)
     uninstall|remove         -> {:op :remove}
     anything else            -> {:op :refresh :names [...]}  (all args;
                                 no names means: read the active file)"
  [args]
  (let [[sub interval] args]
    (case sub
      ("install" "timer")    {:op :install
                              :interval (if (str/blank? interval)
                                          default-interval
                                          (str/trim interval))}
      ("uninstall" "remove") {:op :remove}
      {:op :refresh :names (normalize-names args)})))
