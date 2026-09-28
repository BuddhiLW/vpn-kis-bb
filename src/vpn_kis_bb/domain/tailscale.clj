(ns vpn-kis-bb.domain.tailscale
  "Pure side of the tailnet bypass (bash: the tailscale-routes section of
   vpn-firewall-setup.sh): constants, commands as argv, parsers for
   `ip route show table 52`, `ip rule show`, `systemctl show` and
   `mullvad split-tunnel list` output, the choice of destination set, and
   the text of the nft table and the boot unit.

   The nft table `inet vpn-killswitch-tailscale` gives packets bound for
   the set @tailnet (CGNAT 100.64.0.0/10 plus the RFC1918 routes tailscale
   keeps in table 52) Mullvad's own fwmark and ct mark; forwarded traffic
   gets the same marks; marked connections leaving tailscale0 are
   masqueraded. A destination containing one of protected-ips (Mullvad's
   in-tunnel DNS 10.64.0.1) is never put in the set."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.util :as util]
            [vpn-kis-bb.domain.re :as rx]))

;; ---------------------------------------------------------------- constants

(def route-table
  "tailscaled's routing table."
  "52")

(def cgnat
  "Tailscale's address range; always the first entry of a fresh set."
  "100.64.0.0/10")

(def mullvad-fwmark
  "Packet mark Mullvad's catch-all ip rule skips."
  "0x6d6f6c65")

(def mullvad-ct-mark
  "Conntrack mark Mullvad's firewall accepts."
  "0x00000f41")

(def tailscaled-bypass-mark
  "tailscaled's own sockets carry this fwmark (mask 0x00ff0000); tailscale's
   ip rules send it to the main table, i.e. straight out the physical NIC."
  "0x00080000")

(def nft-table "vpn-killswitch-tailscale")

(def nft-tag
  "Versioned comment on the route_out rule. Present in the live table with
   an unchanged stored set, it makes apply a no-op."
  "vpn-kis tailnet bypasses Mullvad v3")

(def rides-tag
  "Comment on the route_out rule that clears tailscaled-bypass-mark."
  "vpn-kis tailscaled rides Mullvad")

(def protected-ips
  "Addresses that must stay inside the Mullvad tunnel: no set entry may
   contain one."
  ["10.64.0.1"])

(def cidrs-file
  "Last applied destination set, one entry per line."
  "/etc/vpn-killswitch/tailnet.cidrs")

(def web-enabled-file
  "Marker file: apply runs the tailscale-web helper when its table is missing."
  "/etc/vpn-killswitch/tailscale-web.enabled")

(def openclaw-table
  "nft table (family inet) the tailscale-web helper installs."
  "hive_openclaw_client")

(def web-helper-env
  "Environment variable overriding the tailscale-web helper path."
  "TAILSCALE_WEB_HELPER")

(def unit-name "vpn-killswitch-tailscale-routes.service")
(def unit-path (str "/etc/systemd/system/" unit-name))
(def dropin-dir "/etc/systemd/system/tailscaled.service.d")
(def dropin-path (str dropin-dir "/50-vpn-killswitch-mullvad.conf"))

(def drain-limit
  "Upper bound on repetitions of `ip rule del` for one destination."
  16)

;; ---------------------------------------------------------------- commands

(def table-routes-cmd ["ip" "route" "show" "table" route-table])
(def rule-show-cmd ["ip" "rule" "show"])
(def nft-list-cmd ["nft" "list" "table" "inet" nft-table])
(def nft-delete-cmd ["nft" "delete" "table" "inet" nft-table])
(def openclaw-list-cmd ["nft" "list" "table" "inet" openclaw-table])
(def main-pid-cmd ["systemctl" "show" "-p" "MainPID" "--value" "tailscaled"])
(def split-list-cmd ["mullvad" "split-tunnel" "list"])
(def dropin-rmdir-cmd ["rmdir" "--ignore-fail-on-non-empty" dropin-dir])
(def unit-restart-cmd ["systemctl" "restart" unit-name])

(defn split-delete-cmd
  "Removes `pid` from Mullvad's split tunnel."
  [pid]
  ["mullvad" "split-tunnel" "delete" (str pid)])

(defn rule-del-cmd
  "Deletes one legacy `to <cidr> lookup 52` ip rule."
  [cidr]
  ["ip" "rule" "del" "to" cidr "lookup" route-table])

(def nft-load-script
  "sh -c script: its first argument is fed to `nft -f -`."
  "printf '%s' \"$1\" | nft -f -")

(defn nft-load-cmd
  "argv loading `ruleset` through `nft -f -` as one transaction. The
   ruleset is an argument of the command, so no stdin is needed."
  [ruleset]
  ["sh" "-c" nft-load-script "sh" ruleset])

(defn web-helper-cmd
  "Runs the tailscale-web helper with subcommand `sub`."
  [helper sub]
  ["python3" helper sub])

;; ---------------------------------------------------------------- addresses

(def ^:private prefix-len-re #"[0-9]{1,2}")

(defn cidr?
  "True for an IPv4 address with an optional /0../32 prefix length."
  [s]
  (boolean
   (when (string? s)
     (let [[addr len & more] (rx/split* s #"/" -1)]
       (and (nil? more)
            (util/ipv4? addr)
            (or (nil? len)
                (and (rx/re-matches* prefix-len-re len)
                     (<= (parse-long len) 32))))))))

(defn- ip->long [ip]
  (reduce (fn [acc octet] (+ (* acc 256) (parse-long octet)))
          0
          (rx/split* ip #"\.")))

(defn cidr-contains?
  "True when IPv4 address `ip` lies inside `cidr` (an address or a prefix,
   see cidr?)."
  [cidr ip]
  (let [[addr len] (rx/split* cidr #"/")
        bits (if len (parse-long len) 32)
        mask (bit-and 0xFFFFFFFF (bit-shift-left 0xFFFFFFFF (- 32 bits)))]
    (= (bit-and mask (ip->long addr))
       (bit-and mask (ip->long ip)))))

(defn protected?
  "True when `cidr` contains one of protected-ips."
  [cidr]
  (boolean (some #(cidr-contains? cidr %) protected-ips)))

(defn- rfc1918?
  "True for a valid cidr? in 10/8, 172.16/12 or 192.168/16, judged by its
   leading octets like the bash awk filter."
  [cidr]
  (let [[a b] (rx/split* cidr #"[./]")]
    (or (= "10" a)
        (and (= "192" a) (= "168" b))
        (and (= "172" a) (<= 16 (parse-long b) 31)))))

;; ---------------------------------------------------------------- parsers

(defn- fields [line]
  (let [t (str/trim line)]
    (if (= "" t) [] (rx/split* t #"\s+"))))

(defn table-routes
  "RFC1918 destinations of `<dst> dev tailscale* ...` lines in
   `ip route show table 52` output, sorted and distinct."
  [out]
  (->> (rx/split-lines* (or out ""))
       (keep (fn [line]
               (let [[dst dev iface] (fields line)]
                 (when (and (= "dev" dev)
                            (some? iface)
                            (str/starts-with? iface "tailscale")
                            (cidr? dst)
                            (rfc1918? dst))
                   dst))))
       distinct
       sort
       vec))

(defn tailscale-routed?
  "True when table-52 output routes anything through a tailscale device."
  [out]
  (str/includes? (or out "") "dev tailscale"))

(defn stored-cidrs
  "Valid entries of tailnet.cidrs text (whitespace separated), in file
   order, distinct."
  [text]
  (->> (rx/split* (or text "") #"\s+")
       (filter cidr?)
       distinct
       vec))

(defn destinations
  "The set to mark (bash tailnet_destinations): cgnat plus table-routes;
   but when table 52 adds no RFC1918 route and routes nothing through a
   tailscale device (tailscaled restarting), the stored set instead, if it
   has entries. Entries containing a protected IP are dropped; an empty
   result falls back to [cgnat].

   Returns {:dests [cidr ...] :dropped [cidr ...] :source :table|:stored}."
  [table-out stored-text]
  (let [routes      (table-routes table-out)
        stored      (stored-cidrs stored-text)
        use-stored? (boolean (and (empty? routes)
                                  (seq stored)
                                  (not (tailscale-routed? table-out))))
        raw         (if use-stored? stored (into [cgnat] routes))
        kept        (vec (remove protected? raw))]
    {:dests   (if (seq kept) kept [cgnat])
     :dropped (filterv protected? raw)
     :source  (if use-stored? :stored :table)}))

(defn bypass-current?
  "True when the live table text carries nft-tag and the stored set equals
   `dests` (order-insensitive), i.e. applying again would change nothing."
  [live-table stored-text dests]
  (boolean
   (and (str/includes? (or live-table "") nft-tag)
        (= (set (stored-cidrs stored-text)) (set dests)))))

(defn cidrs-text
  "tailnet.cidrs body for `dests`: one entry per line."
  [dests]
  (apply str (map #(str % "\n") dests)))

(defn legacy-rule-cidrs
  "Destinations of legacy `<prio>: from all to <cidr> lookup 52` rules in
   `ip rule show` output (fields 4 to 7 read `to <cidr> lookup 52`),
   distinct, in order."
  [out]
  (->> (rx/split-lines* (or out ""))
       (keep (fn [line]
               (let [f (fields line)]
                 (when (and (= "to" (get f 3))
                            (= "lookup" (get f 5))
                            (= route-table (get f 6)))
                   (get f 4)))))
       distinct
       vec))

(def ^:private pid-re #"[1-9][0-9]*")

(defn main-pid
  "tailscaled's PID from `systemctl show -p MainPID --value` output, or
   nil when blank, 0 (not running) or malformed."
  [out]
  (let [s (str/trim (or out ""))]
    (when (rx/re-matches* pid-re s) s)))

(defn pid-listed?
  "True when `pid` is a whole whitespace-separated field of
   `mullvad split-tunnel list` output (the listing indents PIDs)."
  [listing pid]
  (boolean (some #{pid} (rx/split* (or listing "") #"\s+"))))

(defn tailscale-profile?
  "True when the kill-switch VPN interface list (a string or a seq of
   names) mentions tailscale."
  [vpn-interfaces]
  (str/includes? (if (string? vpn-interfaces)
                   vpn-interfaces
                   (str/join " " vpn-interfaces))
                 "tailscale"))

(defn web-profile?
  "True when providers.active text names both mullvad and tailscale as
   whole words (letters, digits and _ are word characters)."
  [active-text]
  (let [words (set (rx/split* (or active-text "") #"[^A-Za-z0-9_]+"))]
    (boolean (and (words "mullvad") (words "tailscale")))))

(defn web-helper-path
  "The tailscale-web helper: env TAILSCALE_WEB_HELPER when set, else
   <dir of self-path>/../lib/tailscale-web/configure.py; nil when
   self-path has no directory part."
  [env self-path]
  (or (not-empty (get env web-helper-env))
      (when-let [i (some-> self-path (str/last-index-of "/"))]
        (str (subs self-path 0 i) "/../lib/tailscale-web/configure.py"))))

;; ---------------------------------------------------------------- rendered text

(defn render-nft
  "The nft batch loaded by apply (bash render_tailscale_nft): create the
   table if missing, delete it, define it whole. One transaction, so the
   rules are never absent.

   route_out also clears tailscaled-bypass-mark on tailscaled's own
   packets to non-tailnet destinations (control plane, DERP, WireGuard
   UDP). Unmarked, they miss tailscale's `fwmark 0x80000 lookup main`
   rules and take Mullvad's catch-all, whatever the ip rule order. So
   tailscaled always rides the Mullvad tunnel and needs no split-tunnel
   exclusion, no kill-switch allowance and no DNS outside the tunnel."
  [dests]
  (let [elems (str/join ", " dests)
        marks (str "meta mark set " mullvad-fwmark " ct mark set " mullvad-ct-mark)]
    (str "table inet " nft-table "\n"
         "delete table inet " nft-table "\n"
         "table inet " nft-table " {\n"
         "    set tailnet {\n"
         "        type ipv4_addr\n"
         "        flags interval\n"
         "        auto-merge\n"
         "        elements = { " elems " }\n"
         "    }\n"
         "    chain route_out {\n"
         "        type route hook output priority mangle; policy accept;\n"
         "        ip daddr @tailnet " marks " comment \"" nft-tag "\"\n"
         "        meta mark and 0x00ff0000 == " tailscaled-bypass-mark
         " ip daddr != @tailnet meta mark set 0x00000000 comment \"" rides-tag "\"\n"
         "    }\n"
         "    chain mark_forwarded {\n"
         "        type filter hook prerouting priority mangle; policy accept;\n"
         "        iifname != \"tailscale0\" ip daddr @tailnet " marks "\n"
         "    }\n"
         "    chain snat_tailnet {\n"
         "        type nat hook postrouting priority srcnat; policy accept;\n"
         "        oifname \"tailscale0\" ct mark " mullvad-ct-mark " masquerade\n"
         "    }\n"
         "}\n")))

(defn unit-text
  "Oneshot boot unit running `<self-path> tailscale-routes _apply` after
   tailscaled and mullvad-daemon."
  [self-path]
  (str "[Unit]\n"
       "Description=VPN Kill-Switch: tailnet traffic bypasses Mullvad (nft marks)\n"
       "After=network-online.target tailscaled.service mullvad-daemon.service\n"
       "Wants=network-online.target tailscaled.service\n"
       "\n"
       "[Service]\n"
       "Type=oneshot\n"
       "RemainAfterExit=yes\n"
       "ExecStart=" self-path " tailscale-routes _apply\n"
       "\n"
       "[Install]\n"
       "WantedBy=multi-user.target\n"))
