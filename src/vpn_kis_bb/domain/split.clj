(ns vpn-kis-bb.domain.split
  "Pure side of per-domain split tunnels (bash: the split_* family of
   vpn-firewall-setup.sh): names and paths, config validation, the text of
   the dnsmasq drop-in, the openvpn up/down hooks and the boot unit,
   iptables and openvpn argv, the unit-file parser `split rm` needs, and
   the list/status report lines.

   Generated files match the bash output except that the unit Description
   and the up-hook log line are plain ASCII and the drop-in header names
   vpn-kis. Validation and tokenizing use character sets, not regexes
   (ClojureWasm 1.14.11 corrupts some regex results)."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.re :as rx]))

;; ---------------------------------------------------------------- constants

(def default-table
  "Route table a split uses when its conf sets no TABLE."
  142)

(def default-mark
  "fwmark a split uses when its conf sets no MARK."
  "0x42")

(def mangle-chain
  "iptables mangle chain shared by every split (one MARK rule per split)."
  "VPNKIS-SPLIT")

(def conf-dir "/etc/vpn-killswitch/split")
(def dnsmasq-dir "/etc/dnsmasq.d")
(def unit-dir "/etc/systemd/system")

(def unit-glob
  "Glob, in unit-dir, matching every split unit."
  "vpn-killswitch-split-*.service")

(def dnsmasq-glob
  "Glob, in dnsmasq-dir, matching every split drop-in."
  "vpn-kis-split-*.conf")

(def ipset-prefix
  "Name prefix of every split ipset."
  "vpnkis_split_")

(def ipset-opts
  "`ipset create` options of a split set (bash split_install_ipset)."
  {:hashsize 1024 :maxelem 65536 :timeout 3600})

;; ---------------------------------------------------------------- characters (no regex)

(def ^:private letters (set "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"))
(def ^:private digit-chars (set "0123456789"))
(def ^:private hex-chars (into digit-chars "abcdefABCDEF"))
(def ^:private alnum (into letters digit-chars))
(def ^:private name-chars (into alnum "_-"))
(def ^:private token-chars (into alnum "_.-"))
(def ^:private whitespace #{\space \tab \newline \return \formfeed})

(defn- only?
  "True when s is a non-empty string of chars from the set allowed."
  [allowed s]
  (boolean (and (string? s) (seq s) (every? allowed s))))

(defn digits?
  "True when s is a non-empty string of decimal digits."
  [s]
  (only? digit-chars s))

(defn words
  "Whitespace-separated tokens of s (as `for d in $VAR` splits them)."
  [s]
  (->> (str s)
       (partition-by #(contains? whitespace %))
       (remove #(contains? whitespace (first %)))
       (mapv #(apply str %))))

;; ---------------------------------------------------------------- names and paths

(defn ipset-name       [n] (str ipset-prefix n "_dst"))
(defn unit-name        [n] (str "vpn-killswitch-split-" n ".service"))
(defn unit-path        [n] (str unit-dir "/" (unit-name n)))
(defn dnsmasq-name     [n] (str "vpn-kis-split-" n ".conf"))
(defn dnsmasq-path     [n] (str dnsmasq-dir "/" (dnsmasq-name n)))
(defn up-script-path   [n] (str conf-dir "/" n ".up.sh"))
(defn down-script-path [n] (str conf-dir "/" n ".down.sh"))
(defn conf-path        [n] (str conf-dir "/" n ".conf"))
(defn edn-path         [n] (str conf-dir "/" n ".edn"))

(defn valid-name?
  "True for a split name bash accepts: [a-zA-Z0-9_-]+."
  [n]
  (only? name-chars n))

(defn basename
  "Last component of path p."
  [p]
  (let [p (str p)
        i (str/last-index-of p "/")]
    (if i (subs p (inc i)) p)))

(defn conf-names
  "Split names of config file paths (<name>.conf or <name>.edn), distinct
   and sorted."
  [paths]
  (->> paths
       (keep (fn [p]
               (let [f (basename p)]
                 (cond
                   (str/ends-with? f ".conf") (subs f 0 (- (count f) 5))
                   (str/ends-with? f ".edn")  (subs f 0 (- (count f) 4))))))
       (remove str/blank?)
       distinct
       sort
       vec))

(defn split-ipsets
  "Split set names (prefix ipset-prefix) in `ipset list -name` output."
  [text]
  (->> (rx/split-lines* (or text ""))
       (map str/trim)
       (filter #(str/starts-with? % ipset-prefix))
       vec))

;; ---------------------------------------------------------------- validation

(def reserved-tables
  "Route tables a split must not own, since its down hook flushes the
   table: the kernel's unspec, default, main and local."
  #{"0" "253" "254" "255" "unspec" "default" "main" "local"})

(defn- fail [msg] {:ok? false :error msg})

(defn- present
  "x as a trimmed string; nil when nil or blank."
  [x]
  (let [s (when (some? x) (str/trim (str x)))]
    (when-not (str/blank? s) s)))

(defn- patterns-of
  "DOMAINS as a vector of patterns, from a seq or a whitespace-separated
   string."
  [domains]
  (cond
    (nil? domains)        []
    (sequential? domains) (vec (keep present domains))
    :else                 (words domains)))

(defn- strip-wildcard [d] (if (str/starts-with? d "*.") (subs d 2) d))

(defn- domain-ok? [d] (only? token-chars d))

(defn- dev-ok? [d] (only? token-chars d))

(defn- table-of
  "TABLE: nil or blank -> default-table, digits -> a long, an rt_tables
   name ([A-Za-z_][A-Za-z0-9_.-]*) -> the string, else :invalid."
  [t]
  (let [s (present t)]
    (cond
      (nil? s)    default-table
      (digits? s) (or (parse-long s) :invalid)
      (and (only? token-chars s)
           (contains? (conj letters \_) (first s))) s
      :else       :invalid)))

(defn- mark-number?
  "Decimal digits, or 0x / 0X followed by hex digits."
  [s]
  (or (digits? s)
      (and (string? s)
           (or (str/starts-with? s "0x") (str/starts-with? s "0X"))
           (only? hex-chars (subs s 2)))))

(defn- mark-ok?
  "VALUE or VALUE/MASK, each a mark-number."
  [m]
  (if-let [i (str/index-of m "/")]
    (and (mark-number? (subs m 0 i)) (mark-number? (subs m (inc i))))
    (mark-number? m)))

(defn- priority-of
  "PRIORITY: nil, blank, \"auto\" or :auto -> :auto; a non-negative integer
   or digits -> a long; anything else -> :invalid."
  [p]
  (cond
    (or (nil? p) (= :auto p)) :auto
    (integer? p)              (if (neg? p) :invalid (long p))
    :else
    (let [s (str/trim (str p))]
      (cond
        (or (= "" s) (= "auto" s)) :auto
        (digits? s)                (or (parse-long s) :invalid)
        :else                      :invalid))))

(defn validate
  "Validate and normalize a split config: the bash split_load_conf checks,
   plus DEV, TABLE, MARK and domain syntax, so a bad value fails here
   instead of halfway through an install.

   cfg: {:name :domains :dev :table :mark :priority :ovpn-config}; :domains
   a seq or a whitespace-separated string, the rest strings (KEY=VALUE conf)
   or EDN values. source names the config file in messages (default: the
   conf-path of the name).

   {:ok? true :value {:name :patterns [..] :domains [..] :dev :table :mark
                      :priority :ovpn-config :source}}: :patterns as
   written, :domains without a leading \"*.\", :table a long or an
   rt_tables name, :priority a long or :auto, :ovpn-config nil when unset.
   Otherwise {:ok? false :error msg}."
  ([cfg] (validate cfg nil))
  ([cfg source]
   (let [{:keys [name domains dev table mark priority ovpn-config]} (when (map? cfg) cfg)
         where    (or source (when (valid-name? name) (conf-path name)))
         patterns (patterns-of domains)
         doms     (mapv strip-wildcard patterns)
         bad-dom  (first (remove domain-ok? doms))
         dev      (present dev)
         tbl      (table-of table)
         mark     (or (present mark) default-mark)
         prio     (priority-of priority)]
     (cond
       (not (map? cfg))
       (fail "split: config is empty or not a map")

       (nil? (present name))
       (fail "split: name required")

       (not (valid-name? name))
       (fail "split: name must match [a-zA-Z0-9_-]+")

       (empty? doms)
       (fail (str "split: DOMAINS empty in " where))

       bad-dom
       (fail (str "split: invalid domain '" bad-dom "' in " where
                  " (letters, digits, '.', '-', '_', after an optional leading '*.')"))

       (nil? dev)
       (fail (str "split: DEV empty in " where " (must match openvpn --dev)"))

       (not (dev-ok? dev))
       (fail (str "split: DEV '" dev "' in " where " is not an interface name ([A-Za-z0-9_.-]+)"))

       (= :invalid tbl)
       (fail (str "split: TABLE must be a route table number or name, got '" (present table) "'"))

       (contains? reserved-tables (str tbl))
       (fail (str "split: TABLE " tbl " is a kernel table (unspec, default, main, local);"
                  " pick another, e.g. " default-table))

       (not (mark-ok? mark))
       (fail (str "split: MARK must be a number such as " default-mark
                  " (optionally VALUE/MASK), got '" mark "'"))

       (= :invalid prio)
       (fail "split: PRIORITY must be 'auto' or integer")

       :else
       {:ok?   true
        :value {:name        name
                :patterns    patterns
                :domains     doms
                :dev         dev
                :table       tbl
                :mark        mark
                :priority    prio
                :ovpn-config (present ovpn-config)
                :source      where}}))))

;; ---------------------------------------------------------------- generated files

(defn dnsmasq-drop-in-text
  "dnsmasq drop-in of a validated config (bash split_install_dnsmasq): one
   ipset=/<domain>/<set> line per domain."
  [{:keys [name dev domains]}]
  (let [set-name (ipset-name name)]
    (apply str
           "# Generated by vpn-kis split add " name "\n"
           "# Domains routed via auxiliary tunnel " dev "\n"
           (map #(str "ipset=/" % "/" set-name "\n") domains))))

(defn openvpn-up-script-text
  "openvpn --up hook: the split's table gets a default route via the
   tunnel device (bash split_write_updown_scripts)."
  [{:keys [name dev table]}]
  (str "#!/bin/sh\n"
       "# openvpn --up hook for split '" name "'.\n"
       "# Args from openvpn: $1=dev $2=tun_mtu $3=link_mtu $4=ifconfig_local $5=ifconfig_remote\n"
       "set -eu\n"
       "DEV=\"${1:-" dev "}\"\n"
       "ip route replace default dev \"$DEV\" table " table "\n"
       "logger -t vpn-kis-split \"[" name "] route table " table " -> $DEV\"\n"))

(defn openvpn-down-script-text
  "openvpn --down hook: flush the split's table."
  [{:keys [name table]}]
  (str "#!/bin/sh\n"
       "# openvpn --down hook for split '" name "'.\n"
       "set -eu\n"
       "ip route flush table " table " 2>/dev/null || true\n"
       "logger -t vpn-kis-split \"[" name "] route table " table " flushed\"\n"))

(defn systemd-unit-text
  "Boot unit of a validated config whose priority is resolved (bash
   split_install_systemd): recreates the ipset, the mangle hookup and the
   ip rule; ExecStop deletes the rule and the mark and flushes the table."
  [{:keys [name table mark priority]}]
  (let [set-name (ipset-name name)
        ch       mangle-chain
        {:keys [hashsize maxelem timeout]} ipset-opts]
    (str
     "[Unit]\n"
     "Description=VPN Kill-Switch: split '" name "' (mark " mark " -> table " table ")\n"
     "After=network-pre.target\n"
     "Before=network.target\n"
     "\n"
     "[Service]\n"
     "Type=oneshot\n"
     "RemainAfterExit=yes\n"
     "ExecStart=/sbin/ipset create " set-name " hash:ip family inet hashsize " hashsize
     " maxelem " maxelem " timeout " timeout " -exist\n"
     "ExecStart=-/sbin/iptables -t mangle -N " ch "\n"
     "ExecStart=-/sbin/iptables -t mangle -C OUTPUT -j " ch "\n"
     "ExecStart=/bin/sh -c '/sbin/iptables -t mangle -C OUTPUT -j " ch
     " 2>/dev/null || /sbin/iptables -t mangle -A OUTPUT -j " ch "'\n"
     "ExecStart=/bin/sh -c '/sbin/iptables -t mangle -C PREROUTING -j " ch
     " 2>/dev/null || /sbin/iptables -t mangle -A PREROUTING -j " ch "'\n"
     "ExecStart=/bin/sh -c 'while /sbin/iptables -t mangle -D " ch " -m set --match-set " set-name
     " dst -j MARK --set-mark " mark " 2>/dev/null; do :; done'\n"
     "ExecStart=/sbin/iptables -t mangle -A " ch " -m set --match-set " set-name
     " dst -j MARK --set-mark " mark "\n"
     "ExecStart=/bin/sh -c 'while /sbin/ip rule del priority " priority " 2>/dev/null; do :; done'\n"
     "ExecStart=/sbin/ip rule add fwmark " mark " lookup " table " priority " priority "\n"
     "ExecStop=/bin/sh -c 'while /sbin/ip rule del priority " priority " 2>/dev/null; do :; done'\n"
     "ExecStop=-/sbin/iptables -t mangle -D " ch " -m set --match-set " set-name
     " dst -j MARK --set-mark " mark "\n"
     "ExecStop=-/sbin/ip route flush table " table "\n"
     "\n"
     "[Install]\n"
     "WantedBy=multi-user.target\n")))

(defn unit-rule-params
  "fwmark and priority of the `ip rule add` ExecStart line of a split unit
   file (bash split_remove's awk): {:priority s :fwmark s}, each nil when
   absent (both nil for nil text)."
  [unit-text]
  (let [line   (some (fn [l]
                       (when-let [i (str/index-of l "ExecStart=")]
                         (when (str/includes? (subs l i) "ip rule add") l)))
                     (rx/split-lines* (or unit-text "")))
        tokens (if line (words line) [])
        after  (fn [k] (some (fn [[a b]] (when (= a k) b)) (partition 2 1 tokens)))]
    {:priority (after "priority")
     :fwmark   (after "fwmark")}))

;; ---------------------------------------------------------------- commands

(defn- mangle [& args] (into ["iptables" "-t" "mangle"] args))

(def chain-new-cmd (mangle "-N" mangle-chain))

(defn jump-check-cmd
  "iptables -C: does builtin chain `hook` jump to the split chain?"
  [hook]
  (mangle "-C" hook "-j" mangle-chain))

(defn jump-add-cmd [hook] (mangle "-A" hook "-j" mangle-chain))

(defn- mark-args [n mark]
  ["-m" "set" "--match-set" (ipset-name n) "dst" "-j" "MARK" "--set-mark" (str mark)])

(defn mark-del-cmd
  "Deletes one MARK rule of split n from the shared chain."
  [n mark]
  (into (mangle "-D" mangle-chain) (mark-args n mark)))

(defn mark-add-cmd [n mark] (into (mangle "-A" mangle-chain) (mark-args n mark)))

(def chain-teardown-cmds
  "Remove the shared chain: both jumps, flush, delete (bash split_remove_all
   and panic). Each fails harmlessly when the chain is already gone."
  [(mangle "-D" "OUTPUT" "-j" mangle-chain)
   (mangle "-D" "PREROUTING" "-j" mangle-chain)
   (mangle "-F" mangle-chain)
   (mangle "-X" mangle-chain)])

(defn rule-show-cmd [priority] ["ip" "rule" "show" "priority" (str priority)])

(defn route-show-cmd [table] ["ip" "route" "show" "table" (str table)])

(defn openvpn-argv
  "bash split_connect's openvpn command line for a validated config: the
   pushed redirect-gateway and DNS ignored, route-nopull, the --dev pin,
   the up/down hooks."
  [{:keys [name dev ovpn-config]}]
  ["openvpn"
   "--config" (str ovpn-config)
   "--dev" (str dev)
   "--pull-filter" "ignore" "redirect-gateway"
   "--pull-filter" "ignore" "dhcp-option DNS"
   "--route-nopull"
   "--script-security" "2"
   "--up" (up-script-path name)
   "--down" (down-script-path name)])

;; ---------------------------------------------------------------- reports

(defn- pad-right [s width]
  (let [s (str s)]
    (apply str s (repeat (- width (count s)) " "))))

(defn list-line
  "bash split_list's line for {:name :installed?}; prog stands for $0."
  [{:keys [name installed?]} prog]
  (if installed?
    (str "  " (pad-right name 20) "  installed (unit: " (unit-name name) ")")
    (str "  " (pad-right name 20) "  configured (run: " prog " split add " name ")")))

(defn- prefixed [prefix text]
  (if (str/blank? text) [] (mapv #(str prefix %) (rx/split-lines* text))))

(defn status-report
  "bash split_status's output as [[level line] ..]: level :info or :warn
   (stderr) or :say (stdout). cfg: validated, priority resolved. live:
   {:ipset-ok? bool :ipset s :rules s :routes s :enabled s :active s},
   command outputs (:enabled and :active include stderr, as 2>&1)."
  [{:keys [name patterns dev table mark priority ovpn-config]}
   {:keys [ipset-ok? ipset rules routes enabled active]}]
  (let [set-name (ipset-name name)
        says     (fn [lines] (map (fn [l] [:say l]) lines))]
    (-> [[:info (str "Split '" name "':")]
         [:info (str "  domains   : " (str/join " " patterns))]
         [:info (str "  dev       : " dev)]
         [:info (str "  table     : " table)]
         [:info (str "  mark      : " mark)]
         [:info (str "  priority  : " priority)]
         [:info (str "  ovpn      : " (or ovpn-config "(unset)"))]
         [:say ""]
         [:info (str "ipset " set-name ":")]]
        (into (if ipset-ok?
                (says (prefixed "  " ipset))
                [[:warn (str "  ipset " set-name " not present")]]))
        (conj [:say ""] [:info "ip rule:"])
        (into (says (prefixed "  " rules)))
        (conj [:say ""] [:info (str "route table " table ":")])
        (into (says (prefixed "  " routes)))
        (conj [:say ""] [:info "systemd unit:"])
        (into (says (prefixed "  enabled: " enabled)))
        (into (says (prefixed "  active : " active))))))
