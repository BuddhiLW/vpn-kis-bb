(ns vpn-kis-bb.domain.exclude
  "Pure side of the cgroup-based VPN exclusion (bash: the `exclude_*`
   family in vpn-firewall-setup.sh): constants, the before.rules ACCEPT
   block and its rewrite, the systemd unit text, the `exclude run`
   argument grammar, step plans for the mangle / policy-routing / nat
   changes, and parsers for `ip route` output.

   Mechanism: processes in cgroup v2 `vpnkis-exclude` get fwmark 0x51 in
   mangle OUTPUT (loopback, private, link-local and multicast destinations
   excepted); ip rule priority 5080 sends that mark to table 151, whose
   default route is the physical gateway; nat POSTROUTING masquerades it
   to the physical address; one mark-match ACCEPT placed before the
   kill-switch DROP in /etc/ufw/before.rules lets it out.

   Known limitation: Mullvad 2026.x places its catch-all ip rule above the
   lowest existing rule on every reconnect, so while Mullvad is connected
   the priority-5080 rule can be jumped and excluded traffic follows
   Mullvad's table instead. Exclusion is fully reliable with non-Mullvad
   VPNs."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.re :as rx]))

;; ---------------------------------------------------------------- constants

(def mark "0x51")
(def table 151)
(def priority 5080)
(def mangle-chain "VPNKIS-EXCLUDE")
(def nat-chain "VPNKIS-EXCLUDE-NAT")
(def unit-name "vpn-killswitch-exclude.service")
(def unit-path "/etc/systemd/system/vpn-killswitch-exclude.service")
(def cgroup "/sys/fs/cgroup/vpnkis-exclude")
(def cgroup-rel "vpnkis-exclude")
(def cgroup-procs "/sys/fs/cgroup/vpnkis-exclude/cgroup.procs")
(def cgroup-controllers "/sys/fs/cgroup/cgroup.controllers")
(def legacy-users-file "/etc/vpn-killswitch/exclude.users")
(def before-rules-path "/etc/ufw/before.rules")
(def default-prog "vpn-kis")

(def skip-nets
  "Destinations that keep the main table: loopback, RFC1918, link-local,
   multicast, reserved."
  ["127.0.0.0/8" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"
   "169.254.0.0/16" "224.0.0.0/4" "240.0.0.0/4"])

(def block-begin-prefix "# --- BEGIN vpn-kis exclude")
(def block-end-prefix "# --- END vpn-kis exclude")
(def block-begin
  "# --- BEGIN vpn-kis exclude (mark 0x51 via cgroup vpnkis-exclude) ---")
(def block-end "# --- END vpn-kis exclude ---")

(def drain-limit
  "Upper bound on repetitions of a :drain step (`ip rule del` until it fails)."
  16)

;; ---------------------------------------------------------------- before.rules

(defn accept-rule
  "The mark-match ACCEPT for `phys`."
  [phys]
  (str "-A ufw-before-output -o " phys " -m mark --mark " mark " -j ACCEPT"))

(defn drop-rule
  "The kill-switch DROP line the block is inserted before."
  [phys]
  (str "-A ufw-before-output -o " phys " -j DROP"))

(defn before-rules-block
  "Marker-wrapped ACCEPT block: a blank line, BEGIN, the ACCEPT, END, each
   newline-terminated (exclude_emit_before_rules_block)."
  [phys]
  (str "\n" block-begin "\n" (accept-rule phys) "\n" block-end "\n"))

(defn- text->lines
  "awk's view of text: split on \\n, a final newline ends the last line."
  [text]
  (let [parts (vec (rx/split* (or text "") #"\n" -1))]
    (if (= "" (peek parts)) (pop parts) parts)))

(defn- lines->text [lines]
  (apply str (map #(str % "\n") lines)))

(defn- strip-trailing-newlines [s]
  (loop [s s]
    (if (str/ends-with? s "\n") (recur (subs s 0 (dec (count s)))) s)))

(defn- block->lines
  "Lines to insert for a block string (trailing newlines dropped, as by
   bash `$(...)`), or nil when nothing remains."
  [block]
  (let [b (strip-trailing-newlines (or block ""))]
    (when-not (= "" b)
      (vec (rx/split* b #"\n" -1)))))

(defn- end-index
  "Index of the first line at or after i starting with block-end-prefix."
  [lines i]
  (first (filter #(str/starts-with? (nth lines %) block-end-prefix)
                 (range i (count lines)))))

(defn rewrite-before-rules
  "Pure exclude_sync_before_rules: remove every BEGIN..END exclude block
   (matched by the stable prefixes, so blocks written by older versions go
   too) together with the blank line right before each, then insert
   block-or-nil immediately before every line starting with
   `-A ufw-before-output -o <phys> -j DROP`. Idempotent. A BEGIN with no
   END after it loses only its marker line, never the rules that follow.
   Every output line is newline-terminated."
  [text phys block-or-nil]
  (let [lines  (text->lines text)
        n      (count lines)
        blines (block->lines block-or-nil)
        drop-p (drop-rule phys)]
    (loop [i 0 out []]
      (if (>= i n)
        (lines->text out)
        (let [line (nth lines i)]
          (if (str/starts-with? line block-begin-prefix)
            (if-let [j (end-index lines (inc i))]
              (recur (inc j) (if (and (seq out) (str/blank? (peek out))) (pop out) out))
              (recur (inc i) out))
            (recur (inc i)
                   (conj (if (and blines (str/starts-with? line drop-p))
                           (into out blines)
                           out)
                         line))))))))

(def ^:private iface-re #"[A-Za-z0-9_.-]+")

(defn pinned-phys
  "Interface of the first `-A ufw-before-output -o X -j DROP` line, or nil.
   Group-free: capture-group regex results are unreliable on cljw."
  [before-rules-text]
  (some (fn [line]
          (when (str/starts-with? line "-A ufw-before-output -o ")
            (let [x (get (rx/split* line #"\s+") 3)]
              (when (and x
                         (rx/re-matches* iface-re x)
                         (str/starts-with? line (drop-rule x)))
                x))))
        (rx/split-lines* (or before-rules-text ""))))

(defn accept-present?
  "True when before.rules text carries the mark ACCEPT (`--mark 0x51 -j ACCEPT`)."
  [before-rules-text]
  (boolean (and before-rules-text
                (str/includes? before-rules-text (str "--mark " mark " -j ACCEPT")))))

(defn mark-lines
  "Lines of before.rules text mentioning `--mark 0x51`."
  [before-rules-text]
  (filterv #(str/includes? % (str "--mark " mark))
           (rx/split-lines* (or before-rules-text ""))))

;; ---------------------------------------------------------------- systemd unit

(defn unit-text
  "Oneshot unit that re-applies routing at boot (`<self> exclude _apply`)
   and tears it down on stop (`<self> exclude _teardown`)."
  [self-path]
  (str "[Unit]\n"
       "Description=VPN Kill-Switch: cgroup-based VPN exclusion (mark + route excluded cgroup)\n"
       "After=network-online.target\n"
       "Wants=network-online.target\n"
       "\n"
       "[Service]\n"
       "Type=oneshot\n"
       "RemainAfterExit=yes\n"
       "ExecStart=" self-path " exclude _apply\n"
       "ExecStop=" self-path " exclude _teardown\n"
       "\n"
       "[Install]\n"
       "WantedBy=multi-user.target\n"))

;; ---------------------------------------------------------------- exclude run

(defn- scan-flags
  "Leading-option pass of exclude_run. Returns {:as user-or-nil :more [...]}
   or {:error msg}."
  [args]
  (loop [as nil
         xs (vec args)]
    (if (empty? xs)
      {:as as :more []}
      (let [a (first xs)]
        (cond
          (= a "--as")
          (let [u (get xs 1)]
            (if (or (nil? u) (= "" u))
              {:error "exclude run: --as needs a username"}
              (recur u (subvec xs 2))))

          (str/starts-with? a "--as=")
          (recur (not-empty (subs a 5)) (subvec xs 1))

          (= a "--")
          {:as as :more (subvec xs 1)}

          (str/starts-with? a "--")
          {:error (str "exclude run: unknown flag '" a "'")}

          :else
          {:as as :more xs})))))

(defn parse-run-args
  "Parse `exclude run` arguments with the bash exclude_run grammar:
     [--as USER | --as=USER]... [--] COMMAND...
   `--` ends options; an unknown `--flag` is an error; the legacy form
   `USER -- COMMAND...` means `--as USER` when (user-exists? USER).
   Returns {:user u-or-nil :argv [...]} (argv = the command as given) or
   {:error msg}. `prog` names the program in the usage message."
  ([args user-exists?] (parse-run-args args user-exists? default-prog))
  ([args user-exists? prog]
   (let [{:keys [error as more]} (scan-flags args)]
     (if error
       {:error error}
       (let [legacy? (and (nil? as)
                          (>= (count more) 2)
                          (= "--" (get more 1))
                          (user-exists? (get more 0)))
             user    (if legacy? (get more 0) as)
             argv    (if legacy? (subvec more 2) more)]
         (cond
           (empty? argv)
           {:error (str "exclude run: usage: sudo " prog
                        " exclude run [--as USER] -- <command>")}

           (and user (not (user-exists? user)))
           {:error (str "exclude run: user '" user "' does not exist")}

           :else
           {:user user :argv argv}))))))

(defn run-argv
  "Command to exec for a parsed run, wrapped in `runuser -u USER --` when
   a user was given."
  [{:keys [user argv]}]
  (if user
    (into ["runuser" "-u" user "--"] argv)
    (vec argv)))

;; ---------------------------------------------------------------- commands

(defn- ipt [tbl & args]
  (into ["iptables" "-t" tbl] args))

(def mkdir-cgroup-cmd ["mkdir" "-p" cgroup])
(def rmdir-cgroup-cmd ["rmdir" cgroup])
(def default-routes-cmd ["ip" "-4" "route" "ls"])
(def ufw-reload-cmd ["ufw" "reload"])
(def rule-del-cmd ["ip" "rule" "del" "priority" (str priority)])
(def rule-add-cmd ["ip" "rule" "add" "fwmark" mark "lookup" (str table)
                   "priority" (str priority)])
(def route-flush-cmd ["ip" "route" "flush" "table" (str table)])
(def rule-show-cmd ["ip" "rule" "show" "priority" (str priority)])
(def table-show-cmd ["ip" "route" "show" "table" (str table)])
(def unit-active-cmd ["systemctl" "is-active" unit-name])
(def mark-cmd (ipt "mangle" "-A" mangle-chain "-m" "cgroup" "--path" cgroup-rel
                   "-j" "MARK" "--set-mark" mark))

(defn gateway-query-cmd [phys] ["ip" "route" "show" "dev" phys])
(defn user-check-cmd [user] ["id" user])
(defn chain-list-cmd [tbl chain] (ipt tbl "-S" chain))
(defn skip-net-cmd [net] (ipt "mangle" "-A" mangle-chain "-d" net "-j" "RETURN"))

(defn route-replace-cmd [phys gw]
  ["ip" "route" "replace" "default" "via" gw "dev" phys "table" (str table)])

(defn masquerade-cmd [phys]
  (ipt "nat" "-A" nat-chain "-m" "mark" "--mark" mark "-o" phys "-j" "MASQUERADE"))

;; ---------------------------------------------------------------- step plans
;; A step is data the app layer interprets against IShell:
;;   {:op :run    :cmd v :on-fail :ignore|:warn|:abort}  (:warn adds :warning)
;;   {:op :ensure :check v :cmd v}  run :cmd (abort on failure) unless :check exits 0
;;   {:op :drain  :cmd v}           repeat :cmd until it fails, at most drain-limit times

(defn- run-step [cmd on-fail] {:op :run :cmd cmd :on-fail on-fail})
(defn- warn-step [cmd warning] {:op :run :cmd cmd :on-fail :warn :warning warning})
(defn- ensure-step [check cmd] {:op :ensure :check check :cmd cmd})
(defn- drain-step [cmd] {:op :drain :cmd cmd})

(def mangle-steps
  "Chain + OUTPUT jump (created once), flushed and rebuilt: skip-net
   RETURNs, then the cgroup MARK."
  (-> [(run-step (ipt "mangle" "-N" mangle-chain) :ignore)
       (ensure-step (ipt "mangle" "-C" "OUTPUT" "-j" mangle-chain)
                    (ipt "mangle" "-A" "OUTPUT" "-j" mangle-chain))
       (run-step (ipt "mangle" "-F" mangle-chain) :abort)]
      (into (map #(run-step (skip-net-cmd %) :abort) skip-nets))
      (conj (warn-step mark-cmd
                       "exclude: cgroup mark rule failed (xt_cgroup missing, or cgroup absent)"))))

(defn route-steps
  "Table default via the physical gateway; every priority-5080 rule
   deleted, then the fwmark rule added."
  [phys gw]
  [(run-step (route-replace-cmd phys gw) :abort)
   (drain-step rule-del-cmd)
   (run-step rule-add-cmd :abort)])

(defn nat-steps
  "Chain + POSTROUTING jump (created once), flushed, then the MASQUERADE."
  [phys]
  [(run-step (ipt "nat" "-N" nat-chain) :ignore)
   (ensure-step (ipt "nat" "-C" "POSTROUTING" "-j" nat-chain)
                (ipt "nat" "-A" "POSTROUTING" "-j" nat-chain))
   (run-step (ipt "nat" "-F" nat-chain) :abort)
   (run-step (masquerade-cmd phys) :abort)])

(defn apply-steps
  "Full exclude_apply_routing plan once phys and gateway are known."
  [phys gw]
  (-> mangle-steps
      (into (route-steps phys gw))
      (into (nat-steps phys))))

(def teardown-steps
  "exclude_teardown_routing: every step best-effort."
  [(drain-step rule-del-cmd)
   (run-step route-flush-cmd :ignore)
   (run-step (ipt "mangle" "-F" mangle-chain) :ignore)
   (run-step (ipt "mangle" "-D" "OUTPUT" "-j" mangle-chain) :ignore)
   (run-step (ipt "mangle" "-X" mangle-chain) :ignore)
   (run-step (ipt "nat" "-F" nat-chain) :ignore)
   (run-step (ipt "nat" "-D" "POSTROUTING" "-j" nat-chain) :ignore)
   (run-step (ipt "nat" "-X" nat-chain) :ignore)])

(defn step-cmds
  "Every command a plan can issue, in order (an :ensure lists :check then
   :cmd; a :drain lists its command once)."
  [steps]
  (vec (mapcat (fn [{:keys [op check cmd]}]
                 (if (= :ensure op) [check cmd] [cmd]))
               steps)))

;; ---------------------------------------------------------------- parsers

(defn- fields [line]
  (let [t (str/trim line)]
    (if (= "" t) [] (rx/split* t #"\s+"))))

(defn parse-gateway
  "Gateway in `ip route show dev PHYS` output: third field of the first
   `default via` line, else of the first line containing ` via `; nil when
   neither gives one."
  [out]
  (let [lines (rx/split-lines* (or out ""))
        third (fn [pred]
                (when-let [l (first (filter pred lines))]
                  (not-empty (get (fields l) 2))))]
    (or (third #(str/starts-with? % "default via"))
        (third #(str/includes? % " via ")))))

(defn virtual-iface?
  "True for interfaces the kill-switch never pins: lo, Eddie, and names
   starting with tun wg tailscale ppp docker veth virbr br- zt."
  [iface]
  (boolean
   (and iface
        (or (contains? #{"lo" "Eddie"} iface)
            (some #(str/starts-with? iface %)
                  ["tun" "wg" "tailscale" "ppp" "docker" "veth" "virbr" "br-" "zt"])))))

(defn default-route-iface
  "First non-virtual `dev` of the default routes in `ip -4 route ls`
   output, or nil."
  [out]
  (->> (rx/split-lines* (or out ""))
       (filter #(str/starts-with? % "default"))
       (keep (fn [l] (second (drop-while #(not= "dev" %) (fields l)))))
       (remove virtual-iface?)
       first))

(defn nonblank-lines [s]
  (vec (remove str/blank? (rx/split-lines* (or s "")))))

;; ---------------------------------------------------------------- messages

(defn enabled-message
  "Hint printed after `exclude on`."
  [prog]
  (str "exclude: enabled. Run: sudo " prog
       " exclude run -- <command>  (add --as USER to drop root)"))

(defn- indent [prefix lines]
  (map #(str prefix %) lines))

(defn status-lines
  "Printable lines for an app.exclude/status map (exclude_status layout)."
  [{:keys [enabled? prog phys members ip-rules routes mangle nat
           before-rules-accept unit-active]}]
  (if-not enabled?
    [(str "exclude: disabled. Enable + run in one step: sudo "
          (or prog default-prog) " exclude run -- <command>")]
    (-> [(str "exclude: ENABLED (cgroup " cgroup " -> " (or phys "?")
              ", mark " mark " table " table ")")
         "  members (PIDs in cgroup):"]
        (into (if (nil? members)
                ["    (none / cgroup absent)"]
                (indent "    " members)))
        (conj "")
        (conj (str "ip rule (prio " priority "):"))
        (into (indent "  " ip-rules))
        (conj (str "route table " table ":"))
        (into (indent "  " routes))
        (conj "mangle chain:")
        (into (indent "  " mangle))
        (conj "nat chain:")
        (into (indent "  " nat))
        (conj "before.rules ACCEPT:")
        (into (indent "  " before-rules-accept))
        (conj "unit:")
        (conj (str "  active : " unit-active)))))
