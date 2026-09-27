(ns vpn-kis-bb.domain.setup
  "Pure side of `setup` (bash main() tail and what it calls: the banner,
   detect_physical_if, backup_existing, disable_ipv6, setup_ufw,
   add_killswitch_before_rules with setup_endpoint_ipset, make_persistent
   and the closing lines).

   Step plans are data that vpn-kis-bb.app.setup interprets in order:
     {:op :log   :level :info|:warn|:plain :text s}
     {:op :run   :cmd argv :on-fail :abort|:warn|:ignore
                 :warning s (with :warn)  :timeout-ms n (optional)}
     {:op :write :path p :body s}
   :abort is the bash `set -e` default, :ignore is `|| true`, :warn is
   `|| warn`."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.exclude :as exclude]
            [vpn-kis-bb.domain.refresh :as refresh]
            [vpn-kis-bb.domain.rules :as rules]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.domain.re :as rx]))

;; ---------------------------------------------------------------- constants

(def banner-title "VPN Kill-Switch Firewall v3")

(def before-init-path "/etc/ufw/before.init")
(def sysctl-conf-path "/etc/sysctl.d/99-disable-ipv6.conf")
(def modprobe-conf-path "/etc/modprobe.d/disable-ipv6.conf")
(def grub-path "/etc/default/grub")

(def backup-sources
  "Files backup_existing copies (cp -a) into the backup dir. app.unlock
   restores the *.rules files and `ufw` (/etc/default/ufw) from there."
  ["/etc/ufw/user.rules" "/etc/ufw/user6.rules" "/etc/ufw/before.rules"
   "/etc/ufw/before6.rules" "/etc/ufw/after.rules" "/etc/default/ufw"])

(def default-timeout-ms
  "Per-command timeout for setup commands (ufw reset/enable/reload can be slow)."
  120000)

(def install-timeout-ms 600000)

(def routes-cmd ["ip" "-4" "route" "ls"])
(def links-cmd ["ls" "/sys/class/net"])
(def date-cmd ["date" "+%Y%m%d-%H%M%S"])

(def sysctl-conf-text
  "/etc/sysctl.d/99-disable-ipv6.conf (disable_ipv6 heredoc)."
  (str "net.ipv6.conf.all.disable_ipv6 = 1\n"
       "net.ipv6.conf.default.disable_ipv6 = 1\n"
       "net.ipv6.conf.lo.disable_ipv6 = 1\n"
       "net.ipv6.conf.all.accept_ra = 0\n"
       "net.ipv6.conf.default.accept_ra = 0\n"
       "net.ipv6.conf.all.forwarding = 0\n"
       "net.ipv6.conf.default.forwarding = 0\n"))

(def modprobe-conf-text
  "/etc/modprobe.d/disable-ipv6.conf (disable_ipv6 heredoc)."
  (str "install ipv6 /bin/true\n"
       "blacklist ipv6\n"
       "alias net-pf-10 off\n"
       "alias sit0 off\n"))

(def before-init-text
  "/etc/ufw/before.init: UFW runs it with `start` before loading the rules
   that reference the ipsets, so it restores them from /etc/ipset.conf."
  (str "#!/bin/sh\n"
       "# Hook: rehydrate the vpn-kis ipsets (vpn_endpoints, vpn_dns_bootstrap) before UFW loads rules (which reference them).\n"
       "case \"$1\" in\n"
       "    start)\n"
       "        if [ -f /etc/ipset.conf ] && command -v ipset >/dev/null 2>&1; then\n"
       "            ipset restore -exist < /etc/ipset.conf 2>/dev/null || true\n"
       "        fi\n"
       "        ;;\n"
       "    stop|status|flush-all)\n"
       "        ;;\n"
       "esac\n"))

(def ^:private proc-disable-script
  (str "for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do "
       "[ -w \"$f\" ] || continue; echo 1 > \"$f\" 2>/dev/null || true; done"))

(def ^:private grub-sed-expr "s/GRUB_CMDLINE_LINUX_DEFAULT=\"/\\0ipv6.disable=1 /")

(def ^:private grub-update-script
  "update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || true")

;; ---------------------------------------------------------------- steps

(defn- info-step [& parts] {:op :log :level :info :text (apply str parts)})
(defn- warn-step [& parts] {:op :log :level :warn :text (apply str parts)})
(def ^:private blank-step {:op :log :level :plain :text ""})
(defn- run-step [cmd on-fail] {:op :run :cmd cmd :on-fail on-fail})
(defn- warn-run-step [cmd warning] {:op :run :cmd cmd :on-fail :warn :warning warning})
(defn- write-step [path body] {:op :write :path path :body body})

;; ---------------------------------------------------------------- inputs

(defn words
  "Whitespace-separated words of `x` (a string, or a collection of strings
   that may each hold several words): trimmed, blanks dropped, order and
   repeats kept."
  [x]
  (->> (if (string? x) [x] x)
       (mapcat (fn [w] (rx/split* (str/trim (str w)) #"\s+")))
       (remove str/blank?)
       vec))

(def ^:private phys-iface-re #"[A-Za-z0-9_.-]+")
(def ^:private vpn-iface-re #"[A-Za-z0-9_.+-]+")

(defn valid-cidr?
  "True for a.b.c.d or a.b.c.d/n with n in 0..32."
  [s]
  (let [[ip bits & more] (rx/split* (str s) #"/" -1)]
    (boolean
     (and (nil? more)
          (u/ipv4? ip)
          (or (nil? bits)
              (let [n (parse-long bits)]
                (and n (<= 0 n 32))))))))

(defn input-errors
  "Messages for context values that would corrupt before.rules, [] when
   all are fine: a :physical-iface outside [A-Za-z0-9_.-], a :lan-allow
   entry that is not a.b.c.d[/n], a :vpn-interfaces pattern outside
   [A-Za-z0-9_.+-]."
  [{:keys [physical-iface lan-allow vpn-interfaces]}]
  (vec
   (concat
    (when (and physical-iface (not (rx/re-matches* phys-iface-re (str physical-iface))))
      [(str "invalid physical interface name '" physical-iface "'")])
    (for [c lan-allow :when (not (valid-cidr? c))]
      (str "invalid LAN CIDR '" c "' (want a.b.c.d or a.b.c.d/n)"))
    (for [v vpn-interfaces :when (not (rx/re-matches* vpn-iface-re (str v)))]
      (str "invalid VPN interface pattern '" v "'")))))

;; ---------------------------------------------------------------- physical IF

(defn iface-from-routes
  "First non-virtual `dev` of the default routes in `ip -4 route ls`
   output, or nil."
  [routes-out]
  (exclude/default-route-iface routes-out))

(defn iface-from-links
  "First name in `ls /sys/class/net` output that is a real interface
   candidate (not virtual per domain.exclude/virtual-iface?, not
   bonding_masters), or nil."
  [ls-out]
  (->> (words (or ls-out ""))
       (remove #{"bonding_masters"})
       (remove exclude/virtual-iface?)
       first))

;; ---------------------------------------------------------------- banner

(defn banner-steps
  "Lines main() prints before any change: title, mode and, in strict
   mode, the endpoint list."
  [{:keys [mode endpoints]}]
  (-> [blank-step (info-step banner-title)]
      (into (if (= :strict mode)
              [(info-step "Mode: STRICT (endpoint-locked, no DNS/443 pre-holes)")
               (info-step "Endpoints: " (str/join " " (words endpoints)))]
              [(info-step "Mode: PERMISSIVE (DNS/443/VPN ports open pre-tunnel)")]))
      (conj (info-step "VPNs: AirVPN/Eddie + Mullvad + generic OpenVPN/WireGuard")
            blank-step)))

(defn done-steps
  "main()'s closing lines; `prog` names the program in the rollback hint."
  [prog]
  [blank-step
   (info-step "Done. Reboot for full IPv6 disable.")
   (info-step "Rollback: sudo " prog " unlock")])

;; ---------------------------------------------------------------- backup

(defn date-stamp
  "`YYYYMMDD-HHMMSS` from `date +%Y%m%d-%H%M%S` output, or nil."
  [out]
  (let [s (str/trim (str (or out "")))]
    (when (rx/re-matches* #"[0-9]{8}-[0-9]{6}" s) s)))

(defn iso-stamp
  "`YYYYMMDD-HHMMSS` from an ISO-8601 UTC string such as
   \"2026-09-27T16:11:49Z\" (domain.util/now-iso), or nil."
  [iso]
  (date-stamp (-> (str iso)
                  (str/replace "-" "")
                  (str/replace ":" "")
                  (str/replace "Z" "")
                  (str/replace "T" "-"))))

(defn backup-dir
  "The bash layout: /etc/ufw/backup-<stamp>."
  [stamp]
  (str "/etc/ufw/backup-" stamp))

(defn- capture-cmd
  "sh -c running `cmd` with stdout to `path` and stderr dropped."
  [cmd path]
  ["sh" "-c" (str cmd " > " (refresh/sh-quote path) " 2>/dev/null")])

(defn backup-steps
  "backup_existing into `dir`: mkdir -p (abort on failure), cp -a of each
   backup-sources file, then ufw-status.txt, iptables.v4 and iptables.v6
   dumps (every copy and dump ignored on failure)."
  [dir]
  (-> [(info-step "Backing up current UFW config to " dir "...")
       (run-step ["mkdir" "-p" dir] :abort)]
      (into (map #(run-step ["cp" "-a" % (str dir "/")] :ignore)) backup-sources)
      (into [(run-step (capture-cmd "ufw status verbose" (str dir "/ufw-status.txt")) :ignore)
             (run-step (capture-cmd "iptables-save" (str dir "/iptables.v4")) :ignore)
             (run-step (capture-cmd "ip6tables-save" (str dir "/iptables.v6")) :ignore)
             (info-step "Backup done. Restore: cp " dir "/*.rules /etc/ufw/ && ufw reload")])))

;; ---------------------------------------------------------------- IPv6

(defn grub-needs-flag?
  "True when /etc/default/grub text is present and lacks ipv6.disable=1."
  [grub-text]
  (boolean (and (string? grub-text)
                (not (str/includes? grub-text "ipv6.disable=1")))))

(defn ipv6-steps
  "disable_ipv6: the sysctl drop-in, applied at once (/proc writes, then
   sysctl --system, whose failure only warns), the modprobe blacklist, and
   ipv6.disable=1 on the GRUB command line when `grub-text` (nil: no
   /etc/default/grub) lacks it."
  [grub-text]
  (-> [(info-step "Disabling IPv6...")
       (write-step sysctl-conf-path sysctl-conf-text)
       (run-step ["sh" "-c" proc-disable-script] :ignore)
       (warn-run-step ["sysctl" "--system"]
                      "sysctl --system reported errors (net.ipv6 keys are absent when IPv6 is off at boot)")
       (write-step modprobe-conf-path modprobe-conf-text)]
      (into (when (grub-needs-flag? grub-text)
              [(run-step ["sed" "-i" grub-sed-expr grub-path] :abort)
               (run-step ["sh" "-c" grub-update-script] :ignore)
               (warn-step "GRUB updated. Reboot to fully apply IPv6 disable.")]))
      (conj (info-step "IPv6 disabled via sysctl + modprobe."))))

;; ---------------------------------------------------------------- UFW

(defn- allow-out [phys port proto comment]
  ["ufw" "allow" "out" "on" phys "to" "any" "port" (str port) "proto" proto "comment" comment])

(defn ufw-steps
  "setup_ufw: reset, default deny incoming/outgoing/routed, allow lo, the
   pre-tunnel user rules (permissive: DNS, 443 and the VPN ports; strict:
   none, before.rules holds the ipset rules), DHCP and NTP, each VPN
   interface in (failure warns) and out (failure ignored), then enable."
  [{:keys [mode physical-iface vpn-interfaces]}]
  (let [phys    physical-iface
        strict? (= :strict mode)
        ifaces  (or (seq vpn-interfaces) rules/default-vpn-interfaces)]
    (-> [(info-step "Configuring UFW (sole firewall manager)...")
         (run-step ["ufw" "--force" "reset"] :abort)
         (run-step ["ufw" "default" "deny" "incoming"] :abort)
         (run-step ["ufw" "default" "deny" "outgoing"] :abort)
         (run-step ["ufw" "default" "deny" "routed"] :abort)
         (run-step ["ufw" "allow" "in" "on" "lo"] :abort)
         (run-step ["ufw" "allow" "out" "on" "lo"] :abort)]
        (into (if strict?
                [(info-step "VPN endpoints set: skipping DNS rules (strict mode, no DNS leak).")]
                [(run-step (allow-out phys 53 "udp" "DNS-UDP-pre-VPN") :abort)
                 (run-step (allow-out phys 53 "tcp" "DNS-TCP-pre-VPN") :abort)]))
        (conj (run-step (allow-out phys 67 "udp" "DHCP") :abort)
              (run-step (allow-out phys 123 "udp" "NTP") :abort))
        (into (if strict?
                [(info-step "Strict mode: endpoint rules live in before.rules via ipset (fast)")]
                (concat
                 [(run-step (allow-out phys 443 "tcp" "Eddie-HTTPS-auth") :abort)]
                 (for [p rules/default-vpn-ports-udp]
                   (run-step (allow-out phys p "udp" (str "VPN-UDP-" p)) :abort))
                 (for [p rules/default-vpn-ports-tcp]
                   (run-step (allow-out phys p "tcp" (str "VPN-TCP-" p)) :abort)))))
        (into (mapcat (fn [v]
                        [(warn-run-step ["ufw" "allow" "in" "on" v]
                                        (str "ufw reject iface pattern: " v))
                         (run-step ["ufw" "allow" "out" "on" v] :ignore)]))
              ifaces)
        (conj (run-step ["ufw" "--force" "enable"] :abort)
              (info-step "UFW enabled with VPN-only rules + DNS/Eddie pre-connect exceptions.")))))

;; ---------------------------------------------------------------- ipsets

(def install-ipset-step
  "setup_endpoint_ipset when ipset is missing."
  {:op         :run
   :cmd        ["env" "DEBIAN_FRONTEND=noninteractive" "apt-get" "install" "-y" "ipset"]
   :on-fail    :abort
   :timeout-ms install-timeout-ms})

(defn set-load-steps
  "Destroy `set-name` (ignored when absent or busy), then load the valid
   IPv4 in `ips` through `ipset restore`, chunk-size addresses per
   payload, each payload creating the set first (-exist). No valid IPv4
   still creates the set, empty."
  [set-name ips chunk-size]
  (let [valid  (refresh/valid-ips ips)
        chunks (if (seq valid) (partition-all chunk-size valid) [[]])]
    (into [(run-step ["ipset" "destroy" set-name] :ignore)]
          (map #(run-step (refresh/restore-command (refresh/restore-payload set-name %)) :abort))
          chunks)))

(defn ipset-steps
  "setup_endpoint_ipset, strict mode: vpn_endpoints from :endpoints
   (non-IPv4 entries skipped with a warning), vpn_dns_bootstrap from
   :dns-bootstrap (created even when empty, so refresh can always save and
   swap it), both saved to /etc/ipset.conf, and the UFW before.init hook
   that restores them at boot."
  ([ctx] (ipset-steps ctx refresh/restore-chunk-size))
  ([{:keys [endpoints dns-bootstrap]} chunk-size]
   (let [eps (words endpoints)
         dns (words dns-bootstrap)]
     (-> [(info-step "Building ipset '" refresh/set-name "' with " (count eps) " IPs...")]
         (into (map #(warn-step "Skipping non-IPv4 endpoint: " %)) (remove u/ipv4? eps))
         (into (set-load-steps refresh/set-name eps chunk-size))
         (conj (if (seq dns)
                 (info-step "Building ipset '" refresh/dns-set-name "' with " (count dns)
                            " DNS bootstrap IPs (port 53 only)...")
                 (info-step "DNS bootstrap off (DNS_BOOTSTRAP_IPS is empty): "
                            "no DNS before the tunnel is up.")))
         (into (map #(warn-step "Skipping non-IPv4 DNS bootstrap IP: " %)) (remove u/ipv4? dns))
         (into (set-load-steps refresh/dns-set-name dns chunk-size))
         (conj (run-step (refresh/save-command) :abort)
               (write-step before-init-path before-init-text)
               (run-step ["chmod" "755" before-init-path] :abort))))))

;; ---------------------------------------------------------------- kill-switch

(defn rules-plan
  "domain.rules plan for a setup context {:mode :physical-iface
   :vpn-interfaces :lan-allow :endpoints :dns-bootstrap :strict-ports?}.
   Strict mode locks to vpn_endpoints, and opens port 53 to
   vpn_dns_bootstrap only when the bootstrap list holds a valid IPv4.
   exclude? adds the cgroup-exclusion ACCEPT block."
  [{:keys [mode physical-iface vpn-interfaces lan-allow endpoints dns-bootstrap
           strict-ports?]}
   exclude?]
  (let [strict? (= :strict mode)
        eps     (refresh/valid-ips (words endpoints))
        dns     (refresh/valid-ips (words dns-bootstrap))]
    (cond-> {:mode           mode
             :physical-iface physical-iface
             :lan-allow      (words lan-allow)
             :exclude?       (boolean exclude?)}
      (seq vpn-interfaces)
      (assoc :vpn-interfaces (vec vpn-interfaces))

      strict?
      (assoc :ipset-name     refresh/set-name
             :endpoint-count (count eps)
             :strict-ports?  (boolean strict-ports?))

      (and strict? (seq dns))
      (assoc :dns-ipset-name refresh/dns-set-name
             :dns-count      (count dns)))))

(defn killswitch-steps
  "add_killswitch_before_rules once the ipsets exist: write before.rules
   (`before-rules-text`) and before6.rules, reload UFW."
  [phys before-rules-text]
  [(write-step rules/before-rules-path before-rules-text)
   (write-step rules/before6-rules-path rules/before6-rules-text)
   (run-step ["ufw" "reload"] :abort)
   (info-step "Kill-switch active in before.rules. Non-VPN traffic on " phys " is DROP'd.")])

(def persist-steps
  "make_persistent: ufw.service restores the rules at boot."
  [(info-step "UFW persistence handled by ufw.service (systemctl enable ufw).")
   (run-step ["systemctl" "enable" "ufw"] :ignore)
   (run-step ["ufw" "reload"] :ignore)])
