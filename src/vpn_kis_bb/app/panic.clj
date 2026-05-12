(ns vpn-kis-bb.app.panic
  "Emergency recovery: drop the entire kill-switch and restore network
   connectivity. Run from a local TTY when you've locked yourself out.

   Mirrors the bash `panic_recover` (vpn-firewall-setup.sh ~line 317):
     1. ufw --force disable
     2. flush iptables (filter/nat/mangle/raw, v4 + v6), policies ACCEPT
     3. destroy ipsets (vpn_endpoints + vpnkis_split_* + tailscale routes)
     4. remove NM dispatcher hook + UFW before.init
     5. disable + remove tailscale-routes + split systemd units
     6. re-enable IPv6 at runtime (sysctl writes still persist across reboot)
     7. reset /etc/resolv.conf to public resolvers
     8. restart systemd-resolved + NetworkManager + tailscaled
     9. connectivity probe (ping 1.1.1.1 + DNS getent)"
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]))

(def public-resolv-conf
  "# Emergency DNS — restored by vpn-kis-bb panic
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
options timeout:2 attempts:2
")

(defn- safe-exec [shell cmd]
  ;; Each command is best-effort; we never abort the panic flow on a
  ;; single non-zero exit. Capture the result for the report.
  (let [r (proto/shell-exec! shell cmd {:timeout-ms 10000})]
    {:cmd cmd
     :exit (if (r/ok? r) (-> r :ok :exit) :err)
     :stderr (when (r/ok? r) (-> r :ok :stderr str/trim))}))

(defn- flush-iptables [shell]
  (mapv #(safe-exec shell %)
        (for [bin   ["iptables" "ip6tables"]
              tbl   ["filter" "nat" "mangle" "raw"]
              flag  ["-F" "-X"]]
          [bin "-t" tbl flag])))

(defn- reset-policies [shell]
  (mapv #(safe-exec shell %)
        (for [bin   ["iptables" "ip6tables"]
              chain ["INPUT" "OUTPUT" "FORWARD"]]
          [bin "-P" chain "ACCEPT"])))

(defn- destroy-known-ipsets [shell]
  ;; Enumerate any vpnkis_*/vpn_endpoints set and destroy.
  (let [r (proto/shell-exec! shell ["ipset" "list" "-name"] {})
        names (if (r/ok? r)
                (->> (str/split-lines (-> r :ok :stdout))
                     (filter #(or (= % "vpn_endpoints")
                                  (str/starts-with? % "vpnkis_")))
                     vec)
                [])]
    (mapv #(safe-exec shell ["ipset" "destroy" %]) names)))

(defn- remove-split-units [shell delete-fn]
  (let [units (try (->> (fs/glob "/etc/systemd/system"
                                 "vpn-killswitch-{split-*,tailscale-routes}.service")
                        (map str)
                        vec)
                   (catch Throwable _ []))
        disables (mapv (fn [u]
                         (safe-exec shell ["systemctl" "disable" "--now"
                                           (str (fs/file-name u))]))
                       units)]
    (doseq [u units] (delete-fn u))
    {:units units :disables disables}))

(defn- reenable-ipv6 []
  (try
    (doseq [f (fs/glob "/proc/sys/net/ipv6/conf" "*/disable_ipv6")]
      (try (spit (str f) "0") (catch Throwable _ nil)))
    {:ok true}
    (catch Throwable t {:ok false :cause (str t)})))

(defn- reset-resolv-conf [write-fn delete-fn]
  ;; If /etc/resolv.conf is a symlink (systemd-resolved), break it first.
  (try
    (when (and (fs/exists? "/etc/resolv.conf")
               (fs/sym-link? "/etc/resolv.conf"))
      (delete-fn "/etc/resolv.conf"))
    (write-fn "/etc/resolv.conf" public-resolv-conf)
    (catch Throwable t
      (r/err :panic/dns-reset-failed {:cause (str t)}))))

(defn- restart-network [shell]
  (mapv #(safe-exec shell %)
        [["systemctl" "restart" "systemd-resolved"]
         ["systemctl" "restart" "NetworkManager"]
         ["systemctl" "restart" "tailscaled"]]))

(defn- probe [shell]
  {:ping  (safe-exec shell ["ping" "-c" "1" "-W" "3" "1.1.1.1"])
   :dns   (safe-exec shell ["getent" "ahosts" "cloudflare.com"])})

(defn panic!
  "Emergency recovery. Honors :dry-run? to print the plan only.

   Returns Result<{...report}> where the report covers each step."
  [system {:keys [dry-run?] :as _opts}]
  (let [{:keys [shell write-fn delete-fn]} system]
    (cond
      dry-run?
      (r/ok {:dry-run? true
             :steps ["ufw --force disable"
                     "iptables/ip6tables flush + default ACCEPT"
                     "ipset destroy vpn_endpoints + vpnkis_split_*"
                     "remove NM dispatcher + before.init"
                     "remove tailscale-routes + split systemd units"
                     "re-enable ipv6 in /proc"
                     "reset /etc/resolv.conf to public resolvers"
                     "restart systemd-resolved + NetworkManager + tailscaled"
                     "connectivity probe"]})

      :else
      (let [ufw-off (safe-exec shell ["ufw" "--force" "disable"])
            flushed (flush-iptables shell)
            policy  (reset-policies shell)
            destroyed (destroy-known-ipsets shell)
            unit-rm (remove-split-units shell delete-fn)
            nm-dispatcher (do (delete-fn "/etc/NetworkManager/dispatcher.d/90-vpn-killswitch")
                              (delete-fn "/etc/ufw/before.init"))
            ipv6 (reenable-ipv6)
            dns  (reset-resolv-conf write-fn delete-fn)
            restart (restart-network shell)
            probes (probe shell)]
        (r/ok {:ufw-disable ufw-off
               :iptables-flushed (count flushed)
               :policies-reset (count policy)
               :ipsets-destroyed (count destroyed)
               :units-removed unit-rm
               :ipv6 ipv6
               :dns dns
               :restart restart
               :probe probes})))))
