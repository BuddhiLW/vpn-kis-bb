(ns vpn-kis-bb.domain.setup-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.refresh :as refresh]
            [vpn-kis-bb.domain.rules :as rules]
            [vpn-kis-bb.domain.setup :as d]))

(defn- cmds [steps] (mapv :cmd (filter #(= :run (:op %)) steps)))
(defn- texts [steps] (mapv :text (filter #(= :log (:op %)) steps)))

(deftest words-splits-and-keeps-order
  (is (= ["1.2.3.4" "5.6.7.8" "1.2.3.4"] (d/words ["1.2.3.4 5.6.7.8" " 1.2.3.4 " ""])))
  (is (= ["a" "b"] (d/words "  a\tb ")))
  (is (= [] (d/words nil))))

(deftest cidr-validation
  (doseq [ok ["192.168.100.0/24" "10.0.0.1" "0.0.0.0/0" "10.0.0.0/32"]]
    (is (d/valid-cidr? ok) ok))
  (doseq [bad ["192.168.100.0/33" "192.168.100.0/" "300.1.1.1/8" "lan" "1.2.3.4/8/9" "" nil
               "10.0.0.0/24; rm -rf /"]]
    (is (not (d/valid-cidr? bad)) (pr-str bad))))

(deftest input-errors-guard-before-rules
  (is (= [] (d/input-errors {:physical-iface "wlp0s20f3" :lan-allow ["192.168.1.0/24"]
                             :vpn-interfaces ["tun+" "wg0-mullvad" "tailscale0"]})))
  (let [errs (d/input-errors {:physical-iface "eth0 -j ACCEPT"
                              :lan-allow ["192.168.1.0/24" "nas"]
                              :vpn-interfaces ["tun+" "wg*"]})]
    (is (= 3 (count errs)))
    (is (str/includes? (nth errs 0) "physical interface"))
    (is (str/includes? (nth errs 1) "'nas'"))
    (is (str/includes? (nth errs 2) "'wg*'"))))

(deftest physical-iface-detection
  (testing "the token after dev on the first non-virtual default route"
    (is (= "wlan0" (d/iface-from-routes "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n")))
    (is (= "enp3s0" (d/iface-from-routes (str "default dev wg0-mullvad scope link\n"
                                              "default via 10.0.0.1 dev enp3s0 proto static\n")))))
  (testing "no default route"
    (is (nil? (d/iface-from-routes "10.0.0.0/8 dev eth0\n")))
    (is (nil? (d/iface-from-routes nil))))
  (testing "fallback: first real name under /sys/class/net"
    (is (= "eth0" (d/iface-from-links "bonding_masters\ndocker0\neth0\nlo\nwg0\n")))
    (is (nil? (d/iface-from-links "lo\ntun0\nveth1a2b\n")))
    (is (nil? (d/iface-from-links nil)))))

(deftest backup-stamps
  (is (= "20260927-161149" (d/date-stamp "20260927-161149\n")))
  (is (nil? (d/date-stamp "Sun Sep 27 16:11:49 2026")))
  (is (nil? (d/date-stamp nil)))
  (is (= "20260927-191149" (d/iso-stamp "2026-09-27T19:11:49Z")))
  (is (nil? (d/iso-stamp nil)))
  (is (= "/etc/ufw/backup-20260927-161149" (d/backup-dir "20260927-161149"))))

(deftest backup-steps-keep-the-bash-layout
  (let [dir   "/etc/ufw/backup-20260927-161149"
        steps (d/backup-steps dir)]
    (is (= [["mkdir" "-p" dir]
            ["cp" "-a" "/etc/ufw/user.rules" (str dir "/")]
            ["cp" "-a" "/etc/ufw/user6.rules" (str dir "/")]
            ["cp" "-a" "/etc/ufw/before.rules" (str dir "/")]
            ["cp" "-a" "/etc/ufw/before6.rules" (str dir "/")]
            ["cp" "-a" "/etc/ufw/after.rules" (str dir "/")]
            ["cp" "-a" "/etc/default/ufw" (str dir "/")]
            ["sh" "-c" (str "ufw status verbose > '" dir "/ufw-status.txt' 2>/dev/null")]
            ["sh" "-c" (str "iptables-save > '" dir "/iptables.v4' 2>/dev/null")]
            ["sh" "-c" (str "ip6tables-save > '" dir "/iptables.v6' 2>/dev/null")]]
           (cmds steps)))
    (testing "only mkdir aborts, as under bash set -e"
      (is (= [:abort] (distinct (map :on-fail (take 1 (filter :cmd steps))))))
      (is (every? #{:ignore} (map :on-fail (rest (filter :cmd steps))))))
    (is (= [(str "Backing up current UFW config to " dir "...")
            (str "Backup done. Restore: cp " dir "/*.rules /etc/ufw/ && ufw reload")]
           (texts steps)))))

(deftest ipv6-steps-write-the-drop-ins
  (let [steps  (d/ipv6-steps nil)
        writes (filter #(= :write (:op %)) steps)]
    (is (= [d/sysctl-conf-path d/modprobe-conf-path] (mapv :path writes)))
    (is (str/includes? d/sysctl-conf-text "net.ipv6.conf.all.disable_ipv6 = 1\n"))
    (is (str/includes? d/modprobe-conf-text "blacklist ipv6\n"))
    (is (= [:ignore :warn] (mapv :on-fail (filter :cmd steps))) "sysctl --system only warns")
    (is (not-any? #(= "sed" (first %)) (cmds steps)) "no /etc/default/grub: GRUB untouched"))
  (testing "GRUB gets ipv6.disable=1 once"
    (let [steps (d/ipv6-steps "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"\n")]
      (is (some #{["sed" "-i" "s/GRUB_CMDLINE_LINUX_DEFAULT=\"/\\0ipv6.disable=1 /" "/etc/default/grub"]}
                (cmds steps)))
      (is (some #{"GRUB updated. Reboot to fully apply IPv6 disable."} (texts steps))))
    (is (not-any? #(= "sed" (first %))
                  (cmds (d/ipv6-steps "GRUB_CMDLINE_LINUX_DEFAULT=\"ipv6.disable=1 quiet\"\n"))))))

(deftest ufw-steps-permissive-vs-strict
  (let [perm   (cmds (d/ufw-steps {:mode :permissive :physical-iface "wlan0"
                                    :vpn-interfaces ["tun+" "wg+"]}))
        strict (cmds (d/ufw-steps {:mode :strict :physical-iface "wlan0"
                                   :vpn-interfaces ["tun+" "wg+"]}))
        dns    ["ufw" "allow" "out" "on" "wlan0" "to" "any" "port" "53" "proto" "udp"
                "comment" "DNS-UDP-pre-VPN"]]
    (testing "both reset, deny by default, allow lo, DHCP, NTP, the VPN ifaces, enable"
      (doseq [c [perm strict]]
        (is (= [["ufw" "--force" "reset"]
                ["ufw" "default" "deny" "incoming"]
                ["ufw" "default" "deny" "outgoing"]
                ["ufw" "default" "deny" "routed"]
                ["ufw" "allow" "in" "on" "lo"]
                ["ufw" "allow" "out" "on" "lo"]]
               (subvec c 0 6)))
        (is (some #{["ufw" "allow" "out" "on" "wlan0" "to" "any" "port" "67" "proto" "udp"
                     "comment" "DHCP"]} c))
        (is (= [["ufw" "allow" "in" "on" "tun+"] ["ufw" "allow" "out" "on" "tun+"]
                ["ufw" "allow" "in" "on" "wg+"] ["ufw" "allow" "out" "on" "wg+"]
                ["ufw" "--force" "enable"]]
               (subvec c (- (count c) 5))))))
    (testing "permissive opens DNS, 443 and every VPN port as user rules"
      (is (some #{dns} perm))
      (is (some #{["ufw" "allow" "out" "on" "wlan0" "to" "any" "port" "1637" "proto" "udp"
                   "comment" "VPN-UDP-1637"]} perm))
      (is (= (+ 6 2 2 1 10 1 4 1) (count perm))))
    (testing "strict adds no pre-tunnel user rule"
      (is (not (some #{dns} strict)))
      (is (= (+ 6 2 4 1) (count strict))))
    (testing "an interface pattern ufw rejects only warns"
      (let [in-step (first (filter #(= ["ufw" "allow" "in" "on" "tun+"] (:cmd %))
                                   (d/ufw-steps {:mode :strict :physical-iface "wlan0"
                                                 :vpn-interfaces ["tun+"]})))]
        (is (= :warn (:on-fail in-step)))
        (is (= "ufw reject iface pattern: tun+" (:warning in-step)))))))

(deftest set-load-steps-destroy-then-restore
  (let [steps (d/set-load-steps "vpn_endpoints" ["5.5.5.5" "junk" "1.1.1.1" "3.3.3.3"] 2)]
    (is (= ["ipset" "destroy" "vpn_endpoints"] (:cmd (first steps))))
    (is (= :ignore (:on-fail (first steps))))
    (is (= [(refresh/restore-command (refresh/restore-payload "vpn_endpoints" ["1.1.1.1" "3.3.3.3"]))
            (refresh/restore-command (refresh/restore-payload "vpn_endpoints" ["5.5.5.5"]))]
           (mapv :cmd (rest steps))))
    (is (every? #{:abort} (map :on-fail (rest steps)))))
  (testing "an empty list still creates the set"
    (is (= [["ipset" "destroy" "vpn_dns_bootstrap"]
            ["sh" "-c" (str "printf '%s' 'create vpn_dns_bootstrap hash:ip family inet "
                            "hashsize 2048 maxelem 65536 -exist\n' | ipset restore -exist")]]
           (cmds (d/set-load-steps "vpn_dns_bootstrap" [] 2000))))))

(deftest ipset-steps-build-both-sets-and-the-boot-hook
  (let [steps (d/ipset-steps {:endpoints ["1.2.3.4" "bogus" "5.6.7.8"]
                              :dns-bootstrap ["9.9.9.9"]})
        c     (cmds steps)]
    (is (= [["ipset" "destroy" "vpn_endpoints"]
            (refresh/restore-command (refresh/restore-payload "vpn_endpoints" ["1.2.3.4" "5.6.7.8"]))
            ["ipset" "destroy" "vpn_dns_bootstrap"]
            (refresh/restore-command (refresh/restore-payload "vpn_dns_bootstrap" ["9.9.9.9"]))
            (refresh/save-command)
            ["chmod" "755" "/etc/ufw/before.init"]]
           c))
    (is (= [{:op :write :path "/etc/ufw/before.init" :body d/before-init-text}]
           (filter #(= :write (:op %)) steps)))
    (is (= ["Building ipset 'vpn_endpoints' with 3 IPs..."
            "Skipping non-IPv4 endpoint: bogus"
            "Building ipset 'vpn_dns_bootstrap' with 1 DNS bootstrap IPs (port 53 only)..."]
           (texts steps)))
    (testing "the hook restores /etc/ipset.conf when UFW starts"
      (is (str/starts-with? d/before-init-text "#!/bin/sh\n"))
      (is (str/includes? d/before-init-text "ipset restore -exist < /etc/ipset.conf")))))

(deftest rules-plan-from-context
  (let [ctx {:mode :strict :physical-iface "wlan0" :vpn-interfaces ["tun+"]
             :lan-allow ["192.168.1.0/24"] :endpoints ["1.2.3.4" "junk" "1.2.3.4"]
             :dns-bootstrap ["1.1.1.1" "8.8.8.8"] :strict-ports? false}]
    (is (= {:mode :strict :physical-iface "wlan0" :lan-allow ["192.168.1.0/24"] :exclude? true
            :vpn-interfaces ["tun+"] :ipset-name "vpn_endpoints" :endpoint-count 1
            :strict-ports? false :dns-ipset-name "vpn_dns_bootstrap" :dns-count 2}
           (d/rules-plan ctx true)))
    (testing "no bootstrap IP: no DNS rules"
      (is (not (contains? (d/rules-plan (assoc ctx :dns-bootstrap []) false) :dns-ipset-name))))
    (testing "permissive: no set at all"
      (is (= {:mode :permissive :physical-iface "wlan0" :lan-allow [] :exclude? false}
             (d/rules-plan {:mode :permissive :physical-iface "wlan0"} false))))))

(deftest banner-and-closing-lines
  (is (= ["" "VPN Kill-Switch Firewall v3"
          "Mode: STRICT (endpoint-locked, no DNS/443 pre-holes)"
          "Endpoints: 1.2.3.4 5.6.7.8"
          "VPNs: AirVPN/Eddie + Mullvad + generic OpenVPN/WireGuard" ""]
         (texts (d/banner-steps {:mode :strict :endpoints ["1.2.3.4" "5.6.7.8"]}))))
  (is (some #{"Mode: PERMISSIVE (DNS/443/VPN ports open pre-tunnel)"}
            (texts (d/banner-steps {:mode :permissive}))))
  (is (= ["" "Done. Reboot for full IPv6 disable." "Rollback: sudo /usr/local/bin/vpn-kis unlock"]
         (texts (d/done-steps "/usr/local/bin/vpn-kis")))))

(deftest killswitch-and-persist-steps
  (let [steps (d/killswitch-steps "wlan0" "RULES")]
    (is (= [{:op :write :path "/etc/ufw/before.rules" :body "RULES"}
            {:op :write :path "/etc/ufw/before6.rules" :body rules/before6-rules-text}]
           (filter #(= :write (:op %)) steps)))
    (is (= [["ufw" "reload"]] (cmds steps))))
  (is (= [["systemctl" "enable" "ufw"] ["ufw" "reload"]] (cmds d/persist-steps)))
  (is (every? #{:ignore} (map :on-fail (filter :cmd d/persist-steps)))))
