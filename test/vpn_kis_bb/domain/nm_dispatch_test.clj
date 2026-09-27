(ns vpn-kis-bb.domain.nm-dispatch-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.nm-dispatch :as d]))

(defn- text [& lines] (apply str (map #(str % "\n") lines)))

(deftest event-classification
  (testing "only up/down/vpn-up/vpn-down/connectivity-change matter"
    (doseq [a ["pre-up" "pre-down" "dhcp4-change" "hostname" "reapply" "" nil]]
      (is (= :ignore (d/event-kind "eth0" a)) (pr-str a))))
  (testing "tailscale interfaces refresh the tailnet bypass"
    (is (= :tailnet-refresh (d/event-kind "tailscale0" "up")))
    (is (= :tailnet-refresh (d/event-kind "tailscale1" "down"))))
  (testing "other virtual interfaces are ignored"
    (doseq [i ["lo" "tun0" "wg0-mullvad" "Eddie" "ppp0" "docker0" "veth1a2b" "virbr0"
               "br-1234" "zt0"]]
      (is (= :ignore (d/event-kind i "up")) i)))
  (testing "physical or missing interfaces trigger a retarget"
    (is (= :retarget (d/event-kind "wlp3s0" "up")))
    (is (= :retarget (d/event-kind "eth0" "vpn-down")))
    (is (= :retarget (d/event-kind "" "connectivity-change")))
    (is (= :retarget (d/event-kind nil "connectivity-change")))))

(def addrs
  (text "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever"
        "3: wlp3s0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic wlp3s0\\       valid_lft 85000sec"
        "2: enp0s31f6    inet 10.0.0.2/24 brd 10.0.0.255 scope global enp0s31f6\\       valid_lft forever"
        "4: wg0-mullvad    inet 10.66.1.2/32 scope global wg0-mullvad\\       valid_lft forever"
        "5: tailscale0    inet 100.101.12.77/32 scope global tailscale0\\       valid_lft forever"))

(deftest fallback-iface-picks-first-physical-by-name
  (is (= "enp0s31f6" (d/fallback-iface addrs)))
  (is (= "eth1" (d/fallback-iface (text "7: eth1@if6    inet 172.17.0.2/16 scope global eth1"))))
  (is (nil? (d/fallback-iface (text "1: lo    inet 127.0.0.1/8 scope host lo"
                                    "4: wg0-mullvad    inet 10.66.1.2/32 scope global"))))
  (is (nil? (d/fallback-iface "")))
  (is (nil? (d/fallback-iface nil))))

(def rules
  (text "*filter"
        "-A ufw-before-output -o lo -j ACCEPT"
        "-A ufw-before-output -o eth0 -p udp --dport 67 -j ACCEPT"
        "-A ufw-before-output -o eth01 -j ACCEPT"
        "-A ufw-before-output -o tun+ -j ACCEPT"
        "-A ufw-before-output -o eth0 -m mark --mark 0x51 -j ACCEPT"
        "-A ufw-before-output -o eth0 -j DROP"
        "-A ufw-before-input  -i eth0 -j DROP"
        "COMMIT"))

(deftest retarget-rewrites-every-pinned-rule
  (is (= (text "*filter"
               "-A ufw-before-output -o lo -j ACCEPT"
               "-A ufw-before-output -o wlan0 -p udp --dport 67 -j ACCEPT"
               "-A ufw-before-output -o eth01 -j ACCEPT"
               "-A ufw-before-output -o tun+ -j ACCEPT"
               "-A ufw-before-output -o wlan0 -m mark --mark 0x51 -j ACCEPT"
               "-A ufw-before-output -o wlan0 -j DROP"
               "-A ufw-before-input  -i wlan0 -j DROP"
               "COMMIT")
         (d/retarget-rules rules "eth0" "wlan0"))))

(deftest retarget-matches-literally
  (is (= "-o eth0x1 -j DROP\n" (d/retarget-rules "-o eth0x1 -j DROP\n" "eth0.1" "wlan0")))
  (is (= "-o wlan0 -j DROP\n" (d/retarget-rules "-o eth0.1 -j DROP\n" "eth0.1" "wlan0")))
  (is (= "" (d/retarget-rules nil "eth0" "wlan0"))))

(deftest retarget-check
  (is (d/retarget-valid? (d/retarget-rules rules "eth0" "wlan0") "wlan0"))
  (is (not (d/retarget-valid? rules "wlan0")))
  (is (not (d/retarget-valid? nil "wlan0"))))

(deftest commands
  (is (= ["logger" "-t" "vpn-killswitch" "--" "lock held, skip"] (d/logger-cmd "lock held, skip")))
  (is (= ["cp" "-a" "/etc/ufw/before.rules" "/etc/ufw/before.rules.nm-bak"] d/backup-cmd))
  (is (= ["mkdir" "/run/lock/vpn-killswitch.nm.d"] d/lock-cmd))
  (is (= ["find" "/run/lock/vpn-killswitch.nm.d" "-maxdepth" "0" "-mmin" "+2"] d/stale-lock-cmd))
  (is (= ["systemctl" "restart" "vpn-killswitch-exclude.service"] d/exclude-restart-cmd)))
