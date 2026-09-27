(ns vpn-kis-bb.domain.refresh-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.refresh :as refresh]
            [vpn-kis-bb.domain.re :as rx]))

(def ^:private create-live
  ["ipset" "create" "vpn_endpoints" "hash:ip" "family" "inet"
   "hashsize" "2048" "maxelem" "65536" "-exist"])

(def ^:private create-temp
  ["ipset" "create" "vpn_endpoints_new" "hash:ip" "family" "inet"
   "hashsize" "2048" "maxelem" "65536" "-exist"])

(deftest constants-match-bash
  (is (= "/etc/vpn-killswitch/providers.active" refresh/active-file))
  (is (= "vpn_endpoints" refresh/set-name))
  (is (= "vpn_endpoints_new" refresh/tmp-set-name))
  (is (= "/etc/ipset.conf" refresh/ipset-conf))
  (is (= "vpn-killswitch-refresh.service" refresh/service-name))
  (is (= "vpn-killswitch-refresh.timer" refresh/timer-name))
  (is (= "15min" refresh/default-interval))
  (testing "the DNS bootstrap set is separate from the endpoint set"
    (is (= "vpn_dns_bootstrap" refresh/dns-set-name))
    (is (= "vpn_dns_bootstrap_new" refresh/dns-tmp-set-name))))

(deftest active-file-round-trip
  (testing "names are written space separated on one line"
    (is (= "mullvad airvpn tailscale\n"
           (refresh/active-text ["mullvad" :airvpn "tailscale"]))))
  (testing "parse-active reads them back"
    (is (= ["mullvad" "airvpn" "tailscale"]
           (refresh/parse-active "mullvad airvpn tailscale\n")))
    (is (= ["mullvad" "tailscale"]
           (refresh/parse-active (refresh/active-text [:mullvad :tailscale])))))
  (testing "extra whitespace, blanks and repeats are dropped"
    (is (= ["mullvad" "airvpn"]
           (refresh/parse-active "  mullvad\tairvpn   mullvad \n"))))
  (testing "like bash read -ra, only the first line counts"
    (is (= ["mullvad"] (refresh/parse-active "mullvad\nairvpn\n"))))
  (testing "missing or blank file gives no names"
    (is (= [] (refresh/parse-active nil)))
    (is (= [] (refresh/parse-active "")))
    (is (= [] (refresh/parse-active "   \n")))))

(deftest normalize-names-splits-and-dedupes
  (is (= ["mullvad" "airvpn" "funeraria"]
         (refresh/normalize-names [:mullvad "airvpn funeraria" "" "mullvad"])))
  (is (= [] (refresh/normalize-names nil))))

(deftest service-unit-matches-bash-heredoc
  (is (= (str "[Unit]\n"
              "Description=VPN Kill-Switch: refresh endpoint ipset from provider lists\n"
              "Wants=network-online.target\n"
              "After=network-online.target\n"
              "\n"
              "[Service]\n"
              "Type=oneshot\n"
              "ExecStart=/usr/local/bin/vpn-kis refresh\n")
         (refresh/service-unit-text "/usr/local/bin/vpn-kis"))))

(deftest timer-unit-matches-bash-heredoc
  (is (= (str "[Unit]\n"
              "Description=VPN Kill-Switch: periodic endpoint refresh\n"
              "\n"
              "[Timer]\n"
              "OnBootSec=2min\n"
              "OnUnitActiveSec=1h\n"
              "RandomizedDelaySec=30\n"
              "Persistent=true\n"
              "\n"
              "[Install]\n"
              "WantedBy=timers.target\n")
         (refresh/timer-unit-text "1h")))
  (testing "nil interval falls back to the default"
    (is (str/includes? (refresh/timer-unit-text nil) "\nOnUnitActiveSec=15min\n"))))

(deftest interval-validation
  (doseq [ok ["15min" "1h" "1h 30min" "90" "2.5h"]]
    (is (refresh/valid-interval? ok) ok))
  (doseq [bad [nil "" "min" " 15min" "15min\nExecStart=/bin/sh" "15min;reboot"]]
    (is (not (refresh/valid-interval? bad)) (pr-str bad))))

(deftest restore-payload-fills-the-temp-set
  (is (= (str "create vpn_endpoints_new hash:ip family inet hashsize 2048 maxelem 65536 -exist\n"
              "add vpn_endpoints_new 1.1.1.1\n"
              "add vpn_endpoints_new 10.0.0.1\n")
         (refresh/restore-payload "vpn_endpoints_new" ["10.0.0.1" "1.1.1.1"])))
  (testing "only valid IPv4 survive, trimmed and deduplicated"
    (let [payload (refresh/restore-payload
                   "vpn_endpoints_new"
                   ["1.1.1.1" " 1.1.1.1 " "999.1.1.1" "vpn.example.com"
                    "2001:db8::1" "" nil "# comment" "8.8.8.8"])
          adds    (filter #(str/starts-with? % "add ") (rx/split-lines* payload))]
      (is (= ["add vpn_endpoints_new 1.1.1.1" "add vpn_endpoints_new 8.8.8.8"]
             (vec adds))))))

(deftest sh-quote-escapes-single-quotes
  (is (= "'plain'" (refresh/sh-quote "plain")))
  (is (= "'it'\\''s'" (refresh/sh-quote "it's"))))

(def ^:private create-dns-live
  ["ipset" "create" "vpn_dns_bootstrap" "hash:ip" "family" "inet"
   "hashsize" "2048" "maxelem" "65536" "-exist"])

(def ^:private create-dns-temp
  ["ipset" "create" "vpn_dns_bootstrap_new" "hash:ip" "family" "inet"
   "hashsize" "2048" "maxelem" "65536" "-exist"])

(def ^:private save-both
  ["sh" "-c" "{ ipset save vpn_endpoints && ipset save vpn_dns_bootstrap; } > /etc/ipset.conf"])

(def ^:private empty-dns-swap
  [create-dns-live
   create-dns-temp
   ["ipset" "flush" "vpn_dns_bootstrap_new"]
   ["ipset" "swap" "vpn_dns_bootstrap_new" "vpn_dns_bootstrap"]
   ["ipset" "destroy" "vpn_dns_bootstrap_new"]])

(deftest swap-commands-build-aside-then-swap
  (let [payload (refresh/restore-payload "vpn_endpoints_new" ["1.1.1.1" "9.9.9.9"])]
    (is (= (-> [create-live
                create-temp
                ["ipset" "flush" "vpn_endpoints_new"]
                ["sh" "-c" (str "printf '%s' '" payload "' | ipset restore -exist")]
                ["ipset" "swap" "vpn_endpoints_new" "vpn_endpoints"]
                ["ipset" "destroy" "vpn_endpoints_new"]]
               (into empty-dns-swap)
               (conj save-both))
           (refresh/swap-commands ["9.9.9.9" "1.1.1.1" "junk"])))))

(deftest swap-commands-rebuild-the-dns-bootstrap-set-alongside
  (let [cmds    (refresh/swap-commands ["5.5.5.5"] {:dns-ips ["9.9.9.9" "1.1.1.1" "junk"]})
        dns     (refresh/restore-payload "vpn_dns_bootstrap_new" ["1.1.1.1" "9.9.9.9"])
        eps     (refresh/restore-payload "vpn_endpoints_new" ["5.5.5.5"])]
    (testing "the endpoint set holds the provider IPs only"
      (is (= ["sh" "-c" (str "printf '%s' '" eps "' | ipset restore -exist")] (nth cmds 3)))
      (is (not (str/includes? (nth (nth cmds 3) 2) "9.9.9.9"))))
    (testing "the DNS set is built aside and swapped after the endpoint set"
      (is (= [create-dns-live
              create-dns-temp
              ["ipset" "flush" "vpn_dns_bootstrap_new"]
              ["sh" "-c" (str "printf '%s' '" dns "' | ipset restore -exist")]
              ["ipset" "swap" "vpn_dns_bootstrap_new" "vpn_dns_bootstrap"]
              ["ipset" "destroy" "vpn_dns_bootstrap_new"]]
             (subvec cmds 6 12))))
    (testing "both sets are saved for boot, once, last"
      (is (= save-both (peek cmds)))
      (is (= save-both (refresh/save-command)))
      (is (= 13 (count cmds))))))

(deftest swap-commands-never-swap-in-an-empty-set
  (is (= [] (refresh/swap-commands [])))
  (is (= [] (refresh/swap-commands ["not-an-ip" "" nil])))
  (testing "DNS bootstrap IPs alone never replace the endpoint whitelist"
    (is (= [] (refresh/swap-commands [] {:dns-ips ["1.1.1.1"]})))))

(deftest large-lists-load-in-chunks-before-the-swap
  (let [ips      (for [n (range 1 6)] (str "10.0.0." n))
        cmds     (refresh/swap-commands ips {:chunk-size 2})
        restore? #(and (= "sh" (first %)) (str/includes? (nth % 2) "ipset restore"))
        loads    (filter restore? cmds)]
    (is (= 3 (count loads)) "5 IPs in chunks of 2: 2 + 2 + 1")
    (is (= (+ 3 3 2 5 1) (count cmds)) "endpoint set, empty DNS set, save")
    (is (= ["ipset" "flush" "vpn_endpoints_new"] (nth cmds 2)))
    (is (every? restore? (subvec cmds 3 6)) "every load runs before the swap")
    (is (= ["ipset" "swap" "vpn_endpoints_new" "vpn_endpoints"] (nth cmds 6)))
    (is (= (map #(str "add vpn_endpoints_new " %) ips)
           (->> loads
                (mapcat (fn [c] (rx/split-lines* (nth c 2))))
                (filter #(str/starts-with? % "add "))))
        "every address loaded once, in order")))

(deftest default-chunk-fits-one-argv-string
  (let [longest-add (count "add vpn_endpoints_new 255.255.255.255\n")
        wrapper     (count (nth (refresh/restore-command
                                 (refresh/restore-payload "vpn_endpoints_new" []))
                                2))]
    (is (< (+ wrapper (* refresh/restore-chunk-size longest-add)) 131072)
        "a full chunk stays under Linux MAX_ARG_STRLEN")))

(deftest entry-count-parses-ipset-list
  (is (= 812 (refresh/entry-count
              (str "Name: vpn_endpoints\n"
                   "Type: hash:ip\n"
                   "Revision: 6\n"
                   "Header: family inet hashsize 2048 maxelem 65536 bucketsize 12\n"
                   "Size in memory: 30000\n"
                   "References: 3\n"
                   "Number of entries: 812\n"
                   "Members:\n"
                   "1.1.1.1\n"))))
  (is (= 7 (refresh/entry-count "  Number of entries:   7  \n")))
  (is (nil? (refresh/entry-count "Number of entries: many\n")))
  (is (nil? (refresh/entry-count "")))
  (is (nil? (refresh/entry-count nil))))

(deftest parse-command-mirrors-bash-main
  (testing "install|timer [interval]"
    (is (= {:op :install :interval "15min"} (refresh/parse-command ["install"])))
    (is (= {:op :install :interval "1h"} (refresh/parse-command ["timer" "1h"])))
    (is (= {:op :install :interval "15min"} (refresh/parse-command ["install" ""]))))
  (testing "uninstall|remove"
    (is (= {:op :remove} (refresh/parse-command ["uninstall"])))
    (is (= {:op :remove} (refresh/parse-command ["remove"]))))
  (testing "anything else refreshes; every arg is a provider name"
    (is (= {:op :refresh :names []} (refresh/parse-command [])))
    (is (= {:op :refresh :names ["mullvad" "airvpn"]}
           (refresh/parse-command ["mullvad" "airvpn"])))))
