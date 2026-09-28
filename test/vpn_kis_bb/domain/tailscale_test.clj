(ns vpn-kis-bb.domain.tailscale-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.tailscale :as d]
            [vpn-kis-bb.domain.re :as rx]))

(defn- text [& lines] (apply str (map #(str % "\n") lines)))

;; ---------------------------------------------------------------- golden text

(def golden-nft
  (text "table inet vpn-killswitch-tailscale"
        "delete table inet vpn-killswitch-tailscale"
        "table inet vpn-killswitch-tailscale {"
        "    set tailnet {"
        "        type ipv4_addr"
        "        flags interval"
        "        auto-merge"
        "        elements = { 100.64.0.0/10, 10.96.0.0/12, 10.244.0.0/16, 192.168.100.0/24 }"
        "    }"
        "    chain route_out {"
        "        type route hook output priority mangle; policy accept;"
        "        ip daddr @tailnet meta mark set 0x6d6f6c65 ct mark set 0x00000f41 comment \"vpn-kis tailnet bypasses Mullvad v3\""
        "        meta mark and 0x00ff0000 == 0x00080000 ip daddr != @tailnet meta mark set 0x00000000 comment \"vpn-kis tailscaled rides Mullvad\""
        "    }"
        "    chain mark_forwarded {"
        "        type filter hook prerouting priority mangle; policy accept;"
        "        iifname != \"tailscale0\" ip daddr @tailnet meta mark set 0x6d6f6c65 ct mark set 0x00000f41"
        "    }"
        "    chain snat_tailnet {"
        "        type nat hook postrouting priority srcnat; policy accept;"
        "        oifname \"tailscale0\" ct mark 0x00000f41 masquerade"
        "    }"
        "}"))

(deftest render-nft-golden
  (is (= golden-nft
         (d/render-nft ["100.64.0.0/10" "10.96.0.0/12" "10.244.0.0/16" "192.168.100.0/24"]))))

(deftest render-nft-single-entry
  (is (str/includes? (d/render-nft ["100.64.0.0/10"])
                     "\n        elements = { 100.64.0.0/10 }\n")))

(deftest render-nft-replaces-the-table-in-one-batch
  (let [lines (rx/split-lines* (d/render-nft [d/cgnat]))]
    (is (= ["table inet vpn-killswitch-tailscale"
            "delete table inet vpn-killswitch-tailscale"
            "table inet vpn-killswitch-tailscale {"]
           (take 3 lines)))
    (is (= "}" (last lines)))))

(deftest nft-load-cmd-feeds-the-batch-to-nft-stdin
  (is (= ["sh" "-c" "printf '%s' \"$1\" | nft -f -" "sh" "RULESET"]
         (d/nft-load-cmd "RULESET"))))

(deftest unit-text-golden
  (is (= (text "[Unit]"
               "Description=VPN Kill-Switch: tailnet traffic bypasses Mullvad (nft marks)"
               "After=network-online.target tailscaled.service mullvad-daemon.service"
               "Wants=network-online.target tailscaled.service"
               ""
               "[Service]"
               "Type=oneshot"
               "RemainAfterExit=yes"
               "ExecStart=/opt/vpn-kis/bin/vpn-kis tailscale-routes _apply"
               ""
               "[Install]"
               "WantedBy=multi-user.target")
         (d/unit-text "/opt/vpn-kis/bin/vpn-kis"))))

(deftest render-nft-routes-tailscaled-into-mullvad
  (testing "tailscaled's own packets lose tailscale's bypass mark, tailnet ones keep Mullvad's"
    (let [lines (rx/split-lines* (d/render-nft [d/cgnat]))
          rides (filter #(str/includes? % d/rides-tag) lines)]
      (is (= 1 (count rides)))
      (is (str/includes? (first rides) "meta mark and 0x00ff0000 == 0x00080000"))
      (is (str/includes? (first rides) "ip daddr != @tailnet"))
      (is (str/includes? (first rides) "meta mark set 0x00000000"))
      (is (not (str/includes? (first rides) d/mullvad-fwmark))
          "never Mullvad's mark: that would send tailscaled around the tunnel"))))

;; ---------------------------------------------------------------- addresses

(deftest cidr-validation
  (doseq [ok ["10.0.0.0/8" "100.64.0.0/10" "192.168.1.7" "0.0.0.0/0" "1.2.3.4/32"]]
    (is (d/cidr? ok) ok))
  (doseq [bad [nil "" "10.0.0.0/33" "10.0.0.0/" "10.0.0/8" "256.1.1.1/8" "10.0.0.0/8/1"
               "default" "10.0.0.0/x" "fe80::/64"]]
    (is (not (d/cidr? bad)) (pr-str bad))))

(deftest cidr-containment
  (is (d/cidr-contains? "10.0.0.0/8" "10.64.0.1"))
  (is (d/cidr-contains? "10.64.0.0/10" "10.64.0.1"))
  (is (d/cidr-contains? "10.64.0.1" "10.64.0.1"))
  (is (d/cidr-contains? "0.0.0.0/0" "10.64.0.1"))
  (is (not (d/cidr-contains? "10.96.0.0/12" "10.64.0.1")))
  (is (not (d/cidr-contains? "10.64.0.2" "10.64.0.1")))
  (is (not (d/cidr-contains? "100.64.0.0/10" "10.64.0.1")))
  (is (d/protected? "10.0.0.0/8"))
  (is (not (d/protected? "10.244.0.0/16"))))

;; ---------------------------------------------------------------- table 52

(def table52
  (text "10.96.0.0/12 dev tailscale0 "
        "10.244.0.0/16 dev tailscale0 "
        "100.100.100.100 dev tailscale0 "
        "100.101.12.77 dev tailscale0 "
        "throw 127.0.0.0/8 "
        "192.168.100.0/24 dev tailscale0 "
        "172.15.0.0/16 dev tailscale0 "
        "172.16.0.0/12 dev tailscale0 "
        "172.31.4.0/24 dev tailscale0 "
        "172.32.0.0/16 dev tailscale0 "
        "192.168.7.0/24 dev eth0 "
        "default dev tailscale0 "
        "10.96.0.0/12 dev tailscale0 "
        "10.1.2.3 dev tailscale0"))

(deftest table-routes-keeps-rfc1918-via-tailscale
  (is (= ["10.1.2.3" "10.244.0.0/16" "10.96.0.0/12" "172.16.0.0/12" "172.31.4.0/24"
          "192.168.100.0/24"]
         (d/table-routes table52)))
  (is (= [] (d/table-routes "")))
  (is (= [] (d/table-routes nil))))

(deftest destinations-from-table
  (is (= {:dests   ["100.64.0.0/10" "10.1.2.3" "10.244.0.0/16" "10.96.0.0/12"
                    "172.16.0.0/12" "172.31.4.0/24" "192.168.100.0/24"]
          :dropped []
          :source  :table}
         (d/destinations table52 "100.64.0.0/10\n"))))

(deftest destinations-keep-the-stored-set-while-tailscaled-restarts
  (let [stored (text "100.64.0.0/10" "10.96.0.0/12")]
    (testing "table 52 missing or empty: the stored set wins"
      (is (= {:dests ["100.64.0.0/10" "10.96.0.0/12"] :dropped [] :source :stored}
             (d/destinations "" stored)))
      (is (= :stored (:source (d/destinations "throw 127.0.0.0/8\n" stored)))))
    (testing "tailscale routes only CGNAT peers: subnet routes were withdrawn"
      (is (= {:dests ["100.64.0.0/10"] :dropped [] :source :table}
             (d/destinations "100.101.12.77 dev tailscale0\n" stored))))
    (testing "nothing usable stored: CGNAT alone"
      (doseq [s [nil "" "  \n" "garbage\n"]]
        (is (= ["100.64.0.0/10"] (:dests (d/destinations "" s))) (pr-str s))))))

(deftest destinations-never-mark-mullvad-dns
  (testing "a route covering 10.64.0.1 is dropped from the table set"
    (is (= {:dests   ["100.64.0.0/10" "10.96.0.0/12"]
            :dropped ["10.0.0.0/8"]
            :source  :table}
           (d/destinations (text "10.0.0.0/8 dev tailscale0" "10.96.0.0/12 dev tailscale0")
                           nil))))
  (testing "and from a stored set written by an older version"
    (is (= ["100.64.0.0/10"]
           (:dests (d/destinations "" (text "100.64.0.0/10" "10.0.0.0/8")))))
    (is (= ["100.64.0.0/10"] (:dests (d/destinations "" "10.64.0.0/10\n"))))))

;; An oracle independent of cidr-contains?: compare leading address bits.
(defn- ip-bits [ip]
  (apply str (for [o (rx/split* ip #"\.") w [128 64 32 16 8 4 2 1]]
               (if (zero? (bit-and (parse-long o) w)) "0" "1"))))

(defn- covers? [cidr ip]
  (let [[a len] (rx/split* cidr #"/")
        n       (if len (parse-long len) 32)]
    (= (subs (ip-bits a) 0 n) (subs (ip-bits ip) 0 n))))

(defn- rendered-elements [nft]
  (let [line (first (filter #(str/includes? % "elements = {") (rx/split-lines* nft)))]
    (rx/split* (subs line (+ 2 (str/index-of line "{ ")) (str/last-index-of line " }")) #", ")))

(def route-pool
  ["10.0.0.0/8" "10.64.0.0/10" "10.64.0.0/16" "10.64.0.1" "10.96.0.0/12" "10.244.0.0/16"
   "172.16.0.0/12" "192.168.100.0/24"])

(defn- subsets [xs]
  (reduce (fn [acc x] (into acc (map #(conj % x)) acc)) [[]] xs))

(deftest mullvad-dns-is-never-inside-the-rendered-set
  (doseq [routes (subsets route-pool)
          stored [nil (text "100.64.0.0/10" "10.0.0.0/8") (apply text routes)]
          table  [(apply text (map #(str % " dev tailscale0") routes)) ""]]
    (let [{:keys [dests]} (d/destinations table stored)
          elems           (rendered-elements (d/render-nft dests))]
      (is (seq elems))
      (is (every? d/cidr? elems))
      (is (not-any? #(covers? % "10.64.0.1") elems)
          (str "routes " (pr-str routes) " stored " (pr-str stored))))))

;; ---------------------------------------------------------------- current / stored

(def live-table
  (text "table inet vpn-killswitch-tailscale {"
        "\tchain route_out {"
        "\t\tip daddr @tailnet meta mark set 0x6d6f6c65 ct mark set 0x00000f41 comment \"vpn-kis tailnet bypasses Mullvad v3\""
        "\t}"
        "}"))

(deftest bypass-current-needs-tag-and-same-set
  (let [dests ["100.64.0.0/10" "10.96.0.0/12"]]
    (is (d/bypass-current? live-table "10.96.0.0/12\n100.64.0.0/10\n" dests)
        "order does not matter")
    (is (not (d/bypass-current? live-table "100.64.0.0/10\n" dests)))
    (is (not (d/bypass-current? live-table nil dests)))
    (is (not (d/bypass-current? "" (d/cidrs-text dests) dests)))
    (is (not (d/bypass-current? (str/replace live-table "v3" "v2") (d/cidrs-text dests) dests)))))

(deftest cidrs-file-round-trip
  (is (= "100.64.0.0/10\n10.96.0.0/12\n" (d/cidrs-text ["100.64.0.0/10" "10.96.0.0/12"])))
  (is (= ["100.64.0.0/10" "10.96.0.0/12"]
         (d/stored-cidrs (d/cidrs-text ["100.64.0.0/10" "10.96.0.0/12"]))))
  (is (= ["100.64.0.0/10" "10.96.0.0/12"] (d/stored-cidrs "100.64.0.0/10 10.96.0.0/12 bogus"))))

;; ---------------------------------------------------------------- ip rule / mullvad

(deftest legacy-rules-parse
  (let [out (text "0:\tfrom all lookup local"
                  "5099:\tfrom all to 10.96.0.0/12 lookup 52"
                  "5100:\tfrom all to 10.96.0.0/12 lookup 52"
                  "5101:\tfrom all to 100.64.0.0/10 lookup 52"
                  "5209:\tfrom all lookup main suppress_prefixlength 0"
                  "5210:\tnot from all fwmark 0x6d6f6c65 lookup 1836018789"
                  "5270:\tfrom all lookup 52"
                  "5300:\tfrom all to 10.0.0.0/8 lookup 151")]
    (is (= ["10.96.0.0/12" "100.64.0.0/10"] (d/legacy-rule-cidrs out)))
    (is (= [] (d/legacy-rule-cidrs "")))
    (is (= ["ip" "rule" "del" "to" "10.96.0.0/12" "lookup" "52"]
           (d/rule-del-cmd "10.96.0.0/12")))))

(deftest main-pid-parse
  (is (= "4242" (d/main-pid "4242\n")))
  (is (= "42" (d/main-pid "  42 ")))
  (doseq [s [nil "" "0\n" "abc" "-1" "12a"]]
    (is (nil? (d/main-pid s)) (pr-str s))))

(deftest split-tunnel-listing-matches-whole-fields
  (let [listing (text "Split tunneling state: On" "Excluded PIDs:" "    4242" "\t77")]
    (is (d/pid-listed? listing "4242"))
    (is (d/pid-listed? listing "77"))
    (is (not (d/pid-listed? listing "424")))
    (is (not (d/pid-listed? (text "    42421") "4242")))
    (is (not (d/pid-listed? nil "4242")))))

;; ---------------------------------------------------------------- profiles / helper

(deftest tailscale-profile
  (is (d/tailscale-profile? ["tun+" "wg+" "Eddie" "ppp+" "tailscale0"]))
  (is (d/tailscale-profile? "tun+ tailscale0"))
  (is (not (d/tailscale-profile? ["tun+" "wg+"])))
  (is (not (d/tailscale-profile? nil))))

(deftest web-profile-needs-both-words
  (is (d/web-profile? "mullvad tailscale\n"))
  (is (d/web-profile? "tailscale airvpn mullvad"))
  (is (not (d/web-profile? "mullvad airvpn")))
  (is (not (d/web-profile? "mullvadx tailscale")))
  (is (not (d/web-profile? nil))))

(deftest web-helper-location
  (is (= "/srv/configure.py"
         (d/web-helper-path {"TAILSCALE_WEB_HELPER" "/srv/configure.py"} "/opt/vpn-kis/bin/vpn-kis")))
  (is (= "/opt/vpn-kis/bin/../lib/tailscale-web/configure.py"
         (d/web-helper-path {} "/opt/vpn-kis/bin/vpn-kis")))
  (is (= "/opt/vpn-kis/bin/../lib/tailscale-web/configure.py"
         (d/web-helper-path {"TAILSCALE_WEB_HELPER" ""} "/opt/vpn-kis/bin/vpn-kis")))
  (is (nil? (d/web-helper-path {} "vpn-kis")))
  (is (nil? (d/web-helper-path nil nil))))

(deftest texts-carry-no-em-dash
  (doseq [s [(d/render-nft [d/cgnat]) (d/unit-text "/x")]]
    (is (not (str/includes? s "—")))))
