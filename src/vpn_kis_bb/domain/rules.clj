(ns vpn-kis-bb.domain.rules
  "Pure: generate UFW before.rules text from a structured plan.

   Bash equivalent: `add_killswitch_before_rules` in vpn-firewall-setup.sh.
   Layout and rule lines match the bash output, plus one section the bash
   lacks: in strict mode the DNS bootstrap resolvers live in their own
   ipset, reachable on port 53 only.

   The plan is just data: easy to inspect, easy to test. app.setup writes
   the rendered string to /etc/ufw/before.rules and reloads UFW."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.exclude :as exclude]))

(def default-vpn-interfaces
  ["tun+" "wg+" "Eddie" "ppp+" "tailscale0"])

(def default-vpn-ports-udp
  [1194 443 53 51820 1300 1301 1302 1637 41641 3478])

(def default-vpn-ports-tcp
  [443])

(def before-rules-path "/etc/ufw/before.rules")

(def before6-rules-path "/etc/ufw/before6.rules")

(def before6-rules-text
  "/etc/ufw/before6.rules: drop all IPv6 (the kill-switch is IPv4 only)."
  (str "*filter\n"
       ":ufw6-before-input - [0:0]\n"
       ":ufw6-before-output - [0:0]\n"
       ":ufw6-before-forward - [0:0]\n"
       "-A ufw6-before-input -j DROP\n"
       "-A ufw6-before-output -j DROP\n"
       "-A ufw6-before-forward -j DROP\n"
       "COMMIT\n"))

(defn- header []
  (str
   "*filter\n"
   ":ufw-before-input - [0:0]\n"
   ":ufw-before-output - [0:0]\n"
   ":ufw-before-forward - [0:0]\n"
   "\n"
   "# --- Loopback ---\n"
   "-A ufw-before-input -i lo -j ACCEPT\n"
   "-A ufw-before-output -o lo -j ACCEPT\n"
   "\n"
   "# --- Established/related ---\n"
   "-A ufw-before-input -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
   "-A ufw-before-output -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"))

(defn- lan-allow-block [phys cidrs]
  (when (seq cidrs)
    (str
     "\n# --- LAN allow-list (" (str/join " " cidrs) ") ---\n"
     (str/join
      "\n"
      (mapcat (fn [c]
                [(str "-A ufw-before-output -o " phys " -d " c " -j ACCEPT")
                 (str "-A ufw-before-input  -i " phys " -s " c " -j ACCEPT")])
              cidrs))
     "\n")))

(defn- dhcp-ntp [phys]
  (str
   "\n# --- DHCP ---\n"
   "-A ufw-before-output -o " phys " -p udp --dport 67 -j ACCEPT\n"
   "\n# --- NTP ---\n"
   "-A ufw-before-output -o " phys " -p udp --dport 123 -j ACCEPT\n"))

(defn- port-rules
  "One ACCEPT per UDP port, then per TCP port (blank ports skipped, as in
   bash), each newline-terminated; `match` goes before -j ACCEPT."
  [phys udp-ports tcp-ports match]
  (apply str
         (concat
          (for [p udp-ports :when (not (str/blank? (str p)))]
            (str "-A ufw-before-output -o " phys " -p udp --dport " p match " -j ACCEPT\n"))
          (for [p tcp-ports :when (not (str/blank? (str p)))]
            (str "-A ufw-before-output -o " phys " -p tcp --dport " p match " -j ACCEPT\n")))))

(defn- permissive-pre-tunnel [phys udp-ports tcp-ports]
  (str
   "\n# --- DNS on physical IF (resolve VPN hosts) ---\n"
   "-A ufw-before-output -o " phys " -p udp --dport 53 -j ACCEPT\n"
   "-A ufw-before-output -o " phys " -p tcp --dport 53 -j ACCEPT\n"
   "\n# --- Eddie HTTPS auth ---\n"
   "-A ufw-before-output -o " phys " -p tcp --dport 443 -j ACCEPT\n"
   "\n# --- VPN tunnel ports (any host) ---\n"
   (port-rules phys udp-ports tcp-ports "")))

(defn- set-label
  "`ipset NAME: N IPs`, or `ipset NAME` when n is nil."
  [set-name n]
  (str "ipset " set-name (when n (str ": " n " IPs"))))

(defn- strict-pre-tunnel
  "Strict pre-tunnel surface: any port to members of the endpoint set, or,
   with strict-ports?, only the VPN ports (the legacy lock)."
  [phys ipset-name n strict-ports? udp-ports tcp-ports]
  (if strict-ports?
    (str "\n# --- VPN tunnel ports (locked to " (set-label ipset-name n) ") ---\n"
         (port-rules phys udp-ports tcp-ports
                     (str " -m set --match-set " ipset-name " dst")))
    (str "\n# --- VPN endpoints, any port (" (set-label ipset-name n)
         "; STRICT_PORTS=1 for the old port lock) ---\n"
         "-A ufw-before-output -o " phys " -m set --match-set " ipset-name
         " dst -j ACCEPT\n")))

(defn- dns-bootstrap-pre-tunnel
  "Strict mode: DNS (udp and tcp 53) to members of the bootstrap set only."
  [phys set-name n]
  (str "\n# --- DNS bootstrap resolvers, port 53 only (" (set-label set-name n) ") ---\n"
       "-A ufw-before-output -o " phys " -p udp --dport 53 -m set --match-set "
       set-name " dst -j ACCEPT\n"
       "-A ufw-before-output -o " phys " -p tcp --dport 53 -m set --match-set "
       set-name " dst -j ACCEPT\n"))

(defn- vpn-iface-allow [vpn-ifaces]
  (str
   "\n# --- VPN interfaces: allow all ---\n"
   (str/join "\n"
             (mapcat (fn [v]
                       [(str "-A ufw-before-output -o " v " -j ACCEPT")
                        (str "-A ufw-before-input  -i " v " -j ACCEPT")])
                     vpn-ifaces))
   "\n"))

(defn- forward-chain [vpn-ifaces]
  (str
   "\n# --- VPN interfaces: allow forwarded traffic (containers, VMs) ---\n"
   "-A ufw-before-forward -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
   (str/join "\n"
             (for [v vpn-ifaces]
               (str "-A ufw-before-forward -o " v " -j ACCEPT")))
   "\n"))

(defn- killswitch-drop [phys]
  (str
   "\n# --- KILL-SWITCH: drop anything else on physical IF ---\n"
   "-A ufw-before-output -o " phys " -j DROP\n"
   "-A ufw-before-input  -i " phys " -j DROP\n"
   "\nCOMMIT\n"))

(defn before-rules-text
  "Generate /etc/ufw/before.rules text.

   plan: {:physical-iface \"wlan0\"              required
          :mode           :permissive | :strict  required
          :vpn-interfaces [\"tun+\" ...]         default-vpn-interfaces when nil
          :vpn-ports-udp  [..]                   default-vpn-ports-udp when nil
          :vpn-ports-tcp  [..]                   default-vpn-ports-tcp when nil
          :lan-allow      [\"192.168.100.0/24\"]
          :ipset-name     \"vpn_endpoints\"      required when :strict
          :endpoint-count n                      shown in the strict comment
          :strict-ports?  bool                   strict: members on the VPN ports only
          :dns-ipset-name \"vpn_dns_bootstrap\"  strict: port 53 open to this set
          :dns-count      n                      shown in its comment
          :exclude?       bool                   cgroup-exclusion ACCEPT before the DROP}

   Throws ex-info without :physical-iface, for a :mode other than
   :permissive or :strict, and for :strict without :ipset-name."
  [{:keys [physical-iface mode vpn-interfaces vpn-ports-udp vpn-ports-tcp lan-allow
           ipset-name endpoint-count strict-ports? dns-ipset-name dns-count exclude?]}]
  (when (nil? physical-iface)
    (throw (ex-info "physical-iface required" {})))
  (when-not (contains? #{:permissive :strict} mode)
    (throw (ex-info "mode must be :permissive or :strict" {:mode mode})))
  (when (and (= mode :strict) (nil? ipset-name))
    (throw (ex-info "ipset-name required for strict mode" {})))
  (let [ifaces (or vpn-interfaces default-vpn-interfaces)
        udp    (or vpn-ports-udp default-vpn-ports-udp)
        tcp    (or vpn-ports-tcp default-vpn-ports-tcp)]
    (str (header)
         (dhcp-ntp physical-iface)
         (or (lan-allow-block physical-iface lan-allow) "")
         (if (= mode :strict)
           (str (strict-pre-tunnel physical-iface ipset-name endpoint-count strict-ports? udp tcp)
                (if dns-ipset-name
                  (dns-bootstrap-pre-tunnel physical-iface dns-ipset-name dns-count)
                  ""))
           (permissive-pre-tunnel physical-iface udp tcp))
         (vpn-iface-allow ifaces)
         (forward-chain ifaces)
         (if exclude? (exclude/before-rules-block physical-iface) "")
         (killswitch-drop physical-iface))))
