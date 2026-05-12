(ns vpn-kis-bb.domain.rules
  "Pure: generate UFW before.rules text from a structured plan.

   Bash equivalent: `add_killswitch_before_rules` in vpn-firewall-setup.sh.

   The plan is just data — easy to inspect, easy to test. The adapter
   writes the rendered string to /etc/ufw/before.rules and reloads UFW."
  (:require [clojure.string :as str]))

(def default-vpn-interfaces
  ["tun+" "wg+" "Eddie" "ppp+" "tailscale0"])

(def default-vpn-ports-udp
  [1194 443 53 51820 1300 1301 1302 1637 41641 3478])

(def default-vpn-ports-tcp
  [443])

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

(defn- permissive-pre-tunnel [phys udp-ports tcp-ports]
  (str
   "\n# --- DNS on physical IF (resolve VPN hosts) ---\n"
   "-A ufw-before-output -o " phys " -p udp --dport 53 -j ACCEPT\n"
   "-A ufw-before-output -o " phys " -p tcp --dport 53 -j ACCEPT\n"
   "\n# --- HTTPS auth (Eddie/Mullvad API) ---\n"
   "-A ufw-before-output -o " phys " -p tcp --dport 443 -j ACCEPT\n"
   "\n# --- VPN tunnel ports (any host) ---\n"
   (str/join "\n"
             (for [p udp-ports]
               (str "-A ufw-before-output -o " phys " -p udp --dport " p " -j ACCEPT")))
   "\n"
   (str/join "\n"
             (for [p tcp-ports]
               (str "-A ufw-before-output -o " phys " -p tcp --dport " p " -j ACCEPT")))
   "\n"))

(defn- strict-pre-tunnel [phys ipset-name udp-ports tcp-ports]
  (str
   "\n# --- VPN tunnel ports (locked to ipset " ipset-name ") ---\n"
   (str/join "\n"
             (for [p udp-ports]
               (str "-A ufw-before-output -o " phys
                    " -p udp --dport " p
                    " -m set --match-set " ipset-name " dst -j ACCEPT")))
   "\n"
   (str/join "\n"
             (for [p tcp-ports]
               (str "-A ufw-before-output -o " phys
                    " -p tcp --dport " p
                    " -m set --match-set " ipset-name " dst -j ACCEPT")))
   "\n"))

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

   plan: {:physical-iface  \"wlan0\"
          :mode            :permissive | :strict
          :vpn-interfaces  [\"tun+\" \"wg+\" ...]   ; default if absent
          :vpn-ports-udp   [..]                    ; default if absent
          :vpn-ports-tcp   [..]
          :lan-allow       [\"192.168.100.0/24\" ...]
          :ipset-name      \"vpn_endpoints\"}       ; required when :strict}"
  [{:keys [physical-iface mode vpn-interfaces
           vpn-ports-udp vpn-ports-tcp lan-allow ipset-name]
    :or   {vpn-interfaces default-vpn-interfaces
           vpn-ports-udp  default-vpn-ports-udp
           vpn-ports-tcp  default-vpn-ports-tcp
           lan-allow      []}}]
  (when (nil? physical-iface)
    (throw (ex-info "physical-iface required" {})))
  (when (and (= mode :strict) (nil? ipset-name))
    (throw (ex-info "ipset-name required for strict mode" {})))
  (str (header)
       (or (lan-allow-block physical-iface lan-allow) "")
       (dhcp-ntp physical-iface)
       (case mode
         :permissive (permissive-pre-tunnel physical-iface vpn-ports-udp vpn-ports-tcp)
         :strict     (strict-pre-tunnel physical-iface ipset-name vpn-ports-udp vpn-ports-tcp))
       (vpn-iface-allow vpn-interfaces)
       (forward-chain vpn-interfaces)
       (killswitch-drop physical-iface)))
