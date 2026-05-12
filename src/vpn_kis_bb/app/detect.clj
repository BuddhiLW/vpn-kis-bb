(ns vpn-kis-bb.app.detect
  "Auto-detect live VPN endpoint IPs.

   Sources:
     1. `wg show all endpoints` — WireGuard peers
     2. `ss -tunp`              — OpenVPN connected sockets (matches users:openvpn)
     3. `ip route`              — `via <peer>` on tun/wg devices (fallback)

   Equivalent to bash `detect_vpn_endpoints`. Pure functions parse the
   shell output; the I/O calls live behind the IShell port."
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.domain.util :as u]))

(defn parse-wg-endpoints
  "Pure: pull peer IPs out of `wg show all endpoints` lines like
     interface PUBKEY 1.2.3.4:51820"
  [s]
  (->> (str/split-lines (or s ""))
       (keep (fn [line]
               (when-let [m (re-find #"(\d+\.\d+\.\d+\.\d+):\d+" line)]
                 (second m))))
       u/normalize-ips))

(defn parse-ss-openvpn
  "Pure: pull remote peer IPv4s from `ss -tunp` rows whose users tuple
   mentions 'openvpn'. Excludes loopback + 0.0.0.0."
  [s]
  (->> (str/split-lines (or s ""))
       (filter #(str/includes? % "openvpn"))
       (mapcat (fn [line]
                 (re-seq #"\d+\.\d+\.\d+\.\d+" line)))
       (remove #(or (str/starts-with? % "127.")
                    (= "0.0.0.0" %)))
       u/normalize-ips))

(defn parse-route-peers
  "Pure: pull `via <peer>` IPs from `ip route` lines whose dev is a
   tun/wg interface."
  [s]
  (->> (str/split-lines (or s ""))
       (filter (fn [line]
                 (re-find #"dev\s+(tun|wg)" line)))
       (keep (fn [line]
               (when-let [m (re-find #"via\s+(\d+\.\d+\.\d+\.\d+)" line)]
                 (second m))))
       u/normalize-ips))

(defn- shell-out [shell cmd]
  (let [r (proto/shell-exec! shell cmd {})]
    (if (r/ok? r) (-> r :ok :stdout) "")))

(defn detect-endpoints
  "Returns Result<#{ip ...}> — IPs of every actively-connected VPN peer."
  [system]
  (let [shell (:shell system)
        wg    (shell-out shell ["sh" "-c" "wg show all endpoints 2>/dev/null"])
        ss    (shell-out shell ["sh" "-c" "ss -tunp 2>/dev/null"])
        route (shell-out shell ["sh" "-c" "ip route 2>/dev/null"])]
    (r/ok (u/merge-ip-sets (parse-wg-endpoints wg)
                           (parse-ss-openvpn ss)
                           (parse-route-peers route)))))
