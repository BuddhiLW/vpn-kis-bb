(ns vpn-kis-bb.domain.nm-dispatch
  "Pure side of the NetworkManager dispatcher (bash: the hook body that
   install_nm_dispatcher wrote): event classification, the physical-IF
   fallback parser, the before.rules retarget rewrite and its check, and
   the syslog, backup and single-flight lock commands."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.exclude :as ex]
            [vpn-kis-bb.domain.re :as rx]))

(def log-tag
  "syslog tag of every dispatcher message (`logger -t`)."
  "vpn-killswitch")

(def relevant-actions
  "NetworkManager actions the dispatcher reacts to."
  #{"up" "down" "vpn-up" "vpn-down" "connectivity-change"})

(def backup-path
  "Copy of before.rules taken right before a retarget rewrites it."
  (str ex/before-rules-path ".nm-bak"))

(def lock-dir
  "Single-flight lock: a directory, created atomically by `mkdir`."
  "/run/lock/vpn-killswitch.nm.d")

(def lock-stale-minutes
  "A lock directory older than this is taken to be left by a dead run."
  2)

(def addrs-cmd ["ip" "-o" "-4" "addr" "show"])
(def lock-cmd ["mkdir" lock-dir])
(def unlock-cmd ["rmdir" lock-dir])
(def stale-lock-cmd ["find" lock-dir "-maxdepth" "0" "-mmin" (str "+" lock-stale-minutes)])
(def backup-cmd ["cp" "-a" ex/before-rules-path backup-path])

(def exclude-restart-cmd ["systemctl" "restart" ex/unit-name])

(defn logger-cmd
  "Sends `msg` to syslog under log-tag."
  [msg]
  ["logger" "-t" log-tag "--" msg])

(defn event-kind
  "What an (iface, action) event calls for:
     :ignore           an irrelevant action, or a virtual interface other
                       than tailscale*
     :tailnet-refresh  a relevant action on a tailscale* interface
     :retarget         a relevant action on anything else (including no
                       interface)"
  [iface action]
  (cond
    (not (contains? relevant-actions action)) :ignore
    (str/blank? iface)                        :retarget
    (not (ex/virtual-iface? iface))           :retarget
    (str/starts-with? iface "tailscale")      :tailnet-refresh
    :else                                     :ignore))

(defn fallback-iface
  "First non-virtual interface, in name order, holding an IPv4 address in
   `ip -o -4 addr show` output; nil when there is none."
  [out]
  (->> (rx/split-lines* (or out ""))
       (keep (fn [line]
               (let [f (rx/split* (str/trim line) #"\s+")]
                 (when (= "inet" (get f 2))
                   (first (rx/split* (get f 1 "") #"@"))))))
       (remove str/blank?)
       (remove ex/virtual-iface?)
       sort
       first))

(defn retarget-rules
  "before.rules text with every `-o <cur> ` and `-i <cur> ` (trailing space
   included) rewritten to `new-if`, matched literally."
  [text cur new-if]
  (-> (or text "")
      (str/replace (str "-o " cur " ") (str "-o " new-if " "))
      (str/replace (str "-i " cur " ") (str "-i " new-if " "))))

(defn retarget-valid?
  "True when before.rules text carries a `-o <new-if> -j DROP` rule."
  [text new-if]
  (str/includes? (or text "") (str "-o " new-if " -j DROP")))
