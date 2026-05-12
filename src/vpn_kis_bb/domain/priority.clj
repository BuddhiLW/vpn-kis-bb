(ns vpn-kis-bb.domain.priority
  "Pure: detect the right `ip rule` priority to slot below Mullvad's
   fwmark default route.

   Bash equivalent: `detect_tailscale_rule_prio` (vpn-firewall-setup.sh).

   Mullvad app builds have used different priorities over time (5199 today,
   5209 historically). We parse the live `ip rule show` and place ours one
   below. If Mullvad isn't present, fall back to a literal."
  (:require [clojure.string :as str]))

(def mullvad-fwmark "0x6d6f6c65")  ; "mole" in ASCII

(def fallback-priority 5100)

(defn parse-ip-rule-line
  "Parse a single line from `ip rule show`, e.g.
     32766:  from all lookup main
     5199:   not from all fwmark 0x6d6f6c65 lookup 5099
   Returns {:priority N :raw <line>} or nil if unparseable."
  [line]
  (when-let [m (re-find #"^(\d+):\s+(.+)$" (or line ""))]
    {:priority (Long/parseLong (second m))
     :raw      (nth m 2)}))

(defn parse-ip-rule-output
  "Parse the full output of `ip rule show` into a vector of rule maps."
  [s]
  (->> (str/split-lines (or s ""))
       (keep parse-ip-rule-line)
       vec))

(defn mullvad-priority
  "Find the priority of Mullvad's fwmark rule, or nil if not present."
  [rules]
  (some (fn [{:keys [priority raw]}]
          (when (str/includes? raw (str "fwmark " mullvad-fwmark))
            priority))
        rules))

(defn choose-priority
  "Given parsed `ip rule show` data, return the priority at which auxiliary
   rules (Tailscale subnet routes, split-tunnel marks) should slot.

   Strategy: Mullvad's priority minus 1 (slot just above). If Mullvad
   isn't there, fall back to `fallback-priority`.

   Pure: no I/O."
  [rules]
  (if-let [mp (mullvad-priority rules)]
    (if (> mp 1) (dec mp) fallback-priority)
    fallback-priority))

(defn choose-split-priority
  "Like `choose-priority` but ~10 lower so split-tunnel marks beat Tailscale
   subnet routes (which themselves beat Mullvad's default)."
  [rules]
  (let [base (choose-priority rules)]
    (max 1 (- base 10))))
