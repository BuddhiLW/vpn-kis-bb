(ns vpn-kis-bb.domain.priority
  "Pure: the `ip rule` priority of a split tunnel's fwmark rule when its
   conf says PRIORITY=auto (bash: detect_tailscale_rule_prio plus the
   PRIORITY=auto branch of split_load_conf). Only split tunnels still take
   a priority slot; the tailnet bypasses Mullvad by its marks
   (vpn-kis-bb.domain.tailscale).

   `ip rule show` is parsed with index-of and a character set, no regex
   (ClojureWasm 1.14.11 corrupts some regex results)."
  (:require [clojure.string :as str]
            [vpn-kis-bb.domain.re :as rx]))

(def mullvad-fwmark
  "Mark Mullvad's catch-all ip rule skips (\"mole\" in ASCII)."
  "0x6d6f6c65")

(def fallback-priority
  "bash TAILSCALE_RULE_PRIO_FALLBACK: the base priority when Mullvad's
   fwmark rule is absent."
  5100)

(def split-fallback-priority
  "bash SPLIT_RULE_PRIO_FALLBACK: the split priority when the base is 11
   or less."
  5090)

(def ^:private digit-chars (set "0123456789"))

(defn parse-ip-rule-line
  "One line of `ip rule show`, e.g.
     5199:  not from all fwmark 0x6d6f6c65 lookup 1836018789
   as {:priority 5199 :raw \"not from all fwmark ...\"}. nil when the text
   before the first colon is not a decimal priority or nothing follows it."
  [line]
  (let [line (or line "")
        i    (str/index-of line ":")]
    (when (and i (pos? i))
      (let [digits (subs line 0 i)
            raw    (str/trim (subs line (inc i)))
            prio   (when (every? #(contains? digit-chars %) digits) (parse-long digits))]
        (when (and prio (seq raw))
          {:priority prio :raw raw})))))

(defn parse-ip-rule-output
  "`ip rule show` output as a vector of parse-ip-rule-line maps, in order."
  [s]
  (->> (rx/split-lines* (or s ""))
       (keep parse-ip-rule-line)
       vec))

(defn mullvad-priority
  "Priority of the first rule mentioning Mullvad's fwmark, or nil."
  [rules]
  (some (fn [{:keys [priority raw]}]
          (when (str/includes? (str raw) (str "fwmark " mullvad-fwmark))
            priority))
        rules))

(defn choose-priority
  "bash detect_tailscale_rule_prio: one below Mullvad's fwmark rule when
   that sits above priority 1, else fallback-priority."
  [rules]
  (let [mp (mullvad-priority rules)]
    (if (and mp (> mp 1)) (dec mp) fallback-priority)))

(defn choose-split-priority
  "PRIORITY=auto (bash split_load_conf): ten below choose-priority when
   that is above 11, else split-fallback-priority."
  [rules]
  (let [base (choose-priority rules)]
    (if (> base 11) (- base 10) split-fallback-priority)))
