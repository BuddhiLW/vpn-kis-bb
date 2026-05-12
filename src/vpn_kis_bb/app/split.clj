(ns vpn-kis-bb.app.split
  "Split-tunnel workflows. Each function takes a `system` map of
   wired ports (composition root supplies the concrete impls) and
   a validated split config. Returns Result.

   System keys consumed:
     :ipset    — IIpset
     :iproute  — IIpRoute
     :systemd  — ISystemdUnit
     :dnsmasq  — IDnsmasq
     :shell    — IShell (for openvpn exec)
     :write-fn — (fn [path body] -> Result) for openvpn up/down scripts
     :gate     — optional hive-weave gate to serialize privileged ops"
  (:require [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-system.protocols :as sys-proto]
            [vpn-kis-bb.domain.priority :as priority]
            [vpn-kis-bb.domain.split :as split]
            [vpn-kis-bb.ports.dnsmasq :as dns-port]
            [vpn-kis-bb.ports.iproute :as ipr-port]
            [vpn-kis-bb.ports.ipset :as ipset-port]
            [vpn-kis-bb.ports.systemd :as sd-port]))

;; ---------------------------------------------------------------- helpers

(defn- err? [x] (r/err? x))

(defn- thread-results
  "Apply each fn in `steps` to `init`. Short-circuits on first :error.
   Each step is a fn of acc → Result."
  [init steps]
  (reduce (fn [acc step]
            (if (err? acc) (reduced acc) (step acc)))
          init
          steps))

(defn- resolve-priority
  "If config's :priority is :auto, query the live `ip rule show` via
   IIpRoute and slot the split rule below Tailscale's priority."
  [system priority]
  (if (not= :auto priority)
    (r/ok priority)
    (let [show (ipr-port/-rule-show (:iproute system))]
      (if (err? show)
        show
        (r/ok (priority/choose-split-priority (:ok show)))))))

(defn- with-resolved-priority
  "Returns Result<cfg> with :priority resolved from :auto to a concrete int."
  [system cfg]
  (let [p (resolve-priority system (:priority cfg))]
    (if (err? p) p (r/ok (assoc cfg :priority (:ok p))))))

;; ---------------------------------------------------------------- install

(defn install!
  "Install a split tunnel:

     1. ipset create + (no IPs yet — dnsmasq populates on resolution)
     2. mangle rule (handled by systemd unit at ExecStart)
     3. ip rule add (handled by systemd unit at ExecStart)
     4. dnsmasq drop-in
     5. openvpn up/down hook scripts
     6. systemd unit file + enable + daemon-reload
     7. dnsmasq reload"
  [system cfg]
  (let [valid (split/validate cfg)]
    (if-not (:ok? valid)
      (r/err :split/invalid-config {:msg (:error valid)})
      (let [pr (with-resolved-priority system (:value valid))]
        (if (err? pr)
          pr
          (let [v (:ok pr)
                {:keys [ipset iproute systemd dnsmasq write-fn]} system
                set-name  (split/ipset-name (:name v))
                unit-name (split/unit-name  (:name v))]
            (thread-results
             (r/ok :start)
             [(fn [_] (ipset-port/-create! ipset set-name {:timeout 3600}))
              (fn [_] (dns-port/-write-drop-in! dnsmasq
                                                (str "vpn-kis-split-" (:name v) ".conf")
                                                (split/dnsmasq-drop-in-text v)))
              (fn [_] (write-fn (split/up-script-path   (:name v))
                                (split/openvpn-up-script-text   v)))
              (fn [_] (write-fn (split/down-script-path (:name v))
                                (split/openvpn-down-script-text v)))
              (fn [_] (sd-port/-write! systemd unit-name (split/systemd-unit-text v)))
              (fn [_] (sd-port/-daemon-reload! systemd))
              (fn [_] (sd-port/-enable! systemd unit-name))
              (fn [_] (dns-port/-reload! dnsmasq))
              (fn [_] (r/ok {:installed (:name v)
                             :priority  (:priority v)
                             :set       set-name
                             :unit      unit-name}))])))))))

;; ---------------------------------------------------------------- remove

(defn remove!
  "Tear down a split tunnel by name. Idempotent: missing pieces are OK."
  [system split-name]
  (let [{:keys [ipset iproute systemd dnsmasq write-fn]} system
        unit-name (split/unit-name split-name)
        set-name  (split/ipset-name split-name)
        drop-in   (str "vpn-kis-split-" split-name ".conf")]
    (thread-results
     (r/ok :start)
     [(fn [_] (sd-port/-disable! systemd unit-name))
      (fn [_] (sd-port/-remove!  systemd unit-name))
      (fn [_] (sd-port/-daemon-reload! systemd))
      (fn [_] (dns-port/-remove-drop-in! dnsmasq drop-in))
      (fn [_] (dns-port/-reload! dnsmasq))
      (fn [_] (ipset-port/-destroy! ipset set-name))
      ;; up/down scripts are local files — leave them or delete; we delete
      ;; via write-fn's sibling delete if provided. For now, leave scripts
      ;; in place; the systemd unit going away neutralizes them.
      (fn [_] (r/ok {:removed split-name}))])))

;; ---------------------------------------------------------------- list

(defn list-installed
  "Return a vector of installed split names by scanning the conf dir.

   No system port required — pure filesystem read via babashka.fs."
  ([] (list-installed split/conf-dir))
  ([dir]
   (if-not (fs/exists? dir)
     []
     (->> (fs/glob dir "*.{edn,conf}")
          (map fs/file-name)
          (map str)
          (map #(clojure.string/replace % #"\.(edn|conf)$" ""))
          distinct
          sort
          vec))))

;; ---------------------------------------------------------------- status

(defn status
  "Read live state for a split: ipset contents + ip rule + unit state."
  [system split-name]
  (let [{:keys [ipset iproute systemd]} system
        set-name  (split/ipset-name split-name)
        unit-name (split/unit-name  split-name)]
    (r/ok
     {:name      split-name
      :ipset     (let [r (ipset-port/-list ipset set-name)]
                   (if (r/ok? r) (:ok r) {:err (:error r)}))
      :rules     (let [r (ipr-port/-rule-show iproute)]
                   (if (r/ok? r) (:ok r) []))
      :enabled?  (let [r (sd-port/-enabled? systemd unit-name)]
                   (if (r/ok? r) (:ok r) :unknown))
      :active?   (let [r (sd-port/-active? systemd unit-name)]
                   (if (r/ok? r) (:ok r) :unknown))})))

;; ---------------------------------------------------------------- connect

(defn- mullvad-active?
  "Detect whether Mullvad is in the picture — we wrap with mullvad-exclude
   only when Mullvad is connected, so the openvpn handshake bypasses
   Mullvad's fwmark default route."
  [shell]
  (let [which (sys-proto/shell-which shell "mullvad-exclude")]
    (if-not (r/ok? which)
      false
      (let [st (sys-proto/shell-exec! shell ["mullvad" "status"] {:timeout-ms 3000})]
        (and (r/ok? st)
             (zero? (-> st :ok :exit))
             (re-find #"(?i)connected" (-> st :ok :stdout (or ""))))))))

(defn connect-cmd
  "Build the exact `openvpn` command vector for a validated split config.
   Pure: no side effects. Tests assert the shape directly."
  [cfg & {:keys [mullvad-exclude?]}]
  (let [base ["openvpn"
              "--config" (str (:ovpn-config cfg))
              "--dev" (:dev cfg)
              "--pull-filter" "ignore" "redirect-gateway"
              "--pull-filter" "ignore" "dhcp-option DNS"
              "--route-nopull"
              "--script-security" "2"
              "--up"   (split/up-script-path   (:name cfg))
              "--down" (split/down-script-path (:name cfg))]]
    (if mullvad-exclude?
      (into ["mullvad-exclude"] base)
      base)))

(defn connect!
  "exec openvpn for the named split. Will NOT return on success — the
   openvpn process inherits stdio.

   Caller responsibilities:
     - The split must already be installed (`install!`).
     - The :ovpn-config in the conf must point to a valid openvpn file."
  [system cfg]
  (let [valid (split/validate cfg)]
    (cond
      (not (:ok? valid))
      (r/err :split/invalid-config {:msg (:error valid)})

      (not (:ovpn-config (:value valid)))
      (r/err :split/no-ovpn {:hint "Set OVPN_CONFIG in the split conf"})

      :else
      (let [v   (:value valid)
            ex? (mullvad-active? (:shell system))
            cmd (connect-cmd v :mullvad-exclude? ex?)]
        ;; Foreground exec; openvpn keeps running until user kills it.
        (sys-proto/shell-exec! (:shell system) cmd
                               {:inherit-io? true
                                :timeout-ms (* 60 60 24 1000)})))))
