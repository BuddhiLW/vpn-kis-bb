(ns vpn-kis-bb.app.nm-dispatch-test
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.app.nm-dispatch :as app]
            [vpn-kis-bb.log :as log]))

(use-fixtures :each (fn [f] (binding [log/*quiet* true] (f))))

(defn- text [& lines] (apply str (map #(str % "\n") lines)))

;; ---------------------------------------------------------------- fixtures

(def rules-path "/etc/ufw/before.rules")
(def exclude-unit "/etc/systemd/system/vpn-killswitch-exclude.service")

(def eth0-rules
  (text "*filter"
        ":ufw-before-output - [0:0]"
        "-A ufw-before-output -o lo -j ACCEPT"
        "-A ufw-before-output -o eth0 -p udp --dport 67 -j ACCEPT"
        "-A ufw-before-output -o tun+ -j ACCEPT"
        "-A ufw-before-input  -i tun+ -j ACCEPT"
        "# --- KILL-SWITCH: drop anything else on physical IF ---"
        "-A ufw-before-output -o eth0 -j DROP"
        "-A ufw-before-input  -i eth0 -j DROP"
        "COMMIT"))

(def wlan0-rules
  (text "*filter"
        ":ufw-before-output - [0:0]"
        "-A ufw-before-output -o lo -j ACCEPT"
        "-A ufw-before-output -o wlan0 -p udp --dport 67 -j ACCEPT"
        "-A ufw-before-output -o tun+ -j ACCEPT"
        "-A ufw-before-input  -i tun+ -j ACCEPT"
        "# --- KILL-SWITCH: drop anything else on physical IF ---"
        "-A ufw-before-output -o wlan0 -j DROP"
        "-A ufw-before-input  -i wlan0 -j DROP"
        "COMMIT"))

(def lock ["mkdir" "/run/lock/vpn-killswitch.nm.d"])
(def unlock ["rmdir" "/run/lock/vpn-killswitch.nm.d"])
(def stale ["find" "/run/lock/vpn-killswitch.nm.d" "-maxdepth" "0" "-mmin" "+2"])
(def routes ["ip" "-4" "route" "ls"])
(def addrs ["ip" "-o" "-4" "addr" "show"])
(def backup ["cp" "-a" "/etc/ufw/before.rules" "/etc/ufw/before.rules.nm-bak"])
(def reload ["ufw" "reload"])
(def ts-enabled ["systemctl" "is-enabled" "--quiet" "vpn-killswitch-tailscale-routes.service"])
(def ts-restart ["systemctl" "restart" "vpn-killswitch-tailscale-routes.service"])
(def ex-restart ["systemctl" "restart" "vpn-killswitch-exclude.service"])

(defn- logger [msg] ["logger" "-t" "vpn-killswitch" "--" msg])

(def wlan0-routes
  (text "default via 192.168.1.1 dev wlan0 proto dhcp metric 600"
        "192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.50 metric 600"))

(def base-table {routes {:stdout wlan0-routes}})

(defn- responder
  "RecordingShell :respond fn: `table` maps a command vector to a response,
   or to a fn of that command's 1-based call count."
  [table]
  (let [counts (atom {})]
    (fn [cmd _opts]
      (let [n (get (swap! counts update cmd (fnil inc 0)) cmd)
            v (get table cmd)]
        (if (fn? v) (v n) v)))))

(defn- harness
  "Recording system over an in-memory file map (a nil value reads as
   absent). :write-fn answers `write-results` in order (then ok)."
  ([] (harness {}))
  ([{:keys [files table write-results]}]
   (let [fs        (atom (merge {rules-path eth0-rules} files))
         writes    (atom [])
         results   (atom (vec write-results))
         shell     (rec/make {:respond (responder (merge base-table table))})
         write-fn  (fn [p body]
                     (swap! writes conj [p body])
                     (let [res (or (first @results) (r/ok {:path p}))]
                       (swap! results #(vec (rest %)))
                       (when (r/ok? res) (swap! fs assoc p body))
                       res))
         delete-fn (fn [p] (swap! fs dissoc p) (r/ok {:path p}))]
     {:system {:shell     shell
               :systemd   (sd/make shell {:write-fn write-fn :delete-fn delete-fn})
               :read-fn   (fn [p] (get @fs p))
               :write-fn  write-fn
               :delete-fn delete-fn}
      :shell  shell
      :fs     fs
      :writes writes})))

(defn- cmds [h] (rec/cmds (:shell h)))

;; ---------------------------------------------------------------- filtering

(deftest irrelevant-events-do-nothing
  (doseq [[iface action] [["eth0" "pre-up"] ["eth0" "dhcp4-change"] ["wlan0" "hostname"]
                          ["wg0-mullvad" "up"] ["tun0" "vpn-up"] ["docker0" "down"]
                          ["veth9f" "up"] ["lo" "up"]]]
    (let [h   (harness)
          res (app/handle! (:system h) iface action)]
      (is (= :ignored (-> res :ok :action)) (str iface " " action))
      (is (= [] (cmds h)))
      (is (= [] @(:writes h))))))

(deftest tailscale-events-refresh-the-bypass
  (testing "enabled unit: restarted, nothing else"
    (let [h   (harness)
          res (app/handle! (:system h) "tailscale0" "up")]
      (is (= {:action :tailnet-refresh :iface "tailscale0" :refreshed? true} (:ok res)))
      (is (= [ts-enabled ts-restart] (cmds h)))))
  (testing "unit not enabled: left alone"
    (let [h   (harness {:table {ts-enabled {:exit 1}}})
          res (app/handle! (:system h) "tailscale0" "down")]
      (is (false? (-> res :ok :refreshed?)))
      (is (= [ts-enabled] (cmds h)))))
  (testing "a failed restart goes to syslog"
    (let [h   (harness {:table {ts-restart {:exit 1}}})
          res (app/handle! (:system h) "tailscale0" "up")]
      (is (false? (-> res :ok :refreshed?)))
      (is (= [ts-enabled ts-restart (logger "failed to refresh Tailscale bypass")] (cmds h))))))

;; ---------------------------------------------------------------- retarget

(deftest retarget-to-the-new-physical-if
  (let [h   (harness)
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= {:action :retargeted :from "eth0" :to "wlan0"
            :exclude-restarted? false :tailnet-refreshed? true}
           (:ok res)))
    (is (= [lock routes
            (logger "physical IF changed: eth0 -> wlan0, reapplying")
            backup reload
            (logger "killswitch retargeted: eth0 -> wlan0")
            ts-enabled ts-restart
            unlock]
           (cmds h)))
    (is (= [[rules-path wlan0-rules]] @(:writes h)))))

(deftest retarget-restarts-cgroup-exclusion-when-enabled
  (let [h   (harness {:files {exclude-unit "[Unit]\n"}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (true? (-> res :ok :exclude-restarted?)))
    (is (= [(logger "killswitch retargeted: eth0 -> wlan0") ex-restart ts-enabled ts-restart unlock]
           (take-last 5 (cmds h))))))

(deftest same-interface-is-a-no-op
  (let [h   (harness {:table {routes {:stdout "default via 10.0.0.1 dev eth0 proto dhcp\n"}}})
        res (app/handle! (:system h) "eth0" "up")]
    (is (= {:action :unchanged :iface "eth0"} (:ok res)))
    (is (= [lock routes unlock] (cmds h)))
    (is (= [] @(:writes h)))))

(deftest events-without-an-interface-retarget-too
  (let [h (harness)]
    (is (= :retargeted (-> (app/handle! (:system h) nil "connectivity-change") :ok :action)))
    (is (= :unchanged (-> (app/handle! (:system h) "" "connectivity-change") :ok :action))
        "second run finds the pin already moved")))

(deftest a-default-route-through-a-tunnel-is-skipped
  (let [h   (harness {:table {routes {:stdout (text "default dev wg0-mullvad scope link"
                                                    "default via 192.168.1.1 dev wlan0 proto dhcp")}}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= "wlan0" (-> res :ok :to)))
    (is (not-any? #{addrs} (cmds h)))))

(deftest fallback-to-an-interface-holding-ipv4
  (let [h   (harness {:table {routes {:stdout "default dev wg0-mullvad scope link\n"}
                              addrs  {:stdout (text "1: lo    inet 127.0.0.1/8 scope host lo"
                                                    "4: wg0-mullvad    inet 10.66.1.2/32 scope global"
                                                    "3: wlan0    inet 192.168.1.50/24 brd 192.168.1.255")}}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= "wlan0" (-> res :ok :to)))
    (is (= [lock routes addrs] (take 3 (cmds h))))))

(deftest no-candidate-is-skipped
  (let [h   (harness {:table {routes {:stdout "default dev wg0-mullvad scope link\n"}
                              addrs  {:stdout "1: lo    inet 127.0.0.1/8 scope host lo\n"}}})
        res (app/handle! (:system h) "eth0" "down")]
    (is (= {:action :skipped :reason :no-candidate :message "no physical IF candidate, skip"}
           (:ok res)))
    (is (= [lock routes addrs (logger "no physical IF candidate, skip") unlock] (cmds h)))
    (is (= [] @(:writes h)))))

(deftest unparsable-rules-are-skipped
  (let [msg "cannot parse current IF from /etc/ufw/before.rules, skip (manual fix needed)"]
    (doseq [files [{rules-path nil} {rules-path "*filter\nCOMMIT\n"}]]
      (let [h   (harness {:files files})
            res (app/handle! (:system h) "wlan0" "up")]
        (is (= :unparsable-rules (-> res :ok :reason)))
        (is (= [lock routes (logger msg) unlock] (cmds h)))
        (is (= [] @(:writes h)))))))

(deftest a-virtual-pin-is-never-rewritten
  (let [h   (harness {:files {rules-path (text "-A ufw-before-output -o wg0 -j DROP")}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= :virtual-current (-> res :ok :reason)))
    (is (some #{(logger (str "current IF 'wg0' looks virtual/VPN, refusing rewrite"
                             " (rules may be corrupted)"))}
              (cmds h)))
    (is (= [] @(:writes h)))))

;; ---------------------------------------------------------------- lock

(deftest a-held-lock-skips-the-event
  (let [h   (harness {:table {lock {:exit 1 :stderr "mkdir: cannot create directory: File exists"}}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= :lock-held (-> res :ok :reason)))
    (is (= [lock stale (logger "lock held, skip")] (cmds h)) "never releases a lock it does not hold")
    (is (= [] @(:writes h)))))

(deftest a-stale-lock-is-broken-once
  (let [h   (harness {:table {lock  (fn [n] {:exit (if (= n 1) 1 0)})
                              stale {:stdout "/run/lock/vpn-killswitch.nm.d\n"}}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= :retargeted (-> res :ok :action)))
    (is (= [lock stale (logger "stale lock /run/lock/vpn-killswitch.nm.d removed") unlock lock routes]
           (take 6 (cmds h))))
    (is (= unlock (last (cmds h))))))

;; ---------------------------------------------------------------- failures

(deftest reload-failure-restores-the-original
  (let [h   (harness {:table {reload (fn [n] {:exit (if (= n 1) 1 0)})}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= :nm-dispatch/reload-failed (:error res)))
    (is (true? (:restored? res)))
    (is (true? (:reloaded? res)))
    (is (= [[rules-path wlan0-rules] [rules-path eth0-rules]] @(:writes h)))
    (is (= eth0-rules (get @(:fs h) rules-path)))
    (is (= [backup reload (logger "ufw reload failed, restoring backup") reload unlock]
           (take-last 5 (cmds h))))))

(deftest double-reload-failure-asks-for-a-human
  (let [h   (harness {:table {reload {:exit 1}}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= :nm-dispatch/reload-failed (:error res)))
    (is (false? (:reloaded? res)))
    (is (some #{(logger "restore reload also failed, MANUAL INTERVENTION NEEDED")} (cmds h)))
    (is (= unlock (last (cmds h))))))

(deftest backup-failure-aborts-before-writing
  (let [h   (harness {:table {backup {:exit 1}}})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= :nm-dispatch/backup-failed (:error res)))
    (is (= "backup failed, abort" (:hint res)))
    (is (= [] @(:writes h)))
    (is (not-any? #{reload} (cmds h)))
    (is (= unlock (last (cmds h))))))

(deftest write-failure-restores-the-original
  (let [h   (harness {:write-results [(r/err :fs/write-failed {:path rules-path})]})
        res (app/handle! (:system h) "wlan0" "up")]
    (is (= :nm-dispatch/write-failed (:error res)))
    (is (true? (:restored? res)))
    (is (= [[rules-path wlan0-rules] [rules-path eth0-rules]] @(:writes h)))
    (is (not-any? #{reload} (cmds h)))
    (is (some #{(logger "before.rules write failed, restoring backup")} (cmds h)))))

(deftest a-throw-becomes-an-err-and-releases-the-lock
  (let [h   (harness)
        sys (assoc (:system h) :read-fn (fn [_] (throw (ex-info "io error" {}))))
        res (app/handle! sys "wlan0" "up")]
    (is (= :nm-dispatch/threw (:error res)))
    (is (= unlock (last (cmds h))))))
