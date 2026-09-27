(ns vpn-kis-bb.app.unlock-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.adapters.dnsmasq-shell :as dnsmasq]
            [vpn-kis-bb.adapters.iproute-shell :as ipr]
            [vpn-kis-bb.adapters.ipset-shell :as ipset]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.app.unlock :as unlock]))

;; ---------------------------------------------------------------- harness

(defn- which-shell
  "IShell over a RecordingShell whose shell-which finds only `available`.
   Method params stay distinct: cljw reads fields through a second `_`."
  [recorder available]
  (reify proto/IShell
    (shell-exec! [_this cmd opts] (proto/shell-exec! recorder cmd opts))
    (shell-env [_this] {})
    (shell-which [_this program]
      (if (contains? available program)
        (r/ok {:path (str "/usr/bin/" program)})
        (r/err :shell/not-found {:program program})))))

(defn- glob-match?
  "Test double for :glob-fn: a pattern with one `*`, matched against the
   part of path below dir."
  [dir pattern path]
  (let [prefix (str dir "/")
        i      (str/index-of pattern "*")
        head   (subs pattern 0 i)
        tail   (subs pattern (inc i))]
    (and (str/starts-with? path prefix)
         (let [rel (subs path (count prefix))]
           (and (str/starts-with? rel head)
                (str/ends-with? rel tail)
                (>= (count rel) (+ (count head) (count tail))))))))

(def backup "/etc/ufw/backup-20260927-101010/")
(def in-backup #{"user.rules" "before.rules" "ufw"})

(defn- backup-respond
  "The newest backup is `backup` and holds the files in in-backup; the
   exclude ip rule is already gone."
  [cmd _opts]
  (cond
    (= cmd unlock/latest-backup-cmd)
    {:stdout (str backup "\n")}

    (= "test" (first cmd))
    (let [f    (last cmd)
          base (subs f (inc (str/last-index-of f "/")))]
      (if (and (str/starts-with? f "/etc/ufw/backup-") (contains? in-backup base))
        {:exit 0}
        {:exit 1}))

    (= (take 3 cmd) ["ip" "rule" "del"])
    {:exit 2}))

(defn- harness
  "System over a recording shell (:live-shell too when live-respond is
   given), with the ports cli/system wires. files (path -> text) back
   :read-fn and :glob-fn; writes and deletes land in :events, in order."
  [{:keys [respond live-respond files]}]
  (let [recorder  (rec/make {:respond respond})
        shell     (which-shell recorder #{"nft" "ipset"})
        live      (when live-respond (rec/make {:respond live-respond}))
        state     (atom (or files {}))
        events    (atom [])
        write-fn  (fn [p body]
                    (swap! events conj [:write p body])
                    (swap! state assoc p body)
                    (r/ok {:path p}))
        delete-fn (fn [p]
                    (swap! events conj [:delete p])
                    (swap! state dissoc p)
                    (r/ok {:path p}))]
    {:system (cond-> {:shell     shell
                      :read-fn   (fn [p] (get @state p))
                      :write-fn  write-fn
                      :delete-fn delete-fn
                      :glob-fn   (fn [dir pattern] (filter #(glob-match? dir pattern %) (keys @state)))
                      :ipset     (ipset/make shell)
                      :iproute   (ipr/make shell)
                      :systemd   (sd/make shell {:write-fn write-fn :delete-fn delete-fn})
                      :dnsmasq   (dnsmasq/make shell {:write-fn write-fn :delete-fn delete-fn})
                      :settings  {:prog "vpn-kis"}
                      :env       {}
                      :self-path "/opt/vpn-kis/bin/vpn-kis"}
               live (assoc :live-shell (which-shell live #{})))
     :rec    recorder
     :live   live
     :files  state
     :events events}))

(defn- cmds [h] (rec/cmds (:rec h)))

(defn- index-of [coll x]
  (first (keep-indexed (fn [i y] (when (= x y) i)) coll)))

(defn- quietly
  "Run f with stdout and stderr captured: [result output]."
  [f]
  (let [res (atom nil)
        out (with-out-str (binding [*err* *out*] (reset! res (f))))]
    [@res out]))

(def restores
  [["/etc/ufw/backup-20260927-101010/user.rules" "/etc/ufw/user.rules"]
   ["/etc/ufw/backup-20260927-101010/before.rules" "/etc/ufw/before.rules"]
   ["/etc/ufw/backup-20260927-101010/ufw" "/etc/default/ufw"]])

;; ---------------------------------------------------------------- tests

(deftest unlock-without-a-backup
  (let [h         (harness {:respond (fn [cmd _opts]
                                       (when (= cmd unlock/latest-backup-cmd) {:stdout ""}))})
        [res out] (quietly #(unlock/unlock! (:system h) {}))]
    (is (= {:error :unlock/no-backup
            :hint  "No backup found in /etc/ufw/backup-*. Manual recovery needed."}
           res))
    (is (str/includes? out "[+] Rolling back VPN kill-switch..."))
    (is (= [unlock/latest-backup-cmd] (cmds h)))
    (is (empty? @(:events h)))))

(deftest unlock-dry-run-plans-from-the-newest-backup
  (let [h         (harness {:respond backup-respond})
        [res out] (quietly #(unlock/unlock! (:system h) {:dry-run? true}))]
    (is (= {:dry-run?     true
            :backup       backup
            :will-restore (mapv first restores)
            :restores     restores
            :will-remove  ["/etc/NetworkManager/dispatcher.d/90-vpn-killswitch"
                           "/etc/ufw/before.init"
                           "/etc/ipset.conf"]}
           (:ok res)))
    (is (not-any? #(contains? #{"cp" "ufw" "ipset" "nft"} (first %)) (cmds h)))
    (is (empty? @(:events h)))
    (is (str/includes? out (str "[dry-run] unlock: cp -a /etc/ufw/backup-20260927-101010/user.rules"
                                " /etc/ufw/user.rules")))))

(deftest unlock-restores-then-tears-down-in-bash-order
  (let [h         (harness {:respond backup-respond
                            :files   {"/etc/vpn-killswitch/split/a.conf"   "DEV=tun-a\n"
                                      "/etc/vpn-killswitch/tailnet.cidrs" "100.64.0.0/10\n"}})
        [res out] (quietly #(unlock/unlock! (:system h) {}))
        cs        (cmds h)
        evs       @(:events h)
        idx       #(index-of cs %)]
    (is (r/ok? res))
    (is (= backup (-> res :ok :restored)))
    (is (= (mapv second restores) (-> res :ok :files)))
    (is (= [] (-> res :ok :failed)))
    (is (true? (-> res :ok :ufw-reloaded?)))
    (testing "cp -a of exactly the files the backup holds"
      (is (= (mapv (fn [[src dst]] ["cp" "-a" src dst]) restores)
             (filterv #(= "cp" (first %)) cs))))
    (testing "hook, before.init and ipset.conf removed"
      (doseq [p ["/etc/NetworkManager/dispatcher.d/90-vpn-killswitch"
                 "/etc/ufw/before.init"
                 "/etc/ipset.conf"]]
        (is (some #{[:delete p]} evs) p)))
    (testing "tailnet bypass, refresh timer, splits and exclusion removed"
      (is (some #{["nft" "delete" "table" "inet" "vpn-killswitch-tailscale"]} cs))
      (is (some #{[:delete "/etc/vpn-killswitch/tailnet.cidrs"]} evs))
      (is (some #{["systemctl" "disable" "--now" "vpn-killswitch-refresh.timer"]} cs))
      (is (some #{["ipset" "destroy" "vpnkis_split_a_dst"]} cs))
      (is (some #{["iptables" "-t" "mangle" "-X" "VPNKIS-SPLIT"]} cs))
      (is (some #{["ip" "rule" "del" "priority" "5080"]} cs)))
    (testing "bash order: copies, removals, ufw reload, then the sets"
      (is (< (idx ["cp" "-a" "/etc/ufw/backup-20260927-101010/ufw" "/etc/default/ufw"])
             (idx ["nft" "delete" "table" "inet" "vpn-killswitch-tailscale"])
             (idx ["systemctl" "disable" "--now" "vpn-killswitch-refresh.timer"])
             (idx ["ipset" "destroy" "vpnkis_split_a_dst"])
             (idx ["ip" "rule" "del" "priority" "5080"])
             (idx ["ufw" "reload"])
             (idx ["ipset" "destroy" "vpn_endpoints"])
             (idx ["ipset" "destroy" "vpn_dns_bootstrap"]))))
    (testing "bash info lines"
      (is (str/includes? out (str "[+] Restoring from: " backup)))
      (is (str/includes? out (str "[+] Firewall restored from " backup ".")))
      (is (str/includes? out (str "[+] IPv6 disable (sysctl/modprobe/GRUB) NOT reverted;"
                                  " remove manually if desired:"))))))

(deftest unlock-stops-when-a-copy-fails
  (let [h       (harness {:respond (fn [cmd opts]
                                     (if (= "cp" (first cmd))
                                       {:exit 1 :stderr "cp: cannot create regular file: No space left on device"}
                                       (backup-respond cmd opts)))})
        [res _] (quietly #(unlock/unlock! (:system h) {}))]
    (is (= :unlock/restore-failed (:error res)))
    (is (str/includes? (:hint res) "could not restore /etc/ufw/user.rules"))
    (is (str/includes? (:hint res) "No space left on device"))
    (is (= 1 (count (filter #(= "cp" (first %)) (cmds h)))))
    (is (not-any? #{["ufw" "reload"]} (cmds h)))
    (is (empty? @(:events h)))))

(deftest unlock-warns-when-ufw-reload-fails
  (let [h         (harness {:respond (fn [cmd opts]
                                       (if (= cmd ["ufw" "reload"])
                                         {:exit 1}
                                         (backup-respond cmd opts)))})
        [res out] (quietly #(unlock/unlock! (:system h) {}))]
    (is (r/ok? res))
    (is (false? (-> res :ok :ufw-reloaded?)))
    (is (= [{:step "ufw reload" :reason "exit 1"}] (-> res :ok :failed)))
    (is (str/includes? out "[!] ufw reload failed"))
    (is (some #{["ipset" "destroy" "vpn_endpoints"]} (cmds h)) "the sets are still destroyed")))

(deftest unlock-looks-the-backup-up-through-the-live-shell
  (let [h       (harness {:respond backup-respond :live-respond backup-respond})
        [res _] (quietly #(unlock/unlock! (:system h) {:dry-run? true}))]
    (is (= backup (-> res :ok :backup)))
    (is (= restores (-> res :ok :restores)))
    (is (some #{unlock/latest-backup-cmd} (rec/cmds (:live h))))
    (is (empty? (cmds h)) "the (dry-run) :shell saw nothing")))
