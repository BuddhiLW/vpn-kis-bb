(ns vpn-kis-bb.app.split-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.dnsmasq-shell :as dnsmasq]
            [vpn-kis-bb.adapters.firewall-ufw :as fw]
            [vpn-kis-bb.adapters.iproute-shell :as ipr]
            [vpn-kis-bb.adapters.ipset-shell :as ipset]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.app.split :as app]
            [vpn-kis-bb.domain.split :as split-d]))

(def good-cfg
  {:name "example"
   :domains ["*.example.com"]
   :dev "tun-example"
   :priority 5089
   :ovpn-config "/tmp/example.ovpn"})

(defn- recording-system []
  (let [shell   (rec/make {:responses {"ip"        {:exit 0
                                                    :stdout "0:\tfrom all lookup local\n5199:\tnot from all fwmark 0x6d6f6c65 lookup 5099\n32766:\tfrom all lookup main\n"}
                                       "systemctl" {:exit 0}
                                       "pgrep"     {:exit 1}}})
        writes  (atom [])
        write-fn (fn [p body]
                   (swap! writes conj {:path p :body body})
                   (r/ok {:path p}))
        ipset    (ipset/make shell)
        iproute  (ipr/make   shell)
        systemd  (sd/make    shell {:write-fn write-fn
                                    :delete-fn (fn [_] (r/ok {}))})
        dns      (dnsmasq/make shell {:write-fn write-fn
                                      :delete-fn (fn [_] (r/ok {}))})]
    {:system {:shell shell
              :ipset ipset
              :iproute iproute
              :systemd systemd
              :dnsmasq dns
              :write-fn write-fn}
     :shell shell
     :writes writes}))

(defn- cmds [shell] (mapv :cmd (rec/calls shell)))

(defn- written-paths [writes]
  (mapv :path @writes))

;; ---------------------------------------------------------------- install

(deftest install-happy-path
  (let [{:keys [system shell writes]} (recording-system)
        r (app/install! system good-cfg)]
    (is (r/ok? r))
    (testing "all four files written"
      (let [paths (set (written-paths writes))]
        (is (contains? paths "/etc/dnsmasq.d/vpn-kis-split-example.conf"))
        (is (contains? paths "/etc/vpn-killswitch/split/example.up.sh"))
        (is (contains? paths "/etc/vpn-killswitch/split/example.down.sh"))
        (is (contains? paths "/etc/systemd/system/vpn-killswitch-split-example.service"))))
    (testing "ipset create issued"
      (is (some (fn [c] (and (vector? c) (= "ipset" (first c)) (= "create" (second c))))
                (cmds shell))))
    (testing "systemctl daemon-reload + enable issued"
      (let [c (cmds shell)]
        (is (some #{["systemctl" "daemon-reload"]} c))
        (is (some #{["systemctl" "enable" "vpn-killswitch-split-example.service"]} c))))))

(deftest install-auto-priority-resolves-from-rule-show
  ;; Mullvad's fwmark rule at priority 5199 → aux priority 5198 → split priority 5188
  (let [{:keys [system writes]} (recording-system)
        cfg (assoc good-cfg :priority :auto)
        _ (app/install! system cfg)
        unit-body (some (fn [{:keys [path body]}]
                          (when (= path "/etc/systemd/system/vpn-killswitch-split-example.service") body))
                        @writes)]
    (is unit-body)
    (is (str/includes? unit-body "priority 5188"))))

(deftest install-invalid-config
  (let [{:keys [system]} (recording-system)
        r (app/install! system (dissoc good-cfg :dev))]
    (is (r/err? r))
    (is (= :split/invalid-config (:error r)))))

;; ---------------------------------------------------------------- remove

(deftest remove-tears-down
  (let [{:keys [system shell]} (recording-system)
        r (app/remove! system "example")]
    (is (r/ok? r))
    (let [c (cmds shell)]
      (testing "systemctl disable issued"
        (is (some #{["systemctl" "disable" "--now" "vpn-killswitch-split-example.service"]} c)))
      (testing "ipset destroy attempted"
        (is (some (fn [x] (= ["ipset" "destroy" "vpnkis_split_example_dst"] x)) c))))))

;; ---------------------------------------------------------------- connect-cmd

(deftest connect-cmd-pure
  (let [cmd (app/connect-cmd (-> good-cfg split-d/validate :value))]
    (is (= "openvpn" (first cmd)))
    (is (some #{"--route-nopull"} cmd))
    (is (some #{"--script-security"} cmd))
    (is (some #{"redirect-gateway"} cmd))
    (is (some #{"/etc/vpn-killswitch/split/example.up.sh"} cmd))
    (is (some #{"/etc/vpn-killswitch/split/example.down.sh"} cmd))))

(deftest connect-cmd-wraps-mullvad-exclude
  (let [cmd (app/connect-cmd (-> good-cfg split-d/validate :value) :mullvad-exclude? true)]
    (is (= "mullvad-exclude" (first cmd)))
    (is (= "openvpn" (second cmd)))))

;; ---------------------------------------------------------------- list-installed

(deftest list-installed-scans-dir
  (let [tmp (str (babashka.fs/create-temp-dir {:prefix "vpn-kis-bb-list-"}))]
    (try
      (spit (str tmp "/foo.edn")  "{:name \"foo\"}")
      (spit (str tmp "/bar.conf") "DEV=x\n")
      (let [names (app/list-installed tmp)]
        (is (= ["bar" "foo"] names)))
      (finally
        (babashka.fs/delete-tree tmp)))))
