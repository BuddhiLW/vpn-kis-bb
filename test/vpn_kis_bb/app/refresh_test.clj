(ns vpn-kis-bb.app.refresh-test
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hive-dsl.result :as r]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]
            [vpn-kis-bb.app.refresh :as refresh]
            [vpn-kis-bb.domain.refresh :as d]
            [vpn-kis-bb.domain.util :as u]
            [vpn-kis-bb.ports.fetcher :as port]))

;; ---------------------------------------------------------------------------
;; fixtures

;; Method params stay distinct: on cljw a record method written [_ _]
;; resolves its fields through the second `_` (the opts map) and throws.
(defrecord StubFetcher [pid ips]
  port/IProviderFetcher
  (-provider-id [_this] pid)
  (-supports? [_this p] (= (name p) (name pid)))
  (-fetch-ips [_this _opts]
    (if ips
      (r/ok {:provider pid :ips ips :source :stub :fetched-at (u/now-iso)})
      (r/err :stub/offline {:provider pid}))))

(def ^:private live-cache-prefix "/etc/vpn-killswitch/providers/")
(def ^:private self "/usr/local/bin/vpn-kis")

(defn- with-tmp [f]
  (let [d (fs/create-temp-dir {:prefix "vpn-kis-bb-refresh-"})]
    (try (f (str d)) (finally (fs/delete-tree d)))))

(defn- make-system
  "Hand-built system: recording shell, captured writes and deletes, an
   in-memory file map for :read-fn (the active file), stub fetchers
   (ips nil = fetch fails) and a temp providers dir. fetch-one! writes the
   live cache path; those writes are mirrored into the temp dir so
   load-union sees freshly fetched lists."
  [{:keys [dir fetchers active dns respond]}]
  (let [shell    (rec/make {:respond respond})
        files    (atom (if active {d/active-file active} {}))
        writes   (atom [])
        deletes  (atom [])
        write-fn (fn [path body]
                   (swap! writes conj [path body])
                   (if (str/starts-with? path live-cache-prefix)
                     (spit (str dir "/" (subs path (count live-cache-prefix))) body)
                     (swap! files assoc path body))
                   (r/ok {:path path}))
        delete-fn (fn [path]
                    (swap! deletes conj path)
                    (swap! files dissoc path)
                    (r/ok {:path path}))]
    {:system  {:shell         shell
               :write-fn      write-fn
               :delete-fn     delete-fn
               :read-fn       (fn [path] (get @files path))
               :settings      {:dns-bootstrap (or dns []) :prog "vpn-kis"}
               :self-path     self
               :systemd       (sd/make shell {:write-fn write-fn :delete-fn delete-fn})
               :fetchers      (into {} (for [[k ips] fetchers] [k (->StubFetcher k ips)]))
               :providers-dir dir}
     :shell   shell
     :files   files
     :writes  writes
     :deletes deletes}))

(defn- quietly
  "Run f with log output (stdout and stderr) captured: [result log-text]."
  [f]
  (let [res (atom nil)
        out (with-out-str (binding [*err* *out*] (reset! res (f))))]
    [@res out]))

(defn- list-response
  "respond fn: `ipset list vpn_endpoints` reports n entries."
  [n]
  (fn [cmd _]
    (when (= cmd ["ipset" "list" "vpn_endpoints"])
      {:stdout (str "Name: vpn_endpoints\nNumber of entries: " n "\nMembers:\n")})))

(defn- restore-cmd? [cmd]
  (and (= "sh" (first cmd)) (str/includes? (nth cmd 2 "") "ipset restore")))

(defn- expected-swap
  "The exact command sequence refresh! must run for `ips`."
  [ips]
  (conj (d/swap-commands ips) ["ipset" "list" "vpn_endpoints"]))

;; ---------------------------------------------------------------------------
;; refresh!

(deftest refresh-from-active-file-swaps-atomically
  (with-tmp
    (fn [dir]
      (spit (str dir "/custom.ips") "# hand-made\n3.3.3.3\n")
      (let [{:keys [system shell writes]}
            (make-system {:dir      dir
                          :active   "mullvad custom\n"
                          :fetchers {:mullvad #{"1.1.1.1" "2.2.2.2"}}
                          :dns      ["9.9.9.9"]
                          :respond  (list-response 4)})
            [res log] (quietly #(refresh/refresh! system []))]
        (is (r/ok? res))
        (is (= ["mullvad" "custom"] (-> res :ok :providers)))
        (is (= 4 (-> res :ok :count)) "count read from ipset list")
        (is (= {"mullvad" :fetched "custom" :static} (-> res :ok :fetch)))
        (is (= ["9.9.9.9"] (-> res :ok :dns-bootstrap)))
        (testing "exact swap order: build aside, swap, destroy (endpoints, then DNS), save both, count"
          (is (= [["ipset" "create" "vpn_endpoints" "hash:ip" "family" "inet"
                   "hashsize" "2048" "maxelem" "65536" "-exist"]
                  ["ipset" "create" "vpn_endpoints_new" "hash:ip" "family" "inet"
                   "hashsize" "2048" "maxelem" "65536" "-exist"]
                  ["ipset" "flush" "vpn_endpoints_new"]
                  ["sh" "-c" (str "printf '%s' '"
                                  "create vpn_endpoints_new hash:ip family inet hashsize 2048 maxelem 65536 -exist\n"
                                  "add vpn_endpoints_new 1.1.1.1\n"
                                  "add vpn_endpoints_new 2.2.2.2\n"
                                  "add vpn_endpoints_new 3.3.3.3\n"
                                  "' | ipset restore -exist")]
                  ["ipset" "swap" "vpn_endpoints_new" "vpn_endpoints"]
                  ["ipset" "destroy" "vpn_endpoints_new"]
                  ["ipset" "create" "vpn_dns_bootstrap" "hash:ip" "family" "inet"
                   "hashsize" "2048" "maxelem" "65536" "-exist"]
                  ["ipset" "create" "vpn_dns_bootstrap_new" "hash:ip" "family" "inet"
                   "hashsize" "2048" "maxelem" "65536" "-exist"]
                  ["ipset" "flush" "vpn_dns_bootstrap_new"]
                  ["sh" "-c" (str "printf '%s' '"
                                  "create vpn_dns_bootstrap_new hash:ip family inet hashsize 2048 maxelem 65536 -exist\n"
                                  "add vpn_dns_bootstrap_new 9.9.9.9\n"
                                  "' | ipset restore -exist")]
                  ["ipset" "swap" "vpn_dns_bootstrap_new" "vpn_dns_bootstrap"]
                  ["ipset" "destroy" "vpn_dns_bootstrap_new"]
                  ["sh" "-c" "{ ipset save vpn_endpoints && ipset save vpn_dns_bootstrap; } > /etc/ipset.conf"]
                  ["ipset" "list" "vpn_endpoints"]]
                 (rec/cmds shell))))
        (testing "the active file is only read, never rewritten"
          (is (not-any? #(= d/active-file (first %)) @writes)))
        (testing "fetched list written to the provider cache"
          (is (= ["/etc/vpn-killswitch/providers/mullvad.ips"] (mapv first @writes))))
        (is (str/includes? log "custom: no fetcher, keeping static"))
        (is (str/includes? log "vpn_endpoints now has 4 IPs (providers: mullvad custom)"))))))

(deftest explicit-names-become-the-active-set
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell files]}
            (make-system {:dir      dir
                          :active   "airvpn\n"
                          :fetchers {:mullvad #{"1.1.1.1"} :airvpn #{"5.5.5.5"}}})
            [res _] (quietly #(refresh/refresh! system [:mullvad]))]
        (is (r/ok? res))
        (is (= ["mullvad"] (-> res :ok :providers)))
        (is (= "mullvad\n" (get @files d/active-file)))
        (is (= {"mullvad" :fetched} (-> res :ok :fetch)) "airvpn is not fetched")
        (is (= (expected-swap ["1.1.1.1"]) (rec/cmds shell)))
        (is (= 1 (-> res :ok :count)) "no count line: falls back to the IPs loaded")))))

(deftest missing-active-file-is-an-error
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell writes]} (make-system {:dir dir})
            [res _] (quietly #(refresh/refresh! system []))]
        (is (r/err? res))
        (is (= :refresh/no-active (:error res)))
        (is (str/includes? (:hint res) d/active-file))
        (is (str/includes? (:hint res) "vpn-kis refresh <names>"))
        (is (empty? (rec/cmds shell)))
        (is (empty? @writes))))))

(deftest blank-active-file-is-an-empty-list
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell]} (make-system {:dir dir :active "  \n"})
            [res _] (quietly #(refresh/refresh! system nil))]
        (is (= :refresh/empty-list (:error res)))
        (is (empty? (rec/cmds shell)))))))

(deftest failed-fetch-keeps-the-cached-list
  (with-tmp
    (fn [dir]
      (spit (str dir "/mullvad.ips") "# old cache\n5.5.5.5\n")
      (let [{:keys [system shell]}
            (make-system {:dir dir :active "mullvad\n" :fetchers {:mullvad nil}})
            [res log] (quietly #(refresh/refresh! system []))]
        (is (r/ok? res))
        (is (= {"mullvad" :failed} (-> res :ok :fetch)))
        (is (= (expected-swap ["5.5.5.5"]) (rec/cmds shell)))
        (is (str/includes? log "refresh: fetch failed for mullvad, keeping cached list"))))))

(deftest unknown-provider-without-a-list-does-not-abort
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell]}
            (make-system {:dir dir :fetchers {:mullvad #{"1.1.1.1"}}})
            [res log] (quietly #(refresh/refresh! system ["mullvad" "nope"]))]
        (is (r/ok? res))
        (is (= {"mullvad" :fetched "nope" :unknown} (-> res :ok :fetch)))
        (is (= ["mullvad" "nope"] (-> res :ok :providers)))
        (is (= (expected-swap ["1.1.1.1"]) (rec/cmds shell)))
        (is (str/includes? log "unknown provider 'nope'"))))))

(deftest empty-union-never-touches-ipset
  (with-tmp
    (fn [dir]
      (testing "no provider IPs and no DNS bootstrap"
        (let [{:keys [system shell]} (make-system {:dir dir :fetchers {:mullvad nil}})
              [res log] (quietly #(refresh/refresh! system ["mullvad"]))]
          (is (= :refresh/no-ips (:error res)))
          (is (str/includes? (:hint res) "current ipset left untouched"))
          (is (= ["mullvad"] (:missing res)))
          (is (str/includes? log "No cached list for 'mullvad'"))
          (is (empty? (rec/cmds shell)))))
      (testing "DNS bootstrap alone never replaces the provider whitelist"
        (let [{:keys [system shell]} (make-system {:dir dir :dns ["1.1.1.1" "8.8.8.8"]})
              [res _] (quietly #(refresh/refresh! system ["typo"]))]
          (is (= :refresh/no-ips (:error res)))
          (is (empty? (rec/cmds shell))))))))

(deftest failed-load-stops-before-the-swap
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell]}
            (make-system {:dir      dir
                          :fetchers {:mullvad #{"1.1.1.1"}}
                          :respond  (fn [cmd _]
                                      (when (restore-cmd? cmd)
                                        {:exit 1 :stderr "ipset v7: syntax error"}))})
            [res _] (quietly #(refresh/refresh! system ["mullvad"]))
            cmds (rec/cmds shell)]
        (is (= :refresh/command-failed (:error res)))
        (is (= 1 (:exit res)))
        (is (restore-cmd? (last cmds)) "nothing runs after the failed load")
        (is (not-any? #(= "swap" (second %)) cmds) "the live set is never swapped")))))

(deftest throwing-shell-becomes-an-error
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell]}
            (make-system {:dir      dir
                          :fetchers {:mullvad #{"1.1.1.1"}}
                          :respond  (fn [cmd _]
                                      (when (= "create" (second cmd))
                                        (throw (ex-info "no ipset binary" {}))))})
            [res _] (quietly #(refresh/refresh! system ["mullvad"]))]
        (is (= :refresh/command-failed (:error res)))
        (is (= 1 (count (rec/cmds shell))) "stops at the first command")))))

(deftest unreadable-cache-never-touches-ipset
  (with-tmp
    (fn [dir]
      ;; a directory where the .ips file should be: reading it throws on bb
      (fs/create-dirs (str dir "/custom.ips"))
      (let [{:keys [system shell]} (make-system {:dir dir})
            [res _] (quietly #(refresh/refresh! system ["custom"]))]
        (is (r/err? res))
        (is (empty? (rec/cmds shell)))))))

;; ---------------------------------------------------------------------------
;; install-timer! / remove-timer!

(deftest install-timer-writes-units-and-enables
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell files]} (make-system {:dir dir :active "mullvad\n"})
            [res log] (quietly #(refresh/install-timer! system "30min"))]
        (is (r/ok? res))
        (is (= "30min" (-> res :ok :interval)))
        (is (= (d/service-unit-text self)
               (get @files "/etc/systemd/system/vpn-killswitch-refresh.service")))
        (is (= (d/timer-unit-text "30min")
               (get @files "/etc/systemd/system/vpn-killswitch-refresh.timer")))
        (is (= [["systemctl" "daemon-reload"]
                ["systemctl" "enable" "--now" "vpn-killswitch-refresh.timer"]]
               (rec/cmds shell)))
        (is (not (str/includes? log "timer will fail")))
        (is (str/includes? log "Refresh timer active: every 30min"))))))

(deftest install-timer-defaults-and-warns-without-active-file
  (with-tmp
    (fn [dir]
      (let [{:keys [system files]} (make-system {:dir dir})
            [res log] (quietly #(refresh/install-timer! system nil))]
        (is (r/ok? res))
        (is (= d/default-interval (-> res :ok :interval)))
        (is (str/includes? (get @files "/etc/systemd/system/vpn-killswitch-refresh.timer")
                           "OnUnitActiveSec=15min\n"))
        (is (str/includes? log (str "No " d/active-file " yet")))))))

(deftest install-timer-rejects-a-bad-interval
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell writes]} (make-system {:dir dir :active "mullvad\n"})
            [res _] (quietly #(refresh/install-timer! system "15min\nExecStart=/bin/sh"))]
        (is (= :refresh/bad-interval (:error res)))
        (is (empty? @writes))
        (is (empty? (rec/cmds shell)))))))

(deftest install-timer-needs-a-self-path
  (with-tmp
    (fn [dir]
      (let [{:keys [system writes]} (make-system {:dir dir :active "mullvad\n"})
            [res _] (quietly #(refresh/install-timer! (dissoc system :self-path) nil))]
        (is (= :refresh/no-self-path (:error res)))
        (is (empty? @writes))))))

(deftest install-timer-reports-a-failed-enable
  (with-tmp
    (fn [dir]
      (let [{:keys [system]}
            (make-system {:dir     dir
                          :active  "mullvad\n"
                          :respond (fn [cmd _]
                                     (when (= ["systemctl" "enable" "--now"
                                               "vpn-killswitch-refresh.timer"] cmd)
                                       {:exit 1 :stderr "Failed to enable unit"}))})
            [res _] (quietly #(refresh/install-timer! system "1h"))]
        (is (= :refresh/command-failed (:error res)))
        (is (= "Failed to enable unit" (:stderr res)))))))

(deftest remove-timer-disables-removes-and-reloads
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell deletes]} (make-system {:dir dir})
            [res _] (quietly #(refresh/remove-timer! system))]
        (is (r/ok? res))
        (is (empty? (-> res :ok :failures)))
        (is (= [["systemctl" "disable" "--now" "vpn-killswitch-refresh.timer"]
                ["systemctl" "daemon-reload"]]
               (rec/cmds shell)))
        (is (= ["/etc/systemd/system/vpn-killswitch-refresh.timer"
                "/etc/systemd/system/vpn-killswitch-refresh.service"]
               @deletes))))))

(deftest remove-timer-is-best-effort
  (with-tmp
    (fn [dir]
      (let [{:keys [system shell deletes]}
            (make-system {:dir     dir
                          :respond (fn [cmd _]
                                     (when (= "systemctl" (first cmd))
                                       {:exit 1 :stderr "Unit not loaded"}))})
            [res _] (quietly #(refresh/remove-timer! system))]
        (is (r/ok? res) "never fails")
        (is (= [:disable :daemon-reload] (mapv :step (-> res :ok :failures))))
        (is (= 2 (count @deletes)) "unit files removed even though disable failed")
        (is (= ["systemctl" "daemon-reload"] (last (rec/cmds shell))))))))
