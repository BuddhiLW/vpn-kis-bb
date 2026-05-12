(ns vpn-kis-bb.cli.main
  "CLI entry. Dispatch matches the bash 1:1 for muscle-memory."
  (:require [babashka.cli :as cli]
            [clojure.string :as str]
            [hive-dsl.result :as r]
            [vpn-kis-bb.app.detect :as detect]
            [vpn-kis-bb.app.fetch :as fetch]
            [vpn-kis-bb.app.panic :as panic]
            [vpn-kis-bb.app.providers :as providers]
            [vpn-kis-bb.app.setup :as setup]
            [vpn-kis-bb.app.split :as split-app]
            [vpn-kis-bb.app.unlock :as unlock]
            [vpn-kis-bb.app.verify :as verify]
            [vpn-kis-bb.cli.system :as sys-root]
            [vpn-kis-bb.domain.config :as config]
            [vpn-kis-bb.domain.split :as split-d]))

(def known-providers [:mullvad :airvpn :tailscale])

(def global-spec
  {:dry-run        {:coerce :boolean :desc "Preview the plan, no privileged ops"}
   :physical-iface {:coerce :string  :desc "Override auto-detected physical iface"}
   :lan            {:coerce []       :desc "LAN CIDR(s) to bypass killswitch"}
   :help           {:coerce :boolean}})

(defn- build-system [{:keys [dry-run]}]
  (sys-root/make-system {:profile (if dry-run :dry-run :prod)}))

(defn- print-result [tag r]
  (println (str "[" tag "] " (if (r/ok? r) "ok" "error")))
  (println (pr-str r))
  (System/exit (if (r/ok? r) 0 1)))

;; ---------------------------------------------------------------- subcommands

(defn- cmd-help [_ _]
  (println
   "vpn-kis-bb — Babashka kill-switch (sibling of BuddhiLW/vpn-kis)

Usage:
  vpn-kis-bb setup [--strict] [--providers p1,p2] [--lan CIDR]
  vpn-kis-bb fetch [provider ...]
  vpn-kis-bb providers <name> [<name> ...]
  vpn-kis-bb auto
  vpn-kis-bb detect
  vpn-kis-bb split add|rm|list|status|connect <name>
  vpn-kis-bb test
  vpn-kis-bb unlock
  vpn-kis-bb panic
  vpn-kis-bb help

Global flags (before any subcommand):
  --dry-run               Print the plan, no privileged ops
  --physical-iface IF     Override auto-detection
  --lan CIDR              LAN CIDR(s) to bypass killswitch

Providers: mullvad, airvpn, tailscale, plus any /etc/vpn-killswitch/providers/*.ips"))

(defn- cmd-fetch [opts args]
  (let [sys     (build-system opts)
        targets (or (seq (map keyword args)) known-providers)
        result  (fetch/fetch-many! sys targets)]
    (print-result "fetch" result)))

(defn- cmd-providers [opts args]
  (when (empty? args)
    (println "providers: specify at least one provider name")
    (System/exit 1))
  (let [sys (build-system opts)
        union (providers/load-union (map keyword args))]
    (if (r/err? union)
      (print-result "providers" union)
      (do (println (str "Locking to " (count (-> union :ok :union))
                        " endpoints from: " (str/join " " args)))
          (let [r (setup/setup! sys {:mode :strict
                                     :providers (map keyword args)
                                     :lan-allow (or (:lan opts) [])
                                     :physical-iface (:physical-iface opts)
                                     :dry-run? (:dry-run opts)})]
            (print-result "providers" r))))))

(defn- cmd-setup [opts _args]
  (let [sys (build-system opts)
        r (setup/setup! sys {:mode :permissive
                             :lan-allow (or (:lan opts) [])
                             :physical-iface (:physical-iface opts)
                             :dry-run? (:dry-run opts)})]
    (print-result "setup" r)))

(defn- cmd-auto [opts _]
  (let [sys (build-system opts)
        det (detect/detect-endpoints sys)]
    (if (or (r/err? det) (empty? (:ok det)))
      (do (println "auto: no live VPN endpoints detected — connect VPN first")
          (System/exit 1))
      (let [ips (:ok det)
            _ (println (str "Locking to live endpoints: "
                            (str/join " " (sort ips))))
            r (setup/setup! sys {:mode :strict
                                 :physical-iface (:physical-iface opts)
                                 :dry-run? (:dry-run opts)})]
        (print-result "auto" r)))))

(defn- cmd-detect [opts _]
  (let [sys (build-system opts)
        r (detect/detect-endpoints sys)]
    (if (r/err? r)
      (print-result "detect" r)
      (do (println (str "Detected VPN endpoints: "
                        (str/join " " (sort (:ok r)))))
          (System/exit 0)))))

(defn- cmd-unlock [opts _]
  (let [sys (build-system opts)
        r (unlock/unlock! sys {:dry-run? (:dry-run opts)})]
    (print-result "unlock" r)))

(defn- cmd-panic [opts _]
  (let [sys (build-system opts)
        r (panic/panic! sys {:dry-run? (:dry-run opts)})]
    (print-result "panic" r)))

(defn- cmd-test [opts _]
  (let [sys (build-system opts)
        r (verify/verify sys)
        report (:ok r)]
    (println (str "Checks: " (count (:checks report))
                  "  Failed: " (count (:failed report))))
    (doseq [c (:checks report)]
      (println (str "  " (if (:pass? c) "[PASS]" "[fail]") " " (:name c))))
    (System/exit (if (:ok? report) 0 1))))

(defn- cmd-split [opts args]
  (let [sub  (first args)
        name (second args)
        sys  (build-system opts)]
    (case sub
      "add"
      (let [conf-r (config/read-split-conf split-d/conf-dir name)]
        (if-not (:ok? conf-r)
          (do (println (:error conf-r)) (System/exit 1))
          (print-result "split add" (split-app/install! sys (:value conf-r)))))

      ("rm" "remove" "delete")
      (print-result "split rm" (split-app/remove! sys name))

      ("list" "ls" nil)
      (do (doseq [n (split-app/list-installed)]
            (println n))
          (System/exit 0))

      "status"
      (let [r (split-app/status sys name)]
        (println (pr-str r))
        (System/exit 0))

      ("connect" "up")
      (let [conf-r (config/read-split-conf split-d/conf-dir name)]
        (if-not (:ok? conf-r)
          (do (println (:error conf-r)) (System/exit 1))
          (print-result "split connect" (split-app/connect! sys (:value conf-r)))))

      (do (println (str "split: unknown subcommand: " sub))
          (System/exit 1)))))

;; ---------------------------------------------------------------- dispatch

(def commands
  {"help"      cmd-help
   "-h"        cmd-help
   "--help"    cmd-help
   "setup"     cmd-setup
   "fetch"     cmd-fetch
   "providers" cmd-providers
   "auto"      cmd-auto
   "detect"    cmd-detect
   "split"     cmd-split
   "test"      cmd-test
   "unlock"    cmd-unlock
   "panic"     cmd-panic
   "rescue"    cmd-panic
   "emergency" cmd-panic})

(defn parse-args
  "Pure: split argv into {:global-opts ... :cmd ... :cmd-args [...]}."
  [argv]
  (let [{:keys [opts args]} (cli/parse-args argv {:spec global-spec})
        [cmd & rest]        args]
    {:global-opts opts
     :cmd         (or cmd "help")
     :cmd-args    (vec rest)}))

(defn -main [& argv]
  (let [{:keys [global-opts cmd cmd-args]} (parse-args argv)]
    (if-let [f (get commands cmd)]
      (f global-opts cmd-args)
      (do (println (str "unknown command: " cmd))
          (cmd-help nil nil)
          (System/exit 1)))))
