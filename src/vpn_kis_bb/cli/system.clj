(ns vpn-kis-bb.cli.system
  "Composition root. Builds the `system` map that workflow functions
   (app.*) consume. Two profiles:

     :prod    — real shell + spit/delete writes; needs root for most ops.
     :dry-run — RecordingShell + recording write-fn; nothing touches the
                live system. Use this to preview plans.

   Tests use a tailored recording-system constructed by the test file
   itself (see test/vpn_kis_bb/app/split_test.clj) rather than going
   through make-system."
  (:require [babashka.fs :as fs]
            [hive-dsl.result :as r]
            [hive-system.shell.core :as shell-core]
            [vpn-kis-bb.adapters.dns-inetaddress :as dns]
            [vpn-kis-bb.adapters.dnsmasq-shell :as dnsmasq]
            [vpn-kis-bb.adapters.fetcher.airvpn :as airvpn]
            [vpn-kis-bb.adapters.fetcher.custom :as custom]
            [vpn-kis-bb.adapters.fetcher.mullvad :as mullvad]
            [vpn-kis-bb.adapters.fetcher.ovpn-file :as ovpn-file]
            [vpn-kis-bb.adapters.fetcher.tailscale :as tailscale]
            [vpn-kis-bb.adapters.firewall-ufw :as fw]
            [vpn-kis-bb.adapters.http-jvm :as http]
            [vpn-kis-bb.adapters.iproute-shell :as ipr]
            [vpn-kis-bb.adapters.ipset-shell :as ipset]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.systemd-shell :as sd]))

(defn- prod-write [path body]
  (try
    (fs/create-dirs (fs/parent path))
    (spit path body)
    (r/ok {:path path :bytes (count body)})
    (catch Throwable t
      (r/err :fs/write-failed {:path path :cause (str t)}))))

(defn- prod-delete [path]
  (try
    (fs/delete-if-exists path)
    (r/ok {:path path})
    (catch Throwable t
      (r/err :fs/delete-failed {:path path :cause (str t)}))))

(defn- dry-run-write [path body]
  (println (str "[dry-run] write " path " (" (count body) " bytes)"))
  (r/ok {:path path :bytes (count body) :dry-run? true}))

(defn- dry-run-delete [path]
  (println (str "[dry-run] delete " path))
  (r/ok {:path path :dry-run? true}))

(defn- build-fetchers
  "Construct the fetcher registry: provider-name → IProviderFetcher."
  [http-fetcher resolver]
  {:mullvad   (mullvad/make    http-fetcher resolver)
   :airvpn    (airvpn/make     resolver)
   :tailscale (tailscale/make  http-fetcher resolver)})

(defn make-system
  "Build the wired system map.

   opts: {:profile :prod|:dry-run, :recorded-shell <RecordingShell>?}"
  [{:keys [profile recorded-shell]
    :or {profile :prod}}]
  (let [shell    (case profile
                   :prod    (shell-core/make-shell)
                   :dry-run (or recorded-shell (rec/make)))
        write    (case profile :prod prod-write    :dry-run dry-run-write)
        delete   (case profile :prod prod-delete   :dry-run dry-run-delete)
        http-f   (http/make-jvm-fetcher)
        resolver (dns/make-resolver)
        fw-impl  (fw/make shell {:write-fn write})
        ipset-i  (ipset/make shell)
        iproute  (ipr/make   shell)
        systemd  (sd/make    shell {:write-fn write :delete-fn delete})
        dns-i    (dnsmasq/make shell {:write-fn write :delete-fn delete})]
    {:profile  profile
     :shell    shell
     :http     http-f
     :dns      resolver
     :firewall fw-impl
     :ipset    ipset-i
     :iproute  iproute
     :systemd  systemd
     :dnsmasq  dns-i
     :write-fn write
     :delete-fn delete
     :fetchers (build-fetchers http-f resolver)}))

(defn dry-run-system
  "Convenience: build a :dry-run system. Returns {:system .. :shell ..}
   so callers can inspect recorded commands."
  []
  (let [shell (rec/make)
        sys   (make-system {:profile :dry-run :recorded-shell shell})]
    {:system sys :shell shell}))
