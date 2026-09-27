(ns vpn-kis-bb.cli.args-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.cli.args :as args]
            [vpn-kis-bb.cli.usage :as usage]))

(deftest no-command-defaults-to-setup
  (is (= {:cmd "setup" :args [] :opts {}} (args/parse []))))

(deftest command-and-arguments
  (is (= {:cmd "providers" :args ["mullvad" "tailscale"] :opts {}}
         (args/parse ["providers" "mullvad" "tailscale"]))))

(deftest lan-before-the-command
  (is (= {:cmd "providers" :args ["mullvad"] :opts {:lan ["192.168.100.0/24"]}}
         (args/parse ["--lan" "192.168.100.0/24" "providers" "mullvad"]))))

(deftest lan-anywhere-and-quoted-lists-add-up
  (testing "after the command, = form, alias, quoted multi-value"
    (is (= ["10.0.5.0/24" "192.168.100.0/24" "10.9.0.0/16"]
           (-> (args/parse ["providers" "--lan=10.0.5.0/24 192.168.100.0/24"
                            "mullvad" "--lan-allow" "10.9.0.0/16"])
               :opts :lan)))
    (is (= ["mullvad"]
           (:args (args/parse ["providers" "--lan=10.0.5.0/24" "mullvad"]))))))

(deftest missing-flag-value-is-an-error
  (is (str/includes? (:error (args/parse ["providers" "--lan"])) "requires a CIDR"))
  (is (str/includes? (:error (args/parse ["--physical-iface"])) "requires a value")))

(deftest switches-and-physical-iface
  (is (= {:cmd "setup" :args [] :opts {:dry-run? true :physical-iface "eth0"}}
         (args/parse ["--dry-run" "--physical-iface" "eth0"])))
  (is (= "wlan0" (-> (args/parse ["auto" "--physical-iface=wlan0"]) :opts :physical-iface))))

(deftest double-dash-stops-flag-parsing
  (testing "exclude run keeps -- and every later word, flags included"
    (is (= {:cmd "exclude"
            :args ["run" "--as" "klein" "--" "curl" "--lan" "x" "--dry-run"]
            :opts {:lan ["10.0.0.0/8"]}}
           (args/parse ["--lan" "10.0.0.0/8" "exclude" "run" "--as" "klein"
                        "--" "curl" "--lan" "x" "--dry-run"])))))

(deftest unknown-dash-words-are-arguments
  (is (= {:cmd "--help" :args [] :opts {}} (args/parse ["--help"])))
  (is (= ["-h"] (:args (args/parse ["split" "-h"])))))

(deftest usage-names-the-program-and-every-command
  (let [text (usage/text "vpn-kis")]
    (doseq [cmd ["auto" "providers" "fetch" "refresh" "tailscale-routes" "tailscale-web"
                 "detect" "test" "split add" "exclude run" "unlock" "panic" "help"]]
      (is (str/includes? text (str "vpn-kis " cmd)) cmd))
    (is (not (str/includes? text "$0")))))
