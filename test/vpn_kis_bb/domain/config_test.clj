(ns vpn-kis-bb.domain.config-test
  (:require [babashka.fs :as fs]
            [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.domain.config :as c]))

(def legacy-sample
  "# comment
DOMAINS=\"*.example.com other.example.org\"
DEV=tun-example
TABLE=142
MARK=0x42
PRIORITY=auto
OVPN_CONFIG=/path/to.ovpn
")

(deftest parse-key-value-test
  (let [m (c/parse-key-value legacy-sample)]
    (is (= "*.example.com other.example.org" (:domains m)))
    (is (= "tun-example" (:dev m)))
    (is (= "142" (:table m)))
    (is (= "0x42" (:mark m)))
    (is (= "auto" (:priority m)))
    (is (= "/path/to.ovpn" (:ovpn-config m)))))

(deftest parse-key-value-reads-like-split-load-conf
  (testing "leading blanks, indented comments, blank lines"
    (is (= {:dev "tun-a"} (c/parse-key-value "   # c\n\n  DEV=tun-a\n"))))
  (testing "one trailing then leading double quote, then single quote"
    (is (= "a b" (:domains (c/parse-key-value "DOMAINS=\"a b\""))))
    (is (= "a b" (:domains (c/parse-key-value "DOMAINS='a b'"))))
    (is (= "x" (:dev (c/parse-key-value "DEV=\"'x'\"")))))
  (testing "the value is trimmed and is everything after the first ="
    (is (= "/a=b.ovpn" (:ovpn-config (c/parse-key-value "OVPN_CONFIG=  /a=b.ovpn  ")))))
  (testing "exact keys only: a blank before =, lowercase or unknown keys are ignored"
    (is (= {} (c/parse-key-value "DEV =tun-a\ndev=tun-b\nFOO=bar\n"))))
  (testing "a later line wins; a last line without newline counts; CRLF"
    (is (= "tun-b" (:dev (c/parse-key-value "DEV=tun-a\nDEV=tun-b"))))
    (is (= "tun-c" (:dev (c/parse-key-value "DEV=tun-c\r\n"))))))

(deftest legacy->split-edn-test
  (let [out (c/legacy->split-edn (assoc (c/parse-key-value legacy-sample) :name "example"))]
    (is (= "example" (:name out)))
    (is (= ["*.example.com" "other.example.org"] (:domains out)))
    (is (= "tun-example" (:dev out)))
    (is (= 142 (:table out)))
    (is (= "0x42" (:mark out)))
    (is (= :auto (:priority out)))
    (is (= "/path/to.ovpn" (:ovpn-config out))))
  (testing "blank values are dropped so defaults apply; junk is kept for validate"
    (is (= {:name "x" :table "main" :priority "abc"}
           (c/legacy->split-edn {:name "x" :dev "" :table "main" :priority "abc" :mark "  "})))
    (is (= 5089 (:priority (c/legacy->split-edn {:name "x" :priority "5089"}))))))

(defn- files-fn [m] (fn [path] (get m path)))

(deftest read-split-conf-through-read-fn
  (testing ".conf (KEY=VALUE)"
    (let [r (c/read-split-conf "/etc/vpn-killswitch/split" "example"
                               (files-fn {"/etc/vpn-killswitch/split/example.conf" legacy-sample}))]
      (is (:ok? r))
      (is (= "/etc/vpn-killswitch/split/example.conf" (:path r)))
      (is (= "tun-example" (-> r :value :dev)))
      (is (= "example" (-> r :value :name)))))
  (testing ".edn wins over .conf; :name comes from the file name"
    (let [r (c/read-split-conf "/d" "x" (files-fn {"/d/x.edn"  "{:name \"other\" :dev \"tun-e\" :domains [\"a.com\"]}"
                                                   "/d/x.conf" "DEV=tun-c\n"}))]
      (is (= "tun-e" (-> r :value :dev)))
      (is (= "x" (-> r :value :name)))
      (is (= "/d/x.edn" (:path r)))))
  (testing "bash messages"
    (is (= {:ok? false :error "split: config not found: /d/nope.conf"}
           (c/read-split-conf "/d" "nope" (files-fn {}))))
    (is (= "split: name required" (:error (c/read-split-conf "/d" nil (files-fn {})))))
    (is (= "split: name required" (:error (c/read-split-conf "/d" "" (files-fn {})))))
    (is (= "split: name must match [a-zA-Z0-9_-]+"
           (:error (c/read-split-conf "/d" "../etc/passwd" (files-fn {}))))))
  (testing "bad EDN"
    (is (false? (:ok? (c/read-split-conf "/d" "x" (files-fn {"/d/x.edn" "{:dev"})))))
    (is (= "split: /d/x.edn must hold an EDN map"
           (:error (c/read-split-conf "/d" "x" (files-fn {"/d/x.edn" "[1 2]"})))))))

(deftest read-split-conf-from-disk
  (let [dir (str (fs/create-temp-dir {:prefix "vpn-kis-bb-conf-"}))]
    (try
      (spit (str dir "/t.conf") "DOMAINS=a.example\nDEV=tun-t\n")
      (let [r (c/read-split-conf dir "t")]
        (is (:ok? r))
        (is (= ["a.example"] (-> r :value :domains))))
      (finally
        (fs/delete-tree dir)))))
