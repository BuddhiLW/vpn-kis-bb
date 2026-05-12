(ns vpn-kis-bb.adapters.ipset-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.ipset-shell :as ipset]
            [vpn-kis-bb.ports.ipset :as port]))

(defn- cmds [shell] (mapv :cmd (rec/calls shell)))

(deftest create-emits-ipset-create
  (let [s (rec/make)
        i (ipset/make s)]
    (port/-create! i "vpn_endpoints" {:timeout 3600})
    (let [c (first (cmds s))]
      (is (= "ipset" (first c)))
      (is (= "create" (second c)))
      (is (= "vpn_endpoints" (nth c 2)))
      (is (some #{"timeout"} c))
      (is (some #{"3600"} c))
      (is (some #{"-exist"} c)))))

(deftest create-defaults
  (let [s (rec/make)
        i (ipset/make s)]
    (port/-create! i "foo" {})
    (let [c (first (cmds s))]
      (is (some #{"hash:ip"} c))
      (is (some #{"family"} c))
      (is (some #{"inet"} c))
      (is (some #{"hashsize"} c)))))

(deftest add-emits-ipset-add
  (let [s (rec/make)
        i (ipset/make s)]
    (port/-add! i "vpn_endpoints" "1.2.3.4")
    (is (= [["ipset" "add" "vpn_endpoints" "1.2.3.4" "-exist"]]
           (cmds s)))))

(deftest bulk-load-uses-restore
  (let [s (rec/make)
        i (ipset/make s)]
    (port/-add-bulk! i "vpn_endpoints" ["1.1.1.1" "8.8.8.8"])
    (let [c (first (cmds s))]
      ;; Pipes through sh -c "... | ipset restore ..."
      (is (= ["sh" "-c"] (subvec c 0 2)))
      (is (re-find #"ipset restore" (nth c 2)))
      (is (re-find #"add vpn_endpoints 1\.1\.1\.1" (nth c 2)))
      (is (re-find #"add vpn_endpoints 8\.8\.8\.8" (nth c 2))))))

(deftest destroy-is-best-effort
  (let [s (rec/make {:responses {"ipset" {:exit 1 :stderr "set not found"}}})
        i (ipset/make s)
        r (port/-destroy! i "missing")]
    (is (:ok r))))

(deftest list-parses-members
  (let [s (rec/make {:responses {"ipset" {:exit 0
                                          :stdout "Name: foo\nType: hash:ip\nMembers:\n1.1.1.1\n8.8.8.8\n"}}})
        i (ipset/make s)
        r (port/-list i "foo")]
    (is (= #{"1.1.1.1" "8.8.8.8"} (:ok r)))))
