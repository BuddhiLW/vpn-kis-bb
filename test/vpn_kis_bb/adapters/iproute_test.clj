(ns vpn-kis-bb.adapters.iproute-test
  (:require [clojure.test :refer [deftest is testing]]
            [vpn-kis-bb.adapters.shell-recording :as rec]
            [vpn-kis-bb.adapters.iproute-shell :as ipr]
            [vpn-kis-bb.ports.iproute :as port]))

(defn- cmds [shell] (mapv :cmd (rec/calls shell)))

(deftest rule-show-parses-with-domain-priority
  (let [s (rec/make {:responses {"ip" {:exit 0
                                       :stdout "0:\tfrom all lookup local\n5199:\tnot from all fwmark 0x6d6f6c65 lookup 5099\n32766:\tfrom all lookup main\n"}}})
        i (ipr/make s)
        r (port/-rule-show i)]
    (is (:ok r))
    (is (= 3 (count (:ok r))))
    (is (= 5199 (:priority (second (:ok r)))))))

(deftest rule-add-with-fwmark
  (let [s (rec/make)
        i (ipr/make s)]
    (port/-rule-add! i {:fwmark "0x42" :lookup 142 :priority 5089})
    (is (= [["ip" "rule" "add" "fwmark" "0x42" "lookup" "142" "priority" "5089"]]
           (cmds s)))))

(deftest rule-add-with-to
  (let [s (rec/make)
        i (ipr/make s)]
    (port/-rule-add! i {:to "100.64.0.0/10" :lookup 52 :priority 5100})
    (is (= [["ip" "rule" "add" "to" "100.64.0.0/10" "lookup" "52" "priority" "5100"]]
           (cmds s)))))

(deftest rule-del-is-idempotent
  ;; Non-zero exit is NOT treated as error — `ip rule del` when no rule exists.
  (let [s (rec/make {:responses {"ip" {:exit 2 :stderr "RTNETLINK answers: No such file"}}})
        i (ipr/make s)
        r (port/-rule-del! i 5089)]
    (is (:ok r))
    (is (= [["ip" "rule" "del" "priority" "5089"]] (cmds s)))))

(deftest route-replace-default
  (let [s (rec/make)
        i (ipr/make s)]
    (port/-route-replace-default! i {:dev "tun-x" :table 142})
    (is (= [["ip" "route" "replace" "default" "dev" "tun-x" "table" "142"]]
           (cmds s)))))

(deftest table-flush-is-idempotent
  (let [s (rec/make {:responses {"ip" {:exit 2 :stderr "Cannot find device \"...\""}}})
        i (ipr/make s)
        r (port/-table-flush! i 142)]
    (is (:ok r))))
