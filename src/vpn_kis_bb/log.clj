(ns vpn-kis-bb.log
  "Human-facing progress output in the bash original's style:
   [+] info / [!] warn / [-] error on stderr, plain lines on stdout.

   Pure domain code never logs; app and cli namespaces call this while
   effects run so long operations (setup, panic) show progress.")

(def ^:dynamic *quiet*
  "Suppress info lines (warnings and errors still print)."
  false)

(defn- emit [tag parts]
  (binding [*out* *err*]
    (println (str tag " " (apply str parts)))))

(defn info  [& parts] (when-not *quiet* (emit "[+]" parts)))
(defn warn  [& parts] (emit "[!]" parts))
(defn error [& parts] (emit "[-]" parts))

(defn say
  "Plain line on stdout (reports, listings)."
  [& parts]
  (println (apply str parts)))
