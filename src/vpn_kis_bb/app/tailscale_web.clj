(ns vpn-kis-bb.app.tailscale-web
  "The tailscale-web (OpenClaw client) helper (bash: tailscale_web_helper,
   remove_tailscale_web). The helper stays in python:
   `python3 <helper> apply|remove` runs through :shell, its stdout is
   echoed with log/say.

   Helper path: env TAILSCALE_WEB_HELPER (from :env), else
   <dir of :self-path>/../lib/tailscale-web/configure.py
   (vpn-kis-bb.domain.tailscale/web-helper-path).

   System keys: :shell :read-fn (helper presence) :delete-fn :env
   :self-path (or :settings :self-path)."
  (:refer-clojure :exclude [run!])
  (:require [clojure.string :as str]
            [hive-dsl.result :as r]
            [hive-system.protocols :as proto]
            [vpn-kis-bb.domain.tailscale :as d]
            [vpn-kis-bb.log :as log]
            [vpn-kis-bb.domain.re :as rx]))

(def subcommands
  "The subcommands run! accepts."
  #{"apply" "remove"})

(def helper-timeout-ms
  "The helper queries tailscale and probes HTTPS (curl --max-time 20)."
  120000)

;; ---------------------------------------------------------------- helpers

(defn- sh!
  "Run cmd. Returns {:cmd :exit :stdout :stderr}; a shell-level err (spawn
   failure, timeout) or a throw reads as exit -1."
  [system cmd opts]
  (let [res (try (proto/shell-exec! (:shell system) cmd opts)
                 (catch Throwable t (r/err :shell/threw {:message (str t)})))]
    (if (r/ok? res)
      (let [{:keys [exit stdout stderr]} (:ok res)]
        {:cmd cmd :exit exit :stdout (or stdout "") :stderr (or stderr "")})
      {:cmd cmd :exit -1 :stdout "" :stderr (str (or (:message res) (:error res)))})))

(defn- lines [s]
  (remove str/blank? (rx/split-lines* (or s ""))))

(defn helper-path
  "Path of the helper for this system, or nil when it cannot be derived."
  [system]
  (d/web-helper-path (:env system)
                     (or (:self-path system) (get-in system [:settings :self-path]))))

(defn- locate
  "Result<path>: err :tailscale-web/no-helper when the path is unknown or
   :read-fn finds nothing there."
  [system]
  (let [path (helper-path system)]
    (cond
      (nil? path)
      (r/err :tailscale-web/no-helper
             {:hint (str "tailscale-web: helper location unknown; set "
                         d/web-helper-env " to lib/tailscale-web/configure.py")})

      (nil? ((:read-fn system) path))
      (r/err :tailscale-web/no-helper
             {:hint   (str "tailscale-web: helper not found at " path
                           " (set " d/web-helper-env ")")
              :helper path})

      :else (r/ok path))))

(defn- invoke!
  "Run `python3 <path> <sub>`, echoing its stdout. Result<{:sub :helper}>
   or err :tailscale-web/helper-failed whose :hint is the helper's stderr."
  [system path sub]
  (let [x (sh! system (d/web-helper-cmd path sub) {:timeout-ms helper-timeout-ms})]
    (doseq [line (lines (:stdout x))] (log/say line))
    (if (= 0 (:exit x))
      (do (doseq [line (lines (:stderr x))] (log/warn line))
          (r/ok {:sub sub :helper path}))
      (r/err :tailscale-web/helper-failed
             {:hint   (let [e (str/trim (:stderr x))]
                        (if (str/blank? e)
                          (str "tailscale-web " sub ": helper exited " (:exit x))
                          e))
              :sub    sub
              :helper path
              :exit   (:exit x)}))))

(defn- remove-web!
  "bash remove_tailscale_web: delete the marker, then `helper remove`; a
   missing or failing helper only warns."
  [system]
  ((:delete-fn system) d/web-enabled-file)
  (let [loc (locate system)
        res (if (r/err? loc) loc (invoke! system (:ok loc) "remove"))]
    (when (r/err? res)
      (log/warn (:hint res))
      (log/warn "Could not fully remove the OpenClaw client exception."))
    (r/ok {:sub        "remove"
           :helper     (when (r/ok? loc) (:ok loc))
           :helper-ok? (r/ok? res)})))

;; ---------------------------------------------------------------- public

(defn run!
  "Run the tailscale-web helper; sub is \"apply\" or \"remove\".

   apply:  Result<{:sub \"apply\" :helper path}>; err :tailscale-web/no-helper
           (helper missing) or :tailscale-web/helper-failed (non-zero exit,
           :hint = its stderr).
   remove: deletes the tailscale-web.enabled marker, then runs the helper;
           a missing or failing helper only warns, so this is always
           Result<{:sub \"remove\" :helper path-or-nil :helper-ok? bool}>.
   Any other sub: err :tailscale-web/unknown-sub."
  [system sub]
  (cond
    (= "remove" sub) (remove-web! system)

    (= "apply" sub)
    (let [loc (locate system)]
      (if (r/err? loc) loc (invoke! system (:ok loc) "apply")))

    :else
    (r/err :tailscale-web/unknown-sub
           {:sub  sub
            :hint (str "tailscale-web: unknown subcommand '" sub "'. Try: "
                       (str/join "|" (sort subcommands)))})))
