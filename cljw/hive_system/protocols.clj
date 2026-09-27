(ns hive-system.protocols
  "cljw stand-in for hive-system.protocols: only the IShell protocol,
   which is the one vpn-kis-bb depends on.")

(defprotocol IShell
  "Shell execution with capture."
  (shell-exec! [this cmd opts]
    "Execute shell command. Returns Result with {:exit :stdout :stderr :duration-ms}.")
  (shell-env [this]
    "Get current environment map.")
  (shell-which [this program]
    "Resolve program path. Returns Result with {:path} or err."))
