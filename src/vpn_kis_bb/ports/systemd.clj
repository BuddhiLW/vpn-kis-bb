(ns vpn-kis-bb.ports.systemd
  "ISystemdUnit: write, enable, start, disable boot-persistence units.

   The bash version writes the tailscale-routes, refresh, exclude and
   split-tunnel units into /etc/systemd/system/. Same shape here; unit
   bodies come from pure generators in the domain namespaces.")

(defprotocol ISystemdUnit
  (-write! [this unit-name body]
    "Write `/etc/systemd/system/<unit-name>` with `body`. Returns Result.")
  (-remove! [this unit-name]
    "Delete the unit file. Returns Result.")
  (-enable! [this unit-name]
    "systemctl enable. Returns Result.")
  (-start! [this unit-name]
    "systemctl start. Returns Result; err on a non-zero exit.")
  (-disable! [this unit-name]
    "systemctl disable --now. Returns Result.")
  (-daemon-reload! [this]
    "systemctl daemon-reload. Returns Result.")
  (-active? [this unit-name]
    "Returns Result<bool>.")
  (-enabled? [this unit-name]
    "Returns Result<bool>."))
