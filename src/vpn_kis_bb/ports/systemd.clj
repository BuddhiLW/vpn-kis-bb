(ns vpn-kis-bb.ports.systemd
  "ISystemdUnit — write + enable + disable boot-persistence units.

   The bash version writes Tailscale + split-tunnel oneshots into
   /etc/systemd/system/. Same shape here, but the unit body comes from a
   pure generator (`domain.rules/systemd-unit-text`).")

(defprotocol ISystemdUnit
  (-write! [this unit-name body]
    "Write `/etc/systemd/system/<unit-name>` with `body`. Returns Result.")
  (-remove! [this unit-name]
    "Delete the unit file. Returns Result.")
  (-enable! [this unit-name]
    "systemctl enable. Returns Result.")
  (-disable! [this unit-name]
    "systemctl disable --now. Returns Result.")
  (-daemon-reload! [this]
    "systemctl daemon-reload. Returns Result.")
  (-active? [this unit-name]
    "Returns Result<bool>.")
  (-enabled? [this unit-name]
    "Returns Result<bool>."))
