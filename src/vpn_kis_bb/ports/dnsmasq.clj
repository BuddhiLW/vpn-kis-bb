(ns vpn-kis-bb.ports.dnsmasq
  "IDnsmasq: split-tunnel drop-in management, reload signal and preflight.

   A split relies on dnsmasq's `ipset=` directive to tag DNS answers for
   chosen domains. A per-split drop-in goes under /etc/dnsmasq.d/ and
   dnsmasq is told to reload so fresh DNS queries fill the split's ipset.

   Implementations may target standalone dnsmasq (systemctl reload) or
   NetworkManager-managed dnsmasq (SIGHUP).")

(defprotocol IDnsmasq
  (-write-drop-in! [this drop-in-name body]
    "Write /etc/dnsmasq.d/<drop-in-name>. Returns Result.")
  (-remove-drop-in! [this drop-in-name]
    "Delete /etc/dnsmasq.d/<drop-in-name>. Returns Result.")
  (-reload! [this]
    "Make a running dnsmasq re-read its config (bash split_install_dnsmasq):
     `systemctl reload dnsmasq`, falling back to restart, when the dnsmasq
     unit is active; SIGHUP when a dnsmasq process runs outside systemd
     (NetworkManager's); nothing otherwise.
     Result<{:reloaded? bool :via kw}> (:reloaded? false with a :hint when
     no dnsmasq runs); err when both reload and restart fail.")
  (-preflight [this]
    "Can a split's ipset= directive work here (bash split_require_dnsmasq)?
     Result<{:drop-in-dir? bool :fronted? bool}>. :drop-in-dir? is false
     without /etc/dnsmasq.d; :fronted? is false when systemd-resolved is
     active and neither NetworkManager's dnsmasq plugin nor the dnsmasq
     unit is, and is not checked (nil) when the directory is missing."))
