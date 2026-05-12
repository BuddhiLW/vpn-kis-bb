(ns vpn-kis-bb.ports.dnsmasq
  "IDnsmasq — drop-in management + reload signal.

   The split-tunnel feature relies on dnsmasq's `ipset=` directive to
   tag DNS answers for chosen domains. We write a per-split drop-in
   under /etc/dnsmasq.d/ and signal dnsmasq to reload its config so the
   new ipset binding takes effect for fresh DNS queries.

   Implementations may target standalone dnsmasq (systemctl reload) or
   NetworkManager-managed dnsmasq (SIGHUP to nm-dnsmasq).")

(defprotocol IDnsmasq
  (-write-drop-in! [this drop-in-name body]
    "Write /etc/dnsmasq.d/<drop-in-name>. Returns Result.")
  (-remove-drop-in! [this drop-in-name]
    "Delete /etc/dnsmasq.d/<drop-in-name>. Returns Result.")
  (-reload! [this]
    "Signal dnsmasq to reload config. Returns Result.
     Best-effort: returns ok even if dnsmasq isn't running locally —
     a missing dnsmasq is a configuration warning, not a failure of
     the split-tunnel install itself."))
