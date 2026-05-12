(ns vpn-kis-bb.ports.ipset
  "IIpset — kernel ipset management seam.

   The bash version mixes ipset CLI calls with rule generation. Pulling
   them apart lets us swap a stub impl for tests + a real impl for prod.")

(defprotocol IIpset
  (-create! [this set-name opts]
    "opts: {:family :inet :hashsize 2048 :maxelem 65536 :timeout <secs|nil>}
     Idempotent (-exist on the underlying ipset call). Returns Result.")
  (-add! [this set-name ip]
    "Add one IP. Returns Result.")
  (-add-bulk! [this set-name ips]
    "Bulk-load via `ipset restore`. ips = seq of strings. Returns Result.")
  (-list [this set-name]
    "Returns Result<#{ip ...}>.")
  (-destroy! [this set-name]
    "Returns Result.")
  (-save [this set-name out-path]
    "Persist ipset to a file (atom-of-truth at /etc/ipset.conf). Returns Result.")
  (-restore! [this in-path]
    "Re-hydrate a saved file. Returns Result."))
