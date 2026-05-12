(ns vpn-kis-bb.ports.dns
  "IDnsResolver — hostname → IPv4 set.

   Pulled out as a port so AirVPN / OVPN-file fetchers can be tested with
   a deterministic resolver (e.g. an in-memory map) instead of relying on
   the live DNS infrastructure during tests.")

(defprotocol IDnsResolver
  (-resolve-a [this hostname]
    "Returns Result<#{ipv4-str ...}>.
     Empty set is a legitimate answer (NXDOMAIN / no A records);
     err only on transport-level failures."))
