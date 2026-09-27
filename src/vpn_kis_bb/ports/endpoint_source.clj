(ns vpn-kis-bb.ports.endpoint-source
  "IEndpointSource — one strategy for discovering a provider's endpoint IPs.

   A provider fetcher (IProviderFetcher) can be composed from several sources
   tried in order: e.g. a live API source with a local-config-scan fallback.
   Pulling the strategy behind its own small protocol keeps each source a
   single responsibility (SRP) and lets new sources be added without touching
   the fetcher or the existing sources (OCP). Sources depend only on the
   injected ports they need (IWebFetcher / IDnsResolver), inverting the
   dependency on any concrete adapter (DIP).")

(defprotocol IEndpointSource
  "A substitutable strategy that yields a set of endpoint IPv4 addresses."
  (-source-id [this]
    "Human-readable label for diagnostics and the fetcher's :source field
     (e.g. an API URL or \"scanned ovpn/wg configs\").")
  (-endpoints [this opts]
    "Returns Result<#{ipv4-str ...}>.
     An ok-but-EMPTY set is a legitimate 'this source found nothing' answer —
     a composing fetcher may then try the next source. err signals the source
     itself failed (transport, parse, missing inputs).

     opts may carry: :timeout-ms, …"))
