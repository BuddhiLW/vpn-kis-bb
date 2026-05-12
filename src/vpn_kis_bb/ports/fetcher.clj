(ns vpn-kis-bb.ports.fetcher
  "IProviderFetcher — provider-name → set of egress IPs.

   This is the upper DIP boundary for the provider-fetch concern.
   Implementations may layer on top of IWebFetcher (HTTP-backed providers
   like Mullvad/Tailscale) or other sources (filesystem .ovpn parsers,
   custom .ips files). Every method returns a Result.

   Refines: nothing — top-level seam.
   Used by: app.fetch, app.providers, app.detect.")

(defprotocol IProviderFetcher
  "Fetch the IP allowlist for a single provider."
  (-provider-id [this]
    "Returns the keyword identifier of this fetcher (e.g. :mullvad).")
  (-supports? [this provider-name]
    "True when this fetcher can answer for the given provider name (string or keyword).
     Lets a registry dispatch a name to the right fetcher without hardcoding the map.")
  (-fetch-ips [this opts]
    "Returns Result<{:provider <kw>
                     :ips     #{ipv4 ...}
                     :source  <descr>
                     :fetched-at <inst>}>.

     opts may carry: :timeout-ms, :cache-merge?, :extra-hosts, …"))
