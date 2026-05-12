(ns vpn-kis-bb.ports.http
  "IWebFetcher — HTTP fetcher seam. Mirrors basic-tools-mcp/web/collect's
   protocol shape exactly so we stay drop-in compatible if/when we depend
   on it directly.

   We define the protocol here (rather than depending on basic-tools-mcp)
   to keep the dep graph lean — only the concrete adapter needs the JDK
   HTTP client.")

(defprotocol IWebFetcher
  "URL → fetched content. All ops return Result."
  (-fetcher-id [this])
  (-fetch [this url opts]
    "Opts: :timeout-ms (default 30000), :headers, :as-text? (default false).
     Returns Result<{:status N :body s :url u :content-type s
                     :duration-ms N :bytes N}>."))
