# LEDERG PROXY

Cloudflare-hosted collector that builds HAPP-compatible proxy subscriptions from public GitHub feeds.

## Live Cloudflare endpoints

- [`/json`](https://lederg-proxy-scanner.lederg.workers.dev/json) — live HAPP/Xray JSON profile array.
- [`/happ`](https://lederg-proxy-scanner.lederg.workers.dev/happ) — live text subscription with proxy URIs.
- [`/manifest`](https://lederg-proxy-scanner.lederg.workers.dev/manifest) — latest scan status, counts, source list and probe metadata.
- [`/health`](https://lederg-proxy-scanner.lederg.workers.dev/health) — Worker health and most recent run.

Add only one of the live subscription links to HAPP. The `/json` endpoint returns an Xray JSON profile array; `/happ` returns a standard text subscription.

## Storage and schedule

- Runtime and storage: Cloudflare Workers + Workers KV. Cloudflare KV is the canonical store for feed caches, scan state and subscription output.
- No GitHub token or repository write permission is required. GitHub is used only to download public source lists.
- Sources are refreshed gradually: one stale source per minute, with a 9-minute source cache TTL.
- Cron runs every minute and tests up to 20 endpoints per run.
- The endpoint pool is capped at 300 unique host:port pairs. At that cap, each endpoint receives a TCP check in an approximately 15-minute rotation.
- Six TCP connection attempts run concurrently, respecting the Workers Free plan's simultaneous outgoing-connection limit.

## GitHub sources

- [peasoft/NoMoreWalls](https://github.com/peasoft/NoMoreWalls)
- [ts-sf/fly](https://github.com/ts-sf/fly)
- [morpheusadam/v2ray-config](https://github.com/morpheusadam/v2ray-config)
- [Alirewa/V2ray-Configs](https://github.com/Alirewa/V2ray-Configs)
- [chaishpish/free_server_v2ray](https://github.com/chaishpish/free_server_v2ray)

## Measurement caveats

The Worker measures TCP handshake reachability and latency from Cloudflare's edge. This is **not** a Moscow/Russia measurement and does not prove that a full VPN tunnel, authentication, traffic forwarding, or exit-IP routing works. Latency from a Cloudflare location can differ from latency experienced by a user or ISP in Russia.

Country labels are inherited from the source feed or node name; they are not independently verified geolocation. Public proxy nodes are untrusted third-party infrastructure. Do not use them for banking, private accounts, or sensitive traffic.
