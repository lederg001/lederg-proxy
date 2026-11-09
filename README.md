# LEDERG PROXY

Cloudflare-hosted collector that builds HAPP-compatible subscriptions from public GitHub proxy feeds, then ranks TCP-capable nodes using probes located in Moscow, Russia.

## Live HAPP endpoints

- [`/json`](https://lederg-proxy-scanner.lederg.workers.dev/json) — HAPP/Xray JSON profile array.
- [`/happ`](https://lederg-proxy-scanner.lederg.workers.dev/happ) — text subscription with original proxy URIs.
- [`/manifest`](https://lederg-proxy-scanner.lederg.workers.dev/manifest) — scan status, Moscow probe metadata, node quality and feed details.
- [`/health`](https://lederg-proxy-scanner.lederg.workers.dev/health) — Worker health and most recent run.

Add one subscription URL to HAPP. The JSON output includes resolver and transport settings for every generated Xray profile.

## Moscow-first measurement and rating

- Measurement network: [Globalping](https://globalping.io/) community probes.
- Required location: city `Moscow`, country `RU`. Results from other locations are rejected.
- Measurement: TCP ping to the exact proxy host and port, 3 packets per measurement.
- Each candidate gets a rolling history of up to 5 measurements.
- Ranking uses median Moscow latency, RTT spread (jitter), packet loss and recent reliability.
- A node is only published after at least two successful Moscow measurements, at least 80% recent reliability, and two consecutive recent successes.
- Two consecutive failures remove it from the active set.
- The full verifier currently publishes only VLESS nodes using TCP, RAW or WebSocket transports and compatible security settings; VMess, Trojan, Shadowsocks, SOCKS and Hysteria2 remain excluded until their own end-to-end verifiers are implemented. The pool is capped at 30 unique TCP endpoints. Two endpoints are selected per minute, and each receives two independent Moscow TCP measurements in parallel: 4 tests/minute, 240 tests/hour, and a 15-minute full sweep (below Globalping's unauthenticated 250 tests/hour limit).
- This is a TCP availability/routing measurement, not a full protocol authentication or throughput test. UDP-only Hysteria2 nodes are excluded from the Moscow TCP pool.

## DNS and TLS profile settings

Xray JSON profiles use non-Cloudflare DNS-over-HTTPS resolvers, in this order:

1. Yandex DoH — `https://common.dot.dns.yandex.net/dns-query`
2. AdGuard Unfiltered DoH — `https://unfiltered.adguard-dns.com/dns-query`
3. Quad9 non-filtering DoH — `https://dns10.quad9.net/dns-query`
4. Google DoH — `https://dns.google/dns-query`

Resolver hostnames are mapped to their published IP addresses to avoid DNS bootstrap loops. Xray uses sequential fallback if a resolver fails. Queries are configured to follow Xray routing rather than using `+local` direct mode.

TLS profiles use the Chrome uTLS fingerprint by default and preserve source-provided SNI/ALPN. REALITY profiles preserve the public key, short ID, SNI and spider path from the source URI; no fake server parameters are invented. REALITY entries with incompatible transports are skipped.

## Cloudflare storage and source feeds

- Runtime and persistent state: Cloudflare Workers + Workers KV.
- GitHub is used only to fetch public source lists. No GitHub token or repository write permission is required by the deployed Worker.
- Public feeds: [peasoft/NoMoreWalls](https://github.com/peasoft/NoMoreWalls), [ts-sf/fly](https://github.com/ts-sf/fly), [morpheusadam/v2ray-config](https://github.com/morpheusadam/v2ray-config), [Alirewa/V2ray-Configs](https://github.com/Alirewa/V2ray-Configs), and [chaishpish/free_server_v2ray](https://github.com/chaishpish/free_server_v2ray).
- One stale source is refreshed per minute, with a 9-minute cache TTL.

## Important limitations

Moscow TCP ping indicates that the proxy's port is reachable from a Moscow community probe. It does not prove the VLESS/VMess/Trojan/SS credentials work, that the remote server forwards traffic, or that every Russian ISP has the same route. The Moscow probe may use a different ISP/ASN from the user.

DNS-over-HTTPS and TLS/REALITY settings are client-side profile settings; they do not alter the public proxy server. TLS fingerprinting only applies to TLS-capable configurations. REALITY requires the actual server-side parameters supplied in the original link. FakeDNS is a separate Xray feature and is not enabled by default because it can break DNS behavior when the HAPP profile is consumed through a different TUN/DNS setup.

Public proxy nodes are third-party infrastructure. Do not use them for banking, private accounts, or sensitive traffic.
