# LEDERG PROXY

Automated public-node collector for Happ-compatible subscriptions.

## Published files

- [`json`](https://raw.githubusercontent.com/lederg001/lederg-proxy/main/json) — HAPP/Xray JSON profile array.
- [`happ.txt`](https://raw.githubusercontent.com/lederg001/lederg-proxy/main/happ.txt) — text subscription with original proxy URIs.
- [`manifest.json`](https://raw.githubusercontent.com/lederg001/lederg-proxy/main/manifest.json) — scan status, counts, country labels, and probe metadata.

## Cloudflare Worker

Worker name: `lederg-proxy-scanner`

Health: https://lederg-proxy-scanner.lederg.workers.dev/health

Endpoints:
- `/json` — current HAPP JSON array
- `/happ` — current text subscription
- `/manifest` — latest scan manifest

Schedule: every minute (UTC). Each run probes up to 20 endpoints; with the 300-endpoint pool cap, every endpoint is revisited in approximately 15 minutes. A probe uses one Check-Host TCP dispatch and one result poll. Each run refreshes at most one stale source.

## Required secret

In Cloudflare Workers & Pages → `lederg-proxy-scanner` → Settings → Variables and Secrets, add a **Secret**:

- Name: `GITHUB_TOKEN`
- Scope: only this repository, `lederg001/lederg-proxy`
- Permission: Contents — Read and write

The token must be created as a **Secret** (not a plain-text variable), is read only from the Worker secret binding, and is never committed to this repository. A previously configured plain-text token was removed; revoke it in GitHub and create a replacement before adding the new Secret.

## Sources

- Free Nodes Radar global: https://radarhub.top/v2ray.txt
- Free Nodes Radar Netherlands: https://radarhub.top/by-country/netherlands.txt
- peasoft/NoMoreWalls: https://github.com/peasoft/NoMoreWalls
- ts-sf/fly: https://github.com/ts-sf/fly
- mahdibland/V2RayAggregator: https://github.com/mahdibland/V2RayAggregator
- ALIILAPRO/v2rayNG-Config: https://github.com/ALIILAPRO/v2rayNG-Config

## Measurement caveats

The Moscow Check-Host node measures TCP port reachability and connection time. It does **not** prove that a VPN handshake succeeds, measure download throughput, verify the exit IP, or guarantee availability from every Russian ISP.

Country labels are inherited from the source feed or node name; they are not independently verified geolocation. Public proxy nodes are untrusted third-party infrastructure. Do not use them for banking, private accounts, or sensitive traffic.
