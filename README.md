# ZeroBogus

**🌐 English** · [🇮🇹 Italiano](README.it.md)

ZeroBogus is a multi-channel suite for spotting potentially false or misleading
content, with explainable reports:

- risk score `0-100`
- verdict (`low_risk`, `medium_risk`, `high_risk`)
- human-readable reasoning (the "why")
- optional OSINT integration (URLScan), only with consent

ZeroBogus does not deliver an absolute "true/false" answer: it provides signals
and context to support safer decisions.

## Main features

### 1) Link Intelligence
- phishing pattern detection (protocol, hostname, punycode, redirects, suspicious keywords)
- warnings on tracking/affiliate parameters (`utm_*`, `gclid`, `fbclid`, `aff`, `ref`, and similar)
- optional URLScan support, subject to user consent

### 2) News / Claim Check
- heuristic text analysis (sensationalism, urgency, missing sources, unsupported figures)
- "news from URL" mode: page fetch, text extraction and triage of suspicious links in the content

### 3) Social Account Check
- quick analysis of handles and profile URLs for impersonation signals
- social host verification, name patterns, brand spoofing

### 4) Image (preview)
- basic input validation and guidance messages
- an advanced forensics module is on the roadmap

## Repository layout

- `worker.js`: main build for Cloudflare Workers deployment (recommended for production)
- `server.js`: local / self-hosted Node.js build
- `Dockerfile`: local container execution
- `package.json`: base Node scripts
- `README.md`: documentation
- `LICENSE`: MIT license

## Quick start (recommended): Cloudflare Workers

### 1. Deploy the Worker
1. Cloudflare -> Workers & Pages -> Create application -> Worker.
2. Paste the contents of `worker.js`.
3. Deploy.

### 2. Public route
Configure the route:
- `tivustream.com/zerobogus*`

### 3. Variables / secrets
Workers -> Settings -> Variables.

Variables:
- `BASE_PATH` = `/zerobogus`
- `URLSCAN_ENABLED` = `true`
- `URLSCAN_VISIBILITY` = `unlisted`
- `EXTERNAL_CHECKS_REQUIRE_CONSENT` = `true`
- `FETCH_ARTICLE_ENABLED` = `true`
- `FETCH_ARTICLE_MAX_BYTES` = `1200000`
- `FETCH_ARTICLE_TIMEOUT_MS` = `9000`
- `HISTORY_MAX_ITEMS` = `200`

Secret:
- `URLSCAN_API_KEY` = `<your-key>`

### 4. Verify
- `GET /zerobogus/health` -> JSON with `runtime: cloudflare-worker`
- `GET /zerobogus/` -> UI loaded

## Quick start (alternative): local Node / Docker

### Local Node
```bash
npm start
```
Open:
- `http://localhost:3000`

### Local Docker
```bash
docker build -t zerobogus:local .
docker run --rm -p 3000:3000 --name zerobogus zerobogus:local
```

## API (core)

- `GET /health`
- `GET /api/capabilities`
- `POST /api/analyze`
- `GET /api/history?limit=20&offset=0`
- `GET /api/history/<id>`
- `DELETE /api/history`

## IT/EN language

The UI supports an `IT/EN` language toggle:

- querystring: `?lang=it` or `?lang=en`
- a button in the top right corner for quick switching
- the main UI messages and many of the reasons are returned in the selected language

Examples:
- `https://tivustream.com/zerobogus/?lang=it`
- `https://tivustream.com/zerobogus/?lang=en`

## Privacy by design

- No tracking cookies are required by the tool.
- URLScan is used only with explicit consent.
- On Cloudflare Workers, history is best-effort and kept in memory (it can reset on restart or cold start).
- In "news from URL" mode the page fetch is capped and protected against SSRF.

## Roadmap

- History persistence with Cloudflare KV/D1 (opt-in).
- Privacy-friendly image forensics module (perceptual hashing, metadata, technical checks).
- Additional OSINT connectors with consent (e.g. Safe Browsing / VirusTotal).

## Open source

MIT licensed. See `LICENSE`.

If you use this project, a mention of TivuStream is appreciated.
