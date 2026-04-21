# ZeroBogus

ZeroBogus è una suite multi-canale per identificare contenuti potenzialmente falsi/ingannevoli con report spiegabili:

- punteggio rischio `0-100`
- verdetto (`low_risk`, `medium_risk`, `high_risk`)
- motivazioni leggibili (il “perché”)
- integrazione OSINT opzionale (URLScan) solo con consenso

ZeroBogus non fornisce un “vero/falso assoluto”: fornisce segnali e contesto per aiutare decisioni più sicure.

## Funzionalità principali

### 1) Link Intelligence
- rilevamento pattern phishing (protocollo, hostname, punycode, redirect, keyword sospette)
- warning su tracking/affiliazione (`utm_*`, `gclid`, `fbclid`, `aff`, `ref`, ecc.)
- supporto URLScan opzionale con consenso utente

### 2) News / Claim Check
- analisi euristica su testo (sensazionalismo, urgenza, assenza fonti, numeri non supportati)
- modalità “news da URL”: fetch pagina, estrazione testo e triage link sospetti nel contenuto

### 3) Social Account Check
- analisi rapida di handle / URL profilo per segnali di impersonazione
- verifica host social, pattern nome, brand spoofing

### 4) Image (preview)
- controllo base input e messaggi orientativi
- modulo forensics avanzato previsto in roadmap

## Architettura repository

- `worker.js`: versione principale per deploy Cloudflare Workers (produzione consigliata)
- `server.js`: versione Node.js locale/self-host
- `Dockerfile`: esecuzione container locale
- `package.json`: script Node base
- `README.md`: documentazione
- `LICENSE`: licenza MIT

## Quick Start (consigliato): Cloudflare Workers

### 1. Deploy Worker
1. Cloudflare -> Workers & Pages -> Create application -> Worker.
2. Incolla il contenuto di `worker.js`.
3. Deploy.

### 2. Route pubblica
Configura la route:
- `tivustream.com/zerobogus*`

### 3. Variabili / Secret
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

### 4. Verifica
- `GET /zerobogus/health` -> JSON con `runtime: cloudflare-worker`
- `GET /zerobogus/` -> UI caricata

## Quick Start (alternativa): Node / Docker locale

### Node locale
```bash
npm start
```
Apri:
- `http://localhost:3000`

### Docker locale
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

## Lingua IT/EN

La UI supporta un toggle lingua `IT/EN`:

- querystring: `?lang=it` oppure `?lang=en`
- pulsante in alto a destra per cambio rapido lingua
- i messaggi principali UI e molte motivazioni vengono restituite nella lingua selezionata

Esempi:
- `https://tivustream.com/zerobogus/?lang=it`
- `https://tivustream.com/zerobogus/?lang=en`

## Privacy by design

- Nessun tracking cookie richiesto dal tool.
- URLScan viene usato solo con consenso esplicito.
- In Cloudflare Workers la cronologia è best-effort in memoria (può azzerarsi con restart/cold start).
- In modalità News da URL il fetch pagina è limitato e con protezioni anti-SSRF.

## Roadmap

- Persistenza cronologia con Cloudflare KV/D1 (opt-in).
- Modulo image forensics privacy-friendly (hash percettivo, metadati, controlli tecnici).
- Connettori OSINT aggiuntivi con consenso (es. Safe Browsing / VirusTotal).


## Open Source

Licenza MIT. Vedi `LICENSE`.

Se usi questo progetto, una menzione a TivuStream è apprezzata.
