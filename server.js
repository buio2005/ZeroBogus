const http = require("http");
const { URL } = require("url");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const dns = require("dns");
const net = require("net");

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const MAX_BODY_BYTES = 1024 * 1024;
const DATA_DIR = process.env.DATA_DIR ? String(process.env.DATA_DIR) : path.join(process.cwd(), "data");
const STORE_RAW_INPUT = String(process.env.STORE_RAW_INPUT || "").toLowerCase() === "true";
const HISTORY_FILE = path.join(DATA_DIR, "history.jsonl");
const HISTORY_MODE = process.env.HISTORY_MODE ? String(process.env.HISTORY_MODE) : (process.env.NODE_ENV === "production" ? "memory" : "file");
const HISTORY_MAX_ITEMS = Math.max(20, Math.min(2000, Number(process.env.HISTORY_MAX_ITEMS || 300) || 300));
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY ? String(process.env.URLSCAN_API_KEY) : "";
const URLSCAN_VISIBILITY = process.env.URLSCAN_VISIBILITY ? String(process.env.URLSCAN_VISIBILITY) : "unlisted";
const URLSCAN_ENABLED = String(process.env.URLSCAN_ENABLED || "").toLowerCase() !== "false";
const URLSCAN_MAX_POLL_ATTEMPTS = Math.max(1, Math.min(12, Number(process.env.URLSCAN_MAX_POLL_ATTEMPTS || 8) || 8));
const URLSCAN_INFLIGHT = new Set();
const EXTERNAL_CHECKS_REQUIRE_CONSENT = String(process.env.EXTERNAL_CHECKS_REQUIRE_CONSENT || "").toLowerCase() !== "false";
const FETCH_ARTICLE_ENABLED = String(process.env.FETCH_ARTICLE_ENABLED || "").toLowerCase() !== "false";
const FETCH_ARTICLE_MAX_BYTES = Math.max(200000, Math.min(4000000, Number(process.env.FETCH_ARTICLE_MAX_BYTES || 1200000) || 1200000));
const FETCH_ARTICLE_TIMEOUT_MS = Math.max(2000, Math.min(20000, Number(process.env.FETCH_ARTICLE_TIMEOUT_MS || 9000) || 9000));
const THEME_CSS_URL = process.env.THEME_CSS_URL ? String(process.env.THEME_CSS_URL) : "";
const BASE_PATH = (() => {
  const raw = process.env.BASE_PATH ? String(process.env.BASE_PATH).trim() : "";
  if (!raw) return "";
  const withSlash = raw.startsWith("/") ? raw : `/${raw}`;
  return withSlash.endsWith("/") ? withSlash.slice(0, -1) : withSlash;
})();
const historyMemory = [];
const CAPABILITIES = [
  {
    key: "url",
    title: "Link Intelligence",
    status: "available",
    description: "Verifica URL con euristiche anti-phishing, tracking detection e integrazione URLScan.",
    checks: ["protocollo/hostname", "redirect e parametri", "tracking/affiliazione", "osint urlscan (con consenso)"]
  },
  {
    key: "news",
    title: "News & Claim Check",
    status: "available",
    description: "Analizza testi/news per segnali di manipolazione, assenza fonti e linguaggio sensazionalistico. Supporta anche estrazione testo da URL.",
    checks: ["fonti e riferimenti", "claim numerici", "stile allarmistico", "estrazione da URL", "link sospetti nel testo", "osint urlscan (con consenso)"]
  },
  {
    key: "social",
    title: "Social Account Check",
    status: "available",
    description: "Valuta profili/handle social per pattern di impersonazione e naming sospetto.",
    checks: ["handle pattern", "brand spoofing", "host social noto", "parametri sospetti"]
  },
  {
    key: "image",
    title: "Image Forensics",
    status: "preview",
    description: "Modalita base: warning e instradamento. Forensics avanzata in roadmap.",
    checks: ["input validation", "workflow hint", "roadmap reverse search"]
  }
];

function sendText(res, statusCode, text, contentType = "text/plain; charset=utf-8") {
  res.writeHead(statusCode, {
    "Content-Type": contentType,
    "Content-Length": Buffer.byteLength(text),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cache-Control": "no-store"
  });
  res.end(text);
}

function sendJson(res, statusCode, payload) {
  const text = JSON.stringify(payload, null, 2);
  sendText(res, statusCode, text, "application/json; charset=utf-8");
}

function stripBasePath(pathname) {
  if (!BASE_PATH) return pathname;
  if (pathname === BASE_PATH) return "/";
  if (pathname.startsWith(`${BASE_PATH}/`)) {
    const rest = pathname.slice(BASE_PATH.length);
    return rest || "/";
  }
  return pathname;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let bodyBytes = 0;
    const chunks = [];

    req.on("data", (chunk) => {
      bodyBytes += chunk.length;
      if (bodyBytes > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Body too large"), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (chunks.length === 0) return resolve(null);
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(Object.assign(new Error("Invalid JSON"), { statusCode: 400 }));
      }
    });

    req.on("error", (err) => reject(err));
  });
}

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function nowIso() {
  return new Date().toISOString();
}

function makeId() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return crypto.randomBytes(16).toString("hex");
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text), "utf8").digest("hex");
}

function safePreview(text, maxLen) {
  const s = String(text ?? "").replace(/\s+/g, " ").trim();
  if (s.length <= maxLen) return s;
  return `${s.slice(0, maxLen - 1)}…`;
}

function urlHostnameOrNull(value) {
  const input = String(value ?? "").trim();
  if (!input) return null;
  try {
    const normalized = input.startsWith("http://") || input.startsWith("https://") ? input : `https://${input}`;
    return new URL(normalized).hostname || null;
  } catch {
    return null;
  }
}

function persistEvent(record) {
  const payload = { ...record, id: record?.id || makeId(), createdAt: record?.createdAt || nowIso() };
  if (HISTORY_MODE === "off") return payload;

  if (HISTORY_MODE === "memory") {
    historyMemory.push(payload);
    while (historyMemory.length > HISTORY_MAX_ITEMS) historyMemory.shift();
    return payload;
  }

  ensureDataDir();
  fs.appendFileSync(HISTORY_FILE, `${JSON.stringify(payload)}\n`, "utf8");
  return payload;
}

function clearHistory() {
  if (HISTORY_MODE === "off") return;
  if (HISTORY_MODE === "memory") {
    historyMemory.length = 0;
    return;
  }

  ensureDataDir();
  fs.writeFileSync(HISTORY_FILE, "", "utf8");
}

function persistAnalysis({ type, inputValue, result }) {
  const id = makeId();
  const createdAt = nowIso();
  const input = String(inputValue ?? "");
  const inputHash = sha256Hex(input);
  const inputPreview = type === "url" ? (urlHostnameOrNull(input) || safePreview(input, 120)) : safePreview(input, 160);

  const record = {
    kind: "analysis",
    id,
    createdAt,
    type,
    inputHash,
    inputPreview,
    score: result?.score,
    scoreLocal: result?.score,
    verdict: result?.verdict,
    reasons: Array.isArray(result?.reasons) ? result.reasons : [],
    meta: result?.meta || null
  };

  if (STORE_RAW_INPUT) record.input = input;

  persistEvent(record);
  return { id, createdAt };
}

function scoreFromReasons(reasons) {
  const sum = (Array.isArray(reasons) ? reasons : []).reduce((acc, r) => acc + clamp01(Number(r?.severity) || 0), 0);
  return Math.round(100 * (1 - Math.exp(-sum)));
}

function normalizeUrlForScan(value) {
  const input = String(value ?? "").trim();
  if (!input) return "";
  if (input.startsWith("http://") || input.startsWith("https://")) return input;
  return `https://${input}`;
}

function isBlockedHostname(hostname) {
  const h = String(hostname || "").toLowerCase().trim();
  if (!h) return true;
  if (h === "localhost") return true;
  if (h.endsWith(".localhost")) return true;
  if (h === "0.0.0.0") return true;
  if (h === "[::1]") return true;
  return false;
}

function isPrivateIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const parts = ip.split(".").map((x) => Number(x));
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
    return false;
  }
  if (v === 6) {
    const s = ip.toLowerCase();
    if (s === "::1") return true;
    if (s.startsWith("fe80:")) return true;
    if (s.startsWith("fc") || s.startsWith("fd")) return true;
    if (s.startsWith("::ffff:127.")) return true;
    if (s.startsWith("::ffff:10.")) return true;
    if (s.startsWith("::ffff:192.168.")) return true;
    if (s.startsWith("::ffff:172.")) return true;
    return false;
  }
  return true;
}

async function assertPublicHttpUrl(urlValue) {
  const raw = String(urlValue ?? "").trim();
  if (!raw) throw Object.assign(new Error("URL missing"), { statusCode: 400 });
  const parsed = new URL(raw);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw Object.assign(new Error("Unsupported protocol"), { statusCode: 400 });
  if (parsed.username || parsed.password) throw Object.assign(new Error("Credentials in URL not allowed"), { statusCode: 400 });
  if (isBlockedHostname(parsed.hostname)) throw Object.assign(new Error("Blocked hostname"), { statusCode: 400 });
  if (parsed.port && parsed.port !== "80" && parsed.port !== "443") throw Object.assign(new Error("Blocked port"), { statusCode: 400 });

  const directIp = net.isIP(parsed.hostname) ? parsed.hostname : null;
  if (directIp) {
    if (isPrivateIp(directIp)) throw Object.assign(new Error("Blocked IP"), { statusCode: 400 });
    return parsed.toString();
  }

  const lookups = await dns.promises.lookup(parsed.hostname, { all: true }).catch(() => []);
  if (!Array.isArray(lookups) || lookups.length === 0) throw Object.assign(new Error("DNS lookup failed"), { statusCode: 400 });
  for (const a of lookups) {
    if (a?.address && isPrivateIp(String(a.address))) throw Object.assign(new Error("Blocked IP"), { statusCode: 400 });
  }
  return parsed.toString();
}

async function fetchTextFromUrl(urlToFetch) {
  if (typeof fetch !== "function") throw new Error("fetch not available");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_ARTICLE_TIMEOUT_MS);
  try {
    const visited = new Set();
    let current = await assertPublicHttpUrl(urlToFetch);
    let res = null;

    for (let i = 0; i < 6; i += 1) {
      if (visited.has(current)) throw Object.assign(new Error("Redirect loop"), { statusCode: 400 });
      visited.add(current);

      res = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "ZeroBogus/0.1"
        }
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) throw Object.assign(new Error("Redirect without location"), { statusCode: 400 });
        const next = new URL(location, current).toString();
        current = await assertPublicHttpUrl(next);
        continue;
      }

      break;
    }

    const contentType = String(res.headers.get("content-type") || "");
    if (!res.ok) throw new Error(`Fetch failed (${res.status})`);
    if (!contentType.toLowerCase().includes("text/html") && !contentType.toLowerCase().includes("text/plain")) {
      throw new Error("Unsupported content type");
    }

    const reader = res.body?.getReader?.();
    if (!reader) {
      const text = await res.text();
      if (Buffer.byteLength(text, "utf8") > FETCH_ARTICLE_MAX_BYTES) throw new Error("Content too large");
      return { contentType, raw: text };
    }

    let received = 0;
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > FETCH_ARTICLE_MAX_BYTES) throw new Error("Content too large");
      chunks.push(Buffer.from(value));
    }

    const raw = Buffer.concat(chunks).toString("utf8");
    return { contentType, raw };
  } finally {
    clearTimeout(timeout);
  }
}

function htmlToText(html) {
  let s = String(html ?? "");
  s = s.replace(/<script\b[\s\S]*?<\/script>/gi, " ");
  s = s.replace(/<style\b[\s\S]*?<\/style>/gi, " ");
  s = s.replace(/<!--[\s\S]*?-->/g, " ");
  s = s.replace(/<br\s*\/?>/gi, "\n");
  s = s.replace(/<\/p>/gi, "\n");
  s = s.replace(/<[^>]+>/g, " ");
  s = s.replace(/&nbsp;/gi, " ");
  s = s.replace(/&amp;/gi, "&");
  s = s.replace(/&lt;/gi, "<");
  s = s.replace(/&gt;/gi, ">");
  s = s.replace(/&quot;/gi, "\"");
  s = s.replace(/&#039;/gi, "'");
  s = s.replace(/\s+\n/g, "\n");
  s = s.replace(/\n\s+/g, "\n");
  s = s.replace(/[ \t]{2,}/g, " ");
  return s.trim();
}

function extractLinksFromHtml(html, baseUrl) {
  const s = String(html ?? "");
  const links = new Set();
  const re = /\b(?:href|src)\s*=\s*["']([^"'#\s]+)["']/gi;
  let match;
  while ((match = re.exec(s))) {
    const raw = String(match[1] || "").trim();
    if (!raw) continue;
    if (raw.startsWith("mailto:") || raw.startsWith("javascript:") || raw.startsWith("data:")) continue;
    try {
      const u = new URL(raw, baseUrl);
      if (u.protocol === "http:" || u.protocol === "https:") links.add(u.toString());
    } catch {
    }
    if (links.size >= 80) break;
  }
  return Array.from(links);
}

function urlscanResultToReasons(urlscanResult) {
  const verdicts = urlscanResult?.verdicts?.overall;
  const score = Number(verdicts?.score);
  const malicious = verdicts?.malicious === true;
  const categories = Array.isArray(verdicts?.categories) ? verdicts.categories : [];

  const link = urlscanResult?.task?.reportURL || urlscanResult?.task?.url ? `https://urlscan.io/result/${encodeURIComponent(String(urlscanResult?.task?.uuid || ""))}/` : null;
  const evidence = {
    urlscan: {
      uuid: urlscanResult?.task?.uuid || null,
      reportURL: urlscanResult?.task?.reportURL || link,
      score: Number.isFinite(score) ? score : null,
      malicious,
      categories: categories.slice(0, 10)
    }
  };

  if (malicious) {
    return [
      {
        id: "urlscan.malicious",
        label: "URLScan: segnalato malevolo",
        severity: 0.75,
        why: "L’analisi esterna segnala la risorsa come malevola. Verifica comunque il contesto e la fonte.",
        evidence
      }
    ];
  }

  if (Number.isFinite(score) && score >= 60) {
    return [
      {
        id: "urlscan.high_score",
        label: "URLScan: punteggio rischio elevato",
        severity: 0.55,
        why: "L’analisi esterna indica un rischio elevato. Possibili redirect/risorse sospette o pattern tipici di campagne malevole.",
        evidence
      }
    ];
  }

  if (Number.isFinite(score) && score >= 20) {
    return [
      {
        id: "urlscan.suspicious",
        label: "URLScan: segnali sospetti",
        severity: 0.25,
        why: "L’analisi esterna riporta segnali che meritano un controllo aggiuntivo (redirect, richieste a domini terzi, fingerprinting).",
        evidence
      }
    ];
  }

  if (Array.isArray(categories) && categories.length > 0) {
    return [
      {
        id: "urlscan.categories",
        label: "URLScan: categoria rilevata",
        severity: 0.12,
        why: "L’analisi esterna classifica la pagina in una o più categorie. Non è un segnale di frode da solo, ma può aiutare il contesto.",
        evidence
      }
    ];
  }

  return [];
}

async function urlscanSubmit(urlToScan) {
  if (!URLSCAN_API_KEY) throw new Error("URLSCAN_API_KEY missing");
  if (typeof fetch !== "function") throw new Error("fetch not available");

  const res = await fetch("https://urlscan.io/api/v1/scan/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "API-Key": URLSCAN_API_KEY
    },
    body: JSON.stringify({
      url: urlToScan,
      visibility: URLSCAN_VISIBILITY
    })
  });

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const message = data?.message || data?.description || `urlscan submit failed (${res.status})`;
    throw new Error(message);
  }

  return data;
}

async function urlscanGetResult(uuid) {
  if (typeof fetch !== "function") throw new Error("fetch not available");
  const res = await fetch(`https://urlscan.io/api/v1/result/${encodeURIComponent(uuid)}/`, { method: "GET" });
  if (res.status === 404) return { status: "not_ready" };
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const message = data?.message || data?.description || `urlscan result failed (${res.status})`;
    throw new Error(message);
  }
  return { status: "ready", data };
}

function trimUrlscanResult(raw) {
  const page = raw?.page || {};
  const task = raw?.task || {};
  const verdicts = raw?.verdicts || {};
  const stats = raw?.stats || {};

  return {
    task: {
      uuid: task?.uuid,
      url: task?.url,
      domain: task?.domain,
      reportURL: task?.reportURL,
      screenshotURL: task?.screenshotURL
    },
    page: {
      url: page?.url,
      domain: page?.domain,
      ip: page?.ip,
      country: page?.country
    },
    verdicts,
    stats: {
      requests: stats?.requests,
      domains: stats?.domains,
      ips: stats?.ips
    }
  };
}

function scheduleUrlscanPolling({ analysisId, uuid }) {
  const key = `${analysisId}:${uuid}`;
  if (URLSCAN_INFLIGHT.has(key)) return;
  URLSCAN_INFLIGHT.add(key);

  const attempt = async (i) => {
    try {
      const r = await urlscanGetResult(uuid);
      if (r.status === "not_ready") {
        if (i >= URLSCAN_MAX_POLL_ATTEMPTS) {
          persistEvent({ kind: "urlscan.timeout", analysisId, uuid });
          URLSCAN_INFLIGHT.delete(key);
          return;
        }
        const waitMs = Math.min(30000, 1500 * Math.pow(1.6, i));
        setTimeout(() => attempt(i + 1), waitMs);
        return;
      }

      const trimmed = trimUrlscanResult(r.data);
      persistEvent({ kind: "urlscan.result", analysisId, uuid, result: trimmed });
      URLSCAN_INFLIGHT.delete(key);
    } catch (e) {
      persistEvent({ kind: "urlscan.error", analysisId, uuid, error: String(e?.message || e) });
      URLSCAN_INFLIGHT.delete(key);
    }
  };

  setTimeout(() => attempt(0), 750);
}

function readAllHistoryLines() {
  if (HISTORY_MODE === "off") return [];
  if (HISTORY_MODE === "memory") return [...historyMemory];

  ensureDataDir();
  if (!fs.existsSync(HISTORY_FILE)) return [];
  const raw = fs.readFileSync(HISTORY_FILE, "utf8");
  const lines = raw.split("\n").filter(Boolean);
  const records = [];
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      if (parsed && parsed.kind) records.push(parsed);
    } catch {
    }
  }
  return records;
}

function buildHistoryIndex() {
  const records = readAllHistoryLines();
  const analyses = new Map();
  const urlscan = new Map();

  for (const r of records) {
    if (r.kind === "analysis" && r.id) {
      analyses.set(r.id, r);
      continue;
    }

    if (typeof r.analysisId === "string" && r.analysisId) {
      const existing = urlscan.get(r.analysisId) || {};
      if (r.kind === "urlscan.submit") urlscan.set(r.analysisId, { ...existing, submit: r });
      if (r.kind === "urlscan.result") urlscan.set(r.analysisId, { ...existing, result: r });
      if (r.kind === "urlscan.error") urlscan.set(r.analysisId, { ...existing, error: r });
      if (r.kind === "urlscan.timeout") urlscan.set(r.analysisId, { ...existing, timeout: r });
    }
  }

  const items = Array.from(analyses.values()).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return { items, urlscan };
}

function urlscanStatusForBundle(bundle) {
  if (!bundle) return null;
  if (bundle.result?.result) return "ready";
  if (bundle.error?.error) return "error";
  if (bundle.timeout) return "timeout";
  if (bundle.submit?.uuid) return "pending";
  return null;
}

function listHistory({ limit, offset }) {
  const { items, urlscan } = buildHistoryIndex();
  const sliced = items.slice(offset, offset + limit);
  return sliced.map((r) => {
    const bundle = urlscan.get(r.id);
    const status = urlscanStatusForBundle(bundle);
    return {
      id: r.id,
      createdAt: r.createdAt,
      type: r.type,
      inputPreview: r.inputPreview,
      inputHash: r.inputHash,
      score: r.score,
      verdict: r.verdict,
      urlscanStatus: status,
      urlscanUuid: bundle?.submit?.uuid || bundle?.result?.uuid || null
    };
  });
}

function getHistoryById(id) {
  const { items, urlscan } = buildHistoryIndex();
  const analysis = items.find((r) => r.id === id) || null;
  if (!analysis) return null;

  const bundle = urlscan.get(id);
  const status = urlscanStatusForBundle(bundle);
  const urlscanResult = bundle?.result?.result || null;
  const urlscanReasons = urlscanResult ? urlscanResultToReasons(urlscanResult) : [];

  const combinedReasons = [...(analysis.reasons || []), ...urlscanReasons].sort((a, b) => (Number(b?.severity) || 0) - (Number(a?.severity) || 0));
  const combinedScore = scoreFromReasons(combinedReasons);
  const combinedVerdict = scoreToVerdict(combinedScore);

  const reportURL = urlscanResult?.task?.reportURL || (bundle?.submit?.result ? String(bundle.submit.result) : null);

  return {
    ...analysis,
    score: combinedScore,
    verdict: combinedVerdict,
    reasons: combinedReasons,
    osint: {
      urlscan: {
        status,
        uuid: bundle?.submit?.uuid || urlscanResult?.task?.uuid || null,
        reportURL: reportURL || null,
        error: bundle?.error?.error || null
      }
    }
  };
}

function clamp01(n) {
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

function scoreToVerdict(score) {
  if (score >= 75) return "high_risk";
  if (score >= 45) return "medium_risk";
  return "low_risk";
}

function looksLikeUrl(value) {
  if (typeof value !== "string") return false;
  const s = value.trim();
  if (!s) return false;
  if (s.startsWith("http://") || s.startsWith("https://")) return true;
  if (s.startsWith("www.")) return true;
  if (s.includes(".") && !s.includes(" ")) return true;
  return false;
}

function isProbablyIpHostname(hostname) {
  if (!hostname) return false;
  const parts = hostname.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^[0-9]{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isPunycode(hostname) {
  return typeof hostname === "string" && hostname.includes("xn--");
}

function analyzeUrl(urlValue) {
  const input = String(urlValue ?? "").trim();
  const findings = [];

  let parsed;
  try {
    const normalized = input.startsWith("http://") || input.startsWith("https://") ? input : `https://${input}`;
    parsed = new URL(normalized);
  } catch {
    return {
      input,
      type: "url",
      score: 90,
      verdict: "high_risk",
      reasons: [
        {
          id: "url.invalid",
          label: "URL non valida",
          severity: 0.9,
          why: "Il valore non è una URL interpretabile: molti contenuti bogus usano URL spezzate/ambigue per confondere."
        }
      ]
    };
  }

  const hostname = parsed.hostname;
  const full = parsed.toString();

  const add = (id, label, severity, why, evidence) => {
    findings.push({
      id,
      label,
      severity: clamp01(severity),
      why,
      evidence
    });
  };

  if (parsed.protocol !== "https:") {
    add(
      "url.no_https",
      "Connessione non HTTPS",
      0.35,
      "I siti senza HTTPS aumentano il rischio di manomissioni e phishing.",
      { protocol: parsed.protocol }
    );
  }

  if (isProbablyIpHostname(hostname)) {
    add(
      "url.ip_host",
      "Hostname è un IP",
      0.6,
      "Molti link malevoli usano IP diretti per evitare controlli e mascherare il dominio.",
      { hostname }
    );
  }

  if (isPunycode(hostname)) {
    add(
      "url.punycode",
      "Dominio con punycode",
      0.5,
      "Il punycode può essere usato per omografi (domini simili visivamente). Non è sempre malevolo, ma va verificato.",
      { hostname }
    );
  }

  const tld = hostname.split(".").slice(-1)[0]?.toLowerCase();
  const riskyTlds = new Set(["zip", "mov", "top", "xyz", "click", "cam", "live", "support", "fit", "icu"]);
  if (tld && riskyTlds.has(tld)) {
    add(
      "url.risky_tld",
      "TLD frequentemente abusato",
      0.35,
      "Alcuni TLD sono statisticamente più abusati per campagne di spam/phishing.",
      { tld }
    );
  }

  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount >= 3) {
    add(
      "url.many_subdomains",
      "Molti sottodomini",
      0.25,
      "Molti sottodomini possono essere usati per imitare brand (es. login.secure.brand...).",
      { subdomainCount, hostname }
    );
  }

  if (full.length >= 120) {
    add(
      "url.very_long",
      "URL molto lunga",
      0.25,
      "Le URL lunghe possono nascondere parametri ingannevoli (redirect, tracking, esche).",
      { length: full.length }
    );
  }

  if (parsed.username || parsed.password || input.includes("@")) {
    add(
      "url.userinfo_or_at",
      "Carattere @ o credenziali nella URL",
      0.65,
      "Il pattern con @ può essere usato per confondere l’utente sul vero dominio finale.",
      { username: parsed.username ? "[present]" : null }
    );
  }

  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const phishingKeywords = ["login", "signin", "verify", "account", "secure", "update", "password", "bank", "wallet"];
  const hit = phishingKeywords.find((k) => pathAndQuery.includes(k));
  if (hit) {
    add(
      "url.phishing_keyword",
      "Keyword tipica di phishing",
      0.35,
      "Alcune parole in path/parametri sono comuni nei tentativi di furto credenziali. Va valutato il contesto.",
      { keyword: hit }
    );
  }

  const params = Array.from(parsed.searchParams.keys());
  const paramKeysLower = params.map((p) => p.toLowerCase());

  const trackingParams = [
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "msclkid",
    "ttclid",
    "yclid",
    "igshid",
    "ref",
    "referrer",
    "aff",
    "affiliate",
    "aff_id",
    "affid",
    "partner",
    "partner_id",
    "campaign",
    "c_id",
    "clickid",
    "irclickid"
  ];
  const trackingHits = trackingParams.filter((k) => paramKeysLower.includes(k));
  if (trackingHits.length > 0) {
    add(
      "url.tracking_params",
      "Link con tracking/affiliazione",
      0.08,
      "Parametri di tracking/affiliazione non indicano per forza un contenuto bogus, ma possono impattare privacy e mascherare la destinazione reale in catene di redirect.",
      { params: trackingHits.slice(0, 8) }
    );
  }

  const longValueParams = [];
  for (const key of params) {
    const value = parsed.searchParams.get(key) ?? "";
    const cleaned = String(value).trim();
    if (cleaned.length >= 22 && /^[a-z0-9._-]+$/i.test(cleaned)) {
      const digits = (cleaned.match(/[0-9]/g) || []).length;
      const digitRatio = cleaned.length ? digits / cleaned.length : 0;
      if (digitRatio >= 0.35) longValueParams.push(key);
    }
  }
  if (longValueParams.length > 0) {
    add(
      "url.long_id_params",
      "Parametri con ID lunghi",
      0.06,
      "ID lunghi sono comuni in tracking/affiliazione. Non è un segnale di frode da solo, ma vale la pena capire chi sta tracciando e perché.",
      { params: longValueParams.slice(0, 8) }
    );
  }

  const redirectParams = ["redirect", "redir", "url", "next", "target", "dest", "destination", "continue", "return"];
  const redirectKey = params.find((k) => redirectParams.includes(k.toLowerCase()));
  if (redirectKey) {
    add(
      "url.redirect_param",
      "Possibile redirect",
      0.3,
      "I parametri di redirect possono essere usati per catene di reindirizzamento e phishing.",
      { param: redirectKey }
    );
  }

  const digitRatio = (() => {
    const s = hostname.replace(/\./g, "");
    if (!s) return 0;
    const digits = (s.match(/[0-9]/g) || []).length;
    return digits / s.length;
  })();
  if (digitRatio >= 0.35) {
    add(
      "url.digits_in_domain",
      "Dominio con molti numeri",
      0.25,
      "Domini generati automaticamente o usa-e-getta spesso contengono molte cifre.",
      { digitRatio: Number(digitRatio.toFixed(2)), hostname }
    );
  }

  const score = Math.round(100 * (1 - Math.exp(-findings.reduce((acc, f) => acc + f.severity, 0))));
  return {
    input,
    type: "url",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity)
  };
}

function analyzeText(textValue) {
  const input = String(textValue ?? "");
  const s = input.trim();
  const findings = [];

  const add = (id, label, severity, why, evidence) => {
    findings.push({ id, label, severity: clamp01(severity), why, evidence });
  };

  if (!s) {
    add(
      "text.empty",
      "Testo vuoto",
      0.2,
      "Non c’è contenuto da verificare.",
      null
    );
  }

  const upper = s.replace(/[^A-ZÀ-ÖØ-Ý]/g, "").length;
  const letters = s.replace(/[^A-ZÀ-ÖØ-Ýa-zà-öø-ý]/g, "").length;
  const upperRatio = letters ? upper / letters : 0;
  if (upperRatio >= 0.55 && letters >= 40) {
    add(
      "text.allcaps",
      "Molte maiuscole",
      0.2,
      "Testi allarmistici/spam usano spesso maiuscole per forzare attenzione.",
      { upperRatio: Number(upperRatio.toFixed(2)) }
    );
  }

  const exclam = (s.match(/!/g) || []).length;
  if (exclam >= 4) {
    add(
      "text.exclamation",
      "Molti punti esclamativi",
      0.2,
      "Enfasi eccessiva è frequente in contenuti manipolatori.",
      { exclam }
    );
  }

  const sensational = [
    "shock",
    "incredibile",
    "vergogna",
    "non crederai",
    "ecco la verità",
    "ti stanno nascondendo",
    "clamoroso",
    "scandalo",
    "urgente",
    "condividi subito"
  ];
  const lower = s.toLowerCase();
  const sensationalHit = sensational.find((w) => lower.includes(w));
  if (sensationalHit) {
    add(
      "text.sensational",
      "Linguaggio sensazionalistico",
      0.25,
      "Titoli/claim sensazionalistici aumentano la probabilità di clickbait o disinformazione.",
      { keyword: sensationalHit }
    );
  }

  const hasSource = /(fonte|source|secondo|according to|rapport|report|studio|study)\b/i.test(s);
  const hasLink = /\bhttps?:\/\/\S+/i.test(s);
  if (!hasSource && !hasLink && s.length >= 200) {
    add(
      "text.no_sources",
      "Assenza di fonti esplicite",
      0.25,
      "Un contenuto lungo che fa affermazioni senza citare fonti è più difficile da verificare e spesso meno affidabile.",
      null
    );
  }

  const claimsNumbers = (s.match(/\b\d{2,}\b/g) || []).length;
  if (claimsNumbers >= 4 && !hasSource) {
    add(
      "text.many_numbers_no_sources",
      "Molti numeri senza fonte",
      0.25,
      "Statistiche/percentuali senza fonte possono indicare dati inventati o distorti.",
      { numbers: claimsNumbers }
    );
  }

  const score = Math.round(100 * (1 - Math.exp(-findings.reduce((acc, f) => acc + f.severity, 0))));
  return {
    input,
    type: "text",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity)
  };
}

function analyzeNews(newsValue) {
  const base = analyzeText(newsValue);
  const s = String(newsValue ?? "").trim();
  const findings = Array.isArray(base.reasons) ? [...base.reasons] : [];
  const lower = s.toLowerCase();

  const add = (id, label, severity, why, evidence) => {
    findings.push({ id, label, severity: clamp01(severity), why, evidence });
  };

  const hasDate = /\b(20\d{2}|19\d{2})\b/.test(s);
  if (!hasDate && s.length >= 140) {
    add(
      "news.no_date",
      "Nessun riferimento temporale",
      0.14,
      "Una news senza data o periodo di riferimento e piu difficile da contestualizzare e verificare.",
      null
    );
  }

  const fakeUrgencyWords = ["ultima ora", "breaking", "urgente", "diffondi subito", "censurato", "prima che cancellino"];
  const urgencyHit = fakeUrgencyWords.find((w) => lower.includes(w));
  if (urgencyHit) {
    add(
      "news.urgency_narrative",
      "Narrativa di urgenza",
      0.22,
      "Le narrazioni di urgenza estrema sono spesso usate per ridurre il pensiero critico e indurre condivisioni immediate.",
      { keyword: urgencyHit }
    );
  }

  const score = scoreFromReasons(findings);
  return {
    input: base.input,
    type: "news",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity)
  };
}

function analyzeSocial(profileValue) {
  const input = String(profileValue ?? "").trim();
  const findings = [];

  const add = (id, label, severity, why, evidence) => {
    findings.push({ id, label, severity: clamp01(severity), why, evidence });
  };

  if (!input) {
    add("social.empty", "Profilo non fornito", 0.2, "Inserisci handle o URL del profilo social da verificare.", null);
    return {
      input,
      type: "social",
      score: scoreFromReasons(findings),
      verdict: scoreToVerdict(scoreFromReasons(findings)),
      reasons: findings
    };
  }

  const asUrl = looksLikeUrl(input);
  let hostname = "";
  let pathPart = input;
  if (asUrl) {
    try {
      const normalized = input.startsWith("http://") || input.startsWith("https://") ? input : `https://${input}`;
      const parsed = new URL(normalized);
      hostname = parsed.hostname.toLowerCase();
      pathPart = parsed.pathname || "";
    } catch {
      add("social.invalid_url", "URL profilo non valida", 0.35, "Il profilo sembra un URL ma non e interpretabile correttamente.", null);
    }
  }

  const socialHosts = new Set([
    "x.com",
    "twitter.com",
    "instagram.com",
    "facebook.com",
    "tiktok.com",
    "youtube.com",
    "linkedin.com",
    "threads.net",
    "t.me"
  ]);

  if (hostname) {
    const knownHost = Array.from(socialHosts).some((h) => hostname === h || hostname.endsWith(`.${h}`));
    if (!knownHost) {
      add(
        "social.unknown_host",
        "Host social non standard",
        0.2,
        "Il link non punta a una piattaforma social tipica. Potrebbe essere mirror/fake landing o pagina intermedia.",
        { hostname }
      );
    }
  }

  const handle = pathPart.replace(/^\/+/, "").split(/[/?#]/)[0] || input.replace(/^@/, "");
  const handleLower = handle.toLowerCase();
  const handleCompact = handleLower.replace(/[^a-z0-9]/g, "");

  if (handle && handle.length >= 4) {
    const digits = (handle.match(/[0-9]/g) || []).length;
    const digitRatio = digits / handle.length;
    if (digitRatio >= 0.35) {
      add(
        "social.handle_digits",
        "Handle con molte cifre",
        0.2,
        "Handle con molte cifre possono indicare account usa-e-getta o tentativi di impersonazione.",
        { handle }
      );
    }
  }

  const protectedBrands = ["paypal", "poste", "amazon", "google", "netflix", "bancomat", "intesa", "unicredit"];
  const brandHit = protectedBrands.find((b) => handleCompact.includes(b));
  if (brandHit) {
    const exact = handleCompact === brandHit;
    if (!exact) {
      add(
        "social.brand_spoof",
        "Possibile impersonazione brand",
        0.5,
        "L'handle include un nome brand con aggiunte/modifiche: pattern frequente nei profili fake.",
        { brand: brandHit, handle }
      );
    }
  }

  if (/[._-]{2,}/.test(handle)) {
    add(
      "social.handle_noise",
      "Handle con pattern rumoroso",
      0.12,
      "Sequenze ripetute di simboli possono essere indizio di account creato rapidamente o imitazione.",
      { handle }
    );
  }

  const score = scoreFromReasons(findings);
  return {
    input,
    type: "social",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity)
  };
}

function analyzeImage(imageValue) {
  const input = String(imageValue ?? "").trim();
  const findings = [];

  const add = (id, label, severity, why, evidence) => {
    findings.push({ id, label, severity: clamp01(severity), why, evidence });
  };

  if (!input) {
    add("image.empty", "Immagine mancante", 0.2, "Non c’è immagine da verificare.", null);
  } else if (looksLikeUrl(input)) {
    add(
      "image.url_only",
      "Analisi immagine non implementata",
      0.15,
      "Questo MVP accetta solo un link immagine. In una versione successiva può scaricare l’immagine, calcolare hash percettivi e fare controlli OSINT.",
      null
    );
  } else {
    add(
      "image.unsupported",
      "Formato immagine non riconosciuto",
      0.25,
      "Il valore non sembra un URL immagine. In una versione successiva si può supportare upload file o data URL.",
      null
    );
  }

  const score = Math.round(100 * (1 - Math.exp(-findings.reduce((acc, f) => acc + f.severity, 0))));
  return {
    input,
    type: "image",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity)
  };
}

function analyze(payload) {
  const value = payload?.value;
  const explicitType = payload?.type;

  if (explicitType === "url") return analyzeUrl(value);
  if (explicitType === "text") return analyzeText(value);
  if (explicitType === "news") return analyzeNews(value);
  if (explicitType === "social") return analyzeSocial(value);
  if (explicitType === "image") return analyzeImage(value);

  if (looksLikeUrl(value)) return analyzeUrl(value);
  return analyzeNews(value);
}

const INDEX_HTML = `<!doctype html>
<html lang="it">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ZeroBogus (MVP)</title>
    ${THEME_CSS_URL ? `<link rel="stylesheet" href="${THEME_CSS_URL.replace(/"/g, "%22")}" />` : ""}
    <style>
      :root { color-scheme: light dark; }
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; max-width: 880px; }
      .row { display: flex; gap: 12px; flex-wrap: wrap; }
      input, textarea, select, button { font: inherit; }
      textarea { width: 100%; min-height: 140px; }
      .card { border: 1px solid rgba(127,127,127,.35); border-radius: 12px; padding: 16px; }
      .muted { opacity: .75; }
      .badge { display: inline-block; padding: 3px 10px; border-radius: 999px; border: 1px solid rgba(127,127,127,.35); }
      .reasons { margin-top: 12px; }
      .reason { padding: 10px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); margin: 8px 0; }
      .reason b { display: block; }
      .kpi { display: flex; gap: 12px; flex-wrap: wrap; }
      .kpi .card { flex: 1 1 160px; }
      button { padding: 10px 14px; border-radius: 10px; border: 1px solid rgba(127,127,127,.35); cursor: pointer; }
      .history-item { padding: 10px 12px; border-radius: 10px; border: 1px solid rgba(127,127,127,.25); margin: 8px 0; cursor: pointer; }
      .history-item:hover { border-color: rgba(127,127,127,.5); }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      .cap-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
      .cap-card { border: 1px solid rgba(127,127,127,.3); border-radius: 12px; padding: 12px; }
    </style>
  </head>
  <body>
    <h1>ZeroBogus Suite</h1>
    <p class="muted">Piattaforma di verifica multi-canale: link, news/testi, account social e immagini. Il link checker e solo uno dei moduli.</p>

    <div class="card" style="margin-bottom: 16px;">
      <div class="row" style="align-items: center; justify-content: space-between;">
        <div>
          <div style="font-weight: 650;">Copertura Moduli</div>
          <div class="muted">Stato funzionalita e tipologie di verifica disponibili</div>
        </div>
        <button id="refreshCaps">Aggiorna moduli</button>
      </div>
      <div id="capabilities" class="cap-grid" style="margin-top: 10px;"></div>
    </div>

    <div class="card">
      <div class="row" style="align-items: center;">
        <label>
          Modalita
          <select id="type">
            <option value="">Auto</option>
            <option value="url">Link Intelligence</option>
            <option value="news">News/Claim Check</option>
            <option value="social">Social Account Check</option>
            <option value="text">Testo libero</option>
            <option value="image">Immagine (URL)</option>
          </select>
        </label>
        <button id="analyzeBtn">Analizza</button>
        <span id="status" class="muted"></span>
      </div>
      <div style="margin-top: 10px;">
        <textarea id="value" placeholder="Incolla qui un link, testo news/claim, handle social o URL immagine..."></textarea>
      </div>
      <div class="row" style="margin-top: 10px; align-items: center; justify-content: space-between;">
        <label class="muted" style="display:flex; gap:8px; align-items:center;">
          <input id="externalConsent" type="checkbox" />
          Consento verifiche esterne (es. URLScan) per arricchire il report
        </label>
        <span class="muted">Privacy: per default non salva input completo</span>
      </div>
    </div>

    <div id="result" style="margin-top: 16px; display:none;">
      <div class="kpi">
        <div class="card">
          <div class="muted">Verdetto</div>
          <div id="verdict" style="font-size: 20px; font-weight: 650;"></div>
        </div>
        <div class="card">
          <div class="muted">Rischio</div>
          <div id="score" style="font-size: 20px; font-weight: 650;"></div>
        </div>
        <div class="card">
          <div class="muted">ID analisi</div>
          <div id="analysisId" class="mono" style="font-size: 14px; font-weight: 650; word-break: break-all;"></div>
        </div>
        <div class="card">
          <div class="muted">URLScan</div>
          <div id="urlscanStatus" style="font-size: 14px; font-weight: 650;"></div>
          <div style="margin-top: 6px;">
            <a id="urlscanLink" class="muted" href="#" target="_blank" rel="noreferrer" style="display:none;">Apri report</a>
          </div>
        </div>
      </div>

      <div class="card reasons">
        <div class="muted">Motivazioni</div>
        <div id="reasons"></div>
      </div>
    </div>

    <div class="card" style="margin-top: 16px;">
      <div class="row" style="align-items: center; justify-content: space-between;">
        <div>
          <div style="font-weight: 650;">Cronologia</div>
          <div class="muted">Ultime analisi salvate localmente</div>
        </div>
        <div class="row" style="gap: 8px;">
          <button id="refreshHistory">Aggiorna</button>
          <button id="clearHistory">Svuota</button>
        </div>
      </div>
      <div id="history" style="margin-top: 10px;"></div>
    </div>

    <script>
      const basePath = (() => {
        const p = window.location.pathname || "/";
        if (p === "/") return "";
        return p.endsWith("/") ? p.slice(0, -1) : p;
      })();

      const typeEl = document.getElementById("type");
      const valueEl = document.getElementById("value");
      const btn = document.getElementById("analyzeBtn");
      const statusEl = document.getElementById("status");
      const externalConsentEl = document.getElementById("externalConsent");
      const resultEl = document.getElementById("result");
      const verdictEl = document.getElementById("verdict");
      const scoreEl = document.getElementById("score");
      const analysisIdEl = document.getElementById("analysisId");
      const urlscanStatusEl = document.getElementById("urlscanStatus");
      const urlscanLinkEl = document.getElementById("urlscanLink");
      const reasonsEl = document.getElementById("reasons");
      const capabilitiesEl = document.getElementById("capabilities");
      const refreshCapsBtn = document.getElementById("refreshCaps");
      const historyEl = document.getElementById("history");
      const refreshHistoryBtn = document.getElementById("refreshHistory");
      const clearHistoryBtn = document.getElementById("clearHistory");

      function verdictLabel(v) {
        if (v === "high_risk") return "Alto rischio";
        if (v === "medium_risk") return "Rischio medio";
        return "Basso rischio";
      }

      function esc(s) {
        return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#039;" }[c]));
      }

      function typeLabel(type) {
        if (type === "url") return "Link";
        if (type === "news") return "News";
        if (type === "social") return "Social";
        if (type === "image") return "Immagine";
        if (type === "text") return "Testo";
        return type || "";
      }

      function renderCapabilities(items) {
        if (!items || items.length === 0) {
          capabilitiesEl.innerHTML = '<div class="muted">Nessun modulo disponibile.</div>';
          return;
        }
        capabilitiesEl.innerHTML = items.map((it) => (
          '<div class="cap-card">' +
            '<div class="row" style="align-items: baseline; justify-content: space-between;">' +
              '<div style="font-weight:650;">' + esc(it.title || it.key || "") + '</div>' +
              '<span class="badge">' + esc(it.status === "available" ? "attivo" : "preview") + '</span>' +
            '</div>' +
            '<div class="muted" style="margin-top:6px;">' + esc(it.description || "") + '</div>' +
            '<div class="muted" style="margin-top:8px;">' + esc((it.checks || []).slice(0, 3).join(" | ")) + '</div>' +
          '</div>'
        )).join("");
      }

      async function loadCapabilities() {
        try {
          const res = await fetch(basePath + "/api/capabilities");
          const data = await res.json();
          renderCapabilities(data.items || []);
        } catch {
          capabilitiesEl.innerHTML = '<div class="muted">Errore nel caricamento moduli.</div>';
        }
      }

      function renderReasons(reasons) {
        reasonsEl.innerHTML = (reasons || []).map(r => (
          '<div class="reason">' +
            '<b>' + esc(r.label) + ' <span class="badge">sev ' + esc(Number(r.severity || 0).toFixed(2)) + '</span></b>' +
            '<div class="muted">' + esc(r.why) + '</div>' +
          '</div>'
        )).join("") || '<div class="muted">Nessuna motivazione rilevata.</div>';
      }

      function renderUrlscan(osint) {
        const info = osint && osint.urlscan ? osint.urlscan : null;
        const status = info && info.status ? String(info.status) : "";
        if (!status) {
          urlscanStatusEl.textContent = "Non attivo";
          urlscanLinkEl.style.display = "none";
          urlscanLinkEl.removeAttribute("href");
          return;
        }

        if (status === "pending") urlscanStatusEl.textContent = "In corso…";
        else if (status === "ready") urlscanStatusEl.textContent = "Pronto";
        else if (status === "timeout") urlscanStatusEl.textContent = "Timeout";
        else if (status === "error") urlscanStatusEl.textContent = "Errore";
        else urlscanStatusEl.textContent = status;

        const link = info && info.reportURL ? String(info.reportURL) : "";
        if (link) {
          urlscanLinkEl.style.display = "inline";
          urlscanLinkEl.setAttribute("href", link);
        } else {
          urlscanLinkEl.style.display = "none";
          urlscanLinkEl.removeAttribute("href");
        }
      }

      function formatDate(s) {
        const d = new Date(s);
        if (Number.isNaN(d.getTime())) return String(s || "");
        return d.toLocaleString();
      }

      function renderHistory(items) {
        if (!items || items.length === 0) {
          historyEl.innerHTML = '<div class="muted">Nessuna analisi salvata.</div>';
          return;
        }
        historyEl.innerHTML = items.map((it) => (
          '<div class="history-item" data-id="' + esc(it.id) + '">' +
            '<div class="row" style="justify-content: space-between; align-items: baseline;">' +
              '<div>' +
                '<span class="badge">' + esc(typeLabel(it.type || "")) + '</span> ' +
                (it.urlscanStatus ? '<span class="badge">urlscan ' + esc(it.urlscanStatus) + '</span> ' : '') +
                '<span style="font-weight:650;">' + esc(verdictLabel(it.verdict)) + '</span> <span class="muted">' + esc(it.score) + '/100</span>' +
              '</div>' +
              '<div class="muted">' + esc(formatDate(it.createdAt)) + '</div>' +
            '</div>' +
            '<div class="muted" style="margin-top:6px;">' + esc(it.inputPreview || "") + '</div>' +
          '</div>'
        )).join("");
      }

      async function loadHistory() {
        try {
          const res = await fetch(basePath + "/api/history?limit=20");
          const data = await res.json();
          renderHistory(data.items || []);
        } catch {
          historyEl.innerHTML = '<div class="muted">Errore nel caricamento cronologia.</div>';
        }
      }

      historyEl.addEventListener("click", async (ev) => {
        const el = ev.target.closest(".history-item");
        if (!el) return;
        const id = el.getAttribute("data-id");
        if (!id) return;
        statusEl.textContent = "Caricamento analisi...";
        try {
          const res = await fetch(basePath + "/api/history/" + encodeURIComponent(id));
          const data = await res.json();
          resultEl.style.display = "block";
          verdictEl.textContent = verdictLabel(data.verdict);
          scoreEl.textContent = data.score + "/100";
          analysisIdEl.textContent = data.id || "";
          renderUrlscan(data.osint || null);
          renderReasons(data.reasons || []);
          statusEl.textContent = "";
        } catch {
          statusEl.textContent = "Errore nel caricamento analisi.";
        }
      });

      refreshCapsBtn.addEventListener("click", () => loadCapabilities());
      refreshHistoryBtn.addEventListener("click", () => loadHistory());
      clearHistoryBtn.addEventListener("click", async () => {
        if (!confirm("Vuoi svuotare la cronologia delle analisi?")) return;
        statusEl.textContent = "Svuotamento cronologia...";
        try {
          await fetch(basePath + "/api/history", { method: "DELETE" });
          loadHistory();
          statusEl.textContent = "";
        } catch {
          statusEl.textContent = "Errore nello svuotamento cronologia.";
        }
      });

      btn.addEventListener("click", async () => {
        const payload = { type: typeEl.value || undefined, value: valueEl.value, externalConsent: !!externalConsentEl.checked };
        statusEl.textContent = "Analisi in corso...";
        btn.disabled = true;
        try {
          const res = await fetch(basePath + "/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          });
          const data = await res.json();
          resultEl.style.display = "block";
          verdictEl.textContent = verdictLabel(data.verdict);
          scoreEl.textContent = data.score + "/100";
          analysisIdEl.textContent = data.id || "";
          renderUrlscan(data.osint || null);
          renderReasons(data.reasons || []);
          statusEl.textContent = "";
          loadHistory();
        } catch (e) {
          statusEl.textContent = "Errore durante l’analisi.";
        } finally {
          btn.disabled = false;
        }
      });

      loadHistory();
      loadCapabilities();
      renderUrlscan(null);
    </script>
  </body>
</html>`;

const server = http.createServer(async (req, res) => {
  const method = req.method || "GET";
  const reqUrl = req.url || "/";
  const parsedUrl = new URL(reqUrl, "http://localhost");
  const pathname = stripBasePath(parsedUrl.pathname);

  if (method === "GET" && pathname === "/") {
    sendText(res, 200, INDEX_HTML, "text/html; charset=utf-8");
    return;
  }

  if (method === "GET" && pathname === "/health") {
    sendJson(res, 200, { ok: true, name: "ZeroBogus", version: "0.1.0" });
    return;
  }

  if (method === "GET" && pathname === "/api/capabilities") {
    sendJson(res, 200, { items: CAPABILITIES });
    return;
  }

  if (method === "DELETE" && pathname === "/api/history") {
    clearHistory();
    sendJson(res, 200, { ok: true });
    return;
  }

  if (method === "GET" && pathname === "/api/history") {
    const limitRaw = parsedUrl.searchParams.get("limit");
    const offsetRaw = parsedUrl.searchParams.get("offset");
    const limit = Math.max(1, Math.min(200, Number(limitRaw || 50) || 50));
    const offset = Math.max(0, Number(offsetRaw || 0) || 0);
    sendJson(res, 200, { items: listHistory({ limit, offset }) });
    return;
  }

  if (method === "GET" && pathname.startsWith("/api/history/")) {
    const id = decodeURIComponent(pathname.slice("/api/history/".length));
    const record = getHistoryById(id);
    if (!record) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    sendJson(res, 200, record);
    return;
  }

  if (method === "POST" && pathname === "/api/analyze") {
    try {
      const contentType = String(req.headers["content-type"] || "");
      if (!contentType.toLowerCase().includes("application/json")) {
        sendJson(res, 415, { error: "Unsupported Media Type. Use application/json." });
        return;
      }

      const body = await readJsonBody(req);
      const requestedType = String(body?.type || "");
      const inputValue = body?.value;
      const externalConsent = body?.externalConsent === true;

      let preparedValue = inputValue;
      let newsMeta = null;
      let extractedLinks = [];

      if (FETCH_ARTICLE_ENABLED && requestedType === "news" && looksLikeUrl(inputValue)) {
        const urlToFetch = normalizeUrlForScan(inputValue);
        const fetched = await fetchTextFromUrl(urlToFetch);
        if (String(fetched.contentType || "").toLowerCase().includes("text/html")) {
          extractedLinks = extractLinksFromHtml(fetched.raw, urlToFetch);
          preparedValue = htmlToText(fetched.raw);
        } else {
          preparedValue = String(fetched.raw || "");
        }

        newsMeta = {
          sourceUrl: urlToFetch,
          extractedChars: String(preparedValue || "").length,
          extractedLinks: extractedLinks.length
        };
      }

      let result = analyze({ ...(body || {}), value: preparedValue });
      if (requestedType === "news" && newsMeta) {
        const infoReason = {
          id: "news.fetched",
          label: "Contenuto estratto da URL",
          severity: 0,
          why: "Per analizzare la news, il server ha scaricato e convertito la pagina in testo (senza salvare il contenuto completo per default).",
          evidence: newsMeta
        };
        result = { ...result, meta: { ...(result?.meta || {}), ...newsMeta }, reasons: [infoReason, ...(result?.reasons || [])] };

        const linkAnalyses = extractedLinks.slice(0, 40).map((u) => analyzeUrl(u));
        const risky = linkAnalyses
          .filter((a) => a && typeof a.score === "number" && a.score >= 45)
          .sort((a, b) => b.score - a.score)
          .slice(0, 6)
          .map((a) => ({ url: a.input, score: a.score, verdict: a.verdict }));

        if (risky.length > 0) {
          const sev = risky.some((x) => x.score >= 75) ? 0.45 : 0.28;
          const linkReason = {
            id: "news.suspicious_links",
            label: "Link potenzialmente sospetti nel contenuto",
            severity: sev,
            why: "Nel contenuto estratto sono presenti link con segnali tipici di phishing/tracking/redirect. Verifica la destinazione reale e il contesto.",
            evidence: { count: risky.length, top: risky }
          };
          result = { ...result, reasons: [linkReason, ...(result?.reasons || [])] };
        }
      }

      const type = result?.type || requestedType;
      const persisted = persistAnalysis({ type, inputValue, result });
      let urlscan = null;

      const canUseExternal = !EXTERNAL_CHECKS_REQUIRE_CONSENT || externalConsent;

      if (URLSCAN_ENABLED && URLSCAN_API_KEY && canUseExternal && type === "url") {
        const urlToScan = normalizeUrlForScan(inputValue);
        if (urlToScan) {
          try {
            const submit = await urlscanSubmit(urlToScan);
            persistEvent({
              kind: "urlscan.submit",
              analysisId: persisted.id,
              uuid: submit?.uuid,
              result: submit?.result,
              api: submit?.api
            });
            if (submit?.uuid) scheduleUrlscanPolling({ analysisId: persisted.id, uuid: String(submit.uuid) });

            urlscan = {
              status: "pending",
              uuid: submit?.uuid || null,
              reportURL: submit?.result || null
            };
          } catch (e) {
            persistEvent({
              kind: "urlscan.error",
              analysisId: persisted.id,
              uuid: null,
              error: String(e?.message || e)
            });
            urlscan = {
              status: "error",
              uuid: null,
              reportURL: null,
              error: String(e?.message || e)
            };
          }
        }
      }

      if (URLSCAN_ENABLED && URLSCAN_API_KEY && canUseExternal && type === "news" && newsMeta?.sourceUrl) {
        try {
          const submit = await urlscanSubmit(String(newsMeta.sourceUrl));
          persistEvent({
            kind: "urlscan.submit",
            analysisId: persisted.id,
            uuid: submit?.uuid,
            result: submit?.result,
            api: submit?.api
          });
          if (submit?.uuid) scheduleUrlscanPolling({ analysisId: persisted.id, uuid: String(submit.uuid) });
          urlscan = {
            status: "pending",
            uuid: submit?.uuid || null,
            reportURL: submit?.result || null
          };
        } catch (e) {
          persistEvent({
            kind: "urlscan.error",
            analysisId: persisted.id,
            uuid: null,
            error: String(e?.message || e)
          });
          urlscan = {
            status: "error",
            uuid: null,
            reportURL: null,
            error: String(e?.message || e)
          };
        }
      }

      sendJson(res, 200, {
        ...result,
        id: persisted.id,
        createdAt: persisted.createdAt,
        osint: {
          urlscan
        }
      });
      return;
    } catch (err) {
      const statusCode = Number(err?.statusCode) || 500;
      sendJson(res, statusCode, { error: err?.message || "Internal error" });
      return;
    }
  }

  sendJson(res, 404, { error: "Not found" });
});

server.listen(PORT, () => {
  process.stdout.write(`ZeroBogus listening on http://localhost:${PORT}\n`);
});
