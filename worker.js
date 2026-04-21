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

function scoreFromReasons(reasons) {
  const sum = (Array.isArray(reasons) ? reasons : []).reduce((acc, r) => acc + clamp01(Number(r?.severity) || 0), 0);
  return Math.round(100 * (1 - Math.exp(-sum)));
}

function tr(lang, it, en) {
  const l = String(lang || "it").toLowerCase();
  return l.startsWith("en") ? en : it;
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

function normalizeUrlForHttp(value) {
  const input = String(value ?? "").trim();
  if (!input) return "";
  if (input.startsWith("http://") || input.startsWith("https://")) return input;
  return `https://${input}`;
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

function isProbablyIpHostname(hostname) {
  if (!hostname) return false;
  const parts = hostname.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^[0-9]{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isPunycode(hostname) {
  return typeof hostname === "string" && hostname.includes("xn--");
}

function analyzeUrl(urlValue, lang) {
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
          label: tr(lang, "URL non valida", "Invalid URL"),
          severity: 0.9,
          why: tr(
            lang,
            "Il valore non è una URL interpretabile: molti contenuti bogus usano URL spezzate/ambigue per confondere.",
            "The value is not a valid URL: bogus content often uses broken/ambiguous URLs to confuse users."
          )
        }
      ]
    };
  }

  const hostname = parsed.hostname;
  const full = parsed.toString();

  const add = (id, label, severity, why, evidence) => {
    findings.push({ id, label, severity: clamp01(severity), why, evidence });
  };

  if (parsed.protocol !== "https:") {
    add(
      "url.no_https",
      tr(lang, "Connessione non HTTPS", "Non-HTTPS connection"),
      0.35,
      tr(lang, "I siti senza HTTPS aumentano il rischio di manomissioni e phishing.", "Sites without HTTPS increase the risk of tampering and phishing."),
      { protocol: parsed.protocol }
    );
  }

  if (isProbablyIpHostname(hostname)) {
    add(
      "url.ip_host",
      tr(lang, "Hostname è un IP", "Hostname is an IP"),
      0.6,
      tr(
        lang,
        "Molti link malevoli usano IP diretti per evitare controlli e mascherare il dominio.",
        "Many malicious links use raw IPs to bypass checks and hide the real domain."
      ),
      { hostname }
    );
  }

  if (isPunycode(hostname)) {
    add(
      "url.punycode",
      tr(lang, "Dominio con punycode", "Punycode domain"),
      0.5,
      tr(
        lang,
        "Il punycode può essere usato per omografi (domini simili visivamente). Non è sempre malevolo, ma va verificato.",
        "Punycode can be used for homograph attacks (lookalike domains). Not always malicious, but worth checking."
      ),
      { hostname }
    );
  }

  const tld = hostname.split(".").slice(-1)[0]?.toLowerCase();
  const riskyTlds = new Set(["zip", "mov", "top", "xyz", "click", "cam", "live", "support", "fit", "icu"]);
  if (tld && riskyTlds.has(tld)) {
    add(
      "url.risky_tld",
      tr(lang, "TLD frequentemente abusato", "Commonly abused TLD"),
      0.35,
      tr(lang, "Alcuni TLD sono statisticamente più abusati per campagne di spam/phishing.", "Some TLDs are statistically more abused for spam/phishing campaigns."),
      { tld }
    );
  }

  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount >= 3) {
    add(
      "url.many_subdomains",
      tr(lang, "Molti sottodomini", "Many subdomains"),
      0.25,
      tr(
        lang,
        "Molti sottodomini possono essere usati per imitare brand (es. login.secure.brand...).",
        "Many subdomains can be used to imitate brands (e.g. login.secure.brand...)."
      ),
      { subdomainCount, hostname }
    );
  }

  if (full.length >= 120) {
    add(
      "url.very_long",
      tr(lang, "URL molto lunga", "Very long URL"),
      0.25,
      tr(lang, "Le URL lunghe possono nascondere parametri ingannevoli (redirect, tracking, esche).", "Long URLs can hide misleading parameters (redirects, tracking, bait)."),
      { length: full.length }
    );
  }

  if (parsed.username || parsed.password || input.includes("@")) {
    add(
      "url.userinfo_or_at",
      tr(lang, "Carattere @ o credenziali nella URL", "@ in URL or embedded credentials"),
      0.65,
      tr(lang, "Il pattern con @ può essere usato per confondere l’utente sul vero dominio finale.", "The @ pattern can be used to confuse users about the real final domain."),
      { username: parsed.username ? "[present]" : null }
    );
  }

  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const phishingKeywords = ["login", "signin", "verify", "account", "secure", "update", "password", "bank", "wallet"];
  const hit = phishingKeywords.find((k) => pathAndQuery.includes(k));
  if (hit) {
    add(
      "url.phishing_keyword",
      tr(lang, "Keyword tipica di phishing", "Common phishing keyword"),
      0.35,
      tr(
        lang,
        "Alcune parole in path/parametri sono comuni nei tentativi di furto credenziali. Va valutato il contesto.",
        "Some words in the path/query are common in credential theft attempts. Evaluate the context."
      ),
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
      tr(lang, "Link con tracking/affiliazione", "Tracking/affiliate link"),
      0.08,
      tr(
        lang,
        "Parametri di tracking/affiliazione non indicano per forza un contenuto bogus, ma possono impattare privacy e mascherare la destinazione reale in catene di redirect.",
        "Tracking/affiliate parameters are not necessarily bogus, but can impact privacy and hide the real destination in redirect chains."
      ),
      { params: trackingHits.slice(0, 8) }
    );
  }

  const redirectParams = ["redirect", "redir", "url", "next", "target", "dest", "destination", "continue", "return"];
  const redirectKey = params.find((k) => redirectParams.includes(k.toLowerCase()));
  if (redirectKey) {
    add(
      "url.redirect_param",
      tr(lang, "Possibile redirect", "Possible redirect"),
      0.3,
      tr(lang, "I parametri di redirect possono essere usati per catene di reindirizzamento e phishing.", "Redirect parameters can be used for redirect chains and phishing."),
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
      tr(lang, "Dominio con molti numeri", "Domain with many digits"),
      0.25,
      tr(lang, "Domini generati automaticamente o usa-e-getta spesso contengono molte cifre.", "Automatically generated or throwaway domains often contain many digits."),
      { digitRatio: Number(digitRatio.toFixed(2)), hostname }
    );
  }

  const score = scoreFromReasons(findings);
  return {
    input,
    type: "url",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity)
  };
}

function analyzeText(textValue, lang) {
  const input = String(textValue ?? "");
  const s = input.trim();
  const findings = [];

  const add = (id, label, severity, why, evidence) => {
    findings.push({ id, label, severity: clamp01(severity), why, evidence });
  };

  if (!s) {
    add("text.empty", tr(lang, "Testo vuoto", "Empty text"), 0.2, tr(lang, "Non c’è contenuto da verificare.", "There is no content to check."), null);
  }

  const upper = s.replace(/[^A-ZÀ-ÖØ-Ý]/g, "").length;
  const letters = s.replace(/[^A-ZÀ-ÖØ-Ýa-zà-öø-ý]/g, "").length;
  const upperRatio = letters ? upper / letters : 0;
  if (upperRatio >= 0.55 && letters >= 40) {
    add(
      "text.allcaps",
      tr(lang, "Molte maiuscole", "Too many uppercase letters"),
      0.2,
      tr(lang, "Testi allarmistici/spam usano spesso maiuscole per forzare attenzione.", "Alarmist/spam content often uses all-caps to force attention."),
      { upperRatio: Number(upperRatio.toFixed(2)) }
    );
  }

  const exclam = (s.match(/!/g) || []).length;
  if (exclam >= 4) {
    add(
      "text.exclamation",
      tr(lang, "Molti punti esclamativi", "Many exclamation marks"),
      0.2,
      tr(lang, "Enfasi eccessiva è frequente in contenuti manipolatori.", "Excessive emphasis is common in manipulative content."),
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
      tr(lang, "Linguaggio sensazionalistico", "Sensational language"),
      0.25,
      tr(lang, "Titoli/claim sensazionalistici aumentano la probabilità di clickbait o disinformazione.", "Sensational headlines/claims increase the likelihood of clickbait or misinformation."),
      { keyword: sensationalHit }
    );
  }

  const hasSource = /(fonte|source|secondo|according to|rapport|report|studio|study)\b/i.test(s);
  const hasLink = /\bhttps?:\/\/\S+/i.test(s);
  if (!hasSource && !hasLink && s.length >= 200) {
    add(
      "text.no_sources",
      tr(lang, "Assenza di fonti esplicite", "No explicit sources"),
      0.25,
      tr(
        lang,
        "Un contenuto lungo che fa affermazioni senza citare fonti è più difficile da verificare e spesso meno affidabile.",
        "Long content making claims without sources is harder to verify and often less reliable."
      ),
      null
    );
  }

  const claimsNumbers = (s.match(/\b\d{2,}\b/g) || []).length;
  if (claimsNumbers >= 4 && !hasSource) {
    add("text.many_numbers_no_sources", tr(lang, "Molti numeri senza fonte", "Many numbers without sources"), 0.25, tr(lang, "Statistiche/percentuali senza fonte possono indicare dati inventati o distorti.", "Statistics/percentages without sources may be invented or distorted."), {
      numbers: claimsNumbers
    });
  }

  const score = scoreFromReasons(findings);
  return {
    input,
    type: "text",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity)
  };
}

function analyzeNews(newsValue, lang) {
  const base = analyzeText(newsValue, lang);
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
      tr(lang, "Nessun riferimento temporale", "No time reference"),
      0.14,
      tr(lang, "Una news senza data o periodo di riferimento è più difficile da contestualizzare e verificare.", "News without a date/time reference is harder to contextualize and verify."),
      null
    );
  }

  const fakeUrgencyWords = ["ultima ora", "breaking", "urgente", "diffondi subito", "censurato", "prima che cancellino"];
  const urgencyHit = fakeUrgencyWords.find((w) => lower.includes(w));
  if (urgencyHit) {
    add(
      "news.urgency_narrative",
      tr(lang, "Narrativa di urgenza", "Urgency narrative"),
      0.22,
      tr(
        lang,
        "Le narrazioni di urgenza estrema sono spesso usate per ridurre il pensiero critico e indurre condivisioni immediate.",
        "Extreme urgency narratives are often used to reduce critical thinking and push immediate sharing."
      ),
      { keyword: urgencyHit }
    );
  }

  const score = scoreFromReasons(findings);
  return {
    input: base.input,
    type: "news",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity),
    meta: base.meta || null
  };
}

function analyzeSocial(profileValue, lang) {
  const input = String(profileValue ?? "").trim();
  const findings = [];

  const add = (id, label, severity, why, evidence) => {
    findings.push({ id, label, severity: clamp01(severity), why, evidence });
  };

  if (!input) {
    add(
      "social.empty",
      tr(lang, "Profilo non fornito", "No profile provided"),
      0.2,
      tr(lang, "Inserisci handle o URL del profilo social da verificare.", "Paste a social handle or profile URL to check."),
      null
    );
    const score = scoreFromReasons(findings);
    return { input, type: "social", score, verdict: scoreToVerdict(score), reasons: findings };
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
      add(
        "social.invalid_url",
        tr(lang, "URL profilo non valida", "Invalid profile URL"),
        0.35,
        tr(lang, "Il profilo sembra un URL ma non è interpretabile correttamente.", "The value looks like a URL but cannot be parsed correctly."),
        null
      );
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
        tr(lang, "Host social non standard", "Non-standard social host"),
        0.2,
        tr(
          lang,
          "Il link non punta a una piattaforma social tipica. Potrebbe essere mirror/fake landing o pagina intermedia.",
          "The link does not point to a typical social platform. It may be a mirror/fake landing page or intermediate page."
        ),
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
      add("social.handle_digits", tr(lang, "Handle con molte cifre", "Handle with many digits"), 0.2, tr(lang, "Handle con molte cifre possono indicare account usa-e-getta o tentativi di impersonazione.", "Handles with many digits can indicate throwaway accounts or impersonation attempts."), {
        handle
      });
    }
  }

  const protectedBrands = ["paypal", "poste", "amazon", "google", "netflix", "bancomat", "intesa", "unicredit"];
  const brandHit = protectedBrands.find((b) => handleCompact.includes(b));
  if (brandHit) {
    const exact = handleCompact === brandHit;
    if (!exact) {
      add(
        "social.brand_spoof",
        tr(lang, "Possibile impersonazione brand", "Possible brand impersonation"),
        0.5,
        tr(
          lang,
          "L'handle include un nome brand con aggiunte/modifiche: pattern frequente nei profili fake.",
          "The handle contains a brand name with extra characters/changes: a common pattern in fake profiles."
        ),
        { brand: brandHit, handle }
      );
    }
  }

  if (/[._-]{2,}/.test(handle)) {
    add("social.handle_noise", tr(lang, "Handle con pattern rumoroso", "Noisy handle pattern"), 0.12, tr(lang, "Sequenze ripetute di simboli possono essere indizio di account creato rapidamente o imitazione.", "Repeated symbol sequences can indicate a quickly created account or imitation."), {
      handle
    });
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

function analyzeImage(imageValue, lang) {
  const input = String(imageValue ?? "").trim();
  const findings = [];

  const add = (id, label, severity, why, evidence) => {
    findings.push({ id, label, severity: clamp01(severity), why, evidence });
  };

  if (!input) {
    add("image.empty", tr(lang, "Immagine mancante", "Missing image"), 0.2, tr(lang, "Non c’è immagine da verificare.", "There is no image to check."), null);
  } else if (looksLikeUrl(input)) {
    add(
      "image.url_only",
      tr(lang, "Analisi immagine non implementata", "Image analysis not implemented"),
      0.15,
      tr(
        lang,
        "Questo MVP accetta solo un link immagine. In una versione successiva può fare reverse-search con consenso e controlli di manipolazione.",
        "This MVP only accepts an image URL. A future version may support consent-based reverse search and manipulation checks."
      ),
      null
    );
  } else {
    add(
      "image.unsupported",
      tr(lang, "Formato immagine non riconosciuto", "Unrecognized image format"),
      0.25,
      tr(
        lang,
        "Il valore non sembra un URL immagine. In una versione successiva si può supportare upload file o data URL.",
        "The value does not look like an image URL. A future version may support file upload or data URLs."
      ),
      null
    );
  }

  const score = scoreFromReasons(findings);
  return {
    input,
    type: "image",
    score,
    verdict: scoreToVerdict(score),
    reasons: findings.sort((a, b) => b.severity - a.severity)
  };
}

function analyze(payload, lang) {
  const value = payload?.value;
  const explicitType = payload?.type;

  if (explicitType === "url") return analyzeUrl(value, lang);
  if (explicitType === "text") return analyzeText(value, lang);
  if (explicitType === "news") return analyzeNews(value, lang);
  if (explicitType === "social") return analyzeSocial(value, lang);
  if (explicitType === "image") return analyzeImage(value, lang);

  if (looksLikeUrl(value)) return analyzeUrl(value, lang);
  return analyzeNews(value, lang);
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

function isBlockedHostname(hostname) {
  const h = String(hostname || "").toLowerCase().trim();
  if (!h) return true;
  if (h === "localhost") return true;
  if (h.endsWith(".localhost")) return true;
  if (h === "0.0.0.0") return true;
  if (h === "[::1]") return true;
  return false;
}

function isPrivateIpv4(ip) {
  const parts = ip.split(".").map((x) => Number(x));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return true;
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

function assertPublicHttpUrl(urlValue) {
  const raw = String(urlValue ?? "").trim();
  if (!raw) throw Object.assign(new Error("URL missing"), { statusCode: 400 });
  const parsed = new URL(raw);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw Object.assign(new Error("Unsupported protocol"), { statusCode: 400 });
  if (parsed.username || parsed.password) throw Object.assign(new Error("Credentials in URL not allowed"), { statusCode: 400 });
  if (isBlockedHostname(parsed.hostname)) throw Object.assign(new Error("Blocked hostname"), { statusCode: 400 });
  if (parsed.port && parsed.port !== "80" && parsed.port !== "443") throw Object.assign(new Error("Blocked port"), { statusCode: 400 });
  if (isProbablyIpHostname(parsed.hostname) && isPrivateIpv4(parsed.hostname)) throw Object.assign(new Error("Blocked IP"), { statusCode: 400 });
  return parsed.toString();
}

async function fetchTextFromUrl(urlToFetch, { maxBytes, timeoutMs }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const visited = new Set();
    let current = assertPublicHttpUrl(urlToFetch);
    let res = null;

    for (let i = 0; i < 6; i += 1) {
      if (visited.has(current)) throw Object.assign(new Error("Redirect loop"), { statusCode: 400 });
      visited.add(current);

      res = await fetch(current, { method: "GET", redirect: "manual", signal: controller.signal, headers: { "User-Agent": "ZeroBogus/0.1" } });
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) throw Object.assign(new Error("Redirect without location"), { statusCode: 400 });
        current = assertPublicHttpUrl(new URL(location, current).toString());
        continue;
      }
      break;
    }

    const contentType = String(res.headers.get("content-type") || "");
    if (!res.ok) throw Object.assign(new Error(`Fetch failed (${res.status})`), { statusCode: 400 });
    if (!contentType.toLowerCase().includes("text/html") && !contentType.toLowerCase().includes("text/plain")) {
      throw Object.assign(new Error("Unsupported content type"), { statusCode: 400 });
    }

    const reader = res.body?.getReader?.();
    if (!reader) {
      const text = await res.text();
      const bytes = new TextEncoder().encode(text).byteLength;
      if (bytes > maxBytes) throw Object.assign(new Error("Content too large"), { statusCode: 400 });
      return { contentType, raw: text, finalUrl: current };
    }

    let received = 0;
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) throw Object.assign(new Error("Content too large"), { statusCode: 400 });
      chunks.push(value);
    }

    const merged = new Uint8Array(received);
    let offset = 0;
    for (const c of chunks) {
      merged.set(c, offset);
      offset += c.byteLength;
    }
    const raw = new TextDecoder("utf-8", { fatal: false }).decode(merged);
    return { contentType, raw, finalUrl: current };
  } finally {
    clearTimeout(timeout);
  }
}

async function urlscanSubmit(urlToScan, apiKey, visibility) {
  const res = await fetch("https://urlscan.io/api/v1/scan/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "API-Key": apiKey },
    body: JSON.stringify({ url: urlToScan, visibility })
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.message || data?.description || `urlscan submit failed (${res.status})`);
  return data;
}

async function urlscanGetResult(uuid) {
  const res = await fetch(`https://urlscan.io/api/v1/result/${encodeURIComponent(uuid)}/`, { method: "GET" });
  if (res.status === 404) return { status: "not_ready" };
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.message || data?.description || `urlscan result failed (${res.status})`);
  return { status: "ready", data };
}

function trimUrlscanResult(raw) {
  const page = raw?.page || {};
  const task = raw?.task || {};
  const verdicts = raw?.verdicts || {};
  const stats = raw?.stats || {};
  return {
    task: { uuid: task?.uuid, url: task?.url, domain: task?.domain, reportURL: task?.reportURL, screenshotURL: task?.screenshotURL },
    page: { url: page?.url, domain: page?.domain, ip: page?.ip, country: page?.country },
    verdicts,
    stats: { requests: stats?.requests, domains: stats?.domains, ips: stats?.ips }
  };
}

function urlscanResultToReasons(urlscanResult, lang) {
  const verdicts = urlscanResult?.verdicts?.overall;
  const score = Number(verdicts?.score);
  const malicious = verdicts?.malicious === true;
  const categories = Array.isArray(verdicts?.categories) ? verdicts.categories : [];

  const link = urlscanResult?.task?.reportURL || (urlscanResult?.task?.uuid ? `https://urlscan.io/result/${encodeURIComponent(String(urlscanResult.task.uuid))}/` : null);
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
        label: tr(lang, "URLScan: segnalato malevolo", "URLScan: flagged as malicious"),
        severity: 0.75,
        why: tr(
          lang,
          "L’analisi esterna segnala la risorsa come malevola. Verifica comunque il contesto e la fonte.",
          "External analysis flags this resource as malicious. Still verify the context and source."
        ),
        evidence
      }
    ];
  }

  if (Number.isFinite(score) && score >= 60) {
    return [
      {
        id: "urlscan.high_score",
        label: tr(lang, "URLScan: punteggio rischio elevato", "URLScan: high risk score"),
        severity: 0.55,
        why: tr(
          lang,
          "L’analisi esterna indica un rischio elevato. Possibili redirect/risorse sospette o pattern tipici di campagne malevole.",
          "External analysis indicates elevated risk. Possible redirects/suspicious resources or patterns typical of malicious campaigns."
        ),
        evidence
      }
    ];
  }

  if (Number.isFinite(score) && score >= 20) {
    return [
      {
        id: "urlscan.suspicious",
        label: tr(lang, "URLScan: segnali sospetti", "URLScan: suspicious signals"),
        severity: 0.25,
        why: tr(
          lang,
          "L’analisi esterna riporta segnali che meritano un controllo aggiuntivo (redirect, richieste a domini terzi, fingerprinting).",
          "External analysis reports signals that deserve extra checking (redirects, third-party requests, fingerprinting)."
        ),
        evidence
      }
    ];
  }

  if (categories.length > 0) {
    return [
      {
        id: "urlscan.categories",
        label: tr(lang, "URLScan: categoria rilevata", "URLScan: category detected"),
        severity: 0.12,
        why: tr(
          lang,
          "L’analisi esterna classifica la pagina in una o più categorie. Non è un segnale di frode da solo, ma può aiutare il contesto.",
          "External analysis classifies the page into one or more categories. Not a fraud signal by itself, but useful for context."
        ),
        evidence
      }
    ];
  }

  return [];
}

const history = [];
const osintById = new Map();

function makeId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(String(text));
  const hash = await crypto.subtle.digest("SHA-256", data);
  const bytes = Array.from(new Uint8Array(hash));
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function limitHistory(maxItems) {
  while (history.length > maxItems) history.shift();
}

function listHistory({ limit, offset }) {
  const items = history.slice().sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const sliced = items.slice(offset, offset + limit);
  return sliced.map((r) => ({
    id: r.id,
    createdAt: r.createdAt,
    type: r.type,
    inputPreview: r.inputPreview,
    inputHash: r.inputHash,
    score: r.score,
    verdict: r.verdict,
    urlscanStatus: r.osint?.urlscan?.status || null,
    urlscanUuid: r.osint?.urlscan?.uuid || null
  }));
}

function getHistoryById(id) {
  const base = history.find((x) => x.id === id) || null;
  if (!base) return null;

  const urlscan = osintById.get(id) || null;
  const lang = base.lang || "it";
  const urlscanReasons = urlscan?.result ? urlscanResultToReasons(urlscan.result, lang) : [];

  const combinedReasons = [...(base.reasons || []), ...urlscanReasons].sort((a, b) => (Number(b?.severity) || 0) - (Number(a?.severity) || 0));
  const combinedScore = scoreFromReasons(combinedReasons);
  const combinedVerdict = scoreToVerdict(combinedScore);

  return {
    ...base,
    score: combinedScore,
    verdict: combinedVerdict,
    reasons: combinedReasons,
    osint: {
      urlscan: urlscan
        ? { status: urlscan.status, uuid: urlscan.uuid || null, reportURL: urlscan.reportURL || null, error: urlscan.error || null }
        : null
    }
  };
}

function html(basePath, lang) {
  const apiBase = basePath || "";
  return `<!doctype html>
<html lang="${String(lang || "it")}">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${tr(lang, "ZeroBogus Suite", "ZeroBogus Suite")}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
  </head>
  <body class="bg-slate-950 text-slate-100">
    <div class="max-w-6xl mx-auto px-4 py-10">
      <div class="flex items-center justify-between gap-4">
        <div>
		  <img src="https://tivustream.com/downloadzz/logo.png" class="h-[100px] w-[100px] mb-3" /
          <h1 class="text-4xl font-bold tracking-tight">ZeroBogus</h1>
          <p class="text-slate-300 mt-2">${tr(
            lang,
            "Suite multi-canale: link, news/testi, account social e immagini. Verifiche esterne solo con consenso.",
            "Multi-channel suite: links, news/text, social accounts and images. External checks only with consent."
          )}</p>
        </div>
        <button id="langToggle" class="rounded-xl border border-slate-700 px-3 py-2 text-sm hover:bg-slate-800">${tr(lang, "EN", "IT")}</button>
      </div>

      <div class="mt-8 grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <div class="flex items-center justify-between">
            <div class="font-semibold">${tr(lang, "Analisi", "Analysis")}</div>
            <div id="status" class="text-sm text-slate-300"></div>
          </div>
          <div class="mt-4">
            <label class="text-sm text-slate-300">${tr(lang, "Modalità", "Mode")}</label>
            <select id="type" class="mt-2 w-full rounded-xl bg-slate-950 border border-slate-800 px-3 py-2">
              <option value="">${tr(lang, "Auto", "Auto")}</option>
              <option value="url">Link Intelligence</option>
              <option value="news">News/Claim Check</option>
              <option value="social">Social Account Check</option>
              <option value="text">${tr(lang, "Testo libero", "Free text")}</option>
              <option value="image">${tr(lang, "Immagine (URL)", "Image (URL)")}</option>
            </select>
          </div>
          <div class="mt-4">
            <label class="text-sm text-slate-300">${tr(lang, "Input", "Input")}</label>
            <textarea id="value" class="mt-2 w-full min-h-[160px] rounded-xl bg-slate-950 border border-slate-800 px-3 py-2" placeholder="${tr(
              lang,
              "Incolla link, testo news/claim, handle social o URL immagine...",
              "Paste a link, news/claim text, social handle or image URL..."
            )}"></textarea>
          </div>
          <div class="mt-4 flex items-center justify-between gap-3">
            <label class="flex items-center gap-2 text-sm text-slate-300 select-none">
              <input id="externalConsent" type="checkbox" class="accent-emerald-400" />
              ${tr(lang, "Consenso verifiche esterne (URLScan)", "Consent to external checks (URLScan)")}
            </label>
            <button id="analyzeBtn" class="rounded-xl bg-emerald-500 text-slate-950 font-semibold px-4 py-2 hover:bg-emerald-400">${tr(lang, "Analizza", "Analyze")}</button>
          </div>
        </div>

        <div class="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
          <div class="flex items-center justify-between">
            <div class="font-semibold">${tr(lang, "Report", "Report")}</div>
            <div class="text-sm text-slate-400">${tr(lang, "perché + evidenze", "why + evidence")}</div>
          </div>
          <div id="result" class="mt-4 hidden">
            <div class="grid grid-cols-3 gap-3">
              <div class="rounded-xl bg-slate-950 border border-slate-800 p-3">
                <div class="text-xs text-slate-400">${tr(lang, "Verdetto", "Verdict")}</div>
                <div id="verdict" class="mt-1 font-semibold"></div>
              </div>
              <div class="rounded-xl bg-slate-950 border border-slate-800 p-3">
                <div class="text-xs text-slate-400">${tr(lang, "Rischio", "Risk")}</div>
                <div id="score" class="mt-1 font-semibold"></div>
              </div>
              <div class="rounded-xl bg-slate-950 border border-slate-800 p-3">
                <div class="text-xs text-slate-400">URLScan</div>
                <div id="urlscanStatus" class="mt-1 font-semibold"></div>
                <a id="urlscanLink" class="text-sm text-emerald-300 mt-2 inline-block hidden" href="#" target="_blank" rel="noreferrer">${tr(lang, "Apri report", "Open report")}</a>
              </div>
            </div>
            <div class="mt-4 rounded-xl bg-slate-950 border border-slate-800 p-3">
              <div class="text-xs text-slate-400">${tr(lang, "Motivazioni", "Reasons")}</div>
              <div id="reasons" class="mt-2 space-y-2"></div>
            </div>
          </div>
          <div id="emptyReport" class="mt-8 text-slate-400 text-sm">${tr(lang, "Esegui un’analisi per vedere il report.", "Run an analysis to see the report.")}</div>
        </div>
      </div>

      <div class="mt-6 rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <div class="flex items-center justify-between">
          <div>
            <div class="font-semibold">${tr(lang, "Guida & Privacy", "Guide & Privacy")}</div>
            <div class="text-sm text-slate-400">${tr(lang, "come usare ZeroBogus e cosa succede ai dati", "how to use ZeroBogus and what happens to your data")}</div>
          </div>
        </div>

        <div class="mt-4 space-y-3">
          <details class="group rounded-xl border border-slate-800 bg-slate-950">
            <summary class="cursor-pointer select-none list-none px-4 py-3 flex items-center justify-between">
              <span class="font-semibold">${tr(lang, "Come si usa", "How to use")}</span>
              <span class="text-slate-400 group-open:hidden">+</span>
              <span class="text-slate-400 hidden group-open:inline">–</span>
            </summary>
            <div class="px-4 pb-4 text-sm text-slate-300 space-y-2">
              <div>${tr(lang, "1) Scegli una modalità (oppure lascia Auto) e incolla l’input.", "1) Pick a mode (or keep Auto) and paste the input.")}</div>
              <div>${tr(lang, "2) Clicca Analizza: ottieni rischio 0–100 + motivazioni.", "2) Click Analyze: you get a 0–100 risk score + reasons.")}</div>
              <div>${tr(lang, "3) Se vuoi arricchire i risultati con OSINT esterna, spunta il consenso URLScan prima di analizzare.", "3) To enrich results with external OSINT, tick the URLScan consent before analyzing.")}</div>
              <div class="text-slate-400">${tr(
                lang,
                "Suggerimento: in modalità News puoi incollare anche un URL articolo, il sistema prova ad estrarre il testo e a valutare link presenti nella pagina.",
                "Tip: in News mode you can paste an article URL; the system will try to extract text and evaluate links found on the page."
              )}</div>
            </div>
          </details>

          <details class="group rounded-xl border border-slate-800 bg-slate-950">
            <summary class="cursor-pointer select-none list-none px-4 py-3 flex items-center justify-between">
              <span class="font-semibold">${tr(lang, "Come leggere risultati e motivazioni", "How to read results and reasons")}</span>
              <span class="text-slate-400 group-open:hidden">+</span>
              <span class="text-slate-400 hidden group-open:inline">–</span>
            </summary>
            <div class="px-4 pb-4 text-sm text-slate-300 space-y-2">
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">Rischio</span>: punteggio 0–100 calcolato dalla somma di “segnali”. Non è un verdetto assoluto vero/falso.",
                "<span class=\"font-semibold\">Risk</span>: a 0–100 score computed from multiple signals. It is not an absolute true/false verdict."
              )}</div>
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">Motivazioni</span>: ogni voce spiega il “perché” e ha una severità (sev) che contribuisce al punteggio.",
                "<span class=\"font-semibold\">Reasons</span>: each item explains the why and has a severity (sev) that contributes to the score."
              )}</div>
              <div class="text-slate-400">${tr(
                lang,
                "Un rischio alto indica “richiede verifica” (phishing, impersonazione, redirect, tracking aggressivo, ecc.), non una certezza matematica.",
                "High risk means “needs verification” (phishing, impersonation, redirects, aggressive tracking, etc.), not mathematical certainty."
              )}</div>
            </div>
          </details>

          <details class="group rounded-xl border border-slate-800 bg-slate-950">
            <summary class="cursor-pointer select-none list-none px-4 py-3 flex items-center justify-between">
              <span class="font-semibold">${tr(lang, "Perché è richiesto il consenso per URLScan", "Why URLScan consent is required")}</span>
              <span class="text-slate-400 group-open:hidden">+</span>
              <span class="text-slate-400 hidden group-open:inline">–</span>
            </summary>
            <div class="px-4 pb-4 text-sm text-slate-300 space-y-2">
              <div>${tr(lang, "URLScan è un servizio terzo che esegue una scansione esterna dell’URL e genera un report.", "URLScan is a third-party service that scans a URL externally and produces a report.")}</div>
              <div>${tr(
                lang,
                "Per privacy e trasparenza, ZeroBogus invia l’URL a URLScan <span class=\"font-semibold\">solo se l’utente lo autorizza</span> spuntando il consenso.",
                "For privacy and transparency, ZeroBogus sends the URL to URLScan <span class=\"font-semibold\">only if you explicitly consent</span>."
              )}</div>
              <div class="text-slate-400">${tr(
                lang,
                "Senza consenso, ZeroBogus effettua solo controlli locali/euristici e non invia l’URL a servizi esterni. Policy URLScan: <a class=\"text-emerald-300 hover:underline\" href=\"https://urlscan.io/privacy/\" target=\"_blank\" rel=\"noreferrer\">urlscan.io/privacy</a>",
                "Without consent, ZeroBogus runs only local/heuristic checks and does not send the URL to external services. URLScan policy: <a class=\"text-emerald-300 hover:underline\" href=\"https://urlscan.io/privacy/\" target=\"_blank\" rel=\"noreferrer\">urlscan.io/privacy</a>"
              )}</div>
            </div>
          </details>

          <details class="group rounded-xl border border-slate-800 bg-slate-950">
            <summary class="cursor-pointer select-none list-none px-4 py-3 flex items-center justify-between">
              <span class="font-semibold">${tr(lang, "Privacy policy (sommaria)", "Privacy policy (summary)")}</span>
              <span class="text-slate-400 group-open:hidden">+</span>
              <span class="text-slate-400 hidden group-open:inline">–</span>
            </summary>
            <div class="px-4 pb-4 text-sm text-slate-300 space-y-2">
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">Dati inseriti</span>: l’input viene usato per calcolare un report; la cronologia in Cloudflare Workers è best-effort (memoria dell’istanza) e può azzerarsi.",
                "<span class=\"font-semibold\">Submitted data</span>: input is used to generate a report; on Cloudflare Workers the history is best-effort (instance memory) and may reset."
              )}</div>
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">Nessun tracking</span>: lo strumento non usa cookie di tracciamento.",
                "<span class=\"font-semibold\">No tracking</span>: the tool does not require tracking cookies."
              )}</div>
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">Servizi esterni</span>: con consenso, l’URL può essere inviato a URLScan per generare un report. In tal caso valgono anche le policy del servizio terzo.",
                "<span class=\"font-semibold\">External services</span>: with consent, the URL may be sent to URLScan to generate a report. In that case, the third-party policy also applies."
              )}</div>
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">News da URL</span>: in modalità News, se incolli un URL articolo, il server effettua un fetch della pagina per estrarre testo e link (con limiti e blocchi anti-SSRF).",
                "<span class=\"font-semibold\">News from URL</span>: in News mode, if you paste an article URL, the server fetches the page to extract text and links (with limits and anti-SSRF blocks)."
              )}</div>
              <div class="text-slate-400">${tr(
                lang,
                "Se hai contenuti sensibili, evita di incollarli o disattiva le verifiche esterne.",
                "If you have sensitive content, avoid pasting it and keep external checks disabled."
              )}</div>
            </div>
          </details>

          <details class="group rounded-xl border border-slate-800 bg-slate-950">
            <summary class="cursor-pointer select-none list-none px-4 py-3 flex items-center justify-between">
              <span class="font-semibold">${tr(lang, "FAQ", "FAQ")}</span>
              <span class="text-slate-400 group-open:hidden">+</span>
              <span class="text-slate-400 hidden group-open:inline">–</span>
            </summary>
            <div class="px-4 pb-4 text-sm text-slate-300 space-y-2">
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">Perché la cronologia può sparire?</span> In Cloudflare Workers la memoria è best-effort: con restart o cold start l’istanza può cambiare e lo storico si azzera.",
                "<span class=\"font-semibold\">Why can history disappear?</span> On Cloudflare Workers memory is best-effort: after restarts or cold starts the instance can change and history resets."
              )}</div>
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">Posso avere cronologia persistente?</span> Sì, è possibile con Cloudflare KV/D1, ma è opt‑in perché aumenta la persistenza dei dati.",
                "<span class=\"font-semibold\">Can I get persistent history?</span> Yes, via Cloudflare KV/D1, but it is opt-in because it increases data persistence."
              )}</div>
              <div>${tr(
                lang,
                "<span class=\"font-semibold\">URLScan a volte è lento</span>: la scansione può richiedere alcuni secondi. Il link “Apri report” appare solo quando il report è pronto.",
                "<span class=\"font-semibold\">URLScan can be slow</span>: scans may take a few seconds. The “Open report” link appears only when the report is ready."
              )}</div>
            </div>
          </details>
        </div>
      </div>

      <div class="mt-6 rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
        <div class="flex items-center justify-between">
          <div>
            <div class="font-semibold">${tr(lang, "Cronologia", "History")}</div>
            <div class="text-sm text-slate-400">${tr(lang, "in Workers è best-effort (sessione/istanza)", "on Workers it's best-effort (session/instance)")}</div>
          </div>
          <div class="flex gap-2">
            <button id="refreshHistory" class="rounded-xl border border-slate-700 px-3 py-2 text-sm hover:bg-slate-800">${tr(lang, "Aggiorna", "Refresh")}</button>
            <button id="clearHistory" class="rounded-xl border border-slate-700 px-3 py-2 text-sm hover:bg-slate-800">${tr(lang, "Svuota", "Clear")}</button>
          </div>
        </div>
        <div id="history" class="mt-4 space-y-2"></div>
      </div>
    </div>

    <script>
      const basePath = ${JSON.stringify(apiBase)};
      const currentLang = ${JSON.stringify(String(lang || "it").toLowerCase().startsWith("en") ? "en" : "it")};
      const typeEl = document.getElementById("type");
      const valueEl = document.getElementById("value");
      const consentEl = document.getElementById("externalConsent");
      const btn = document.getElementById("analyzeBtn");
      const statusEl = document.getElementById("status");
      const langToggleEl = document.getElementById("langToggle");
      const resultEl = document.getElementById("result");
      const emptyReportEl = document.getElementById("emptyReport");
      const verdictEl = document.getElementById("verdict");
      const scoreEl = document.getElementById("score");
      const reasonsEl = document.getElementById("reasons");
      const urlscanStatusEl = document.getElementById("urlscanStatus");
      const urlscanLinkEl = document.getElementById("urlscanLink");
      const historyEl = document.getElementById("history");

      function esc(s) {
        return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#039;" }[c]));
      }

      function verdictLabel(v) {
        if (currentLang === "en") {
          if (v === "high_risk") return "High risk";
          if (v === "medium_risk") return "Medium risk";
          return "Low risk";
        }
        if (v === "high_risk") return "Alto rischio";
        if (v === "medium_risk") return "Rischio medio";
        return "Basso rischio";
      }

      function renderReasons(reasons) {
        reasonsEl.innerHTML = (reasons || []).map(r => (
          '<div class="rounded-xl border border-slate-800 bg-slate-900/40 p-3">' +
            '<div class="flex items-center justify-between gap-3">' +
              '<div class="font-semibold">' + esc(r.label) + '</div>' +
              '<div class="text-xs text-slate-400">sev ' + esc(Number(r.severity || 0).toFixed(2)) + '</div>' +
            '</div>' +
            '<div class="mt-1 text-sm text-slate-300">' + esc(r.why || "") + '</div>' +
          '</div>'
        )).join("") || (currentLang === "en" ? '<div class="text-slate-400 text-sm">No reasons detected.</div>' : '<div class="text-slate-400 text-sm">Nessuna motivazione rilevata.</div>');
      }

      function renderUrlscan(osint) {
        const info = osint && osint.urlscan ? osint.urlscan : null;
        const status = info && info.status ? String(info.status) : "";
        if (!status) {
          urlscanStatusEl.textContent = currentLang === "en" ? "Not active" : "Non attivo";
          urlscanLinkEl.classList.add("hidden");
          urlscanLinkEl.removeAttribute("href");
          return;
        }
        if (status === "pending") urlscanStatusEl.textContent = currentLang === "en" ? "Running… (may take 10–60s)" : "In corso… (può richiedere 10–60s)";
        else if (status === "ready") urlscanStatusEl.textContent = currentLang === "en" ? "Ready" : "Pronto";
        else if (status === "timeout") urlscanStatusEl.textContent = "Timeout";
        else if (status === "disabled") urlscanStatusEl.textContent = currentLang === "en" ? "Disabled" : "Disattivato";
        else if (status === "consent_required") urlscanStatusEl.textContent = currentLang === "en" ? "Consent required" : "Consenso richiesto";
        else if (status === "not_configured") urlscanStatusEl.textContent = currentLang === "en" ? "Not configured" : "Non configurato";
        else if (status === "error") urlscanStatusEl.textContent = info && info.error ? ((currentLang === "en" ? "Error: " : "Errore: ") + String(info.error).slice(0, 90)) : (currentLang === "en" ? "Error" : "Errore");
        else urlscanStatusEl.textContent = status;
        const link = info && info.reportURL ? String(info.reportURL) : "";
        const canOpen = status === "ready" && !!link;
        if (canOpen) {
          urlscanLinkEl.classList.remove("hidden");
          urlscanLinkEl.setAttribute("href", link);
        } else {
          urlscanLinkEl.classList.add("hidden");
          urlscanLinkEl.removeAttribute("href");
        }
      }

      async function loadAnalysisById(id, { silent = false } = {}) {
        if (!id) return null;
        if (!silent) statusEl.textContent = "Caricamento analisi...";
        try {
          const res = await fetch(basePath + "/api/history/" + encodeURIComponent(id));
          const data = await res.json();
          if (res.status >= 400) throw new Error(data && data.error ? data.error : "Errore");
          emptyReportEl.classList.add("hidden");
          resultEl.classList.remove("hidden");
          verdictEl.textContent = verdictLabel(data.verdict);
          scoreEl.textContent = data.score + "/100";
          renderUrlscan(data.osint || null);
          renderReasons(data.reasons || []);
          if (!silent) statusEl.textContent = "";
          return data;
        } catch {
          if (!silent) statusEl.textContent = "Errore nel caricamento analisi.";
          return null;
        }
      }

      async function followUrlscanStatus(id) {
        if (!id) return;
        for (let i = 0; i < 10; i += 1) {
          await new Promise((resolve) => setTimeout(resolve, 2500));
          const data = await loadAnalysisById(id, { silent: true });
          const status = data && data.osint && data.osint.urlscan ? String(data.osint.urlscan.status || "") : "";
          if (!status || status === "ready" || status === "error" || status === "timeout" || status === "not_configured" || status === "disabled" || status === "consent_required") {
            return;
          }
        }
      }

      async function loadHistory() {
        try {
          const res = await fetch(basePath + "/api/history?limit=20");
          const data = await res.json();
          const items = data.items || [];
          if (!items.length) {
            historyEl.innerHTML = currentLang === "en" ? '<div class="text-slate-400 text-sm">No saved analyses.</div>' : '<div class="text-slate-400 text-sm">Nessuna analisi salvata.</div>';
            return;
          }
          historyEl.innerHTML = items.map(it => (
            '<button class="w-full text-left rounded-xl border border-slate-800 bg-slate-950 hover:bg-slate-900/60 p-3" data-id="' + esc(it.id) + '">' +
              '<div class="flex items-center justify-between gap-3">' +
                '<div class="text-sm"><span class="text-slate-400">' + esc(it.type) + '</span> <span class="font-semibold">' + esc(verdictLabel(it.verdict)) + '</span> <span class="text-slate-400">' + esc(it.score) + '/100</span></div>' +
                '<div class="text-xs text-slate-500">' + esc(it.createdAt) + '</div>' +
              '</div>' +
              '<div class="mt-1 text-xs text-slate-400">' + esc(it.inputPreview || "") + '</div>' +
            '</button>'
          )).join("");
        } catch {
          historyEl.innerHTML = currentLang === "en" ? '<div class="text-slate-400 text-sm">Error loading history.</div>' : '<div class="text-slate-400 text-sm">Errore nel caricamento cronologia.</div>';
        }
      }

      historyEl.addEventListener("click", async (e) => {
        const btn = e.target.closest("button[data-id]");
        if (!btn) return;
        const id = btn.getAttribute("data-id");
        const data = await loadAnalysisById(id);
        const s = data && data.osint && data.osint.urlscan ? String(data.osint.urlscan.status || "") : "";
        if (s === "pending") followUrlscanStatus(id);
      });

      document.getElementById("refreshHistory").addEventListener("click", () => loadHistory());
      document.getElementById("clearHistory").addEventListener("click", async () => {
        if (!confirm(currentLang === "en" ? "Do you want to clear the analysis history?" : "Vuoi svuotare la cronologia delle analisi?")) return;
        statusEl.textContent = currentLang === "en" ? "Clearing history..." : "Svuotamento cronologia...";
        try {
          await fetch(basePath + "/api/history", { method: "DELETE" });
          await loadHistory();
          statusEl.textContent = "";
        } catch {
          statusEl.textContent = currentLang === "en" ? "Error clearing history." : "Errore nello svuotamento cronologia.";
        }
      });

      langToggleEl.addEventListener("click", () => {
        const next = currentLang === "en" ? "it" : "en";
        const target = basePath + "/?lang=" + encodeURIComponent(next);
        window.location.assign(target);
      });

      btn.addEventListener("click", async () => {
        const payload = { type: typeEl.value || undefined, value: valueEl.value, externalConsent: !!consentEl.checked, lang: currentLang };
        statusEl.textContent = currentLang === "en" ? "Analyzing..." : "Analisi in corso...";
        btn.disabled = true;
        try {
          const res = await fetch(basePath + "/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
          const data = await res.json();
          emptyReportEl.classList.add("hidden");
          resultEl.classList.remove("hidden");
          verdictEl.textContent = verdictLabel(data.verdict);
          scoreEl.textContent = data.score + "/100";
          renderUrlscan(data.osint || null);
          renderReasons(data.reasons || []);
          statusEl.textContent = "";
          loadHistory();
          const s = data && data.osint && data.osint.urlscan ? String(data.osint.urlscan.status || "") : "";
          if (s === "pending" && data.id) followUrlscanStatus(data.id);
        } catch {
          statusEl.textContent = currentLang === "en" ? "Error during analysis." : "Errore durante l’analisi.";
        } finally {
          btn.disabled = false;
        }
      });

      loadHistory();
      renderUrlscan(null);
    </script>
  </body>
</html>`;
}

const CAPABILITIES = [
  {
    key: "url",
    title: "Link Intelligence",
    status: "available",
    description: "Verifica URL con euristiche anti-phishing, tracking detection e (opzionale) integrazione URLScan con consenso.",
    checks: ["protocollo/hostname", "redirect e parametri", "tracking/affiliazione", "osint urlscan (consenso)"]
  },
  {
    key: "news",
    title: "News & Claim Check",
    status: "available",
    description: "Analizza testi/news. Se incolli un URL in modalità News, estrae testo dalla pagina e valuta anche i link presenti.",
    checks: ["fonti e riferimenti", "claim numerici", "stile allarmistico", "estrazione da URL", "link sospetti nel testo"]
  },
  {
    key: "social",
    title: "Social Account Check",
    status: "available",
    description: "Valuta profili/handle social per pattern di impersonazione e naming sospetto.",
    checks: ["handle pattern", "brand spoofing", "host social noto"]
  },
  {
    key: "image",
    title: "Image Forensics",
    status: "preview",
    description: "Modalità base: warning e instradamento. Forensics avanzata in roadmap.",
    checks: ["input validation", "workflow hint"]
  }
];

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function textResponse(body, status = 200, contentType = "text/html; charset=utf-8") {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": contentType,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function stripBasePath(pathname, basePath) {
  if (!basePath) return pathname;
  if (pathname === basePath) return "/";
  if (pathname.startsWith(`${basePath}/`)) return pathname.slice(basePath.length) || "/";
  return pathname;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const basePath = (env?.BASE_PATH ? String(env.BASE_PATH) : "/zerobogus").replace(/\/+$/, "") || "/zerobogus";
    const pathname = stripBasePath(url.pathname, basePath);
    const qsLang = String(url.searchParams.get("lang") || "");
    const viewLang = qsLang.toLowerCase().startsWith("en") ? "en" : "it";

    if (request.method === "GET" && pathname === "/") {
      return textResponse(html(basePath, viewLang));
    }

    if (request.method === "GET" && pathname === "/health") {
      return jsonResponse({ ok: true, name: "ZeroBogus", runtime: "cloudflare-worker" });
    }

    if (request.method === "GET" && pathname === "/api/capabilities") {
      return jsonResponse({ items: CAPABILITIES });
    }

    if (request.method === "DELETE" && pathname === "/api/history") {
      history.length = 0;
      osintById.clear();
      return jsonResponse({ ok: true });
    }

    if (request.method === "GET" && pathname === "/api/history") {
      const limit = Math.max(1, Math.min(200, Number(url.searchParams.get("limit") || 50) || 50));
      const offset = Math.max(0, Number(url.searchParams.get("offset") || 0) || 0);
      return jsonResponse({ items: listHistory({ limit, offset }) });
    }

    if (request.method === "GET" && pathname.startsWith("/api/history/")) {
      const id = decodeURIComponent(pathname.slice("/api/history/".length));
      const record = getHistoryById(id);
      if (!record) return jsonResponse({ error: "Not found" }, 404);
      return jsonResponse(record);
    }

    if (request.method === "POST" && pathname === "/api/analyze") {
      try {
        const contentType = String(request.headers.get("content-type") || "");
        if (!contentType.toLowerCase().includes("application/json")) return jsonResponse({ error: "Unsupported Media Type. Use application/json." }, 415);

        const body = await request.json().catch(() => ({}));
        const reqLangRaw = String(body?.lang || "");
        const lang = reqLangRaw.toLowerCase().startsWith("en") ? "en" : "it";
        const requestedType = String(body?.type || "");
        const inputValue = body?.value;
        const externalConsent = body?.externalConsent === true;
        const requireConsent = String(env?.EXTERNAL_CHECKS_REQUIRE_CONSENT ?? "true").toLowerCase() !== "false";
        const canUseExternal = !requireConsent || externalConsent;

        let preparedValue = inputValue;
        let newsMeta = null;
        let extractedLinks = [];
        const fetchArticleEnabled = String(env?.FETCH_ARTICLE_ENABLED ?? "true").toLowerCase() !== "false";

        if (fetchArticleEnabled && requestedType === "news" && looksLikeUrl(String(inputValue ?? ""))) {
          const maxBytes = Math.max(200000, Math.min(4000000, Number(env?.FETCH_ARTICLE_MAX_BYTES || 1200000) || 1200000));
          const timeoutMs = Math.max(2000, Math.min(20000, Number(env?.FETCH_ARTICLE_TIMEOUT_MS || 9000) || 9000));
          const urlToFetch = normalizeUrlForHttp(inputValue);
          const fetched = await fetchTextFromUrl(urlToFetch, { maxBytes, timeoutMs });
          const raw = String(fetched.raw || "");
          if (String(fetched.contentType || "").toLowerCase().includes("text/html")) {
            extractedLinks = extractLinksFromHtml(raw, fetched.finalUrl);
            preparedValue = htmlToText(raw);
          } else {
            preparedValue = raw;
          }
          newsMeta = { sourceUrl: fetched.finalUrl, extractedChars: String(preparedValue || "").length, extractedLinks: extractedLinks.length };
        }

        let result = analyze({ ...(body || {}), value: preparedValue }, lang);
        if (requestedType === "news" && newsMeta) {
          const infoReason = {
            id: "news.fetched",
            label: tr(lang, "Contenuto estratto da URL", "Content extracted from URL"),
            severity: 0,
            why: tr(
              lang,
              "Per analizzare la news, il sistema ha scaricato e convertito la pagina in testo. In Workers lo storico è best-effort e non salva l’input completo.",
              "To analyze the news, the system fetched the page and converted it to text. On Workers the history is best-effort and does not store the full input."
            ),
            evidence: newsMeta
          };
          result = { ...result, meta: { ...(result?.meta || {}), ...newsMeta }, reasons: [infoReason, ...(result?.reasons || [])] };

          const linkAnalyses = extractedLinks.slice(0, 40).map((u) => analyzeUrl(u, lang));
          const risky = linkAnalyses
            .filter((a) => a && typeof a.score === "number" && a.score >= 45)
            .sort((a, b) => b.score - a.score)
            .slice(0, 6)
            .map((a) => ({ url: a.input, score: a.score, verdict: a.verdict }));
          if (risky.length > 0) {
            const sev = risky.some((x) => x.score >= 75) ? 0.45 : 0.28;
            const linkReason = {
              id: "news.suspicious_links",
              label: tr(lang, "Link potenzialmente sospetti nel contenuto", "Potentially suspicious links in the content"),
              severity: sev,
              why: tr(
                lang,
                "Nel contenuto estratto sono presenti link con segnali tipici di phishing/tracking/redirect. Verifica la destinazione reale e il contesto.",
                "The extracted content contains links with signals typical of phishing/tracking/redirects. Verify the real destination and context."
              ),
              evidence: { count: risky.length, top: risky }
            };
            result = { ...result, reasons: [linkReason, ...(result?.reasons || [])] };
          }
        }

        const id = makeId();
        const createdAt = new Date().toISOString();
        const input = String(inputValue ?? "");
        const inputHash = await sha256Hex(input);
        const inputPreview = result?.type === "url" ? (urlHostnameOrNull(input) || safePreview(input, 120)) : safePreview(input, 160);

        const record = {
          kind: "analysis",
          id,
          createdAt,
          lang,
          type: result?.type || requestedType || "unknown",
          inputHash,
          inputPreview,
          score: result?.score,
          verdict: result?.verdict,
          reasons: Array.isArray(result?.reasons) ? result.reasons : [],
          meta: result?.meta || null
        };

        history.push(record);
        limitHistory(Math.max(20, Math.min(2000, Number(env?.HISTORY_MAX_ITEMS || 200) || 200)));

        let urlscan = null;
        const urlscanEnabled = String(env?.URLSCAN_ENABLED ?? "true").toLowerCase() !== "false";
        const urlscanKey = env?.URLSCAN_API_KEY ? String(env.URLSCAN_API_KEY) : "";
        const visibility = env?.URLSCAN_VISIBILITY ? String(env.URLSCAN_VISIBILITY) : "unlisted";

        const shouldUrlscan =
          urlscanEnabled && urlscanKey && canUseExternal && (record.type === "url" || (record.type === "news" && newsMeta?.sourceUrl));

        if (!urlscanEnabled && (record.type === "url" || record.type === "news")) {
          urlscan = { status: "disabled" };
        } else if (urlscanEnabled && !canUseExternal && (record.type === "url" || record.type === "news")) {
          urlscan = { status: "consent_required" };
        } else if (urlscanEnabled && canUseExternal && !urlscanKey && (record.type === "url" || record.type === "news")) {
          urlscan = { status: "not_configured" };
        } else if (shouldUrlscan) {
          const urlToScan = record.type === "url" ? normalizeUrlForHttp(inputValue) : String(newsMeta.sourceUrl);
          try {
            const submit = await urlscanSubmit(urlToScan, urlscanKey, visibility);
            urlscan = { status: "pending", uuid: submit?.uuid || null, reportURL: submit?.result || null };
            osintById.set(id, { status: "pending", uuid: submit?.uuid || null, reportURL: submit?.result || null, result: null, error: null });

            if (submit?.uuid) {
              const uuid = String(submit.uuid);
              ctx.waitUntil(
                (async () => {
                  for (let i = 0; i < 8; i += 1) {
                    const r = await urlscanGetResult(uuid);
                    if (r.status === "not_ready") {
                      await new Promise((resolve) => setTimeout(resolve, Math.min(15000, 800 * Math.pow(1.7, i))));
                      continue;
                    }
                    osintById.set(id, {
                      status: "ready",
                      uuid,
                      reportURL: submit?.result || null,
                      result: trimUrlscanResult(r.data),
                      error: null
                    });
                    return;
                  }
                  const existing = osintById.get(id) || {};
                  osintById.set(id, { ...existing, status: "timeout" });
                })().catch((e) => {
                  const existing = osintById.get(id) || {};
                  osintById.set(id, { ...existing, status: "error", error: String(e?.message || e) });
                })
              );
            }
          } catch (e) {
            urlscan = { status: "error", uuid: null, reportURL: null, error: String(e?.message || e) };
            osintById.set(id, { status: "error", uuid: null, reportURL: null, result: null, error: String(e?.message || e) });
          }
        }

        return jsonResponse({ ...result, id, createdAt, osint: { urlscan } });
      } catch (e) {
        const status = Number(e?.statusCode) || 500;
        return jsonResponse({ error: String(e?.message || "Internal error") }, status);
      }
    }

    return jsonResponse({ error: "Not found" }, 404);
  }
};
