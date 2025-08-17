// app/api/check/route.js
// export const runtime = "nodejs";
export const runtime = "edge";

/** ---------- polite request headers ---------- */
const UA_HEADERS = {
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
  "accept-language": "en-GB,en;q=0.9",
};

// More “browser-like” headers for WAF retry
const BROWSER_HEADERS = {
  "user-agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
  accept:
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language": "en-GB,en;q=0.9",
  "upgrade-insecure-requests": "1",
  "sec-fetch-site": "none",
  "sec-fetch-mode": "navigate",
  "sec-fetch-user": "?1",
  "sec-fetch-dest": "document",
  "sec-ch-ua":
    '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
  "sec-ch-ua-mobile": "?0",
  "sec-ch-ua-platform": '"macOS"',
  referer: "https://www.google.com/",
};

const BLOCK_CODES = new Set([401, 403, 429]);

// Global cap for the whole audit (leave headroom for cold start)
const OVERALL_BUDGET_MS = parseInt(process.env.AUDIT_BUDGET_MS || "8500", 10);

const LIMITS = {
  SITEMAP_SAMPLES: 1,     // was 2
  IMAGE_HEADS: 2,         // was 4
  TIME_PAGE_MS: 6000,     // was 12000
  TIME_ASSET_MS: 2000,    // was 5000
  TIME_SMALL_MS: 1500,    // was 4000
  TIME_PSI_MS: 2500,      // was 10000
  MAX_SUBREQUESTS: 8,     // was 12
};

/** ---------- omit compute, but return locked placeholders ---------- */
const OMIT_CHECKS = new Set([
  "mixed-content",
  "security-headers",
  "https-redirect",
  "compression",
  "structured-data",
]);

const LABELS = {
  "mixed-content": "No mixed content",
  "security-headers": "Security headers",
  "https-redirect": "HTTP → HTTPS redirect",
  "compression": "HTML compression",
  "structured-data": "Structured data (JSON-LD)",
  "h1-structure": "Headings (H1/H2) Structure",
  llms: "LLMs.txt",
  timeout: "Site response timed out",
};
const LOCK_PLACEHOLDER = (id) => ({
  id,
  label: LABELS[id] || id,
  status: "locked",
  locked: true,
});

/** ---------- CORS (dynamic echo) ---------- */
function corsHeadersFrom(req) {
  const origin = req?.headers?.get("origin") || "*";
  const reqHdrs =
    req?.headers?.get("access-control-request-headers") || "Content-Type";
  return {
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": reqHdrs,
    "Access-Control-Max-Age": "86400",
  };
}
const json = (req, status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeadersFrom(req), "Content-Type": "application/json" },
  });

export async function OPTIONS(req) {
  return new Response(null, { status: 204, headers: corsHeadersFrom(req) });
}

/** ---------- simple in-memory cache (per process) ---------- */
const CACHE_TTL_MS = parseInt(process.env.AUDIT_CACHE_TTL_MS || "90000", 10); // 90s
const CACHE = new Map(); // key -> { payload, createdAt, expiresAt }

function normalizeKey(rawUrl) {
  try {
    const u = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
    u.hash = ""; u.search = "";
    const path = u.pathname.replace(/\/+$/, "/");
    return `${u.origin}${path}`;
  } catch {
    return String(rawUrl || "");
  }
}
function cacheGet(key) {
  const rec = CACHE.get(key);
  if (!rec) return null;
  if (Date.now() > rec.expiresAt) { CACHE.delete(key); return null; }
  return rec;
}
function cacheSet(key, payload) {
  const now = Date.now();
  CACHE.set(key, { payload, createdAt: now, expiresAt: now + CACHE_TTL_MS });
}

/** ---------- GET ---------- */
export async function GET(req) {
  const { searchParams } = new URL(req.url);
  const rawUrl = searchParams.get("url");
  if (!rawUrl) return json(req, 200, { ok: true, ping: "pong" });

  const noCache = searchParams.get("nocache") === "1";
  const key = normalizeKey(rawUrl);
  if (!noCache) {
    const hit = cacheGet(key);
    if (hit) {
      const age = Date.now() - hit.createdAt;
      return json(req, 200, { ...hit.payload, cached: true, cacheAgeMs: age });
    }
  }

  try {
    const out = await runAudit(req, rawUrl);
    const { _diag, ...copy } = out;
    if (!copy.blocked && !copy.timeout) cacheSet(key, copy); // don't cache blocked/timeout
    return json(req, 200, { ...copy, _diag });
  } catch (e) {
    const msg = e?.message || "Unknown error";
    return json(req, 500, { ok: false, errors: [msg] });
  }
}

/** ---------- POST ---------- */
export async function POST(req) {
  try {
    const body = await req.json().catch(() => ({}));
    const rawUrl = body?.url;
    const noCache = !!body?.nocache;
    if (!rawUrl) return json(req, 400, { ok: false, errors: ["Invalid URL"] });

    const key = normalizeKey(rawUrl);
    if (!noCache) {
      const hit = cacheGet(key);
      if (hit) {
        const age = Date.now() - hit.createdAt;
        return json(req, 200, { ...hit.payload, cached: true, cacheAgeMs: age });
      }
    }

    const out = await runAudit(req, rawUrl);
    const { _diag, ...copy } = out;
    if (!copy.blocked && !copy.timeout) cacheSet(key, copy);
    return json(req, 200, { ...copy, _diag });
  } catch (e) {
    const msg = e?.message || "Unknown error";
    return json(req, 500, { ok: false, errors: [msg] });
  }
}

/** ---------- utils ---------- */
const isOk = (res) => res && res.status >= 200 && res.status < 400;

const withTimeout = (ms = 12000) => {
  const c = new AbortController();
  const id = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(id) };
};

// retries on AbortError / common network errors, with backoff + jitter
async function retry(fn, { tries = 2, baseDelay = 400 } = {}) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try { return await fn(); }
    catch (e) {
      lastErr = e;
      const msg = String(e?.message || "");
      const isAbort = e?.name === "AbortError";
      const isNetty = /fetch failed|network|ECONNRESET|EAI_AGAIN|ENOTFOUND|ETIMEDOUT/i.test(msg);
      if (i < tries - 1 && (isAbort || isNetty)) {
        const jitter = Math.floor(Math.random() * 250);
        await new Promise((r) => setTimeout(r, baseDelay * (i + 1) + jitter));
        continue;
      }
      throw e;
    }
  }
  throw lastErr;
}

const tryHeadThenGet = async (
  url,
  { timeoutMs = LIMITS.TIME_ASSET_MS, redirect = "follow", headers = UA_HEADERS } = {}
) => {
  return retry(async () => {
    const t1 = withTimeout(timeoutMs);
    try {
      const r = await fetch(url, { method: "HEAD", redirect, signal: t1.signal, headers, cache: "no-store" });
      if (r.status === 405 || r.status === 501) throw new Error("HEAD not allowed");
      return r;
    } catch {
      const t2 = withTimeout(timeoutMs);
      try {
        return await fetch(url, { method: "GET", redirect, signal: t2.signal, headers, cache: "no-store" });
      } finally { t2.done(); }
    } finally { t1.done(); }
  });
};

const absUrl = (base, href) => { try { return new URL(href, base).toString(); } catch { return undefined; } };
const parseTitle = (html) => { const m = /<title>([\s\S]*?)<\/title>/i.exec(html); return m ? m[1].trim() : ""; };
const getMetaBy = (html, attr, name) => {
  const re = new RegExp(`<meta[^>]*${attr}=["']${name}["'][^>]*>`, "i");
  const m = re.exec(html);
  if (!m) return undefined;
  const tag = m[0]; const c = /content=["']([^"']+)["']/i.exec(tag);
  return c ? c[1] : "";
};
const getMetaName = (html, name) => getMetaBy(html, "name", name);
const getMetaProp = (html, prop) => getMetaBy(html, "property", prop);

/** ---------- audit core ---------- */
async function runAudit(req, rawUrl) {
  const normalizedUrl = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;

  // diag (only when DEBUG_AUDIT=1)
  const DIAG = [];
  const timed = async (label, fn) => {
    const t = Date.now();
    try { return await fn(); }
    finally { if (process.env.DEBUG_AUDIT === "1") DIAG.push({ label, ms: Date.now() - t }); }
  };

  // overall budget
  const startedAt = Date.now();
  const timeLeft = () => Math.max(0, OVERALL_BUDGET_MS - (Date.now() - startedAt));
  const within = (ms) => Math.max(150, Math.min(ms, timeLeft())); // never less than 150ms

  // sub-request budget
  let budget = LIMITS.MAX_SUBREQUESTS;
  const spend = (n = 1) => { if (budget - n < 0) return false; budget -= n; return true; };

  // Helper: partial fallback for TIMEOUT (no HTML)
  const timeoutPartial = async (statusText = "Main page fetch exceeded time budget") => {
    const checks = [];

    // Emit a dedicated timeout card (you’ll map this in Framer under Performance)
    checks.push({
      id: "timeout",
      label: LABELS.timeout,
      status: "warn",
      details: statusText,
    });

   // favicon
    try {
      const favUrl = new URL("/favicon.ico", normalizedUrl).toString();
      const r = await tryHeadThenGet(favUrl, { timeoutMs: within(LIMITS.TIME_ASSET_MS), headers: BROWSER_HEADERS });
      checks.push({ id: "favicon", label: "Favicon present & loads", status: isOk(r) ? "pass" : "warn", details: favUrl, value: isOk(r) });
    } catch {
      checks.push({ id: "favicon", label: "Favicon present & loads", status: "warn", details: "Unknown" });
    }

   // robots.txt (best-effort + capture Sitemap: URLs + quick allow check)
let robotsSitemaps = [];           // <-- make sure this is in scope for the sitemap probe below
try {
  // Always resolve from the site origin, not the deep page
  const origin = (() => { try { return new URL(normalizedUrl).origin; } catch { return normalizedUrl; } })();
  const robotsURL = new URL("/robots.txt", origin).toString();

  await timed("robots-timeout", async () => {
    const toR = withTimeout(within(LIMITS.TIME_SMALL_MS));
    try {
      const r = await fetch(robotsURL, {
        signal: toR.signal,
        headers: BROWSER_HEADERS,
        cache: "no-store",
      });

      if (r.ok) {
        const txt = await r.text();

        // Collect all explicit Sitemap: URLs (absolute them against robots location)
        const matches = [...txt.matchAll(/^\s*Sitemap:\s*(\S+)\s*$/gim)];
        robotsSitemaps = matches
          .map((m) => absUrl(robotsURL, m[1]))
          .filter(Boolean);

        // Quick “is everything disallowed for * ?”
        const blocks = txt.split(/(?=^User-agent:\s*)/gim);
        const star = blocks.find((b) => /^User-agent:\s*\*/im.test(b)) || "";
        const disallowAll = /^\s*Disallow:\s*\/\s*$/im.test(star);

        checks.push({
          id: "robots",
          label: "robots.txt allows indexing",
          status: disallowAll ? "fail" : "warn",
          details:
            (disallowAll ? "User-agent: * disallows /" : "Accessible") +
            (robotsSitemaps.length ? ` • ${robotsSitemaps.length} sitemap URL(s) listed` : ""),
        });
      } else {
        checks.push({
          id: "robots",
          label: "robots.txt allows indexing",
          status: "warn",
          details: `Unavailable (HTTP ${r.status})`,
        });
      }
    } finally {
      toR.done();
    }
  });
} catch {
  checks.push({
    id: "robots",
    label: "robots.txt allows indexing",
    status: "warn",
    details: "Unavailable",
  });
}

// Sitemap (HEAD only; common paths + robots.txt advertised URLs)
const origin = (() => { try { return new URL(normalizedUrl).origin; } catch { return normalizedUrl; } })();

let sitemapFound = null;
const candidates = new Set([
  new URL("/sitemap.xml", origin).toString(),
  new URL("/sitemap_index.xml", origin).toString(),
  new URL("/sitemap-index.xml", origin).toString(),
  new URL("/wp-sitemap.xml", origin).toString(),   // WordPress core
  ...(robotsSitemaps || []),
]);

for (const u of candidates) {
  if (timeLeft && timeLeft() < 300) break;
  try {
    const h = await tryHeadThenGet(u, {
      timeoutMs: within ? within(LIMITS.TIME_SMALL_MS) : LIMITS.TIME_SMALL_MS,
      headers: BROWSER_HEADERS,
    });
    if (isOk(h)) { sitemapFound = u; break; }
  } catch {}
}

checks.push({
  id: "sitemap",
  label: "Sitemap exists & URLs valid",
  status: sitemapFound ? "warn" : "fail",
  details: sitemapFound
    ? `Found: ${sitemapFound} (content not parsed in this fast path)`
    : "No sitemap found at common paths or in robots.txt",
});
   

    // placeholders
    for (const id of OMIT_CHECKS) checks.push(LOCK_PLACEHOLDER(id));
    for (const id of ["h1-structure", "llms"]) checks.push(LOCK_PLACEHOLDER(id));

    // PSI only if we still have some budget
    let psi;
    if (timeLeft() > 2000) {
      await timed("psi-timeout", async () => {
        try {
          const key = process.env.PSI_API_KEY;
          const u = new URL("https://www.googleapis.com/pagespeedonline/v5/runPagespeed");
          u.searchParams.set("url", normalizedUrl);
          u.searchParams.set("strategy", "mobile");
          if (key) u.searchParams.set("key", key);
          const to = withTimeout(within(LIMITS.TIME_PSI_MS));
          try {
            const res = await fetch(u.toString(), { signal: to.signal });
            if (res.ok) {
              const data = await res.json();
              const score = data?.lighthouseResult?.categories?.performance?.score;
              if (typeof score === "number") psi = Math.round(score * 100);
            }
          } finally { to.done(); }
        } catch {}
      });
      if (typeof psi === "number") {
        checks.push({ id: "psi", label: "PageSpeed (mobile)", status: psi >= 70 ? "pass" : "warn", details: `${psi}/100`, value: psi });
      }
    }

    const payload = {
      ok: true,
      timeout: true,
      url: rawUrl,
      normalizedUrl,
      finalUrl: normalizedUrl,
      fetchedStatus: 0,
      timingMs: OVERALL_BUDGET_MS,
      title: "",
      speed: psi,
      checks,
    };
    if (process.env.DEBUG_AUDIT === "1") payload._diag = DIAG;
    return payload;
  };

  // MAIN PAGE FETCH (with soft timeout)
  const t0 = Date.now();
  let pageRes;
  try {
    pageRes = await timed("page", () =>
      retry(async () => {
        const to = withTimeout(within(LIMITS.TIME_PAGE_MS));
        try {
          return await fetch(normalizedUrl, {
            redirect: "follow",
            signal: to.signal,
            headers: UA_HEADERS,
            cache: "no-store",
          });
        } finally { to.done(); }
      })
    );
  } catch (e) {
    // SOFT TIMEOUT: return partial instead of throwing up to GET/POST
    if (e?.name === "AbortError") {
      return timeoutPartial(`Main page fetch exceeded ~${LIMITS.TIME_PAGE_MS}ms`);
    }
    throw e; // non-timeout errors behave as before
  }

  // ---- Blocked handling (401/403/429) ----
  if (BLOCK_CODES.has(pageRes.status)) {
    await timed("blocked-retry", async () => {
      try {
        const to2 = withTimeout(within(6000));
        try {
          const r = await fetch(normalizedUrl, {
            redirect: "follow",
            signal: to2.signal,
            headers: BROWSER_HEADERS,
            cache: "no-store",
          });
          pageRes = r;
        } finally { to2.done(); }
      } catch {}
    });

    if (BLOCK_CODES.has(pageRes.status)) {
      // (unchanged) — your enriched blocked fallback
      // ... [SNIP: keep your existing blocked fallback from previous version] ...
      // For brevity here, keep the same "blocked" branch we added earlier, it already returns ok:true.
      return await timeoutPartial(`Blocked by WAF (HTTP ${pageRes.status})`); // <- OPTIONAL: or keep your detailed blocked branch
    }
  }

  // ---- Normal path ----
  const html = await pageRes.text();
  const timingMs = Date.now() - t0;
  const finalUrl = pageRes.url;

  const title = parseTitle(html);
  const urlObj = new URL(finalUrl);
  const origin = `${urlObj.protocol}//${urlObj.host}`;
  const host = urlObj.host;

  const checks = [];

  /** -------- Open Graph -------- */
  const ogTitle = getMetaProp(html, "og:title");
  const ogDesc = getMetaProp(html, "og:description");
  const ogImageRel = getMetaProp(html, "og:image");
  const ogImage = ogImageRel ? absUrl(finalUrl, ogImageRel) : undefined;
  let ogImageLoads = undefined;
  if (ogImage && spend() && timeLeft() > 300) {
    try {
      await timed("og:image", async () => {
        const to = withTimeout(within(LIMITS.TIME_ASSET_MS));
        try {
          const r = await fetch(ogImage, { method: "GET", signal: to.signal, headers: UA_HEADERS, cache: "no-store" });
          ogImageLoads = r.ok;
        } finally { to.done(); }
      });
    } catch { ogImageLoads = false; }
  }
  checks.push({
    id: "opengraph",
    label: "Open Graph tags",
    status:
      ogTitle && (ogImage && ogImageLoads !== false)
        ? "pass"
        : ogTitle || ogDesc || ogImage
        ? "warn"
        : "fail",
    details: `og:title=${!!ogTitle} og:description=${!!ogDesc} og:image=${!!ogImage} (image loads: ${
      ogImageLoads === true ? "yes" : ogImageLoads === false ? "no" : "unknown"
    })`,
  });

  /** -------- Favicon -------- */
  let faviconLoads = undefined;
  let faviconUrl = undefined;
  const iconRelMatch = [...html.matchAll(/<link[^>]*rel=["'][^"']*icon[^"']*["'][^>]*>/gi)][0]?.[0];
  const iconHref = iconRelMatch ? iconRelMatch.match(/href=["']([^"']+)["']/i)?.[1] : null;
  faviconUrl = absUrl(finalUrl, iconHref || "/favicon.ico");
  if (faviconUrl && spend() && timeLeft() > 250) {
    try {
      await timed("favicon", async () => {
        const r = await tryHeadThenGet(faviconUrl, { timeoutMs: within(LIMITS.TIME_ASSET_MS) });
        faviconLoads = isOk(r);
      });
    } catch { faviconLoads = false; }
  }
  checks.push({
    id: "favicon",
    label: "Favicon present & loads",
    status: faviconLoads === true ? "pass" : faviconLoads === false ? "fail" : "warn",
    details: faviconUrl || "No favicon reference found",
    value: faviconLoads,
  });

  /** -------- robots.txt -------- */
let robotsExists = false;
let robotsAllowsIndex = true;
let robotsSitemapListed = false;
let robotsText = "";
let robotsSitemaps = [];

if (timeLeft() > 250) {
  try {
    const robotsURL = absUrl(origin + "/", "/robots.txt");
    await timed("robots", async () => {
      const r = await retry(async () => {
        const tor = withTimeout(within(LIMITS.TIME_SMALL_MS));
        try {
          return await fetch(robotsURL, {
            redirect: "follow",
            signal: tor.signal,
            headers: UA_HEADERS,
            cache: "no-store",
          });
        } finally {
          tor.done();
        }
      });
      if (r.ok) {
        robotsExists = true;
        robotsText = await r.text();

        // index allow/deny (simple check for User-agent: * + Disallow: /)
        const blocks = robotsText.split(/(?=^User-agent:\s*)/gim);
        const star = blocks.find((b) => /^User-agent:\s*\*/im.test(b)) || "";
        if (/^\s*Disallow:\s*\/\s*$/im.test(star)) robotsAllowsIndex = false;

        // extract explicit Sitemap: lines
        const sitemapMatches = [...robotsText.matchAll(/^\s*Sitemap:\s*(\S+)\s*$/gim)];
        robotsSitemaps = sitemapMatches
          .map((m) => absUrl(robotsURL, m[1]))
          .filter(Boolean);
        robotsSitemapListed = robotsSitemaps.length > 0;
      }
    });
  } catch {}
}

checks.push({
  id: "robots",
  label: "robots.txt allows indexing",
  status: robotsExists ? (robotsAllowsIndex ? "pass" : "fail") : "warn",
  details: robotsExists
    ? `${robotsAllowsIndex ? "User-agent: * allowed" : "User-agent: * disallows /"}${
        robotsSitemapListed ? ` • ${robotsSitemaps.length} sitemap URL(s) listed` : ""
      }`
    : "robots.txt not found",
});


 /** -------- sitemap.xml -------- */
let sitemapUrl = null;
let sitemapHasUrls = false;
let sitemapSampleOk = 0;
let sitemapGzipped = false;

// common paths + robots.txt advertised URLs (unique)
const commonPaths = [
  "/sitemap.xml",
  "/sitemap_index.xml",
  "/sitemap-index.xml",
  "/wp-sitemap.xml", // ← important for WordPress core
];
const candidateSet = new Set([
  ...commonPaths.map((p) => absUrl(origin + "/", p)),
  ...robotsSitemaps,
]);
const candidates = [...candidateSet].filter(Boolean);

// find a reachable sitemap URL
for (const u of candidates) {
  if (timeLeft() < 250) break;
  try {
    await timed(`sitemap-head ${new URL(u).pathname}`, async () => {
      const h = await tryHeadThenGet(u, { timeoutMs: within(LIMITS.TIME_SMALL_MS) });
      if (isOk(h) && !sitemapUrl) {
        sitemapUrl = u;
        const ct = (h.headers.get("content-type") || "").toLowerCase();
        sitemapGzipped =
          /\.gz(\?|#|$)/i.test(u) ||
          /application\/gzip|application\/x-gzip/i.test(ct);
      }
    });
    if (sitemapUrl) break;
  } catch {}
}

if (sitemapUrl) {
  // If gzipped, don’t try to parse (Edge runtime lacks Node zlib); just report found.
  if (sitemapGzipped) {
    checks.push({
      id: "sitemap",
      label: "Sitemap exists & URLs valid",
      status: "warn",
      details: `Found gzipped sitemap: ${sitemapUrl} (content not parsed)`,
    });
  } else {
    try {
      await timed("sitemap-get", async () => {
        const r = await retry(async () => {
          const tos = withTimeout(within(LIMITS.TIME_PAGE_MS));
          try {
            return await fetch(sitemapUrl, {
              redirect: "follow",
              signal: tos.signal,
              headers: UA_HEADERS,
              cache: "no-store",
            });
          } finally {
            tos.done();
          }
        });
        if (r.ok) {
          const xml = await r.text();

          // Works for both urlset and sitemapindex because we just gather all <loc> values
          const locs = [...xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)].map((m) =>
            m[1].trim()
          );
          const absLocs = locs.map((h) => absUrl(sitemapUrl, h)).filter(Boolean);
          sitemapHasUrls = absLocs.length > 0;

          const toCheck = absLocs.slice(0, LIMITS.SITEMAP_SAMPLES);
          const results = await Promise.all(
            toCheck.map(async (u, i) => {
              if (!spend() || timeLeft() < 200) return false;
              try {
                return await timed(`sitemap-sample-${i}`, async () => {
                  const rr = await tryHeadThenGet(u, {
                    timeoutMs: within(LIMITS.TIME_ASSET_MS),
                  });
                  return isOk(rr);
                });
              } catch {
                return false;
              }
            })
          );
          sitemapSampleOk = results.filter(Boolean).length;
        }
      });
    } catch {}
    checks.push({
      id: "sitemap",
      label: "Sitemap exists & URLs valid",
      status:
        sitemapHasUrls && sitemapSampleOk > 0 ? "pass" : "warn",
      details: `Found: ${sitemapUrl} • URLs: ${
        sitemapHasUrls ? "yes" : "no"
      } • Valid samples: ${sitemapSampleOk}`,
    });
  }
} else {
  checks.push({
    id: "sitemap",
    label: "Sitemap exists & URLs valid",
    status: "fail",
    details: `No sitemap found at common paths or in robots.txt`,
  });
}


  /** -------- www ↔ non-www redirect -------- */
  let canonicalization = { tested: false, from: "", to: "", code: 0, good: false };
  if (timeLeft() > 250) {
    try {
      const variantHost = /^www\./i.test(host) ? host.replace(/^www\./i, "") : "www." + host;
      if (variantHost !== host && spend()) {
        const variantOrigin = `${urlObj.protocol}//${variantHost}`;
        const variantUrl = variantOrigin + "/";
        await timed("www-variant", async () => {
          const r = await retry(async () => {
            const tv = withTimeout(within(LIMITS.TIME_SMALL_MS));
            try {
              return await fetch(variantUrl, { method: "GET", redirect: "manual", signal: tv.signal, headers: UA_HEADERS, cache: "no-store" });
            } finally { tv.done(); }
          });
          const code = r.status;
          const loc = r.headers.get("location");
          let good = false; let to2 = "";
          if (loc) {
            const resolved = absUrl(variantUrl, loc);
            to2 = resolved || loc;
            try { good = new URL(to2).host === host && [301, 308, 302, 307].includes(code); } catch {}
          }
          canonicalization = { tested: true, from: variantUrl, to: to2, code, good };
        });
      }
    } catch { canonicalization = { tested: true, from: "", to: "", code: 0, good: false }; }
  }
  checks.push({
    id: "www-canonical",
    label: "www/non-www redirects to canonical",
    status: canonicalization.tested ? (canonicalization.good ? "pass" : "warn") : "warn",
    details: canonicalization.tested
      ? `from ${canonicalization.from} → ${canonicalization.to || "(no redirect)"} (${canonicalization.code})`
      : "Not applicable",
  });

  /** -------- simple status/ttfb -------- */
  checks.push({
    id: "http",
    label: "HTTP status 200–399",
    status: pageRes.status < 400 ? "pass" : "fail",
    details: String(pageRes.status),
  });
  checks.push({
    id: "ttfb",
    label: "Response time < 1500ms",
    status: timingMs < 1500 ? "pass" : "warn",
    details: `${timingMs} ms`,
  });

  /** -------- Canonical tag (robust-ish) -------- */
  const canonTags = [...html.matchAll(/<link\b[^>]*>/gi)]
    .map((m) => m[0])
    .filter((tag) => /\brel\s*=\s*["']?\s*canonical\s*["']?/i.test(tag));
  let canonicalHref, canonicalOk, multipleCanon = canonTags.length > 1;
  if (canonTags.length) {
    const hrefm = canonTags[0].match(/\bhref\s*=\s*["']?([^"'\s>]+)["']?/i);
    canonicalHref = hrefm ? absUrl(finalUrl, hrefm[1]) : undefined;
    try {
      const a = new URL(canonicalHref);
      const b = new URL(finalUrl);
      a.hash = ""; a.search = ""; a.hostname = a.hostname.toLowerCase();
      b.hash = ""; b.search = ""; b.hostname = b.hostname.toLowerCase();
      if (a.pathname !== "/") a.pathname = a.pathname.replace(/\/+$/, "");
      if (b.pathname !== "/") b.pathname = b.pathname.replace(/\/+$/, "");
      canonicalOk = a.toString() === b.toString();
    } catch { canonicalOk = undefined; }
  }
  checks.push({
    id: "canonical",
    label: "Canonical tag",
    status: canonicalHref ? (canonicalOk && !multipleCanon ? "pass" : "warn") : "fail",
    details: canonicalHref
      ? `${canonicalOk ? "Matches URL" : `Points to ${canonicalHref}`}${multipleCanon ? " • multiple canonicals" : ""}`
      : "Missing",
  });

  /** -------- Meta robots & X-Robots-Tag -------- */
  const robotsMetaVal = getMetaName(html, "robots")?.toLowerCase() || "";
  const robotsHeader = pageRes.headers.get("x-robots-tag")?.toLowerCase() || "";
  const noindex =
    /(^|,|\s)noindex(\s|,|$)/.test(robotsMetaVal) || /noindex/.test(robotsHeader);
  checks.push({
    id: "meta-robots",
    label: "Robots directives",
    status: noindex ? "fail" : "pass",
    details: robotsHeader ? `Header: ${robotsHeader}` : robotsMetaVal ? `Meta: ${robotsMetaVal}` : "None",
  });

  /** -------- Meta description + title length -------- */
  const metaDesc = getMetaName(html, "description") || "";
  const titleLen = (title || "").trim().length;
  checks.push({
    id: "meta-description",
    label: "Meta description length",
    status: metaDesc ? (metaDesc.length >= 50 && metaDesc.length <= 160 ? "pass" : "warn") : "fail",
    details: metaDesc ? `${metaDesc.length} chars` : "Missing",
  });
  checks.push({
    id: "title-length",
    label: "Title length",
    status: titleLen ? (titleLen >= 15 && titleLen <= 60 ? "pass" : "warn") : "fail",
    details: titleLen ? `${titleLen} chars` : "Missing",
  });

  /** -------- Viewport -------- */
  const hasViewport = /<meta[^>]+name=["']viewport["'][^>]*>/i.test(html);
  checks.push({ id: "viewport", label: "Mobile viewport tag", status: hasViewport ? "pass" : "fail", details: hasViewport ? "Present" : "Missing" });

  /** -------- Images -------- */
  const imgTags = [...html.matchAll(/<img[^>]*>/gi)].map((m) => m[0]).slice(0, 40);
  const imgSrcs = imgTags
    .map((t) => t.match(/src=["']([^"']+)["']/i)?.[1])
    .filter(Boolean)
    .map((s) => absUrl(finalUrl, s))
    .filter(Boolean);
  const alts = imgTags.map((t) => t.match(/alt=["']([^"']*)["']/i)?.[1] ?? "").filter((a) => a !== null);
  const altOk = alts.length ? alts.filter((a) => a.trim().length > 0).length / alts.length : 1;
  const modernFmt = imgSrcs.filter((u) => /\.(avif|webp)(\?|#|$)/i.test(u)).length;
  const lazyCount = imgTags.filter((t) => /loading=["']lazy["']/i.test(t)).length;

  let huge = 0;
  for (const [i, u] of imgSrcs.slice(0, LIMITS.IMAGE_HEADS).entries()) {
    if (!spend() || timeLeft() < 200) break;
    try {
      await timed(`img-head-${i}`, async () => {
        const r = await retry(async () => {
          const th = withTimeout(within(LIMITS.TIME_ASSET_MS));
          try {
            return await fetch(u, { method: "HEAD", signal: th.signal, headers: UA_HEADERS, cache: "no-store" });
          } finally { th.done(); }
        });
        const len = parseInt(r.headers.get("content-length") || "0", 10);
        if (len > 300_000) huge++;
      });
    } catch {}
  }

  checks.push({ id: "img-alt", label: "Images have alt text", status: altOk >= 0.9 ? "pass" : altOk >= 0.6 ? "warn" : "fail", details: `Alt coverage: ${Math.round(altOk * 100)}%` });
  checks.push({ id: "img-modern", label: "Modern image formats", status: modernFmt > 0 ? "pass" : "warn", details: `${modernFmt} AVIF/WebP seen` });
  checks.push({ id: "img-size", label: "Large images", status: huge === 0 ? "pass" : huge <= 2 ? "warn" : "fail", details: `${huge} images >300KB (first ${LIMITS.IMAGE_HEADS})` });
  checks.push({ id: "img-lazy", label: "Lazy-loading", status: lazyCount > 0 ? "pass" : "warn", details: `${lazyCount} images with loading="lazy"` });

  /** -------- placeholders -------- */
  for (const id of OMIT_CHECKS) checks.push(LOCK_PLACEHOLDER(id));
  for (const id of ["h1-structure", "llms"]) checks.push(LOCK_PLACEHOLDER(id));

  /** -------- PSI (optional) -------- */
  let psi = undefined;
  if (spend(2) && timeLeft() > 2000) {
    try {
      await timed("psi", async () => {
        const key = process.env.PSI_API_KEY;
        const u = new URL("https://www.googleapis.com/pagespeedonline/v5/runPagespeed");
        u.searchParams.set("url", finalUrl);
        u.searchParams.set("strategy", "mobile");
        if (key) u.searchParams.set("key", key);
        const to = withTimeout(within(LIMITS.TIME_PSI_MS));
        try {
          const res = await fetch(u.toString(), { signal: to.signal });
          if (res.ok) {
            const data = await res.json();
            const score = data?.lighthouseResult?.categories?.performance?.score;
            if (typeof score === "number") psi = Math.round(score * 100);
          }
        } finally { to.done(); }
      });
    } catch {}
  }
  if (typeof psi === "number") {
    checks.push({ id: "psi", label: "PageSpeed (mobile)", status: psi >= 70 ? "pass" : "warn", details: `${psi}/100`, value: psi });
  }

  const payload = {
    ok: true,
    url: rawUrl,
    normalizedUrl,
    finalUrl,
    fetchedStatus: pageRes.status,
    timingMs,
    title,
    speed: psi,
    checks,
  };
  if (process.env.DEBUG_AUDIT === "1") payload._diag = DIAG;
  return payload;
}



