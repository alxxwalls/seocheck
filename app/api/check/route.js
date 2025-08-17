// app/api/check/route.js
// Prefer Node for longer time limits + fewer host blocks (you can switch to "edge" if you want).
export const runtime = "nodejs";

/** ---------- polite request headers for target sites ---------- */
const UA_HEADERS = {
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
  "accept-language": "en-GB,en;q=0.9",
};

/** ---------- CORS (dynamic echo) ---------- */
function corsHeadersFrom(req) {
  const origin = req?.headers?.get("origin") || "*";
  const reqHdrs = req?.headers?.get("access-control-request-headers") || "Content-Type";
  return {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
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

/** 
 * GET
 * - /api/check            -> health ping
 * - /api/check?url=...    -> run audit (no preflight)
 */
export async function GET(req) {
  const { searchParams } = new URL(req.url);
  const rawUrl = searchParams.get("url");
  if (!rawUrl) {
    return json(req, 200, { ok: true, ping: "pong" });
  }
  try {
    return await runAudit(req, rawUrl);
  } catch (e) {
    const msg = e?.name === "AbortError" ? "Upstream fetch timed out" : e?.message || "Unknown error";
    return json(req, e?.name === "AbortError" ? 504 : 500, { ok: false, errors: [msg] });
  }
}

/** ---------- utils ---------- */
const isOk = (res) => res && res.status >= 200 && res.status < 400;

const withTimeout = (ms = 12000) => {
  const c = new AbortController();
  const id = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(id) };
};

const tryHeadThenGet = async (url, { timeoutMs = 12000, redirect = "follow" } = {}) => {
  const t1 = withTimeout(timeoutMs);
  try {
    const r = await fetch(url, {
      method: "HEAD",
      redirect,
      signal: t1.signal,
      headers: UA_HEADERS,
      cache: "no-store",
    });
    t1.done();
    if (r.status === 405 || r.status === 501) throw new Error("HEAD not allowed");
    return r;
  } catch {
    const t2 = withTimeout(timeoutMs);
    const r = await fetch(url, {
      method: "GET",
      redirect,
      signal: t2.signal,
      headers: UA_HEADERS,
      cache: "no-store",
    });
    t2.done();
    return r;
  }
};

const absUrl = (base, href) => {
  try {
    return new URL(href, base).toString();
  } catch {
    return undefined;
  }
};

const parseTitle = (html) => {
  const m = /<title>([\s\S]*?)<\/title>/i.exec(html);
  return m ? m[1].trim() : "";
};

const getMetaBy = (html, attr, name) => {
  const re = new RegExp(`<meta[^>]*${attr}=["']${name}["'][^>]*>`, "i");
  const m = re.exec(html);
  if (!m) return undefined;
  const tag = m[0];
  const c = /content=["']([^"']+)["']/i.exec(tag);
  return c ? c[1] : "";
};
const getMetaName = (html, name) => getMetaBy(html, "name", name);
const getMetaProp = (html, prop) => getMetaBy(html, "property", prop);

const findIconHref = (html) => {
  const links = [...html.matchAll(/<link[^>]*>/gi)].map((x) => x[0]);
  const iconLinks = links.filter((l) => /rel=["'][^"']*icon[^"']*["']/i.test(l));
  for (const tag of iconLinks) {
    const m = /href=["']([^"']+)["']/i.exec(tag);
    if (m) return m[1];
  }
  return null;
};

const getHostVariant = (host) => (/^www\./i.test(host) ? host.replace(/^www\./i, "") : "www." + host);

/** Optional PSI performance score */
async function fetchPsiPerformance(url) {
  try {
    const key = process.env.PSI_API_KEY;
    const u = new URL("https://www.googleapis.com/pagespeedonline/v5/runPagespeed");
    u.searchParams.set("url", url);
    u.searchParams.set("strategy", "mobile");
    if (key) u.searchParams.set("key", key);
    const res = await fetch(u.toString());
    if (!res.ok) return undefined;
    const data = await res.json();
    const score = data?.lighthouseResult?.categories?.performance?.score;
    if (typeof score === "number") return Math.round(score * 100);
  } catch {}
  return undefined;
}

/** ---------- POST (JSON body { url }) ---------- */
export async function POST(req) {
  try {
    const body = await req.json().catch(() => ({}));
    const rawUrl = body?.url;
    if (!rawUrl) return json(req, 400, { ok: false, errors: ["Invalid URL"] });
    return await runAudit(req, rawUrl);
  } catch (e) {
    const msg = e?.name === "AbortError" ? "Upstream fetch timed out" : e?.message || "Unknown error";
    return json(req, e?.name === "AbortError" ? 504 : 500, { ok: false, errors: [msg] });
  }
}

/** ---------- shared audit logic (used by GET & POST) ---------- */
async function runAudit(req, rawUrl) {
  const normalizedUrl = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;

  // Fetch the page with timeout + UA
  const t0 = Date.now();
  const to = withTimeout(12000);
  let pageRes;
  try {
    pageRes = await fetch(normalizedUrl, {
      redirect: "follow",
      signal: to.signal,
      headers: UA_HEADERS,
      cache: "no-store",
    });
  } finally {
    to.done();
  }
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
  if (ogImage) {
    try {
      const r = await tryHeadThenGet(ogImage, { timeoutMs: 8000 });
      ogImageLoads = isOk(r);
    } catch {
      ogImageLoads = false;
    }
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
  const iconRel = findIconHref(html) || "/favicon.ico";
  const faviconUrl = absUrl(finalUrl, iconRel);
  let faviconLoads = undefined;
  if (faviconUrl) {
    try {
      const r = await tryHeadThenGet(faviconUrl, { timeoutMs: 6000 });
      faviconLoads = isOk(r);
    } catch {
      faviconLoads = false;
    }
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
  try {
    const robotsURL = absUrl(origin + "/", "/robots.txt");
    const tor = withTimeout(8000);
    try {
      const r = await fetch(robotsURL, {
        redirect: "follow",
        signal: tor.signal,
        headers: UA_HEADERS,
        cache: "no-store",
      });
      if (r.ok) {
        robotsExists = true;
        const text = await r.text();
        const blocks = text.split(/(?=^User-agent:\s*)/gim);
        const star = blocks.find((b) => /^User-agent:\s*\*/im.test(b)) || "";
        if (/^\s*Disallow:\s*\/\s*$/im.test(star)) robotsAllowsIndex = false;
        robotsSitemapListed = /(^|\n)\s*Sitemap:\s*https?:\/\//i.test(text);
      }
    } finally {
      tor.done();
    }
  } catch {}
  checks.push({
    id: "robots",
    label: "robots.txt allows indexing",
    status: robotsExists ? (robotsAllowsIndex ? "pass" : "fail") : "warn",
    details: robotsExists
      ? `${robotsAllowsIndex ? "User-agent: * allowed" : "User-agent: * disallows /"}${
          robotsSitemapListed ? " • sitemap listed" : ""
        }`
      : "robots.txt not found",
  });

  /** -------- sitemap.xml -------- */
  let sitemapUrl = null,
    sitemapHasUrls = false,
    sitemapSampleOk = 0;
  for (const p of ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]) {
    const u = absUrl(origin + "/", p);
    try {
      const h = await tryHeadThenGet(u, { timeoutMs: 7000 });
      if (isOk(h)) {
        sitemapUrl = u;
        break;
      }
    } catch {}
  }
  if (sitemapUrl) {
    try {
      const tos = withTimeout(12000);
      try {
        const r = await fetch(sitemapUrl, {
          redirect: "follow",
          signal: tos.signal,
          headers: UA_HEADERS,
          cache: "no-store",
        });
        if (r.ok) {
          const xml = await r.text();
          const locs = [...xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)].map((m) => m[1].trim());
          const absLocs = locs.map((h) => absUrl(sitemapUrl, h)).filter(Boolean);
          sitemapHasUrls = absLocs.length > 0;
          const toCheck = absLocs.slice(0, 5);
          const results = await Promise.all(
            toCheck.map(async (u) => {
              try {
                const rr = await tryHeadThenGet(u, { timeoutMs: 6000 });
                return isOk(rr);
              } catch {
                return false;
              }
            })
          );
          sitemapSampleOk = results.filter(Boolean).length;
        }
      } finally {
        tos.done();
      }
    } catch {}
  }
  checks.push({
    id: "sitemap",
    label: "Sitemap exists & URLs valid",
    status: sitemapUrl ? (sitemapHasUrls && sitemapSampleOk > 0 ? "pass" : "warn") : "fail",
    details: sitemapUrl
      ? `Found: ${sitemapUrl} • URLs: ${sitemapHasUrls ? "yes" : "no"} • Valid samples: ${sitemapSampleOk}`
      : "No sitemap found",
  });

  /** -------- www ↔ non-www redirect -------- */
  let canonicalization = { tested: false, from: "", to: "", code: 0, good: false };
  try {
    const variantHost = getHostVariant(host);
    if (variantHost !== host) {
      const variantOrigin = `${urlObj.protocol}//${variantHost}`;
      const variantUrl = variantOrigin + "/";
      const tv = withTimeout(7000);
      try {
        const r = await fetch(variantUrl, {
          method: "GET",
          redirect: "manual",
          signal: tv.signal,
          headers: UA_HEADERS,
          cache: "no-store",
        });
        const code = r.status;
        const loc = r.headers.get("location");
        let good = false;
        let to2 = "";
        if (loc) {
          const resolved = absUrl(variantUrl, loc);
          to2 = resolved || loc;
          try {
            good = new URL(to2).host === host && [301, 308, 302, 307].includes(code);
          } catch {}
        }
        canonicalization = { tested: true, from: variantUrl, to: to2, code, good };
      } finally {
        tv.done();
      }
    }
  } catch {
    canonicalization = { tested: true, from: "", to: "", code: 0, good: false };
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

  /** -------- Canonical tag -------- */
  const canonTags = [...html.matchAll(/<link[^>]+rel=["']canonical["'][^>]*>/gi)];
  let canonicalHref,
    canonicalOk,
    multipleCanon = false;
  if (canonTags.length) {
    multipleCanon = canonTags.length > 1;
    const hrefm = canonTags[0][0].match(/href=["']([^"']+)["']/i);
    canonicalHref = hrefm ? absUrl(finalUrl, hrefm[1]) : undefined;
    try {
      const a = new URL(canonicalHref);
      const b = new URL(finalUrl);
      a.search = "";
      a.hash = "";
      b.search = "";
      b.hash = "";
      canonicalOk = a.toString() === b.toString();
    } catch {
      canonicalOk = undefined;
    }
  }
  checks.push({
    id: "canonical",
    label: "Canonical tag",
    status: canonicalHref ? (canonicalOk && !multipleCanon ? "pass" : "warn") : "fail",
    details: canonicalHref
      ? `${canonicalOk ? "Matches URL" : "Points elsewhere"}${multipleCanon ? " • multiple canonicals" : ""}`
      : "Missing",
  });

  /** -------- Meta robots & X-Robots-Tag -------- */
  const robotsMetaVal = getMetaName(html, "robots")?.toLowerCase() || "";
  const robotsHeader = pageRes.headers.get("x-robots-tag")?.toLowerCase() || "";
  const noindex = /(^|,|\s)noindex(\s|,|$)/.test(robotsMetaVal) || /noindex/.test(robotsHeader);
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
  checks.push({
    id: "viewport",
    label: "Mobile viewport tag",
    status: hasViewport ? "pass" : "fail",
    details: hasViewport ? "Present" : "Missing",
  });

  /** -------- HTTP → HTTPS redirect -------- */
  let httpToHttps = undefined,
    httpCode = 0,
    httpLoc = "";
  try {
    const httpUrl = finalUrl.replace(/^https:/i, "http:");
    if (httpUrl !== finalUrl) {
      const th = withTimeout(7000);
      try {
        const r = await fetch(httpUrl, {
          method: "GET",
          redirect: "manual",
          signal: th.signal,
          headers: UA_HEADERS,
          cache: "no-store",
        });
        httpCode = r.status;
        httpLoc = r.headers.get("location") || "";
        httpToHttps = httpLoc.startsWith("https://");
      } finally {
        th.done();
      }
    }
  } catch {}
  checks.push({
    id: "https-redirect",
    label: "HTTP → HTTPS redirect",
    status: httpToHttps === true ? "pass" : httpToHttps === false ? "fail" : "warn",
    details: httpCode ? `${httpCode} → ${httpLoc || "(no location)"}` : "Not applicable",
  });

  /** -------- Security headers -------- */
  const h = pageRes.headers;
  const sec = {
    csp: !!h.get("content-security-policy"),
    xfo: !!h.get("x-frame-options"),
    xcto: !!h.get("x-content-type-options"),
    ref: !!h.get("referrer-policy"),
    hsts: !!h.get("strict-transport-security"),
  };
  const have = Object.values(sec).filter(Boolean).length;
  checks.push({
    id: "security-headers",
    label: "Security headers",
    status: have >= 4 ? "pass" : have >= 2 ? "warn" : "fail",
    details: `CSP=${sec.csp} XFO=${sec.xfo} XCTO=${sec.xcto} Referrer-Policy=${sec.ref} HSTS=${sec.hsts}`,
  });

  /** -------- Images: alt, format, size, lazy -------- */
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
  for (const u of imgSrcs.slice(0, 8)) {
    try {
      const th = withTimeout(6000);
      try {
        const r = await fetch(u, {
          method: "HEAD",
          signal: th.signal,
          headers: UA_HEADERS,
          cache: "no-store",
        });
        const len = parseInt(r.headers.get("content-length") || "0", 10);
        if (len > 300_000) huge++;
      } finally {
        th.done();
      }
    } catch {}
  }

  checks.push({
    id: "img-alt",
    label: "Images have alt text",
    status: altOk >= 0.9 ? "pass" : altOk >= 0.6 ? "warn" : "fail",
    details: `Alt coverage: ${Math.round(altOk * 100)}%`,
  });
  checks.push({
    id: "img-modern",
    label: "Modern image formats",
    status: modernFmt > 0 ? "pass" : "warn",
    details: `${modernFmt} AVIF/WebP seen`,
  });
  checks.push({
    id: "img-size",
    label: "Large images",
    status: huge === 0 ? "pass" : huge <= 2 ? "warn" : "fail",
    details: `${huge} images >300KB (first 8)`,
  });
  checks.push({
    id: "img-lazy",
    label: "Lazy-loading",
    status: lazyCount > 0 ? "pass" : "warn",
    details: `${lazyCount} images with loading="lazy"`,
  });

  /** -------- Mixed content (on HTTPS) -------- */
  let mixed = 0;
  if (finalUrl.startsWith("https://")) {
    const httpRefs = [...html.matchAll(/\s(?:src|href)=["']http:\/\/[^"']+["']/gi)];
    mixed = httpRefs.length;
  }
  checks.push({
    id: "mixed-content",
    label: "No mixed content",
    status: mixed === 0 ? "pass" : mixed <= 3 ? "warn" : "fail",
    details: mixed ? `${mixed} http:// references` : "None detected",
  });

  /** -------- Structured data presence -------- */
  const jsonLdBlocks = [
    ...html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi),
  ]
    .map((m) => m[1].trim())
    .slice(0, 5);
  let ldTypes = [];
  for (const block of jsonLdBlocks) {
    try {
      const data = JSON.parse(block);
      const arr = Array.isArray(data) ? data : [data];
      for (const item of arr) if (item && typeof item === "object" && item["@type"]) ldTypes.push(String(item["@type"]));
    } catch {}
  }
  checks.push({
    id: "structured-data",
    label: "Structured data (JSON-LD)",
    status: ldTypes.length ? "pass" : "warn",
    details: ldTypes.length ? `Types: ${Array.from(new Set(ldTypes)).join(", ").slice(0, 120)}` : "No JSON-LD found",
  });

  /** -------- Compression -------- */
  const enc = pageRes.headers.get("content-encoding") || "";
  checks.push({
    id: "compression",
    label: "HTML compression",
    status: /br|gzip/i.test(enc) ? "pass" : "warn",
    details: enc ? `content-encoding: ${enc}` : "No content-encoding header",
  });

  /** -------- PSI (optional) -------- */
  const psi = await fetchPsiPerformance(finalUrl);
  if (typeof psi === "number") {
    checks.push({
      id: "psi",
      label: "PageSpeed (mobile)",
      status: psi >= 70 ? "pass" : "warn",
      details: `${psi}/100`,
      value: psi,
    });
  }

  // Success
  return json(req, 200, {
    ok: true,
    url: rawUrl,
    normalizedUrl,
    finalUrl,
    fetchedStatus: pageRes.status,
    timingMs,
    title,
    speed: psi,
    meta: { ogTitle, ogDesc, ogImage },
    checks,
  });
}
