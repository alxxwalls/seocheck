export const runtime = "edge";

/** CORS */
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders });
}

/** ---------- utils ---------- */
const isOk = (res) => res && res.status >= 200 && res.status < 400;

const withTimeout = (ms = 5000) => {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(t) };
};

const tryHeadThenGet = async (url, { timeoutMs = 5000, redirect = "follow" } = {}) => {
  const t1 = withTimeout(timeoutMs);
  try {
    const r = await fetch(url, { method: "HEAD", redirect, signal: t1.signal });
    t1.done();
    if (r.status === 405 || r.status === 501) throw new Error("HEAD not allowed");
    return r;
  } catch {
    const t2 = withTimeout(timeoutMs);
    const r = await fetch(url, { method: "GET", redirect, signal: t2.signal });
    t2.done();
    return r;
  }
};

const absUrl = (base, href) => {
  try { return new URL(href, base).toString(); } catch { return undefined; }
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
  const iconLinks = links.filter(l => /rel=["'][^"']*icon[^"']*["']/i.test(l));
  for (const tag of iconLinks) {
    const m = /href=["']([^"']+)["']/i.exec(tag);
    if (m) return m[1];
  }
  return null;
};

const getHostVariant = (host) => (/^www\./i.test(host) ? host.replace(/^www\./i, "") : "www." + host);

/** PSI optional */
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

/** ---------- main ---------- */
export async function POST(req) {
  try {
    const body = await req.json().catch(() => ({}));
    const rawUrl = body?.url;
    if (!rawUrl) {
      return new Response(JSON.stringify({ ok: false, errors: ["Invalid URL"] }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const normalizedUrl = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;

    // 1) Fetch page
    const t0 = Date.now();
    const pageRes = await fetch(normalizedUrl, { redirect: "follow" });
    const html = await pageRes.text();
    const timingMs = Date.now() - t0;
    const finalUrl = pageRes.url;
    const title = parseTitle(html);
    const urlObj = new URL(finalUrl);
    const origin = `${urlObj.protocol}//${urlObj.host}`;
    const host = urlObj.host;

    const checks = [];

    /** -------- Existing checks -------- */

    // Open Graph
    const ogTitle = getMetaProp(html, "og:title");
    const ogDesc = getMetaProp(html, "og:description");
    const ogImageRel = getMetaProp(html, "og:image");
    const ogImage = ogImageRel ? absUrl(finalUrl, ogImageRel) : undefined;
    let ogImageLoads = undefined;
    if (ogImage) {
      try {
        const r = await tryHeadThenGet(ogImage, { timeoutMs: 5000 });
        ogImageLoads = isOk(r);
      } catch { ogImageLoads = false; }
    }
    checks.push({
      id: "opengraph",
      label: "Open Graph tags",
      status: (ogTitle && (ogImage && ogImageLoads !== false)) ? "pass" : (ogTitle || ogDesc || ogImage) ? "warn" : "fail",
      details: `og:title=${!!ogTitle} og:description=${!!ogDesc} og:image=${!!ogImage} (image loads: ${ogImageLoads === true ? "yes" : ogImageLoads === false ? "no" : "unknown"})`
    });

    // Favicon
    const iconRel = findIconHref(html) || "/favicon.ico";
    const faviconUrl = absUrl(finalUrl, iconRel);
    let faviconLoads = undefined;
    if (faviconUrl) {
      try {
        const r = await tryHeadThenGet(faviconUrl, { timeoutMs: 5000 });
        faviconLoads = isOk(r);
      } catch { faviconLoads = false; }
    }
    checks.push({
      id: "favicon",
      label: "Favicon present & loads",
      status: faviconLoads === true ? "pass" : faviconLoads === false ? "fail" : "warn",
      details: faviconUrl || "No favicon reference found",
      value: faviconLoads
    });

    // robots.txt
    let robotsExists = false;
    let robotsAllowsIndex = true;
    let robotsSitemapListed = false;
    try {
      const robotsURL = absUrl(origin + "/", "/robots.txt");
      const r = await fetch(robotsURL, { redirect: "follow" });
      if (r.ok) {
        robotsExists = true;
        const text = await r.text();
        const blocks = text.split(/(?=^User-agent:\s*)/gim);
        const star = blocks.find(b => /^User-agent:\s*\*/im.test(b)) || "";
        if (/^\s*Disallow:\s*\/\s*$/im.test(star)) robotsAllowsIndex = false;
        robotsSitemapListed = /(^|\n)\s*Sitemap:\s*https?:\/\//i.test(text);
      }
    } catch {}
    checks.push({
      id: "robots",
      label: "robots.txt allows indexing",
      status: robotsExists ? (robotsAllowsIndex ? "pass" : "fail") : "warn",
      details: robotsExists ? (robotsAllowsIndex ? "User-agent: * allowed" : "User-agent: * disallows /") : "robots.txt not found"
    });

    // sitemap.xml
    let sitemapUrl = null, sitemapHasUrls = false, sitemapSampleOk = 0;
    for (const p of ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]) {
      const u = absUrl(origin + "/", p);
      try {
        const h = await tryHeadThenGet(u, { timeoutMs: 5000 });
        if (isOk(h)) { sitemapUrl = u; break; }
      } catch {}
    }
    if (sitemapUrl) {
      try {
        const r = await fetch(sitemapUrl, { redirect: "follow" });
        if (r.ok) {
          const xml = await r.text();
          const locs = [...xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)].map(m => m[1].trim());
          const absLocs = locs.map(h => absUrl(sitemapUrl, h)).filter(Boolean);
          sitemapHasUrls = absLocs.length > 0;
          const toCheck = absLocs.slice(0, 5);
          const results = await Promise.all(toCheck.map(async u => {
            try { const rr = await tryHeadThenGet(u, { timeoutMs: 5000 }); return isOk(rr); } catch { return false; }
          }));
          sitemapSampleOk = results.filter(Boolean).length;
        }
      } catch {}
    }
    checks.push({
      id: "sitemap",
      label: "Sitemap exists & URLs valid",
      status: sitemapUrl ? (sitemapHasUrls && sitemapSampleOk > 0 ? "pass" : "warn") : "fail",
      details: sitemapUrl ? `Found: ${sitemapUrl} • URLs: ${sitemapHasUrls ? "yes" : "no"} • Valid samples: ${sitemapSampleOk}` : "No sitemap found"
    });

    // www ↔ non-www canonical redirect
    let canonicalization = { tested: false, from: "", to: "", code: 0, good: false };
    try {
      const variantHost = getHostVariant(host);
      if (variantHost !== host) {
        const variantOrigin = `${urlObj.protocol}//${variantHost}`;
        const variantUrl = variantOrigin + "/";
        const r = await fetch(variantUrl, { method: "GET", redirect: "manual" });
        const code = r.status;
        const loc = r.headers.get("location");
        let good = false; let to = "";
        if (loc) {
          const resolved = absUrl(variantUrl, loc);
          to = resolved || loc;
          try { good = (new URL(to).host === host) && [301,308,302,307].includes(code); } catch {}
        }
        canonicalization = { tested: true, from: variantUrl, to, code, good };
      }
    } catch { canonicalization = { tested: true, from: "", to: "", code: 0, good: false }; }
    checks.push({
      id: "www-canonical",
      label: "www/non-www redirects to canonical",
      status: canonicalization.tested ? (canonicalization.good ? "pass" : "warn") : "warn",
      details: canonicalization.tested ? `from ${canonicalization.from} → ${canonicalization.to || "(no redirect)"} (${canonicalization.code})` : "Not applicable"
    });

    // HTTP status + response time
    checks.push({ id: "http", label: "HTTP status 200–399", status: pageRes.status < 400 ? "pass" : "fail", details: String(pageRes.status) });
    checks.push({ id: "ttfb", label: "Response time < 1500ms", status: timingMs < 1500 ? "pass" : "warn", details: `${timingMs} ms` });

    /** -------- NEW checks you asked for -------- */

    // Canonical tag
    const canonTags = [...html.matchAll(/<link[^>]+rel=["']canonical["'][^>]*>/gi)];
    let canonicalHref, canonicalOk, multipleCanon = false;
    if (canonTags.length) {
      multipleCanon = canonTags.length > 1;
      const hrefm = canonTags[0][0].match(/href=["']([^"']+)["']/i);
      canonicalHref = hrefm ? absUrl(finalUrl, hrefm[1]) : undefined;
      try {
        const a = new URL(canonicalHref); const b = new URL(finalUrl);
        a.search = ""; a.hash = ""; b.search = ""; b.hash = "";
        canonicalOk = a.toString() === b.toString();
      } catch { canonicalOk = undefined; }
    }
    checks.push({
      id: "canonical",
      label: "Canonical tag",
      status: canonicalHref ? (canonicalOk && !multipleCanon ? "pass" : "warn") : "fail",
      details: canonicalHref ? `${canonicalOk ? "Matches URL" : "Points elsewhere"}${multipleCanon ? " • multiple canonicals" : ""}` : "Missing"
    });

    // Meta robots & X-Robots-Tag
    const robotsMetaVal = getMetaName(html, "robots")?.toLowerCase() || "";
    const robotsHeader = pageRes.headers.get("x-robots-tag")?.toLowerCase() || "";
    const noindex = /(^|,|\s)noindex(\s|,|$)/.test(robotsMetaVal) || /noindex/.test(robotsHeader);
    const nofollow = /(^|,|\s)nofollow(\s|,|$)/.test(robotsMetaVal) || /nofollow/.test(robotsHeader);
    checks.push({
      id: "meta-robots",
      label: "Robots directives",
      status: noindex ? "fail" : "pass",
      details: robotsHeader ? `Header: ${robotsHeader}` : (robotsMetaVal ? `Meta: ${robotsMetaVal}` : "None")
    });

    // Meta description length
    const metaDesc = getMetaName(html, "description") || "";
    checks.push({
      id: "meta-description",
      label: "Meta description length",
      status: metaDesc ? (metaDesc.length >= 50 && metaDesc.length <= 160 ? "pass" : "warn") : "fail",
      details: metaDesc ? `${metaDesc.length} chars` : "Missing"
    });

    // Title length
    const titleLen = (title || "").trim().length;
    checks.push({
      id: "title-length",
      label: "Title length",
      status: titleLen ? (titleLen >= 15 && titleLen <= 60 ? "pass" : "warn") : "fail",
      details: titleLen ? `${titleLen} chars` : "Missing"
    });

    // Viewport
    const hasViewport = /<meta[^>]+name=["']viewport["'][^>]*>/i.test(html);
    checks.push({
      id: "viewport",
      label: "Mobile viewport tag",
      status: hasViewport ? "pass" : "fail",
      details: hasViewport ? "Present" : "Missing"
    });

    // HTTP → HTTPS redirect
    let httpToHttps = undefined, httpCode = 0, httpLoc = "";
    try {
      const httpUrl = finalUrl.replace(/^https:/i, "http:");
      if (httpUrl !== finalUrl) {
        const r = await fetch(httpUrl, { method: "GET", redirect: "manual" });
        httpCode = r.status; httpLoc = r.headers.get("location") || "";
        httpToHttps = httpLoc.startsWith("https://");
      }
    } catch {}
    checks.push({
      id: "https-redirect",
      label: "HTTP → HTTPS redirect",
      status: httpToHttps === true ? "pass" : httpToHttps === false ? "fail" : "warn",
      details: httpCode ? `${httpCode} → ${httpLoc || "(no location)"}` : "Not applicable"
    });

    // Security headers (CSP, XFO, X-CTO, Referrer-Policy, HSTS)
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
      details: `CSP=${sec.csp} XFO=${sec.xfo} XCTO=${sec.xcto} Referrer-Policy=${sec.ref} HSTS=${sec.hsts}`
    });

    // Images: alt text, modern formats, size, lazy-loading
    const imgTags = [...html.matchAll(/<img[^>]*>/gi)].map(m => m[0]).slice(0, 40);
    const imgSrcs = imgTags.map(t => t.match(/src=["']([^"']+)["']/i)?.[1]).filter(Boolean)
      .map(s => absUrl(finalUrl, s)).filter(Boolean);
    const alts = imgTags.map(t => (t.match(/alt=["']([^"']*)["']/i)?.[1] ?? "")).filter(a => a !== null);
    const altOk = alts.length ? alts.filter(a => a.trim().length > 0).length / alts.length : 1;
    const modernFmt = imgSrcs.filter(u => /\.(avif|webp)(\?|#|$)/i.test(u)).length;
    const lazyCount = imgTags.filter(t => /loading=["']lazy["']/i.test(t)).length;
    let huge = 0;
    for (const u of imgSrcs.slice(0, 8)) {
      try {
        const r = await fetch(u, { method: "HEAD" });
        const len = parseInt(r.headers.get("content-length") || "0", 10);
        if (len > 300_000) huge++;
      } catch {}
    }
    checks.push({
      id: "img-alt",
      label: "Images have alt text",
      status: altOk >= 0.9 ? "pass" : altOk >= 0.6 ? "warn" : "fail",
      details: `Alt coverage: ${Math.round(altOk * 100)}%`
    });
    checks.push({
      id: "img-modern",
      label: "Modern image formats",
      status: modernFmt > 0 ? "pass" : "warn",
      details: `${modernFmt} AVIF/WebP seen`
    });
    checks.push({
      id: "img-size",
      label: "Large images",
      status: huge === 0 ? "pass" : huge <= 2 ? "warn" : "fail",
      details: `${huge} images >300KB (first 8)`
    });
    checks.push({
      id: "img-lazy",
      label: "Lazy-loading",
      status: lazyCount > 0 ? "pass" : "warn",
      details: `${lazyCount} images with loading="lazy"`
    });

    // Mixed content on HTTPS pages
    let mixed = 0;
    if (finalUrl.startsWith("https://")) {
      const httpRefs = [...html.matchAll(/\s(?:src|href)=["']http:\/\/[^"']+["']/gi)];
      mixed = httpRefs.length;
    }
    checks.push({
      id: "mixed-content",
      label: "No mixed content",
      status: mixed === 0 ? "pass" : mixed <= 3 ? "warn" : "fail",
      details: mixed ? `${mixed} http:// references` : "None detected"
    });

    // Structured data (JSON-LD) presence
    const jsonLdBlocks = [...html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)]
      .map(m => m[1].trim()).slice(0, 5);
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
      details: ldTypes.length ? `Types: ${Array.from(new Set(ldTypes)).join(", ").slice(0,120)}` : "No JSON-LD found"
    });

    // Compression (page)
    const enc = pageRes.headers.get("content-encoding") || "";
    checks.push({
      id: "compression",
      label: "HTML compression",
      status: /br|gzip/i.test(enc) ? "pass" : "warn",
      details: enc ? `content-encoding: ${enc}` : "No content-encoding header"
    });

    // Optional PSI
    const psi = await fetchPsiPerformance(finalUrl);
    if (typeof psi === "number") {
      checks.push({ id: "psi", label: "PageSpeed (mobile)", status: psi >= 70 ? "pass" : "warn", details: `${psi}/100`, value: psi });
    }

    return new Response(JSON.stringify({
      ok: true,
      url: rawUrl,
      normalizedUrl,
      finalUrl,
      fetchedStatus: pageRes.status,
      timingMs,
      title,
      speed: psi,
      meta: { ogTitle, ogDesc, ogImage },
      checks
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (e) {
    return new Response(JSON.stringify({ ok: false, errors: [e?.message || "Unknown error"] }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
}
