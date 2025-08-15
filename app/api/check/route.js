export const runtime = "edge";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

// --- utils
const withTimeout = (p, ms = 5000) => {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return {
    signal: c.signal,
    done: (fn) => (val) => { clearTimeout(t); return fn(val); },
    controller: c
  };
};

const isOk = (res) => res && res.status >= 200 && res.status < 400;

const tryHeadThenGet = async (url, { timeoutMs = 5000, redirect = "follow" } = {}) => {
  // Some servers reject HEAD; fallback to GET
  const t1 = withTimeout(null, timeoutMs);
  try {
    const res = await fetch(url, { method: "HEAD", redirect, signal: t1.signal });
    if (res.status === 405 || res.status === 501) throw new Error("HEAD not allowed");
    return res;
  } catch {
    const t2 = withTimeout(null, timeoutMs);
    return fetch(url, { method: "GET", redirect, signal: t2.signal });
  }
};

const absUrl = (base, href) => {
  try { return new URL(href, base).toString(); } catch { return undefined; }
};

const getMeta = (html, nameOrProp, isProp = false) => {
  const attr = isProp ? "property" : "name";
  const re = new RegExp(`<meta[^>]*${attr}=["']${nameOrProp}["'][^>]*>`, "i");
  const m = re.exec(html);
  if (!m) return undefined;
  const tag = m[0];
  const c = /content=["']([^"']+)["']/i.exec(tag);
  return c ? c[1] : "";
};

const findIconHref = (html) => {
  // look for <link rel="icon" ...>, "shortcut icon", "apple-touch-icon"
  const links = [...html.matchAll(/<link[^>]*>/gi)].map((x) => x[0]);
  const iconLinks = links.filter(l => /rel=["'][^"']*icon[^"']*["']/i.test(l));
  for (const tag of iconLinks) {
    const m = /href=["']([^"']+)["']/i.exec(tag);
    if (m) return m[1];
  }
  return null;
};

const parseTitle = (html) => {
  const m = /<title>([\s\S]*?)<\/title>/i.exec(html);
  return m ? m[1].trim() : "";
};

const getHostVariant = (host) => {
  if (/^www\./i.test(host)) return host.replace(/^www\./i, "");
  return "www." + host;
};

// --- PSI (mobile) optional
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

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders });
}

export async function POST(req) {
  try {
    const body = await req.json();
    const rawUrl = body?.url;
    if (!rawUrl) {
      return new Response(JSON.stringify({ ok: false, errors: ["Invalid URL"] }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    const normalizedUrl = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;

    // 1) Fetch the page
    const t0 = Date.now();
    const pageRes = await fetch(normalizedUrl, { redirect: "follow" });
    const html = await pageRes.text();
    const timingMs = Date.now() - t0;
    const finalUrl = pageRes.url;
    const urlObj = new URL(finalUrl);
    const host = urlObj.host;
    const origin = `${urlObj.protocol}//${urlObj.host}`;

    // Basic info
    const title = parseTitle(html);

    // 2) Open Graph
    const ogTitle = getMeta(html, "og:title", true);
    const ogDesc = getMeta(html, "og:description", true);
    const ogImageRel = getMeta(html, "og:image", true);
    const ogImage = ogImageRel ? absUrl(finalUrl, ogImageRel) : undefined;

    let ogImageLoads = undefined;
    if (ogImage) {
      try {
        const res = await tryHeadThenGet(ogImage, { timeoutMs: 5000 });
        ogImageLoads = isOk(res);
      } catch { ogImageLoads = false; }
    }

    // 3) Favicon
    const iconRel = findIconHref(html) || "/favicon.ico";
    const faviconUrl = absUrl(finalUrl, iconRel);
    let faviconLoads = undefined;
    if (faviconUrl) {
      try {
        const res = await tryHeadThenGet(faviconUrl, { timeoutMs: 5000 });
        faviconLoads = isOk(res);
      } catch { faviconLoads = false; }
    }

    // 4) robots.txt
    let robotsExists = false;
    let robotsAllowsIndex = true; // default assume allowed if missing/empty
    try {
      const robotsURL = absUrl(origin + "/", "/robots.txt");
      const r = await fetch(robotsURL, { redirect: "follow" });
      if (r.ok) {
        robotsExists = true;
        const text = await r.text();
        // find the User-agent: * block and see if it contains 'Disallow: /'
        const blocks = text.split(/(?=^User-agent:\s*)/gim);
        const starBlock = blocks.find(b => /^User-agent:\s*\*/im.test(b)) || "";
        if (/^\s*Disallow:\s*\/\s*$/im.test(starBlock)) robotsAllowsIndex = false;
      }
    } catch {}

    // 5) Sitemap
    let sitemapUrl = null;
    let sitemapHasUrls = false;
    let sitemapSampleOk = 0;
    const sitemapCandidates = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"];
    for (const p of sitemapCandidates) {
      const u = absUrl(origin + "/", p);
      try {
        const head = await tryHeadThenGet(u, { timeoutMs: 5000 });
        if (isOk(head)) {
          sitemapUrl = u;
          break;
        }
      } catch {}
    }
    if (sitemapUrl) {
      try {
        const res = await fetch(sitemapUrl, { redirect: "follow" });
        if (res.ok) {
          const xml = await res.text();
          const locs = [...xml.matchAll(/<loc>([\s\S]*?)<\/loc>/gi)].map(m => m[1].trim());
          const absLocs = locs.map(h => absUrl(sitemapUrl, h)).filter(Boolean);
          sitemapHasUrls = absLocs.length > 0;
          // validate up to 5 URLs quickly
          const toCheck = absLocs.slice(0, 5);
          const checks = await Promise.all(
            toCheck.map(async (u) => {
              try {
                const r = await tryHeadThenGet(u, { timeoutMs: 5000 });
                return isOk(r);
              } catch { return false; }
            })
          );
          sitemapSampleOk = checks.filter(Boolean).length;
        }
      } catch {}
    }

    // 6) www ↔ non-www canonical redirect
    // Canonical host is the final one we loaded.
    let canonicalization = { tested: false, from: "", to: "", code: 0, good: false, details: "" };
    try {
      const variantHost = getHostVariant(host);
      if (variantHost !== host) {
        const variantOrigin = `${urlObj.protocol}//${variantHost}`;
        const variantUrl = variantOrigin + "/";

        const res = await fetch(variantUrl, { method: "GET", redirect: "manual" });
        const code = res.status;
        const loc = res.headers.get("location");
        let good = false;
        let to = "";
        if (loc) {
          // resolve possibly relative location
          const resolved = absUrl(variantUrl, loc);
          to = resolved || loc;
          try {
            const toHost = new URL(to).host;
            // good if it lands (or intends to land) on canonical host
            good = toHost === host && (code === 301 || code === 308 || code === 302 || code === 307);
          } catch {}
        }
        canonicalization = { tested: true, from: variantUrl, to, code, good, details: loc ? "redirect present" : "no redirect" };
      }
    } catch (e) {
      canonicalization = { tested: true, from: "", to: "", code: 0, good: false, details: "error testing redirect" };
    }

    // 7) Optional PSI
    const psi = await fetchPsiPerformance(finalUrl);

    // Build checks
    const checks = [];

    // Favicon
    checks.push({
      id: "favicon",
      label: "Favicon present & loads",
      status: faviconLoads === true ? "pass" : faviconLoads === false ? "fail" : "warn",
      details: faviconUrl || "No favicon reference found",
      value: faviconLoads
    });

    // OG
    const ogPresent = !!(ogTitle || ogDesc || ogImage);
    const ogStrong = !!(ogTitle && ogImage && ogImageLoads !== false);
    checks.push({
      id: "opengraph",
      label: "Open Graph tags",
      status: ogStrong ? "pass" : ogPresent ? "warn" : "fail",
      details: `og:title=${!!ogTitle}, og:description=${!!ogDesc}, og:image=${!!ogImage} (image loads: ${ogImageLoads === true ? "yes" : ogImageLoads === false ? "no" : "unknown"})`
    });

    // robots.txt
    checks.push({
      id: "robots",
      label: "robots.txt allows indexing",
      status: robotsExists ? (robotsAllowsIndex ? "pass" : "fail") : "warn",
      details: robotsExists ? (robotsAllowsIndex ? "User-agent: * is allowed" : "User-agent: * disallows /") : "robots.txt not found"
    });

    // sitemap
    checks.push({
      id: "sitemap",
      label: "Sitemap exists & URLs valid",
      status: sitemapUrl ? (sitemapHasUrls && sitemapSampleOk > 0 ? "pass" : "warn") : "fail",
      details: sitemapUrl
        ? `Found: ${sitemapUrl} • URLs: ${sitemapHasUrls ? "yes" : "no"} • Valid samples: ${sitemapSampleOk}`
        : "No sitemap found at common locations"
    });

    // www/non-www redirect
    checks.push({
      id: "www-canonical",
      label: "www/non-www redirects to canonical",
      status: canonicalization.tested ? (canonicalization.good ? "pass" : "warn") : "warn",
      details: canonicalization.tested ? `from ${canonicalization.from} → ${canonicalization.to || "(no redirect)"} (${canonicalization.code})` : "Not applicable"
    });

    // Response basics + PSI
    checks.push({ id: "http", label: "HTTP status 200–399", status: pageRes.status < 400 ? "pass" : "fail", details: String(pageRes.status) });
    checks.push({ id: "ttfb", label: "Response time < 1500ms", status: timingMs < 1500 ? "pass" : "warn", details: `${timingMs} ms` });
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
