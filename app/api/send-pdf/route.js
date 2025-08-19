// /app/api/send-pdf/route.js
export const runtime = "nodejs";

import React from "react";
import { Resend } from "resend";
import {
  Document,
  Page,
  Text,
  View,
  StyleSheet,
  renderToBuffer,
} from "@react-pdf/renderer";

/* ----------------------- CORS ----------------------- */
const ALLOWED =
  (process.env.CORS_ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

function allowOrigin(req) {
  const origin = req.headers.get("origin");
  if (!origin) return "*";
  if (ALLOWED.length === 0 || ALLOWED.includes("*")) return "*";
  return ALLOWED.includes(origin) ? origin : ALLOWED[0];
}

function corsHeaders(req) {
  return {
    "Access-Control-Allow-Origin": allowOrigin(req),
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

export async function OPTIONS(request) {
  return new Response(null, { status: 204, headers: corsHeaders(request) });
}

/* -------------------- HTML entity decoder (server) -------------------- */
// Decodes numeric (&#123; &#x1F4A9;) and a few common named entities (&amp; &lt; &gt; &quot; &apos; &nbsp;)
function decodeHtmlServer(str = "") {
  let s = String(str);

  // numeric decimal: &#123;
  s = s.replace(/&#(\d+);/g, (_, n) => {
    try { return String.fromCodePoint(parseInt(n, 10)); } catch { return _; }
  });

  // numeric hex: &#x1F4A9;
  s = s.replace(/&#x([\da-fA-F]+);/g, (_, n) => {
    try { return String.fromCodePoint(parseInt(n, 16)); } catch { return _; }
  });

  // common named entities
  const map = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
  s = s.replace(/&([a-zA-Z]+);/g, (m, name) => (map[name] ?? m));

  return s;
}

/* ------------------- Audit constants ------------------- */
const CATS = {
  SEO: [
    "sitemap",
    "robots",
    "favicon",
    "opengraph",
    "canonical",
    "noindex",
    "meta-robots",
    "meta-description",
    "title-length",
    "viewport",
    "www-canonical",
    "img-alt",
    "structured-data",
    "h1-structure",
    "llms",
  ],
  PERFORMANCE: ["timeout", "psi", "ttfb", "img-modern", "img-size", "img-lazy", "compression"],
  SECURITY: ["blocked", "http", "https-redirect", "mixed-content", "security-headers"],
};

const LOCKED_IDS = new Set([
  "h1-structure",
  "llms",
  "mixed-content",
  "security-headers",
  "compression",
  "structured-data",
  "https-redirect",
]);

const EXCLUDE_FROM_SCORE = new Set(["blocked", "timeout"]);

const WEIGHTS = {
  // SEO
  sitemap: 2.2,
  canonical: 2.0,
  "meta-robots": 1.0,
  robots: 1.6,
  "www-canonical": 1.2,
  noindex: 5,
  "img-alt": 1.2,
  viewport: 1.1,
  "meta-description": 0.8,
  "title-length": 0.8,
  opengraph: 0.5,
  favicon: 0.3,
  // Performance
  psi: 2.4,
  ttfb: 1.4,
  "img-size": 1.2,
  "img-modern": 0.8,
  "img-lazy": 0.6,
  // Security / Tech
  http: 2.0,
  // locked (kept for sorting if you ever include them)
  "https-redirect": 1.8,
  "mixed-content": 1.8,
  "security-headers": 1.0,
  compression: 1.2,
  "structured-data": 1.4,
};

const LABELS = {
  sitemap: ["Sitemap.xml", "Checks if sitemap.xml exists and contains valid URLs"],
  favicon: ["Favicon", "Checks for favicon presence and that it loads successfully"],
  opengraph: ["Open Graph tags", "OG tags used by social platforms for rich previews"],
  robots: ["Robots.txt", "File exists and allows proper indexing"],
  "www-canonical": ["www ↔ non-www", "Other host should redirect to the canonical host"],
  http: ["HTTP status", "Page returns a valid 2xx/3xx status"],
  ttfb: ["Response time", "Server responds in under ~1.5s"],
  canonical: ["Canonical tag", "Present and points to this URL"],
  "meta-robots": ["Robots directives", "Page meta/header (noindex/nofollow)"],
  noindex: ["Noindex directive", "Fails if page disallows indexing"],
  "meta-description": ["Meta description length", "Aim for ~50–160 characters"],
  "title-length": ["Title length", "Aim for ~15–60 characters"],
  viewport: ["Mobile viewport tag", "Required for proper mobile rendering"],
  "https-redirect": ["HTTP → HTTPS redirect", "Force secure canonical"],
  "security-headers": ["Security headers", "CSP, XFO, XCTO, RP, HSTS"],
  timeout: ["Site timed out", "Partial results returned"],
  "img-alt": ["Images have alt text", "Accessibility & image SEO"],
  "img-modern": ["Modern image formats", "Prefer WebP/AVIF"],
  "img-size": ["Large images", "Flags images over ~300 KB"],
  "img-lazy": ["Lazy-loading", 'Use loading="lazy" offscreen'],
  "mixed-content": ["No mixed content", "Avoid http:// assets on https:// pages"],
  "structured-data": ["Structured data (JSON-LD)", "Detects common @type schemas"],
  compression: ["HTML compression", "Check for br/gzip on HTML"],
  blocked: ["Blocked by WAF/bot protection", "Firewall denied automated requests"],
  psi: ["PageSpeed (mobile)", "Google PSI performance score (0–100)"],
  "h1-structure": ["H1 Structure", "Single H1 and sensible heading order"],
  llms: ["LLMs.txt", "Guidance for AI crawlers"],
};

const CATEGORY_WEIGHTS = { SEO: 0.55, PERFORMANCE: 0.35, SECURITY: 0.1 };

/* ---------------- Score helpers (server-side) ---------------- */
const usable = (c) => c && !LOCKED_IDS.has(c.id) && !EXCLUDE_FROM_SCORE.has(c.id);
const vFor = (st) => (st === "pass" ? 1 : st === "warn" ? 0.5 : 0);

function catWeightedScore(checks, ids) {
  const items = (checks || []).filter((c) => usable(c) && ids.includes(c.id));
  if (!items.length) return null;
  let sum = 0, wsum = 0;
  for (const c of items) {
    const w = Number.isFinite(WEIGHTS[c.id]) ? WEIGHTS[c.id] : 1;
    sum += w * vFor(String(c.status).toLowerCase());
    wsum += w;
  }
  return wsum ? sum / wsum : 1;
}

function harmonicMean(catScores, catWeights) {
  const entries = Object.entries(catScores).filter(([, v]) => typeof v === "number" && v > 0);
  if (!entries.length) return 1;
  let num = 0, denom = 0;
  for (const [cat, s] of entries) {
    const w = Number(catWeights?.[cat] ?? 1);
    const sClamped = Math.max(0.05, Math.min(1, s));
    num += w;
    denom += w / sClamped;
  }
  return num / denom;
}

function applyGates(overall0to100, checks = []) {
  const byId = Object.fromEntries((checks || []).map((c) => [c.id, c]));
  const isFail = (id) => String(byId[id]?.status || "").toLowerCase() === "fail";
  let out = overall0to100;
  if (isFail("noindex")) return 0;
  if (isFail("http")) out = Math.min(out, 40);
  if (isFail("canonical")) out = Math.min(out, 65);
  if (isFail("sitemap") || isFail("robots")) out = Math.min(out, 80);
  return out;
}

function computeOverall(checks) {
  const catScores = {
    SEO: catWeightedScore(checks, CATS.SEO),
    PERFORMANCE: catWeightedScore(checks, CATS.PERFORMANCE),
    SECURITY: catWeightedScore(checks, CATS.SECURITY),
  };
  let overall = Math.round(harmonicMean(catScores, CATEGORY_WEIGHTS) * 100);
  overall = applyGates(overall, checks);
  return { overall, catScores };
}

/* --------------------- PDF styles --------------------- */
const styles = StyleSheet.create({
  page: { padding: 36, fontSize: 11, color: "#111" },
  h1: { fontSize: 18, fontWeight: 700, marginBottom: 8 },
  h2: { fontSize: 14, fontWeight: 700, marginTop: 16, marginBottom: 6 },
  p: { marginBottom: 4, lineHeight: 1.4 },
  small: { fontSize: 9, color: "#555" },
  chipRow: { display: "flex", flexDirection: "row", gap: 8 },
  chip: { fontSize: 9, backgroundColor: "#f3f4f6", padding: 4, borderRadius: 4, marginRight: 6 },
  table: { marginTop: 6, borderTopWidth: 1, borderTopColor: "#e5e7eb", borderTopStyle: "solid" },
  tr: { display: "flex", flexDirection: "row", borderBottomWidth: 1, borderBottomColor: "#e5e7eb", borderBottomStyle: "solid" },
  th: { flex: 2, fontWeight: 700, paddingVertical: 4 },
  th2: { flex: 1, fontWeight: 700, paddingVertical: 4, textAlign: "right" },
  tdName: { flex: 2, paddingVertical: 4 },
  tdStatus: { flex: 1, paddingVertical: 4, textAlign: "right" },
  badge: { fontSize: 9, borderRadius: 4, paddingVertical: 2, paddingHorizontal: 4, alignSelf: "flex-end" },
  bPass: { backgroundColor: "#E8F8F0" },
  bWarn: { backgroundColor: "#FFF7E6" },
  bFail: { backgroundColor: "#FDECEA" },
  muted: { color: "#666" },
  listItem: { marginBottom: 4 },
});

/* -------------------- PDF components -------------------- */
function Badge({ status }) {
  const s = String(status).toLowerCase();
  const base = [styles.badge];
  if (s === "pass") base.push(styles.bPass);
  else if (s === "warn") base.push(styles.bWarn);
  else base.push(styles.bFail);
  return <Text style={base}>{s}</Text>;
}

function titleFor(id) {
  return (LABELS[id]?.[0]) || id;
}
function descFor(id) {
  return (LABELS[id]?.[1]) || "";
}

function byCategory(checks) {
  const out = {};
  for (const [cat, ids] of Object.entries(CATS)) {
    out[cat] = (checks || [])
      .filter((c) => ids.includes(c.id))
      .map((c) => ({
        ...c,
        label: titleFor(c.id),
        desc: descFor(c.id),
      }));
  }
  return out;
}

function summarize(catList) {
  const present = (catList || []).filter((c) => !LOCKED_IDS.has(c.id));
  const pass = present.filter((c) => c.status === "pass").length;
  const warn = present.filter((c) => c.status === "warn").length;
  const fail = present.filter((c) => c.status === "fail").length;
  return { pass, warn, fail, total: present.length };
}

function sortIssues(checks) {
  // fails first, then warns; sort within group by weight desc
  const score = (c) => Number.isFinite(WEIGHTS[c.id]) ? WEIGHTS[c.id] : 1;
  const rank = (c) => (c.status === "fail" ? 2 : c.status === "warn" ? 1 : 0);
  return [...checks].sort((a, b) => {
    const r = rank(b) - rank(a);
    if (r !== 0) return r;
    return score(b) - score(a);
  });
}

function SectionTable({ name, list = [] }) {
  if (!list.length) return null;
  return (
    <View wrap>
      <Text style={styles.h2}>{name}</Text>
      <View style={styles.table}>
        <View style={styles.tr}>
          <Text style={styles.th}>Check</Text>
          <Text style={styles.th2}>Status</Text>
        </View>
        {list.map((c, i) => (
          <View key={`${c.id}-${i}`} style={styles.tr}>
            <View style={styles.tdName}>
              <Text>{c.label}</Text>
              {c.details ? <Text style={[styles.small, styles.muted]}>{c.details}</Text> : null}
            </View>
            <View style={styles.tdStatus}>
              <Badge status={c.status} />
            </View>
          </View>
        ))}
      </View>
    </View>
  );
}

function IssuesList({ title, items = [] }) {
  if (!items.length) return null;
  return (
    <View wrap>
      <Text style={styles.h2}>{title}</Text>
      {items.map((c, i) => (
        <View key={`${c.id}-${i}`} style={styles.listItem}>
          <Text>
            • {c.label} — {c.details ? c.details : descFor(c.id)}
          </Text>
        </View>
      ))}
    </View>
  );
}

function pct(v) {
  if (typeof v !== "number") return "-";
  return `${Math.round(v * 100)}%`;
}

function AuditPdf({
  url,
  metaTitle,
  metaDescription,
  overall,
  catScores,
  cats,
  topFails = [],
  warns = [],
  shareUrl,
}) {
  const seoSum = summarize(cats.SEO);
  const perfSum = summarize(cats.PERFORMANCE);
  const secSum = summarize(cats.SECURITY);

  return (
    <Document>
      <Page size="A4" style={styles.page}>
        <Text style={styles.h1}>SEO Audit Snapshot</Text>

        <View style={{ marginBottom: 10 }}>
          <Text style={styles.p}>URL: {url || "-"}</Text>
          {metaTitle ? <Text style={styles.p}>Meta title: {metaTitle}</Text> : null}
          {metaDescription ? <Text style={styles.p}>Meta description: {metaDescription}</Text> : null}
          {shareUrl ? <Text style={[styles.p, styles.small]}>Share link: {shareUrl}</Text> : null}
        </View>

        <Text style={styles.h2}>Score</Text>
        <View>
          <Text style={styles.p}>Overall: {Number.isFinite(overall) ? overall : "-"}</Text>
          {catScores ? (
            <Text style={styles.small}>
              SEO {pct(catScores.SEO)} · Performance {pct(catScores.PERFORMANCE)} · Security {pct(catScores.SECURITY)}
            </Text>
          ) : null}
          <Text style={[styles.small, { marginTop: 4 }]}>
            Legend: <Text>pass</Text> ✓ · <Text>warn</Text> ! · <Text>fail</Text> ✕
          </Text>
        </View>

        <View style={{ marginTop: 10 }}>
          <Text style={styles.h2}>Summary</Text>
          <Text style={styles.small}>
            SEO {seoSum.pass}/{seoSum.total} pass, {seoSum.warn} warn, {seoSum.fail} fail ·
            Performance {perfSum.pass}/{perfSum.total} pass, {perfSum.warn} warn, {perfSum.fail} fail ·
            Security {secSum.pass}/{secSum.total} pass, {secSum.warn} warn, {secSum.fail} fail
          </Text>
        </View>

        <IssuesList title="Top issues to fix first" items={topFails.slice(0, 10)} />
        <IssuesList title="Warnings / opportunities" items={warns.slice(0, 10)} />

        <SectionTable name="SEO checks" list={cats.SEO} />
        <SectionTable name="Performance checks" list={cats.PERFORMANCE} />
        <SectionTable name="Security checks" list={cats.SECURITY} />

        <Text style={[styles.small, { marginTop: 12 }]}>
          Generated by Lekker Marketing
        </Text>
      </Page>
    </Document>
  );
}

/* ---------------------- POST handler ---------------------- */
export async function POST(request) {
  const headers = { "Content-Type": "application/json", ...corsHeaders(request) };

  try {
    const body = await request.json().catch(() => ({}));
    const p = body?.payload && typeof body.payload === "object" ? body.payload : body;

    const to = body?.email || p?.email;
    if (!to) {
      return new Response(JSON.stringify({ ok: false, errors: ["Missing email"] }), {
        status: 400, headers,
      });
    }

    // Extract & decode payload fields
    const url = p.url || p.finalUrl || p.normalizedUrl || "";
    const metaTitle = decodeHtmlServer(p.metaTitle || p.title || "");
    const metaDescription = decodeHtmlServer(p.metaDescription || "");
    const shareUrl = p.shareUrl || "";

    const checks = Array.isArray(p.checks)
      ? p.checks.map((c) => ({
          id: String(c.id || ""),
          status: String(c.status || "").toLowerCase(),
          details: decodeHtmlServer(c.details ? String(c.details) : ""),
          value: typeof c.value !== "undefined" ? c.value : undefined,
        }))
      : [];

    // Ensure we have a score (compute if missing)
    const providedOverall = Number.isFinite(p.overall) ? p.overall : null;
    const providedCatScores = p.catScores && typeof p.catScores === "object" ? p.catScores : null;
    const { overall, catScores } =
      providedOverall !== null && providedCatScores
        ? { overall: providedOverall, catScores: providedCatScores }
        : computeOverall(checks);

    // Group & sort issues
    const cats = byCategory(checks);
    const allVisible = sortIssues(checks.filter((c) => !LOCKED_IDS.has(c.id)));
    const topFails = allVisible.filter((c) => c.status === "fail");
    const warns = allVisible.filter((c) => c.status === "warn");

    // Build PDF buffer
    const pdfBuffer = await renderToBuffer(
      <AuditPdf
        url={url}
        metaTitle={metaTitle}
        metaDescription={metaDescription}
        overall={overall}
        catScores={catScores}
        cats={cats}
        topFails={topFails}
        warns={warns}
        shareUrl={shareUrl}
      />
    );

    // Send email
    const resendKey = process.env.RESEND_API_KEY;
    const from = process.env.FROM_EMAIL;
    if (!resendKey || !from) {
      return new Response(
        JSON.stringify({ ok: false, errors: ["Server misconfigured: missing RESEND_API_KEY or FROM_EMAIL"] }),
        { status: 500, headers }
      );
    }

    const resend = new Resend(resendKey);

    await resend.emails.send({
      from,
      to,
      subject: "Your SEO Audit PDF",
      text:
`Hi,

Attached is your SEO audit snapshot for: ${url || "your site"}.

- Overall score: ${Number.isFinite(overall) ? overall : "-"}
- SEO ${pct(catScores?.SEO)} · Performance ${pct(catScores?.PERFORMANCE)} · Security ${pct(catScores?.SECURITY)}
${shareUrl ? `\nView the interactive snapshot: ${shareUrl}\n` : ""}

— Lekker Marketing`,
      attachments: [
        {
          filename: "seo-audit.pdf",
          content: pdfBuffer, // Buffer
          contentType: "application/pdf",
        },
      ],
    });

    return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, errors: [err?.message || "Unknown error"] }),
      { status: 500, headers }
    );
  }
}
