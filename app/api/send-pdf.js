// /api/send-pdf.js  (CommonJS, no JSX)
const React = require("react");
const { Resend } = require("resend");
const { Document, Page, Text, View, StyleSheet, pdf } = require("@react-pdf/renderer");

function titleForId(id) {
  const map = {
    sitemap: "Sitemap.xml",
    favicon: "Favicon",
    opengraph: "Open Graph tags",
    robots: "Robots.txt",
    canonical: "Canonical tag",
    "meta-robots": "Meta robots",
    noindex: "Noindex directive",
    "meta-description": "Meta description length",
    "title-length": "Title length",
    viewport: "Viewport tag",
    "www-canonical": "www ↔ non-www",
    http: "HTTP status",
    ttfb: "Response time",
    psi: "PageSpeed score",
    "img-alt": "Image alts",
    "img-modern": "Modern image formats",
    "img-size": "Large images",
    "img-lazy": "Lazy-loading",
  };
  return map[id] || id;
}

async function renderPdfBuffer(payload = {}) {
  const failed = (payload.checks || []).filter((c) => c.status === "fail");
  const warns  = (payload.checks || []).filter((c) => c.status === "warn");

  const styles = StyleSheet.create({
    page: { padding: 32, fontSize: 11, color: "#111" },
    h1: { fontSize: 20, marginBottom: 4, fontWeight: 700 },
    url: { color: "#2563eb", marginBottom: 10, wordBreak: "break-all" },
    section: { marginTop: 12, fontSize: 12, fontWeight: 700 },
    item: { marginTop: 6 },
    muted: { color: "#555" },
  });

  const Doc = React.createElement(
    Document,
    null,
    React.createElement(
      Page,
      { size: "A4", style: styles.page },
      React.createElement(Text, { style: styles.h1 }, payload.host || ""),
      React.createElement(Text, { style: styles.url }, payload.url || ""),
      React.createElement(Text, null, `Overall score: ${payload.score ?? "-"} / 100`),

      React.createElement(Text, { style: styles.section }, "Meta"),
      payload.metaTitle
        ? React.createElement(Text, null, `Title: ${payload.metaTitle}`)
        : null,
      payload.metaDescription
        ? React.createElement(Text, null, `Description: ${payload.metaDescription}`)
        : null,

      React.createElement(Text, { style: styles.section }, "Issues to fix"),
      failed.length
        ? failed.map((c) =>
            React.createElement(
              View,
              { key: c.id, style: styles.item },
              React.createElement(Text, null, `• ${titleForId(c.id)}`),
              c.details
                ? React.createElement(
                    Text,
                    { style: styles.muted },
                    String(c.details).slice(0, 300)
                  )
                : null
            )
          )
        : React.createElement(Text, { style: styles.muted }, "No fails 🎉"),

      React.createElement(Text, { style: styles.section }, "Warnings"),
      warns.length
        ? warns.map((c) =>
            React.createElement(
              View,
              { key: c.id, style: styles.item },
              React.createElement(Text, null, `• ${titleForId(c.id)}`)
            )
          )
        : React.createElement(Text, { style: styles.muted }, "None"),

      payload.shareUrl
        ? React.createElement(
            React.Fragment,
            null,
            React.createElement(Text, { style: styles.section }, "View online"),
            React.createElement(Text, { style: styles.url }, payload.shareUrl)
          )
        : null,

      React.createElement(Text, { style: styles.section }, "Generated"),
      React.createElement(Text, { style: styles.muted }, payload.timestamp || new Date().toISOString())
    )
  );

  return await pdf(Doc).toBuffer();
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, errors: ["POST required"] });
    return;
  }

  const { email, payload } = req.body || {};
  if (!email || !payload) {
    res.status(400).json({ ok: false, errors: ["email and payload required"] });
    return;
  }

  try {
    const buffer = await renderPdfBuffer(payload);

    const resend = new Resend(process.env.RESEND_API_KEY);
    await resend.emails.send({
      from: "onboarding@resend.dev", // configure in Resend
      to: email,
      subject: `Your SEO audit for ${payload.host || payload.url}`,
      text: `Attached is your SEO audit PDF.\nOnline view: ${payload.shareUrl || payload.url}`,
      attachments: [{ filename: "seo-audit.pdf", content: buffer }],
    });

    res.status(200).json({ ok: true });
  } catch (e) {
    console.error("[send-pdf] error:", e);
    res.status(500).json({ ok: false, errors: [e.message || "Send failed"] });
  }
};

// Make sure this runs as a Node function (not Edge)
module.exports.config = { runtime: "nodejs18.x" };
