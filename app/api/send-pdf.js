// /api/send-pdf.js
import { Resend } from "resend"
import { PDFDocument, StandardFonts, rgb } from "pdf-lib"

// --- ENV ---
const resend = new Resend(process.env.RESEND_API_KEY)
const FROM = process.env.FROM_EMAIL || "onboarding@resend.dev"
const BCC = process.env.MARKETING_BCC || "" // optional

// Category map (used for simple counts if catScores/overall are missing)
const CATS = {
  SEO: [
    "sitemap", "robots", "favicon", "opengraph", "canonical",
    "noindex", "meta-robots", "meta-description", "title-length",
    "viewport", "www-canonical", "img-alt", "structured-data",
    "h1-structure", "llms",
  ],
  PERFORMANCE: ["timeout", "psi", "ttfb", "img-modern", "img-size", "img-lazy", "compression"],
  SECURITY: ["blocked", "http", "https-redirect", "mixed-content", "security-headers"],
}
const LOCKED = new Set([
  "h1-structure","llms","mixed-content","security-headers","compression","structured-data","https-redirect",
])

// --- CORS helper ---
function withCORS(res) {
  res.setHeader("Access-Control-Allow-Origin", "*")
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS")
  res.setHeader("Access-Control-Allow-Headers", "Content-Type")
}

// --- tiny utils ---
function asString(v, fallback = "") {
  return typeof v === "string" ? v : fallback
}
function parseURLHost(u) {
  try { return new URL(u).host } catch { return "" }
}
function pickUrl(p = {}) {
  return asString(p.finalUrl) || asString(p.normalizedUrl) || asString(p.url) || asString(p.targetUrl)
}
function nowPretty() {
  return new Date().toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })
}
function computeCounts(checks = [], ids = []) {
  const usable = ids.filter(id => !LOCKED.has(id))
  const byId = Object.fromEntries((checks || []).map(c => [c.id, c]))
  const present = usable.map(id => byId[id]).filter(Boolean)
  const passed = present.filter(c => String(c.status).toLowerCase() === "pass").length
  return { passed, total: usable.length }
}
function topIssues(checks = [], limit = 12) {
  const bad = (checks || []).filter(c => String(c.status).toLowerCase() !== "pass")
  bad.sort((a, b) => {
    const sa = String(a.status).toLowerCase()
    const sb = String(b.status).toLowerCase()
    const w = v => (v === "fail" ? 0 : v === "warn" ? 1 : 2)
    return w(sa) - w(sb)
  })
  return bad.slice(0, limit)
}

// --- PDF builder ---
async function buildPdf(payload) {
  const url = pickUrl(payload)
  const host = parseURLHost(url) || payload.host || ""
  const title = asString(payload.metaTitle) || asString(payload.title) || ""
  const description = asString(payload.metaDescription) || ""
  const overall = Number.isFinite(payload.overall) ? payload.overall : null
  const catScores = payload.catScores && typeof payload.catScores === "object" ? payload.catScores : null
  const checks = Array.isArray(payload.checks) ? payload.checks : []

  // If no catScores provided, compute simple counts (pass/total) for display
  const seoCnt = computeCounts(checks, CATS.SEO)
  const perfCnt = computeCounts(checks, CATS.PERFORMANCE)
  const secCnt = computeCounts(checks, CATS.SECURITY)

  const doc = await PDFDocument.create()
  const page = doc.addPage()
  const { width, height } = page.getSize()
  const margin = 50
  let cursorY = height - margin

  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold)
  const fontReg = await doc.embedFont(StandardFonts.Helvetica)

  const drawText = (text, { x = margin, y, size = 12, color = rgb(0,0,0), font = fontReg } = {}) => {
    page.drawText(String(text ?? ""), { x, y, size, color, font })
  }

  const wrapText = (text, { x = margin, y, size = 12, font = fontReg, maxWidth = width - margin * 2, lineHeight = 1.35 } = {}) => {
    const words = String(text ?? "").split(/\s+/).filter(Boolean)
    let line = ""
    let lines = []
    for (const w of words) {
      const test = line ? line + " " + w : w
      if (font.widthOfTextAtSize(test, size) > maxWidth && line) {
        lines.push(line)
        line = w
      } else {
        line = test
      }
    }
    if (line) lines.push(line)
    for (const ln of lines) {
      drawText(ln, { x, y, size, font })
      y -= size * lineHeight
      if (y < margin + 40) {
        // new page if needed
        const p2 = doc.addPage()
        y = p2.getSize().height - margin
        // switch drawing page reference
        page = p2
      }
    }
    return y
  }

  // Header
  drawText(`SEO Audit — ${host || "Site"}`, { y: cursorY, size: 20, font: fontBold })
  cursorY -= 26
  drawText(url || "—", { y: cursorY, size: 11, color: rgb(0.25, 0.25, 0.25) })
  cursorY -= 18
  drawText(nowPretty(), { y: cursorY, size: 10, color: rgb(0.45, 0.45, 0.45) })
  cursorY -= 20

  // Divider
  page.drawLine({ start: { x: margin, y: cursorY }, end: { x: width - margin, y: cursorY }, thickness: 1, color: rgb(0.9,0.9,0.92) })
  cursorY -= 16

  // Meta
  if (title || description) {
    drawText("Meta", { y: cursorY, size: 13, font: fontBold })
    cursorY -= 16
    if (title) {
      drawText("Title:", { y: cursorY, size: 11, font: fontBold })
      cursorY -= 14
      cursorY = wrapText(title, { y: cursorY, size: 11, font: fontReg })
      cursorY -= 6
    }
    if (description) {
      drawText("Description:", { y: cursorY, size: 11, font: fontBold })
      cursorY -= 14
      cursorY = wrapText(description, { y: cursorY, size: 11, font: fontReg })
      cursorY -= 6
    }
    cursorY -= 6
    page.drawLine({ start: { x: margin, y: cursorY }, end: { x: width - margin, y: cursorY }, thickness: 1, color: rgb(0.9,0.9,0.92) })
    cursorY -= 16
  }

  // Scores (prefer provided; else show simple pass/total)
  drawText("Scores", { y: cursorY, size: 13, font: fontBold })
  cursorY -= 16

  if (overall !== null) {
    drawText(`Overall: ${overall}/100`, { y: cursorY, size: 12 })
    cursorY -= 16
  }

  if (catScores && (catScores.SEO != null || catScores.PERFORMANCE != null || catScores.SECURITY != null)) {
    const fmt = v => (typeof v === "number" ? Math.round(v * 100) + "/100" : "—")
    drawText(`SEO: ${fmt(catScores.SEO)}    Performance: ${fmt(catScores.PERFORMANCE)}    Security: ${fmt(catScores.SECURITY)}`, { y: cursorY, size: 12 })
    cursorY -= 18
  } else {
    drawText(`SEO: ${seoCnt.passed}/${seoCnt.total}    Performance: ${perfCnt.passed}/${perfCnt.total}    Security: ${secCnt.passed}/${secCnt.total}`, { y: cursorY, size: 12 })
    cursorY -= 18
  }

  cursorY -= 4
  page.drawLine({ start: { x: margin, y: cursorY }, end: { x: width - margin, y: cursorY }, thickness: 1, color: rgb(0.9,0.9,0.92) })
  cursorY -= 16

  // Key findings (non-pass checks)
  const issues = topIssues(checks, 14)
  drawText("Key findings", { y: cursorY, size: 13, font: fontBold })
  cursorY -= 16

  if (issues.length === 0) {
    drawText("All checks passed or no issues to show.", { y: cursorY, size: 12 })
    cursorY -= 14
  } else {
    for (const c of issues) {
      const label = `${c.id} — ${String(c.status).toUpperCase()}`
      drawText("• " + label, { y: cursorY, size: 12, font: fontBold })
      cursorY -= 14
      if (c.details) {
        const details = String(c.details).slice(0, 400)
        cursorY = wrapText(details, { y: cursorY, size: 11, font: fontReg })
        cursorY -= 6
      }
      cursorY -= 6
      if (cursorY < margin + 60) {
        const p2 = doc.addPage()
        page = p2
        cursorY = p2.getSize().height - margin
      }
    }
  }

  // Footer
  cursorY -= 8
  page.drawLine({ start: { x: margin, y: cursorY }, end: { x: width - margin, y: cursorY }, thickness: 1, color: rgb(0.9,0.9,0.92) })
  cursorY -= 14
  drawText("Generated by your SEO checker", { y: cursorY, size: 9, color: rgb(0.5,0.5,0.55) })

  return await doc.save()
}

export default async function handler(req, res) {
  withCORS(res)
  if (req.method === "OPTIONS") {
    return res.status(200).end()
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", ["POST","OPTIONS"])
    return res.status(405).json({ ok: false, errors: ["Method not allowed"] })
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {})
    const { email, payload } = body

    if (!email || !payload) {
      return res.status(400).json({ ok: false, errors: ["Missing email or payload"] })
    }

    // Build PDF
    const pdfBytes = await buildPdf(payload)

    // Compose email
    const url = pickUrl(payload)
    const host = payload.host || parseURLHost(url)
    const subject = `Your SEO audit for ${host || url || "your site"}`
    const text = [
      `Hi,`,
      ``,
      `Attached is the PDF of your SEO audit for ${url || host || "your site"}.`,
      ``,
      `Thanks!`,
    ].join("\n")

    const sendInput = {
      from: FROM,
      to: email,
      subject,
      text,
      attachments: [
        {
          filename: "seo-audit.pdf",
          content: Buffer.from(pdfBytes).toString("base64"),
          contentType: "application/pdf",
        },
      ],
    }
    if (BCC) sendInput.bcc = BCC

    const resp = await resend.emails.send(sendInput)

    if (resp?.error) {
      console.error("Resend error:", resp.error)
      return res.status(502).json({ ok: false, errors: [String(resp.error)] })
    }

    return res.status(200).json({ ok: true })
  } catch (e) {
    console.error("send-pdf error:", e)
    return res.status(500).json({ ok: false, errors: [e?.message || "Unknown error"] })
  }
}
