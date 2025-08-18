// /app/api/send-pdf/route.js
export const runtime = "nodejs"

import { NextResponse } from "next/server"
import { Resend } from "resend"
import { PDFDocument, StandardFonts, rgb } from "pdf-lib"

// (same helpers as above) — START
const resend = new Resend(process.env.RESEND_API_KEY)
const FROM = process.env.FROM_EMAIL || "onboarding@resend.dev"
const BCC = process.env.MARKETING_BCC || ""
const CATS = { SEO:["sitemap","robots","favicon","opengraph","canonical","noindex","meta-robots","meta-description","title-length","viewport","www-canonical","img-alt","structured-data","h1-structure","llms"], PERFORMANCE:["timeout","psi","ttfb","img-modern","img-size","img-lazy","compression"], SECURITY:["blocked","http","https-redirect","mixed-content","security-headers"] }
const LOCKED = new Set(["h1-structure","llms","mixed-content","security-headers","compression","structured-data","https-redirect"])
const asString = (v, f = "") => (typeof v === "string" ? v : f)
const pickUrl = (p={}) => asString(p.finalUrl) || asString(p.normalizedUrl) || asString(p.url) || asString(p.targetUrl)
const parseHost = (u) => { try { return new URL(u).host } catch { return "" } }
const nowPretty = () => new Date().toLocaleString("en-GB", { day:"2-digit", month:"short", year:"numeric", hour:"2-digit", minute:"2-digit" })
function counts(checks = [], ids = []) { const usable = ids.filter(id => !LOCKED.has(id)); const byId = Object.fromEntries((checks||[]).map(c => [c.id, c])); const present = usable.map(id => byId[id]).filter(Boolean); const passed = present.filter(c => String(c.status).toLowerCase() === "pass").length; return { passed, total: usable.length } }
function keyIssues(checks = [], limit = 14) { const bad = (checks||[]).filter(c => String(c.status).toLowerCase() !== "pass"); const rank = s => (s==="fail" ? 0 : s==="warn" ? 1 : 2); bad.sort((a,b) => rank(String(a.status).toLowerCase()) - rank(String(b.status).toLowerCase())); return bad.slice(0, limit) }

async function buildPdf(payload) {
  const url = pickUrl(payload)
  const host = parseHost(url) || payload.host || ""
  const title = asString(payload.metaTitle) || asString(payload.title) || ""
  const description = asString(payload.metaDescription) || ""
  const overall = Number.isFinite(payload.overall) ? payload.overall : null
  const catScores = payload.catScores && typeof payload.catScores === "object" ? payload.catScores : null
  const checks = Array.isArray(payload.checks) ? payload.checks : []

  const seoCnt = counts(checks, CATS.SEO)
  const perfCnt = counts(checks, CATS.PERFORMANCE)
  const secCnt = counts(checks, CATS.SECURITY)

  const doc = await PDFDocument.create()
  let page = doc.addPage()
  let { width, height } = page.getSize()
  const margin = 50
  let y = height - margin

  const fontBold = await doc.embedFont(StandardFonts.HelveticaBold)
  const fontReg = await doc.embedFont(StandardFonts.Helvetica)

  const drawText = (text, { x = margin, size = 12, color = rgb(0,0,0), font = fontReg } = {}) => {
    page.drawText(String(text ?? ""), { x, y, size, color, font })
  }
  const newPageIfNeeded = () => {
    if (y < margin + 60) {
      page = doc.addPage()
      ;({ width, height } = page.getSize())
      y = height - margin
    }
  }
  const wrap = (text, { x = margin, size = 12, font = fontReg, maxWidth = width - margin*2, lh = 1.35 } = {}) => {
    const words = String(text ?? "").split(/\s+/).filter(Boolean)
    let line = ""
    for (const w of words) {
      const t = line ? line + " " + w : w
      if (font.widthOfTextAtSize(t, size) > maxWidth && line) {
        drawText(line, { x, size, font })
        y -= size * lh
        newPageIfNeeded()
        line = w
      } else {
        line = t
      }
    }
    if (line) { drawText(line, { x, size, font }); y -= size * lh; newPageIfNeeded() }
  }

  // Header
  drawText(`SEO Audit — ${host || "Site"}`, { size: 20, font: fontBold })
  y -= 26
  drawText(url || "—", { size: 11, color: rgb(0.25,0.25,0.25) })
  y -= 18
  drawText(nowPretty(), { size: 10, color: rgb(0.45,0.45,0.45) })
  y -= 20
  page.drawLine({ start:{x:margin,y}, end:{x:width-margin,y}, thickness:1, color: rgb(0.9,0.9,0.92) })
  y -= 16

  // Meta
  if (title || description) {
    drawText("Meta", { size: 13, font: fontBold })
    y -= 16
    if (title) { drawText("Title:", { size: 11, font: fontBold }); y -= 14; wrap(title, { size: 11 }); y -= 6 }
    if (description) { drawText("Description:", { size: 11, font: fontBold }); y -= 14; wrap(description, { size: 11 }); y -= 6 }
    page.drawLine({ start:{x:margin,y}, end:{x:width-margin,y}, thickness:1, color: rgb(0.9,0.9,0.92) })
    y -= 16
  }

  // Scores
  drawText("Scores", { size: 13, font: fontBold })
  y -= 16
  if (overall !== null) { drawText(`Overall: ${overall}/100`); y -= 16 }
  if (catScores && (catScores.SEO != null || catScores.PERFORMANCE != null || catScores.SECURITY != null)) {
    const fmt = v => (typeof v === "number" ? Math.round(v*100) + "/100" : "—")
    drawText(`SEO: ${fmt(catScores.SEO)}    Performance: ${fmt(catScores.PERFORMANCE)}    Security: ${fmt(catScores.SECURITY)}`)
    y -= 18
  } else {
    drawText(`SEO: ${seoCnt.passed}/${seoCnt.total}    Performance: ${perfCnt.passed}/${perfCnt.total}    Security: ${secCnt.passed}/${secCnt.total}`)
    y -= 18
  }
  page.drawLine({ start:{x:margin,y}, end:{x:width-margin,y}, thickness:1, color: rgb(0.9,0.9,0.92) })
  y -= 16

  // Key findings
  drawText("Key findings", { size: 13, font: fontBold })
  y -= 16
  const issues = keyIssues(checks, 14)
  if (!issues.length) { drawText("All checks passed or no issues to show."); y -= 14 }
  else {
    for (const c of issues) {
      drawText(`• ${c.id} — ${String(c.status).toUpperCase()}`, { font: fontBold })
      y -= 14
      if (c.details) { wrap(String(c.details).slice(0, 400), { size: 11 }) }
      y -= 6; newPageIfNeeded()
    }
  }

  // Footer
  page.drawLine({ start:{x:margin,y}, end:{x:width-margin,y}, thickness:1, color: rgb(0.9,0.9,0.92) })
  y -= 14
  drawText("Generated by your SEO checker", { size: 9, color: rgb(0.5,0.5,0.55) })

  return await doc.save()
}
// (helpers) — END

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 200, headers: cors })
}

export async function POST(req) {
  try {
    const { email, payload } = await req.json()
    if (!email || !payload) {
      return NextResponse.json({ ok:false, errors:["Missing email or payload"] }, { status: 400, headers: cors })
    }

    const pdfBytes = await buildPdf(payload)
    const url = pickUrl(payload)
    const host = parseHost(url)
    const subject = `Your SEO audit for ${host || url || "your site"}`
    const text = `Hi,\n\nAttached is the PDF of your SEO audit for ${url || host || "your site"}.\n\nThanks!`

    const input = {
      from: FROM,
      to: email,
      subject,
      text,
      attachments: [{
        filename: "seo-audit.pdf",
        content: Buffer.from(pdfBytes).toString("base64"),
        contentType: "application/pdf",
      }],
    }
    if (BCC) input.bcc = BCC

    const out = await resend.emails.send(input)
    if (out?.error) {
      return NextResponse.json({ ok:false, errors:[String(out.error)] }, { status: 502, headers: cors })
    }

    return NextResponse.json({ ok:true }, { status: 200, headers: cors })
  } catch (e) {
    console.error("send-pdf error:", e)
    return NextResponse.json({ ok:false, errors:[e?.message || "Unknown error"] }, { status: 500, headers: cors })
  }
}
