// /app/api/send-pdf/route.js
export const runtime = "nodejs"; // ensure Node runtime (Buffer, etc.)
export const dynamic = "force-dynamic";

/**
 * Expected request JSON (fields are flexible; send what you have):
 * {
 *   "email": "user@example.com",                  // required
 *   "url": "https://example.com",                 // required
 *   "metaTitle": "Meta title here",               // optional
 *   "metaDescription": "Meta description here",   // optional
 *   "score": 87,                                  // optional (0..100)
 *   "categories": {                               // optional
 *     "SEO": { "passed": 7, "total": 10 },
 *     "PERFORMANCE": { "passed": 3, "total": 5 },
 *     "SECURITY": { "passed": 2, "total": 3 }
 *   },
 *   "checks": [                                   // optional
 *     { "id": "sitemap", "status": "pass", "label": "Sitemap.xml", "details": "" },
 *     { "id": "canonical", "status": "fail", "label": "Canonical tag", "details": "Missing or wrong URL" }
 *   ],
 *   "shareUrl": "https://yoursite.com/audit?blob=..." // optional
 * }
 */

export async function POST(req) {
  try {
    const body = await req.json().catch(() => ({}));
    const {
      email,
      url,
      metaTitle,
      metaDescription,
      score,
      categories = {},
      checks = [],
      shareUrl,
    } = body || {};

    if (!email || !url) {
      return json({ ok: false, errors: ["Missing email or url"] }, 400);
    }

    // Use server-only dynamic import for pdf-lib
    const { PDFDocument, StandardFonts, rgb } = await import("pdf-lib");
    const { Resend } = await import("resend");

    const resend = new Resend(process.env.RESEND_API_KEY);
    const from = process.env.FROM_EMAIL;

    if (!process.env.RESEND_API_KEY) {
      return json({ ok: false, errors: ["RESEND_API_KEY not set"] }, 500);
    }
    if (!from) {
      return json({ ok: false, errors: ["FROM_EMAIL not set"] }, 500);
    }

    // --- Build PDF (A4 portrait) ---
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([595.28, 841.89]); // A4 in points
    const { width, height } = page.getSize();

    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

    const margin = 40;
    const contentWidth = width - margin * 2;
    let cursorY = height - margin;

    const drawText = (text, opts = {}) => {
      const {
        x = margin,
        y = cursorY,
        size = 12,
        color = rgb(0.12, 0.12, 0.12),
        f = font,
      } = opts;
      page.drawText(String(text ?? ""), { x, y, size, font: f, color });
    };

    const newPage = () => {
      const p = pdfDoc.addPage([595.28, 841.89]);
      cursorY = p.getSize().height - margin;
      return p;
    };

    const ensureRoom = (needed = 16) => {
      if (cursorY - needed < margin) {
        // start new page
        const p = newPage();
        return p;
      }
      return page;
    };

    const wrapAndDraw = (text, size = 12, f = font, lineGap = 4) => {
      if (!text) return;
      const words = String(text).split(/\s+/);
      let line = "";
      const maxWidth = contentWidth;

      const widthOf = (t) => f.widthOfTextAtSize(t, size);

      for (let i = 0; i < words.length; i++) {
        const test = line ? `${line} ${words[i]}` : words[i];
        if (widthOf(test) > maxWidth) {
          ensureRoom(size + lineGap);
          drawText(line, { size, f });
          cursorY -= size + lineGap;
          line = words[i];
        } else {
          line = test;
        }
      }
      if (line) {
        ensureRoom(size + lineGap);
        drawText(line, { size, f });
        cursorY -= size + lineGap;
      }
    };

    // Header
    const host = (() => {
      try {
        return new URL(url).hostname;
      } catch {
        return url;
      }
    })();

    drawText("SEO Audit", { size: 22, f: bold, color: rgb(0, 0, 0) });
    cursorY -= 26;

    drawText(host, { size: 14, color: rgb(0.2, 0.2, 0.2) });
    cursorY -= 18;

    drawText(url, { size: 10, color: rgb(0.35, 0.35, 0.35) });
    cursorY -= 18;

    if (typeof score === "number") {
      drawText(`Overall score: ${score}`, {
        size: 14,
        f: bold,
        color: rgb(0.12, 0.45, 0.18),
      });
      cursorY -= 18;
    }

    // Categories line
    const catLine = [
      categories.SEO
        ? `SEO ${categories.SEO.passed}/${categories.SEO.total ?? 0}`
        : null,
      categories.PERFORMANCE
        ? `PERF ${categories.PERFORMANCE.passed}/${categories.PERFORMANCE.total ?? 0}`
        : null,
      categories.SECURITY
        ? `SEC ${categories.SECURITY.passed}/${categories.SECURITY.total ?? 0}`
        : null,
    ]
      .filter(Boolean)
      .join(" · ");
    if (catLine) {
      drawText(catLine, { size: 11, color: rgb(0.35, 0.35, 0.35), f: bold });
      cursorY -= 16;
    }

    // Divider
    ensureRoom(12);
    page.drawLine({
      start: { x: margin, y: cursorY },
      end: { x: width - margin, y: cursorY },
      thickness: 1,
      color: rgb(0.92, 0.94, 0.96),
    });
    cursorY -= 14;

    // Meta Title
    if (metaTitle) {
      drawText("Meta title", {
        size: 11,
        f: bold,
        color: rgb(0.3, 0.3, 0.3),
      });
      cursorY -= 14;
      wrapAndDraw(metaTitle, 12, bold);
    }

    // Meta Description
    if (metaDescription) {
      cursorY -= 6;
      drawText("Meta description", {
        size: 11,
        f: bold,
        color: rgb(0.3, 0.3, 0.3),
      });
      cursorY -= 14;
      wrapAndDraw(metaDescription, 12, font);
    }

    // Divider
    ensureRoom(18);
    page.drawLine({
      start: { x: margin, y: cursorY },
      end: { x: width - margin, y: cursorY },
      thickness: 1,
      color: rgb(0.92, 0.94, 0.96),
    });
    cursorY -= 16;

    // Top Issues (fails then warns)
    const fails = checks.filter((c) => c?.status === "fail").slice(0, 10);
    const warns = checks.filter((c) => c?.status === "warn").slice(0, 10);

    const drawIssueList = (title, items) => {
      if (!items.length) return;
      drawText(title, { size: 12, f: bold });
      cursorY -= 16;
      for (const c of items) {
        ensureRoom(28);
        // bullet
        page.drawCircle({
          x: margin + 4,
          y: cursorY + 6,
          size: 2.2,
          color: rgb(0.15, 0.15, 0.15),
        });
        // label
        drawText(c.label || c.id || "Check", {
          x: margin + 12,
          size: 12,
          f: bold,
        });
        cursorY -= 14;
        if (c.details) {
          wrapAndDraw(String(c.details), 11, font, 3);
        } else {
          cursorY -= 2;
        }
      }
      cursorY -= 6;
    };

    if (fails.length || warns.length) {
      drawIssueList("Failed checks", fails);
      drawIssueList("Warnings", warns);
    }

    // Snapshot link
    if (shareUrl) {
      ensureRoom(18);
      drawText("Snapshot link:", { size: 11, f: bold });
      cursorY -= 14;
      wrapAndDraw(shareUrl, 11, font);
    }

    const pdfBytes = await pdfDoc.save();
    const pdfBuffer = Buffer.from(pdfBytes);

    // --- Send email via Resend ---
    const subject = `Your SEO audit for ${host}`;
    const html = `
      <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">
        <p>Hi! Attached is your PDF audit for <a href="${escapeHtml(
          url
        )}">${escapeHtml(url)}</a>.</p>
        ${
          shareUrl
            ? `<p>You can also view the snapshot here: <a href="${escapeHtml(
                shareUrl
              )}">${escapeHtml(shareUrl)}</a></p>`
            : ""
        }
        <p>Thanks for using the SEO checker!</p>
      </div>
    `;

    await resend.emails.send({
      from,
      to: email,
      subject,
      html,
      attachments: [
        {
          filename: `seo-audit-${sanitizeFilename(host)}.pdf`,
          content: pdfBuffer,
        },
      ],
    });

    return json({ ok: true });
  } catch (e) {
    console.error("[send-pdf] error:", e);
    return json(
      { ok: false, errors: [e?.message || "Internal server error"] },
      500
    );
  }
}

/* ---------------- helpers ---------------- */

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function sanitizeFilename(name = "audit") {
  return String(name).replace(/[^\w.-]+/g, "_").slice(0, 80) || "audit";
}

function escapeHtml(s = "") {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
