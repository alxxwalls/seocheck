// app/api/lead/route.js
export const runtime = "edge";

/* ---------------- CORS ---------------- */
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  // nice to add Vary for caches
  Vary: "Origin",
};

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS });
}

/* ---------------- Utils ---------------- */
const esc = (s = "") =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const looksLikeEmail = (e = "") => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

const normalizeUrl = (u = "") => (/^https?:\/\//i.test(u) ? u : u ? `https://${u}` : "");

const hostFromUrl = (u = "") => {
  try { return new URL(normalizeUrl(u)).host; } catch { return u; }
};

/* ---------------- POST ---------------- */
export async function POST(req) {
  try {
    const body = await req.json().catch(() => ({}));
    const name = (body.name || "").trim();
    const email = (body.email || "").trim();
    const websiteRaw = (body.website || "").trim();
    const website = normalizeUrl(websiteRaw);
    const source = String(body.source || "bespoke-audit").toLowerCase(); // <- key difference
    const extraMsg = (body.message || "").trim(); // optional

    if (!looksLikeEmail(email) || !websiteRaw) {
      return new Response(
        JSON.stringify({ ok: false, errors: ["Email and website are required"] }),
        { status: 400, headers: { ...CORS, "Content-Type": "application/json" } }
      );
    }

    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
      return new Response(
        JSON.stringify({ ok: false, errors: ["Missing RESEND_API_KEY"] }),
        { status: 501, headers: { ...CORS, "Content-Type": "application/json" } }
      );
    }

    // TO/FROM
    const toEmail = process.env.LEAD_TO_EMAIL || "hello@lekker.marketing";
    const fromEmail = process.env.FROM_EMAIL || "Audit Bot <onboarding@resend.dev>";

    // Subject + intro copy varies by `source`
    const h = hostFromUrl(website);
    const isPdf = source === "pdf-email";
    const subject = isPdf
      ? `SEO PDF requested: ${h}`
      : `Bespoke audit request: ${h}`;

    const intro = isPdf
      ? "A user requested the SEO audit PDF."
      : "A user requested a bespoke SEO audit.";

    const text =
`${intro}

Name: ${name || "(not provided)"}
Email: ${email}
Website: ${website}
Source: ${source}${extraMsg ? `

Message:
${extraMsg}` : ""}

— Lekker Marketing`;

    const html = `
      <div style="font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45">
        <h2 style="margin:0 0 8px">${esc(intro)}</h2>
        <p style="margin:0 0 6px"><strong>Name:</strong> ${esc(name || "(not provided)")}</p>
        <p style="margin:0 0 6px"><strong>Email:</strong> ${esc(email)}</p>
        <p style="margin:0 0 6px"><strong>Website:</strong> <a href="${esc(website)}" target="_blank" rel="noreferrer">${esc(website)}</a></p>
        <p style="margin:12px 0 0;color:#6B7280"><strong>Source:</strong> ${esc(source)}</p>
        ${extraMsg ? `<hr style="margin:12px 0;border:none;border-top:1px solid #eee" />
        <p style="white-space:pre-wrap;margin:0"><strong>Message:</strong><br/>${esc(extraMsg)}</p>` : ""}
      </div>
    `;

    // Send via Resend (Edge-safe: use fetch)
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [toEmail],
        subject,
        text,
        html,
      }),
    });

    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const msg = data?.message || data?.error || `Resend error (${r.status})`;
      return new Response(
        JSON.stringify({ ok: false, errors: [msg], debug: data }),
        { status: 502, headers: { ...CORS, "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ ok: true, id: data?.id || null }),
      { status: 200, headers: { ...CORS, "Content-Type": "application/json" } }
    );
  } catch (e) {
    return new Response(
      JSON.stringify({ ok: false, errors: [e?.message || "Unknown error"] }),
      { status: 500, headers: { ...CORS, "Content-Type": "application/json" } }
    );
  }
}
