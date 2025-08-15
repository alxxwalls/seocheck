// app/api/lead/route.js
export const runtime = "edge";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS });
}

const esc = (s = "") =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const looksLikeEmail = (e = "") => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

export async function POST(req) {
  try {
    const body = await req.json().catch(() => ({}));
    const name = (body.name || "").trim();
    const email = (body.email || "").trim();
    const websiteRaw = (body.website || "").trim();
    const website = /^https?:\/\//i.test(websiteRaw) ? websiteRaw : `https://${websiteRaw}`;

    if (!looksLikeEmail(email) || !websiteRaw) {
      return new Response(JSON.stringify({ ok: false, errors: ["Email and website are required"] }), {
        status: 400, headers: { ...CORS, "Content-Type": "application/json" },
      });
    }

    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ ok: false, errors: ["Missing RESEND_API_KEY"] }), {
        status: 501, headers: { ...CORS, "Content-Type": "application/json" },
      });
    }

    // TO/FROM — adjust as you verify things
    const toEmail = process.env.LEAD_TO_EMAIL || "hello@lekker.marketing"; // <- fixed the likely typo
    const fromEmail = process.env.FROM_EMAIL || "Audit Bot <onboarding@resend.dev>";
    const subject = `New SEO audit request: ${website}`;

    const html = `
      <h2>New Bespoke SEO Audit Request</h2>
      <p><b>Name:</b> ${esc(name || "—")}</p>
      <p><b>Email:</b> ${esc(email)}</p>
      <p><b>Website:</b> <a href="${esc(website)}">${esc(website)}</a></p>
      <hr/>
      <p>Sent from the Website Analysis widget.</p>
    `;

    // Send email via Resend
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ from: fromEmail, to: [toEmail], subject, html }),
    });

    const data = await r.json().catch(() => ({}));

    if (!r.ok) {
      // Bubble up Resend’s exact error so you can see it in the browser/console
      const msg = data?.message || data?.error || `Resend error (${r.status})`;
      return new Response(JSON.stringify({ ok: false, errors: [msg], debug: data }), {
        status: 502, headers: { ...CORS, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ ok: true, id: data?.id || null }), {
      status: 200, headers: { ...CORS, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, errors: [e?.message || "Unknown error"] }), {
      status: 500, headers: { ...CORS, "Content-Type": "application/json" },
    });
  }
}
