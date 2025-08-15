// app/api/lead/route.js
export const runtime = "edge";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders });
}

// tiny HTML escaper
const esc = (s = "") =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export async function POST(req) {
  try {
    const body = await req.json();
    const name = (body?.name || "").trim();
    const email = (body?.email || "").trim();
    const website = (body?.website || "").trim();

    if (!email || !website) {
      return new Response(JSON.stringify({ ok: false, errors: ["Email and website are required"] }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Where to send the lead
    const toEmail = process.env.LEAD_TO_EMAIL || "hello@lekker.marekting"; // ← uses your address by default
    // From address (Resend provides onboarding@resend.dev for testing; switch to your verified domain later)
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

    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ ok: false, errors: ["Missing RESEND_API_KEY"] }), {
        status: 501, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

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
        html,
      }),
    });

    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      throw new Error(data?.message || "Email send failed");
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, errors: [e?.message || "Unknown error"] }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
}
