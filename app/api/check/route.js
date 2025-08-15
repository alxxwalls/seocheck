// app/api/check/route.js
export const runtime = "edge";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders });
}

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

export async function POST(req) {
  try {
    const body = await req.json();
    if (!body?.url) {
      return new Response(JSON.stringify({ ok: false, errors: ["Invalid URL"] }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const normalizedUrl = /^https?:\/\//i.test(body.url) ? body.url : `https://${body.url}`;

    const t0 = Date.now();
    const pageRes = await fetch(normalizedUrl, { redirect: "follow" });
    const html = await pageRes.text();
    const timingMs = Date.now() - t0;

    const m = /<title>([\s\S]*?)<\/title>/i.exec(html);
    const title = m ? m[1].trim() : "";

    const psiScore = await fetchPsiPerformance(normalizedUrl);

    return new Response(JSON.stringify({
      ok: true,
      url: body.url,
      normalizedUrl,
      fetchedStatus: pageRes.status,
      timingMs,
      title,
      speed: psiScore
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
