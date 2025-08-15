export const runtime = "edge";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

type Input = { url: string };

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders });
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as Input;
    if (!body?.url) {
      return new Response(JSON.stringify({ ok: false, errors: ["Invalid URL"] }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const normalizedUrl = /^https?:\/\//i.test(body.url) ? body.url : `https://${body.url}`;
    const t0 = Date.now();
    const res = await fetch(normalizedUrl, { redirect: "follow" });
    const html = await res.text();
    const timingMs = Date.now() - t0;

    const m = /<title>([\s\S]*?)<\/title>/i.exec(html);
    const title = m ? m[1].trim() : "";

    const result = {
      ok: true,
      url: body.url,
      normalizedUrl,
      fetchedStatus: res.status,
      timingMs,
      title
    };

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ ok: false, errors: [e?.message || "Unknown error"] }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
}
