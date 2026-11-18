import { createClient } from "npm:@supabase/supabase-js@2.49.1";

const allowedOrigin = "https://kumarrohit20803.github.io";
const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function toHex(bytes: Uint8Array) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return new Uint8Array(digest);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return toHex(bytes);
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  if (origin && origin !== allowedOrigin) return json({ error: "Origin not allowed" }, 403);
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const sharedPassword = Deno.env.get("SHARED_PASSWORD");
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!sharedPassword || !supabaseUrl || !serviceRoleKey) {
    return json({ error: "Backend configuration is incomplete" }, 503);
  }

  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  let body: Record<string, unknown>;
  try {
    body = await req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Invalid body");
  } catch {
    return json({ error: "A valid JSON body is required" }, 400);
  }

  if (body.action === "login") {
    if (typeof body.password !== "string" || body.password.length > 1024) {
      return json({ error: "Invalid password" }, 400);
    }
    const [expected, supplied] = await Promise.all([
      sha256(sharedPassword),
      sha256(body.password),
    ]);
    if (!constantTimeEqual(expected, supplied)) {
      return json({ error: "Incorrect password" }, 401);
    }

    const token = randomToken();
    const tokenHash = toHex(await sha256(token));
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const { error } = await supabase.from("officers_goal_sessions").insert({
      token_hash: tokenHash,
      expires_at: expiresAt,
    });
    if (error) return json({ error: "Could not create session" }, 500);
    return json({ token, expires_at: expiresAt });
  }

  const authorization = req.headers.get("authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!/^[a-f0-9]{64}$/.test(token)) return json({ error: "Authentication required" }, 401);
  const tokenHash = toHex(await sha256(token));
  const { data: session, error: sessionError } = await supabase
    .from("officers_goal_sessions")
    .select("id")
    .eq("token_hash", tokenHash)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();
  if (sessionError || !session) return json({ error: "Session expired or invalid" }, 401);

  await supabase.from("officers_goal_sessions")
    .update({ last_seen_at: new Date().toISOString() })
    .eq("id", session.id);

  if (body.action === "get") {
    const { data, error } = await supabase.from("officers_goal_state")
      .select("payload, updated_at").eq("id", 1).maybeSingle();
    if (error) return json({ error: "Could not load shared data" }, 500);
    return json({ payload: data?.payload ?? {}, updated_at: data?.updated_at ?? null });
  }

  if (body.action === "save") {
    if (!body.payload || typeof body.payload !== "object" || Array.isArray(body.payload)) {
      return json({ error: "Payload must be a JSON object" }, 400);
    }
    const serialized = JSON.stringify(body.payload);
    if (serialized.length > 1_000_000) return json({ error: "Payload is too large" }, 413);
    const savedAt = new Date().toISOString();
    const { error } = await supabase.from("officers_goal_state").upsert({
      id: 1,
      payload: body.payload,
      updated_at: savedAt,
    }, { onConflict: "id" });
    if (error) return json({ error: "Could not save shared data" }, 500);
    return json({ saved: true, updated_at: savedAt });
  }

  if (body.action === "logout") {
    const { error } = await supabase.from("officers_goal_sessions").delete().eq("id", session.id);
    if (error) return json({ error: "Could not end session" }, 500);
    return json({ logged_out: true });
  }

  return json({ error: "Unknown action" }, 400);
});