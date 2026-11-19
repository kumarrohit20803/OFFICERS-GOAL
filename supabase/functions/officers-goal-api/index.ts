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

type SharedRecord = Record<string, unknown>;

function isRecord(value: unknown): value is SharedRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function sameValue(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const aKeys = Object.keys(a as Record<string, unknown>).sort();
  const bKeys = Object.keys(b as Record<string, unknown>).sort();
  if (aKeys.length !== bKeys.length || aKeys.some((key, index) => key !== bKeys[index])) return false;
  return aKeys.every((key) => sameValue(
    (a as Record<string, unknown>)[key],
    (b as Record<string, unknown>)[key],
  ));
}

function mergeSharedCollection(baseValue: unknown, localValue: unknown, remoteValue: unknown): SharedRecord[] {
  const toRecords = (value: unknown) => Array.isArray(value)
    ? value.filter(isRecord)
    : [];
  const baseItems = toRecords(baseValue);
  const localItems = toRecords(localValue);
  const remoteItems = toRecords(remoteValue);
  const baseMap = new Map(baseItems.map((item) => [item.id, item]));
  const localMap = new Map(localItems.map((item) => [item.id, item]));
  const remoteMap = new Map(remoteItems.map((item) => [item.id, item]));
  const ids = new Set([...baseMap.keys(), ...localMap.keys(), ...remoteMap.keys()]);
  const merged: SharedRecord[] = [];

  for (const id of ids) {
    const base = baseMap.get(id);
    const local = localMap.get(id);
    const remote = remoteMap.get(id);
    const localChanged = !sameValue(local, base);
    const remoteChanged = !sameValue(remote, base);
    let chosen: SharedRecord | undefined;

    if (!localChanged) {
      chosen = remote;
    } else if (!remoteChanged || sameValue(local, remote)) {
      chosen = local;
    } else if (!local || !remote) {
      // A concurrent delete/edit keeps the surviving edit instead of losing it.
      chosen = local || remote;
    } else {
      chosen = { ...base, ...remote, ...local };
      const fields = new Set([
        ...Object.keys(base || {}),
        ...Object.keys(local),
        ...Object.keys(remote),
      ]);
      for (const field of fields) {
        const localFieldChanged = !sameValue(local[field], base?.[field]);
        const remoteFieldChanged = !sameValue(remote[field], base?.[field]);
        if (remoteFieldChanged && !localFieldChanged) chosen[field] = remote[field];
        else if (localFieldChanged) chosen[field] = local[field];
      }
    }

    if (chosen) {
      // Archiving is a one-way lifecycle transition. A stale device must never
      // clear or move an archive date forward and make the old habit active again.
      const localArchive = typeof local?.archived_at === "string" ? local.archived_at : null;
      const remoteArchive = typeof remote?.archived_at === "string" ? remote.archived_at : null;
      const archiveDates = [localArchive, remoteArchive].filter((value): value is string => !!value);
      if (archiveDates.length > 0) {
        chosen = { ...chosen, archived_at: archiveDates.sort()[0] };
      }
      merged.push(chosen);
    }
  }

  return merged;
}

function mergeSharedPayload(base: SharedRecord, local: SharedRecord, remote: SharedRecord): SharedRecord {
  const result: SharedRecord = {};
  for (const key of ["habits", "habitLogs", "dailyGoals", "mockTests", "examDates", "streakReasons"]) {
    result[key] = mergeSharedCollection(base[key], local[key], remote[key]);
  }
  return result;
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
    if (!isRecord(body.payload)) {
      return json({ error: "Payload must be a JSON object" }, 400);
    }
    const serialized = JSON.stringify(body.payload);
    if (serialized.length > 1_000_000) return json({ error: "Payload is too large" }, 413);

    const submittedPayload = body.payload as SharedRecord;
    const basePayload = isRecord(body.base_payload) ? body.base_payload : {};
    const hasVersionedBase = typeof body.base_updated_at === "string" && isRecord(body.base_payload);

    // Compare-and-swap prevents two devices from silently overwriting each other.
    // On a conflict, reload the newest row, three-way merge by record ID, and retry.
    for (let attempt = 0; attempt < 5; attempt++) {
      const { data: current, error: readError } = await supabase
        .from("officers_goal_state")
        .select("payload, updated_at")
        .eq("id", 1)
        .maybeSingle();
      if (readError) return json({ error: "Could not load shared data before saving" }, 500);

      const currentPayload = isRecord(current?.payload) ? current.payload : {};
      const mergedPayload = current
        ? mergeSharedPayload(hasVersionedBase ? basePayload : {}, submittedPayload, currentPayload)
        : submittedPayload;

      const mergedSerialized = JSON.stringify(mergedPayload);
      if (mergedSerialized.length > 1_000_000) return json({ error: "Merged payload is too large" }, 413);

      const previousTime = current?.updated_at ? Date.parse(current.updated_at) : 0;
      const savedAt = new Date(Math.max(Date.now(), previousTime + 1)).toISOString();

      if (current) {
        let updateQuery = supabase
          .from("officers_goal_state")
          .update({ payload: mergedPayload, updated_at: savedAt })
          .eq("id", 1);
        updateQuery = current.updated_at
          ? updateQuery.eq("updated_at", current.updated_at)
          : updateQuery.is("updated_at", null);

        const { data: updated, error: updateError } = await updateQuery
          .select("updated_at")
          .maybeSingle();
        if (updateError) return json({ error: "Could not save shared data" }, 500);
        if (updated) return json({ saved: true, updated_at: savedAt, payload: mergedPayload });
      } else {
        const { data: inserted, error: insertError } = await supabase
          .from("officers_goal_state")
          .insert({ id: 1, payload: mergedPayload, updated_at: savedAt })
          .select("updated_at")
          .maybeSingle();
        if (inserted) return json({ saved: true, updated_at: savedAt, payload: mergedPayload });
        if (insertError && insertError.code !== "23505") {
          return json({ error: "Could not create shared data" }, 500);
        }
      }
    }

    return json({ error: "Shared data changed repeatedly; sync again before saving" }, 409);
  }

  if (body.action === "logout") {
    const { error } = await supabase.from("officers_goal_sessions").delete().eq("id", session.id);
    if (error) return json({ error: "Could not end session" }, 500);
    return json({ logged_out: true });
  }

  return json({ error: "Unknown action" }, 400);
});