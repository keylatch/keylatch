import { normalizeTelemetryEvent, type KeylatchEventRow } from "./schema";

interface Env {
  TINYBIRD_TOKEN: string;
  TINYBIRD_URL?: string;
  TINYBIRD_DATASOURCE?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method !== "POST" || url.pathname !== "/v1/events") {
      return new Response("Not Found", { status: 404 });
    }

    const body = await request.text().catch(() => null);
    if (!body || body.length > 64 * 1024) {
      return new Response("Request too large", { status: 413 });
    }

    // Accept NDJSON (one JSON object per line) or a single JSON object.
    const lines = body.trim().split("\n").filter(Boolean);
    const events: KeylatchEventRow[] = [];

    for (const line of lines) {
      let obj: unknown;
      try { obj = JSON.parse(line); } catch {
        return new Response("Invalid JSON on line", { status: 400 });
      }
      const event = normalizeTelemetryEvent(obj);
      if (event === null) {
        return new Response("Event rejected: unknown or disallowed fields", { status: 422 });
      }
      events.push(event);
    }

    if (events.length === 0) {
      return new Response("No events", { status: 400 });
    }

    // Forward to Tinybird Events API (NDJSON).
    const ndjson = events.map((e) => JSON.stringify(e)).join("\n");
    const tinybirdUrl = (env.TINYBIRD_URL || "https://api.tinybird.co").replace(/\/+$/, "");
    const datasource = encodeURIComponent(env.TINYBIRD_DATASOURCE || "keylatch_events");
    const tb = await fetch(
      `${tinybirdUrl}/v0/events?name=${datasource}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.TINYBIRD_TOKEN}`,
          "Content-Type": "application/ndjson",
        },
        body: ndjson,
      }
    );

    if (!tb.ok) {
      // Swallow Tinybird errors — don't expose them to the client.
      return new Response("OK", { status: 200 });
    }

    return new Response("OK", { status: 200 });
  },
};
