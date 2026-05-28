import { validate } from "./schema";
import { renderReceipt } from "./render";

interface Env {
  RECEIPTS: KVNamespace;
}

// Nano-ID generator (URL-safe, 10 chars) — no external dependency.
function nanoid(len = 10): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // POST /v1/receipts — store a sanitised receipt.
    if (request.method === "POST" && url.pathname === "/v1/receipts") {
      // Body size limit: 16 KiB.
      const body = await request.text().catch(() => null);
      if (!body || body.length > 16 * 1024) {
        return new Response("Request too large", { status: 413 });
      }

      let data: unknown;
      try { data = JSON.parse(body); } catch {
        return new Response("Invalid JSON", { status: 400 });
      }

      if (!validate(data)) {
        return new Response(
          "Invalid receipt: unknown fields or missing required fields",
          { status: 422 }
        );
      }

      const id = nanoid();
      // Store with 30-day TTL (seconds).
      await env.RECEIPTS.put(`receipt:${id}`, JSON.stringify(data), {
        expirationTtl: 30 * 24 * 60 * 60,
      });

      const shareUrl = `${url.origin}/r/${id}`;
      return Response.json({ id, url: shareUrl }, { status: 201 });
    }

    // GET /r/<id> — render the receipt as an HTML page.
    if (request.method === "GET" && url.pathname.startsWith("/r/")) {
      const id = url.pathname.slice(3);
      if (!id || id.length > 20) {
        return new Response("Not Found", { status: 404 });
      }

      const raw = await env.RECEIPTS.get(`receipt:${id}`);
      if (!raw) {
        return new Response("Receipt not found or expired", { status: 404 });
      }

      let data: unknown;
      try { data = JSON.parse(raw); } catch {
        return new Response("Corrupt receipt", { status: 500 });
      }

      if (!validate(data)) {
        return new Response("Corrupt receipt", { status: 500 });
      }

      return new Response(renderReceipt(id, data), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
};
