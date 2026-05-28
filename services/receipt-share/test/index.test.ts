import { describe, it, expect } from "vitest";

// Minimal KV mock.
class MockKV {
  private store = new Map<string, { value: string; expires?: number }>();
  async put(key: string, value: string, _opts?: { expirationTtl?: number }) {
    this.store.set(key, { value });
  }
  async get(key: string): Promise<string | null> {
    return this.store.get(key)?.value ?? null;
  }
}

async function makeWorker() {
  const { default: worker } = await import("../src/index");
  return worker;
}

describe("receipt-share worker", () => {
  it("POST /v1/receipts stores and returns URL", async () => {
    const worker = await makeWorker();
    const kv = new MockKV();
    const body = JSON.stringify({
      timestamp: "2026-05-16T12:00:00Z",
      exit_code_class: "success",
      provider_name: "openai",
      runtime_mode: "gateway_typed",
      agent_name: "claude",
    });
    const req = new Request("https://share.keylatch.dev/v1/receipts", {
      method: "POST",
      body,
    });
    const resp = await worker.fetch(req, { RECEIPTS: kv } as any);
    expect(resp.status).toBe(201);
    const json = await resp.json() as { id: string; url: string };
    expect(json.url).toContain("/r/");
  });

  it("POST rejects unknown fields (422)", async () => {
    const worker = await makeWorker();
    const kv = new MockKV();
    const body = JSON.stringify({
      timestamp: "2026-05-16T12:00:00Z",
      exit_code_class: "success",
      secret_key: "sk-leak", // NOT in allowlist
    });
    const req = new Request("https://share.keylatch.dev/v1/receipts", {
      method: "POST",
      body,
    });
    const resp = await worker.fetch(req, { RECEIPTS: kv } as any);
    expect(resp.status).toBe(422);
  });

  it("GET /r/<id> renders HTML", async () => {
    const worker = await makeWorker();
    const kv = new MockKV();
    await kv.put("receipt:testid123", JSON.stringify({
      timestamp: "2026-05-16T12:00:00Z",
      exit_code_class: "success",
      provider_name: "openai",
      runtime_mode: "gateway_typed",
      agent_name: "claude",
    }));
    const req = new Request("https://share.keylatch.dev/r/testid123");
    const resp = await worker.fetch(req, { RECEIPTS: kv } as any);
    expect(resp.status).toBe(200);
    const html = await resp.text();
    expect(html).toContain("Verified by Keylatch");
    expect(html).toContain("testid123");
  });

  it("GET /r/<missing> returns 404", async () => {
    const worker = await makeWorker();
    const kv = new MockKV();
    const req = new Request("https://share.keylatch.dev/r/doesnotexist");
    const resp = await worker.fetch(req, { RECEIPTS: kv } as any);
    expect(resp.status).toBe(404);
  });
});
