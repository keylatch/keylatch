// SanitisedReceipt — the ONLY fields allowed in the KV store and rendered page.
// No credential values, no key material, no paths.
export interface SanitisedReceipt {
  timestamp: string;        // ISO-8601
  runtime_mode: string;     // e.g. "gateway_typed"
  exit_code_class: string;  // "success" | "failure" | "error"
  provider_name: string;    // e.g. "openai"
  agent_name: string;       // e.g. "claude"
}

const ALLOWED_FIELDS = new Set<string>([
  "timestamp", "runtime_mode", "exit_code_class", "provider_name", "agent_name",
]);

export function validate(body: unknown): body is SanitisedReceipt {
  if (typeof body !== "object" || body === null) return false;
  const keys = Object.keys(body as object);
  // Reject if any field is not in the allowlist (defence-in-depth against credential leak).
  if (!keys.every((k) => ALLOWED_FIELDS.has(k))) return false;
  // Require at minimum timestamp and exit_code_class.
  const r = body as Record<string, unknown>;
  return typeof r.timestamp === "string" && typeof r.exit_code_class === "string";
}
