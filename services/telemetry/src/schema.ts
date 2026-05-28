// Strict allowlist — any field not in this set causes the entire event to be rejected.
// This is the primary defence against accidental credential emission.
const ALLOWED_TOP_LEVEL_FIELDS = new Set(["event", "timestamp", "fields"]);

const ALLOWED_FLAT_FIELDS = new Set([
  "backend", "provider", "provider_id", "runtime_mode",
  "exit_code_class", "overall_status", "trigger", "count",
  "agent", "agent_id", "kl_code", "keylatch_version", "os", "arch",
  "session_id", "sequence_id",
  // gateway_request_completed fields
  "outcome", "duration_ms",
  // token_minted fields
  "runtime",
]);

const ALLOWED_EVENTS = new Set([
  "setup_completed", "connect_succeeded", "run_invoked",
  "doctor_run", "daemon_started", "guard_blocked", "error_occurred",
  // observability events
  "gateway_request_completed", "vault_error", "token_minted",
]);

export interface TelemetryEvent {
  event: string;
  timestamp: string;
  fields?: Record<string, string | number | undefined>;
  [key: string]: string | number | Record<string, string | number | undefined> | undefined;
}

export interface KeylatchEventRow {
  event_type: string;
  runtime_mode: string;
  provider_id: string;
  agent_id: string;
  exit_code_class: string;
  keylatch_version: string;
  os: string;
  arch: string;
  session_id: string;
  timestamp: string;
  sequence_id: number;
}

export function validate(e: unknown): e is TelemetryEvent {
  return normalizeTelemetryEvent(e) !== null;
}

export function normalizeTelemetryEvent(e: unknown): KeylatchEventRow | null {
  if (typeof e !== "object" || e === null) return null;
  const obj = e as Record<string, unknown>;
  if (!ALLOWED_EVENTS.has(String(obj.event))) return null;
  if (typeof obj.timestamp !== "string") return null;

  const fields = readFields(obj);
  if (fields === null) return null;

  for (const key of Object.keys(obj)) {
    if (!ALLOWED_TOP_LEVEL_FIELDS.has(key) && !ALLOWED_FLAT_FIELDS.has(key)) return null;
  }

  const timestamp = normalizeTimestamp(obj.timestamp);
  if (timestamp === null) return null;

  return {
    event_type: String(obj.event),
    runtime_mode: readString(fields, "runtime_mode"),
    provider_id: readString(fields, "provider_id") || readString(fields, "provider"),
    agent_id: readString(fields, "agent_id") || readString(fields, "agent"),
    exit_code_class: readString(fields, "exit_code_class"),
    keylatch_version: readString(fields, "keylatch_version"),
    os: readString(fields, "os"),
    arch: readString(fields, "arch"),
    session_id: readString(fields, "session_id"),
    timestamp,
    sequence_id: readUInt32(fields, "sequence_id"),
  };
}

function readFields(obj: Record<string, unknown>): Record<string, string | number | undefined> | null {
  const fields: Record<string, string | number | undefined> = {};

  for (const key of Object.keys(obj)) {
    if (ALLOWED_FLAT_FIELDS.has(key)) {
      const value = obj[key];
      if (!isSafeFieldValue(value)) return null;
      fields[key] = value;
    }
  }

  if (obj.fields !== undefined) {
    if (typeof obj.fields !== "object" || obj.fields === null || Array.isArray(obj.fields)) {
      return null;
    }
    for (const [key, value] of Object.entries(obj.fields as Record<string, unknown>)) {
      if (!ALLOWED_FLAT_FIELDS.has(key) || !isSafeFieldValue(value)) return null;
      fields[key] = value;
    }
  }

  return fields;
}

function isSafeFieldValue(value: unknown): value is string | number | undefined {
  return value === undefined || typeof value === "string" || typeof value === "number";
}

function readString(fields: Record<string, string | number | undefined>, key: string): string {
  const value = fields[key];
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  return "";
}

function readUInt32(fields: Record<string, string | number | undefined>, key: string): number {
  const value = fields[key];
  const parsed = typeof value === "number" ? value : Number.parseInt(String(value ?? "0"), 10);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 4294967295) return 0;
  return parsed;
}

function normalizeTimestamp(value: string): string | null {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 19).replace("T", " ");
}
