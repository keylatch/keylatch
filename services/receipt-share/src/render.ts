import type { SanitisedReceipt } from "./schema";

export function renderReceipt(id: string, r: SanitisedReceipt): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Keylatch Receipt ${id}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; }
    .badge { background: #3b82f6; color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.875rem; }
    table { border-collapse: collapse; width: 100%; margin: 1.5rem 0; }
    td { padding: 0.5rem 0; border-bottom: 1px solid #e5e7eb; }
    td:first-child { font-weight: 600; color: #6b7280; width: 160px; }
    .cta { background: #f3f4f6; padding: 1rem; border-radius: 0.5rem; margin-top: 2rem; }
    .report { color: #9ca3af; font-size: 0.875rem; margin-top: 1rem; }
  </style>
</head>
<body>
  <p><span class="badge">Verified by Keylatch</span></p>
  <h1>Agent Run Receipt</h1>
  <table>
    <tr><td>Receipt ID</td><td><code>${id}</code></td></tr>
    <tr><td>Timestamp</td><td>${r.timestamp}</td></tr>
    <tr><td>Runtime mode</td><td>${r.runtime_mode ?? "—"}</td></tr>
    <tr><td>Exit status</td><td>${r.exit_code_class}</td></tr>
    <tr><td>Provider</td><td>${r.provider_name ?? "—"}</td></tr>
    <tr><td>Agent</td><td>${r.agent_name ?? "—"}</td></tr>
  </table>
  <div class="cta">
    <strong>Secured by Keylatch</strong> — zero-trust credential broker for AI agents.<br>
    <a href="https://keylatch.dev">keylatch.dev</a> · <a href="https://keylatch.dev/docs/quickstart">Get started in 5 minutes</a>
  </div>
  <p class="report"><a href="mailto:security@keylatch.dev?subject=Report+receipt+${id}">Report this page</a></p>
</body>
</html>`;
}
