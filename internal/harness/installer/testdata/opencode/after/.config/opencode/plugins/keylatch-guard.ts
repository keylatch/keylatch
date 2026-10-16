// Keylatch guard for OpenCode. Every tool call goes to the Keylatch guard
// (keylatch guard hook --harness opencode); a denial, a crash or a missing
// binary blocks the call.
import { spawnSync } from "node:child_process";

const KEYLATCH = "/opt/keylatch/bin/keylatch";

export const KeylatchGuard = async () => ({
  "tool.execute.before": async (input: { tool: string }, output: { args?: unknown }) => {
    const payload = JSON.stringify({
      tool_name: input.tool,
      tool_input: output.args ?? {},
      cwd: process.cwd(),
    });
    const run = spawnSync(KEYLATCH, ["guard", "hook", "--harness", "opencode"], {
      input: payload,
      encoding: "utf8",
      timeout: 10000,
    });
    if (run.error || run.status !== 0) {
      throw new Error(
        (run.stderr || "").trim() || "Keylatch guard did not run; the tool call is blocked.",
      );
    }
  },
});
