// Keylatch guard plugin for OpenCode.
// Blocks credential-exfiltrating tool calls via tool.execute.before hook.
export default async () => ({
  "tool.execute.before": async (input: unknown, output: unknown) => {
    const o = output as { args?: { command?: string; cmd?: string } } | undefined;
    const i = input as { tool?: string } | undefined;
    const cmd = o?.args?.command ?? o?.args?.cmd ?? i?.tool ?? "";
    const blocked = [
      /keylatch\s+(get|secret\s+get)/,
      /security\s+find-(password|generic-password)/,
      /op\s+read/,
      /bw\s+get/,
      /\.keylatch\/keylatch\.keychain-db/,
      /cat\s+.*\.keylatch\/config\.yaml/,
      /(^|[\s'"])direnv\s+(export|dump)\b/,
      /(^|[\s'"])direnv\s+exec\s+\S+\s+(env|printenv)\b/,
      /(^|[\s'"])mise\s+(env|e)\b/,
      /(^|[\s'"])mise\s+(exec|x)\b.*--\s+(env|printenv)\b/,
      /(^|[\s'"])atuin\s+(search|history)\b/,
    ];
    if (blocked.some((p) => p.test(cmd))) {
      throw new Error(
        "Keylatch guard: credential access blocked. Use `keylatch run` instead."
      );
    }
  },
});
