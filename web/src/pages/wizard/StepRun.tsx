// StepRun — show how keylatch injects credentials into a CLI command.
import { useState } from "react";
import { safeInvoke as invoke } from "@/lib/tauri";
import { Button } from "@/components/ui/button";

export function StepRun({
  provider,
  onSuccess,
}: {
  provider: string;
  onSuccess: () => void;
}) {
  const [status, setStatus] = useState<"idle" | "running" | "ok" | "error">("idle");
  const [output, setOutput] = useState("");

  const ENV_VAR: Record<string, string> = {
    anthropic: "ANTHROPIC_API_KEY",
    openai: "OPENAI_API_KEY",
    openrouter: "OPENROUTER_API_KEY",
    github: "GITHUB_TOKEN",
    stripe: "STRIPE_SECRET_KEY",
    slack: "SLACK_BOT_TOKEN",
    elevenlabs: "ELEVENLABS_API_KEY",
    replicate: "REPLICATE_API_TOKEN",
  };
  const envVar = ENV_VAR[provider] ?? `${provider.toUpperCase().replace(/-/g, "_")}_API_KEY`;
  const exampleCommand = `keylatch run ${provider} -- claude "summarise this repo"`;

  const run = async () => {
    setStatus("running");
    setOutput("");
    try {
      const result = await invoke<{ exit_code: number; stdout: string }>(
        "run_agent",
        { provider, command: exampleCommand }
      );
      setOutput(result.stdout);
      setStatus(result.exit_code === 0 ? "ok" : "error");
      if (result.exit_code === 0) onSuccess();
    } catch (e) {
      setStatus("error");
      setOutput(String(e));
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-foreground">See it in action</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Keylatch wraps your command and injects the credential at runtime. The agent process never receives the raw key — only a short-lived scoped token.
        </p>
      </div>

      {/* Visual explanation */}
      <div className="rounded-lg border border-border bg-muted p-4 text-xs font-mono space-y-4">
        <div>
          <p className="text-muted-foreground mb-1">without keylatch</p>
          <p className="text-foreground break-all">{envVar}=sk-… claude "…"</p>
        </div>
        <div className="border-t border-border" />
        <div>
          <p className="text-emerald-600 mb-1">with keylatch</p>
          <p className="text-foreground break-all">{exampleCommand}</p>
        </div>
      </div>

      {status === "idle" && (
        <div className="flex gap-3">
          <Button type="button" onClick={run} className="flex-1">
            Run demo
          </Button>
          <Button type="button" variant="outline" onClick={onSuccess}>
            Skip
          </Button>
        </div>
      )}

      {status === "running" && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <div className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-primary" />
          Running…
        </div>
      )}

      {output && (
        <pre className="overflow-x-auto rounded-md bg-neutral-900 p-3 font-mono text-xs text-neutral-100 whitespace-pre-wrap">
          {output}
        </pre>
      )}

      {status === "ok" && (
        <p className="rounded-md bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/50 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-300" role="status">
          Credential injected successfully. A receipt was logged to your dashboard.
        </p>
      )}

      {status === "error" && (
        <div className="space-y-2">
          <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive" role="alert">
            Demo run failed — you can skip this and try from the dashboard later.
          </p>
          <Button type="button" variant="outline" className="w-full" onClick={onSuccess}>
            Continue anyway
          </Button>
        </div>
      )}
    </div>
  );
}
