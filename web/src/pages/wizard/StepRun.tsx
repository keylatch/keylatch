// StepRun — test run an agent command through Keylatch.
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function StepRun({
  provider,
  onSuccess,
}: {
  provider: string;
  onSuccess: () => void;
}) {
  const [command, setCommand] = useState("claude --version");
  const [output, setOutput] = useState("");
  const [status, setStatus] = useState<
    "idle" | "running" | "ok" | "error"
  >("idle");

  const run = async () => {
    setStatus("running");
    setOutput("");
    try {
      const result = await invoke<{
        exit_code: number;
        stdout: string;
        receipt_id?: string;
      }>("run_agent", { provider, command });
      setOutput(result.stdout);
      if (result.exit_code === 0) {
        setStatus("ok");
        onSuccess();
      } else {
        setStatus("error");
      }
    } catch (e) {
      setStatus("error");
      setOutput(String(e));
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-[var(--color-text-primary)]">
        Try It
      </h2>
      <p className="text-[var(--color-text-secondary)]">
        Run an agent command through Keylatch. Your credentials are injected
        securely — the agent never sees the raw key.
      </p>

      <div className="space-y-1.5">
        <Label htmlFor="command-input">Command</Label>
        <Input
          id="command-input"
          type="text"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          placeholder="e.g. claude --version"
        />
      </div>

      <Button
        type="button"
        className="w-full"
        onClick={run}
        disabled={status === "running" || !command}
      >
        {status === "running" ? "Running..." : "Run"}
      </Button>

      {output && (
        <pre className="overflow-x-auto rounded-md bg-[var(--color-neutral-900)] p-3 font-mono text-xs text-[var(--color-neutral-100)]">
          {output}
        </pre>
      )}

      {status === "ok" && (
        <p
          className="rounded-md bg-[var(--color-success-light)] px-3 py-2 text-sm text-[var(--color-success-dark)]"
          role="status"
          aria-live="polite"
        >
          Agent ran successfully. Check the Dashboard for your receipt.
        </p>
      )}
      {status === "error" && (
        <Button type="button" variant="outline" className="w-full" onClick={run}>
          Try Again
        </Button>
      )}
    </div>
  );
}
