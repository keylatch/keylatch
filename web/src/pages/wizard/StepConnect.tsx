// StepConnect — provider picker + API key input + inline verification.
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const PROVIDERS = [
  "openai",
  "anthropic",
  "openrouter",
  "github",
  "stripe",
  "slack",
];

interface StepConnectProps {
  /** Backend chosen in step 2 — forwarded to the IPC call so the daemon
   * stores the credential in the correct backend (fix #3). */
  backend: string;
  onSuccess: () => void;
}

export function StepConnect({ backend, onSuccess }: StepConnectProps) {
  const [provider, setProvider] = useState(PROVIDERS[0]);
  const [key, setKey] = useState("");
  const [status, setStatus] = useState<"idle" | "verifying" | "ok" | "error">(
    "idle"
  );
  const [error, setError] = useState("");

  const connect = async () => {
    setStatus("verifying");
    try {
      const result = await invoke<{ verified: boolean; error?: string }>(
        "connect_provider",
        // Fix #3: pass the selected backend so the daemon stores the key correctly.
        { provider, key, backend }
      );
      if (result.verified) {
        setStatus("ok");
        onSuccess();
      } else {
        setStatus("error");
        setError(result.error ?? "Verification failed");
      }
    } catch (e) {
      setStatus("error");
      setError(String(e));
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-[var(--color-text-primary)]">
        Connect a Provider
      </h2>
      <p className="text-[var(--color-text-secondary)]">
        Choose a provider and enter your API key. Keylatch stores it securely
        and never exposes the raw value to agents.
      </p>

      <div className="space-y-3">
        <div className="space-y-1.5">
          <Label htmlFor="provider-select">Provider</Label>
          <Select value={provider} onValueChange={setProvider}>
            <SelectTrigger id="provider-select" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PROVIDERS.map((p) => (
                <SelectItem key={p} value={p}>
                  {p}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="api-key-input">API Key</Label>
          <Input
            id="api-key-input"
            type="password"
            placeholder="Paste your API key"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            autoComplete="new-password"
          />
        </div>
      </div>

      <Button
        type="button"
        className="w-full"
        onClick={connect}
        disabled={!key || status === "verifying"}
      >
        {status === "verifying" ? "Verifying..." : "Connect"}
      </Button>

      {status === "ok" && (
        <p
          className="rounded-md bg-[var(--color-success-light)] px-3 py-2 text-sm text-[var(--color-success-dark)]"
          role="status"
          aria-live="polite"
        >
          Connected successfully.
        </p>
      )}
      {status === "error" && (
        <p
          className="rounded-md bg-[var(--color-danger-light)] px-3 py-2 text-sm text-[var(--color-danger-dark)]"
          role="alert"
        >
          {error}
        </p>
      )}
    </div>
  );
}
