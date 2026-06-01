// StepConnect — provider picker + API key input + inline verification.
import { useState, useEffect } from "react";
import { safeInvoke as invoke } from "@/lib/tauri";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ProviderBadge } from "@/components/ProviderBadge";
import { api } from "@/lib/api";

interface ProviderTemplate {
  slug: string;
  display_name: string;
  category: string;
}

interface StepConnectProps {
  backend: string;
  onSuccess: (providerSlug: string) => void;
}

export function StepConnect({ backend, onSuccess }: StepConnectProps) {
  const [providers, setProviders] = useState<ProviderTemplate[]>([]);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<ProviderTemplate | null>(null);
  const [key, setKey] = useState("");
  const [status, setStatus] = useState<"idle" | "verifying" | "ok" | "error">("idle");
  const [error, setError] = useState("");

  useEffect(() => {
    api.get<ProviderTemplate[]>("/v1/providers").then(setProviders).catch(() => {});
  }, []);

  const connect = async () => {
    if (!selected) return;
    setStatus("verifying");
    setError("");
    try {
      const result = await invoke<{ verified: boolean; error?: string }>(
        "connect_provider",
        { provider: selected.slug, key, backend }
      );
      if (result.verified) {
        setStatus("ok");
        onSuccess(selected.slug);
      } else {
        setStatus("error");
        setError(result.error ?? "Verification failed");
      }
    } catch (e) {
      setStatus("error");
      setError(String(e));
    }
  };

  const filtered = search
    ? providers.filter(
        (p) =>
          p.display_name.toLowerCase().includes(search.toLowerCase()) ||
          p.category.toLowerCase().includes(search.toLowerCase())
      )
    : providers;

  if (!selected) {
    return (
      <div className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold text-foreground">Connect a Provider</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Choose a provider and enter your API key.
          </p>
        </div>

        {/* Search */}
        <div className="relative">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" strokeWidth="2"
            strokeLinecap="round" strokeLinejoin="round"
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" />
          </svg>
          <Input
            type="search"
            placeholder="Search providers…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8"
            aria-label="Search providers"
          />
        </div>

        {/* Provider list */}
        {providers.length === 0 ? (
          <div className="flex items-center gap-2 py-2 text-sm text-muted-foreground">
            <div className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-primary" />
            Loading providers…
          </div>
        ) : (
          <ul className="flex flex-col gap-1.5" role="listbox">
            {filtered.map((p) => (
              <li key={p.slug} role="option" aria-selected={false}>
                <button
                  type="button"
                  className="w-full flex items-center gap-3 rounded-lg border border-border bg-background px-3 py-2.5 text-left hover:bg-accent hover:border-primary/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring transition-colors"
                  onClick={() => setSelected(p)}
                >
                  <ProviderBadge provider={p.slug} className="h-7 w-7 text-xs" />
                  <div className="flex flex-col min-w-0 flex-1">
                    <span className="text-sm font-medium text-foreground">{p.display_name}</span>
                    <span className="text-xs text-muted-foreground capitalize">{p.category}</span>
                  </div>
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted-foreground shrink-0" aria-hidden="true">
                    <path d="m9 18 6-6-6-6" />
                  </svg>
                </button>
              </li>
            ))}
            {filtered.length === 0 && (
              <p className="py-3 text-center text-sm text-muted-foreground">No providers found</p>
            )}
          </ul>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Selected provider header */}
      <div className="flex items-center gap-3">
        <ProviderBadge provider={selected.slug} className="h-8 w-8 text-xs" />
        <div>
          <p className="text-sm font-semibold text-foreground">{selected.display_name}</p>
          <p className="text-xs text-muted-foreground capitalize">{selected.category}</p>
        </div>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="api-key-input">API Key <span className="text-destructive">*</span></Label>
        <Input
          id="api-key-input"
          type="password"
          placeholder={`Enter ${selected.display_name} API key`}
          value={key}
          onChange={(e) => { setKey(e.target.value); setStatus("idle"); }}
          autoComplete="new-password"
        />
      </div>

      <Button type="button" className="w-full" onClick={connect} disabled={!key || status === "verifying"}>
        {status === "verifying" ? "Verifying…" : "Connect"}
      </Button>

      {status === "ok" && (
        <p className="rounded-md bg-emerald-50 border border-emerald-200 px-3 py-2 text-sm text-emerald-700" role="status">
          Connected successfully.
        </p>
      )}
      {status === "error" && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
