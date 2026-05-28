// FirstRun — 5-step self-sufficient onboarding wizard (Epic 42).
//
// Steps:
//   1. Welcome    — "Get Started" button
//   2. Backend    — choose from dynamic backend list (calls bootstrap IPC)
//   3. Connect    — provider picker + API key + inline verify
//   4. Try It     — run a command through Keylatch
//   5. Done       — success + optional CLI install
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { StepConnect } from "./StepConnect";
import { StepRun } from "./StepRun";
import { StepInstallCLI } from "./StepInstallCLI";

const TOTAL_STEPS = 5;

// img01–img04 map to steps 1–4; step 5 (Done) reuses img04.
const STEP_IMAGES: Record<number, string> = {
  1: "/onboarding/img01.png",
  2: "/onboarding/img02.png",
  3: "/onboarding/img03.png",
  4: "/onboarding/img04.png",
  5: "/onboarding/img04.png",
};

const STEP_ALT: Record<number, string> = {
  1: "Welcome to Keylatch",
  2: "Choose a credential backend",
  3: "Connect a provider",
  4: "Try a live credential request",
  5: "Setup complete",
};

/** Side-panel illustration that changes with each wizard step. */
function OnboardingVisual({ step }: { step: number }) {
  return (
    <div className="hidden lg:flex lg:flex-1 lg:items-center lg:justify-center" aria-hidden="true">
      <img
        key={step}
        className="max-h-[480px] w-full max-w-sm rounded-xl object-cover"
        src={STEP_IMAGES[step]}
        alt={STEP_ALT[step]}
        draggable={false}
      />
    </div>
  );
}

/** FirstRun — zero-terminal onboarding wizard. */
export function FirstRun() {
  const [currentStep, setCurrentStep] = useState(1);
  // Track the selected provider so StepRun can use it.
  const [selectedProvider] = useState("openai");
  // Track the backend chosen in step 2 so StepConnect can pass it to IPC.
  const [selectedBackend, setSelectedBackend] = useState("keychain");

  const advance = () =>
    setCurrentStep((s) => Math.min(s + 1, TOTAL_STEPS));

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--color-neutral-50)] p-4">
      <div className="flex w-full max-w-4xl gap-12">
        {/* Main wizard panel */}
        <div className="flex flex-1 flex-col gap-6">
          <div
            className="text-center text-sm font-medium text-[var(--color-text-secondary)]"
            aria-label="Wizard progress"
          >
            Step {currentStep} of {TOTAL_STEPS}
          </div>

          <div className="rounded-xl bg-[var(--color-surface)] p-8 shadow-sm ring-1 ring-[var(--color-neutral-200)]">
            {currentStep === 1 && <StepWelcome onNext={advance} />}
            {currentStep === 2 && (
              <StepBackend
                onNext={(backend) => {
                  setSelectedBackend(backend);
                  advance();
                }}
              />
            )}
            {currentStep === 3 && (
              <StepConnect
                backend={selectedBackend}
                onSuccess={() => {
                  advance();
                }}
              />
            )}
            {currentStep === 4 && (
              <StepRun provider={selectedProvider} onSuccess={advance} />
            )}
            {currentStep === 5 && <StepDone />}
          </div>

          {/* Step dots */}
          <div className="flex justify-center gap-2" aria-hidden="true">
            {Array.from({ length: TOTAL_STEPS }, (_, i) => (
              <span
                key={i}
                className={
                  i + 1 === currentStep
                    ? "h-2 w-5 rounded-full bg-[var(--color-accent)]"
                    : "h-2 w-2 rounded-full bg-[var(--color-neutral-300)]"
                }
              />
            ))}
          </div>
        </div>

        <OnboardingVisual step={currentStep} />
      </div>
    </div>
  );
}

// ── Step 1: Welcome ──────────────────────────────────────────────────────────

function StepWelcome({ onNext }: { onNext: () => void }) {
  return (
    <div className="space-y-4 text-center">
      <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">
        Welcome to Keylatch
      </h1>
      <p className="text-[var(--color-text-secondary)]">
        Keylatch is your zero-trust credential broker for AI agents. Your
        secrets stay locked — agents never see raw API keys.
      </p>
      <p className="text-[var(--color-text-secondary)]">
        This wizard will have you up and running in about 2 minutes.
      </p>
      <Button type="button" className="mt-2" onClick={onNext}>
        Get Started
      </Button>
    </div>
  );
}

// ── Step 2: Backend Setup ────────────────────────────────────────────────────

interface BackendItem {
  name: string;
  display_name: string;
  available: boolean;
  install_hint?: string;
}

// StepBackend calls onNext with the chosen backend name so the parent can
// forward it to StepConnect (fix #3).
function StepBackend({ onNext }: { onNext: (backend: string) => void }) {
  const [backends, setBackends] = useState<BackendItem[]>([]);
  const [fetchError, setFetchError] = useState("");
  const [isFetchingBackends, setIsFetchingBackends] = useState(true);
  const [bootstrapStatus, setBootstrapStatus] = useState<"idle" | "loading" | "error">("idle");
  const [bootstrapError, setBootstrapError] = useState("");
  const [selectedBackend, setSelectedBackend] = useState("");

  useEffect(() => {
    // Fix #4: abort fetch on unmount to prevent state updates on unmounted component.
    const controller = new AbortController();
    setIsFetchingBackends(true);
    fetch("/v1/backends", { signal: controller.signal })
      // Fix #5: treat non-2xx responses as errors.
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data: BackendItem[]) => {
        setBackends(data);
        const firstAvailable = data.find((b) => b.available);
        if (firstAvailable) {
          setSelectedBackend(firstAvailable.name);
        }
        setIsFetchingBackends(false);
      })
      .catch((e: unknown) => {
        // Fix #4: suppress AbortError — it means the component unmounted.
        if (e instanceof Error && e.name === "AbortError") return;
        setFetchError(String(e));
        // Fall back to keychain so the wizard is not completely blocked.
        setBackends([{ name: "keychain", display_name: "macOS Keychain", available: true }]);
        setSelectedBackend("keychain");
        setIsFetchingBackends(false);
      });
    return () => controller.abort();
  }, []);

  const bootstrap = async (backendName: string) => {
    setBootstrapStatus("loading");
    setBootstrapError("");
    try {
      // Fix #2: check the result and only advance on success.
      const result = await invoke<{ ok: boolean; error?: string }>("bootstrap", { backend: backendName });
      if (!result.ok) {
        setBootstrapStatus("error");
        setBootstrapError(result.error ?? "Backend setup failed");
        return;
      }
      onNext(backendName);
    } catch (e) {
      setBootstrapStatus("error");
      setBootstrapError(String(e));
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-[var(--color-text-primary)]">
        Choose a Credential Backend
      </h2>
      <p className="text-[var(--color-text-secondary)]">
        Where should Keylatch store your secrets?
      </p>

      {fetchError && (
        <p className="text-sm text-[var(--color-text-secondary)]" role="status">
          Could not load backends — showing defaults.
        </p>
      )}

      {/* Fix #10: show a loading indicator while fetching backends. */}
      {isFetchingBackends ? (
        <p role="status" aria-live="polite" className="text-sm text-[var(--color-text-secondary)]">
          Loading backends…
        </p>
      ) : (
        <>
          <div className="space-y-2">
            {backends.map((b) => (
              <div key={b.name} className="space-y-1">
                <Button
                  type="button"
                  className="w-full"
                  variant={selectedBackend === b.name ? "default" : "outline"}
                  onClick={() => {
                    if (b.available) {
                      setSelectedBackend(b.name);
                    }
                  }}
                  disabled={!b.available || bootstrapStatus === "loading"}
                  aria-pressed={selectedBackend === b.name}
                >
                  {b.display_name}
                  {!b.available && " (not installed)"}
                </Button>
                {!b.available && b.install_hint && (
                  <p className="pl-1 text-xs text-[var(--color-text-secondary)]">
                    {b.install_hint}
                  </p>
                )}
              </div>
            ))}
          </div>

          {backends.length > 0 && (
            <Button
              type="button"
              className="w-full"
              onClick={() => bootstrap(selectedBackend)}
              disabled={!selectedBackend || bootstrapStatus === "loading"}
            >
              {bootstrapStatus === "loading" ? "Setting up..." : "Continue"}
            </Button>
          )}
        </>
      )}

      {bootstrapStatus === "loading" && (
        <p role="status" aria-live="polite" className="text-sm text-[var(--color-text-secondary)]">
          Setting up...
        </p>
      )}
      {bootstrapStatus === "error" && (
        <p
          className="rounded-md bg-[var(--color-danger-light)] px-3 py-2 text-sm text-[var(--color-danger-dark)]"
          role="alert"
        >
          {bootstrapError}
        </p>
      )}
    </div>
  );
}

// ── Step 5: Done ─────────────────────────────────────────────────────────────

function StepDone() {
  return (
    <div className="flex flex-col items-center gap-4 text-center">
      <div className="flex items-center justify-center mb-2" aria-hidden="true">
        <CheckCircle2
          size={56}
          strokeWidth={1.5}
          className="text-[var(--color-success)]"
        />
      </div>

      <h2 className="m-0 text-xl font-semibold text-[var(--color-text-primary)]">
        You're all set!
      </h2>
      <p className="m-0 max-w-[32ch] text-[var(--color-text-secondary)]">
        Your credentials are secure. Agents request access through Keylatch —
        raw API keys never leave the vault.
      </p>

      <StepInstallCLI />

      <div className="pt-2 w-full space-y-2">
        <Button asChild className="w-full">
          <a href="/">Go to Dashboard</a>
        </Button>
        <Button asChild variant="outline" className="w-full">
          <a href="/diagnostics">Run Diagnostics</a>
        </Button>
      </div>
    </div>
  );
}

// Re-export step components for testing / lazy-loading.
export { StepConnect } from "./StepConnect";
export { StepRun } from "./StepRun";
export { StepInstallCLI } from "./StepInstallCLI";
