// FirstRun — 5-step self-sufficient onboarding wizard (Epic 42).
//
// Steps:
//   1. Welcome    — "Get Started" button
//   2. Backend    — choose from dynamic backend list (calls bootstrap IPC)
//   3. Connect    — provider picker + API key + inline verify
//   4. Try It     — run a command through Keylatch
//   5. Done       — success + optional CLI install
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { safeInvoke as invoke } from "@/lib/tauri";
import { CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { KeylatchLogo } from "@/components/KeylatchLogo";
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

/** Side-panel illustration — full-height, 50% width, image covers the panel. */
function OnboardingVisual({ step }: { step: number }) {
  return (
    <div className="hidden lg:block lg:w-1/2 lg:shrink-0 relative overflow-hidden" style={{ maxWidth: 592 }} aria-hidden="true">
      <img
        key={step}
        className="absolute inset-0 h-full w-full object-cover"
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
  const [selectedProvider, setSelectedProvider] = useState("openai");
  // Track the backend chosen in step 2 so StepConnect can pass it to IPC.
  const [selectedBackend, setSelectedBackend] = useState("keychain");

  const advance = () =>
    setCurrentStep((s) => Math.min(s + 1, TOTAL_STEPS));
  const goBack = () =>
    setCurrentStep((s) => Math.max(s - 1, 1));

  return (
    <div className="flex h-[100dvh] bg-white overflow-hidden flex-col">
      {/* Topbar */}
      <header className="h-14 shrink-0 border-b border-border flex items-center px-6 gap-4 z-10">
        {currentStep > 1 && (
          <button
            type="button"
            onClick={goBack}
            aria-label="Go back"
            className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="m15 18-6-6 6-6" />
            </svg>
          </button>
        )}
        <KeylatchLogo className="h-7 w-auto" />
        <div className="ml-auto flex gap-2" aria-label="Wizard progress">
          {Array.from({ length: TOTAL_STEPS }, (_, i) => (
            <span
              key={i}
              className={
                i + 1 === currentStep
                  ? "h-1.5 w-6 rounded-full bg-primary"
                  : i + 1 < currentStep
                  ? "h-1.5 w-1.5 rounded-full bg-primary/40"
                  : "h-1.5 w-1.5 rounded-full bg-neutral-200"
              }
            />
          ))}
        </div>
      </header>

      {/* Body: left content + right image */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: step content — top-aligned, max 480px centred */}
        <div className="flex-1 overflow-y-auto pt-16 pb-16">
          <div className="mx-auto w-full px-8" style={{ maxWidth: 480 }}>
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
              onSuccess={(providerSlug) => {
                setSelectedProvider(providerSlug);
                advance();
              }}
            />
          )}
          {currentStep === 4 && (
            <StepRun provider={selectedProvider} onSuccess={advance} />
          )}
          {currentStep === 5 && <StepDone />}
          </div>
        </div>

        {/* Right: illustration — full height, 50% width */}
        <OnboardingVisual step={currentStep} />
      </div>
    </div>
  );
}

// ── Step 1: Welcome ──────────────────────────────────────────────────────────

function StepWelcome({ onNext }: { onNext: () => void }) {
  return (
    <div className="space-y-4 text-center">
      <h1 className="text-2xl font-bold text-foreground">
        Welcome to Keylatch
      </h1>
      <p className="text-muted-foreground">
        Keylatch is your zero-trust credential broker for AI agents. Your
        secrets stay locked — agents never see raw API keys.
      </p>
      <p className="text-muted-foreground">
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
  const [isFetchingBackends, setIsFetchingBackends] = useState(true);
  const [bootstrapStatus, setBootstrapStatus] = useState<"idle" | "loading" | "error">("idle");
  const [bootstrapError, setBootstrapError] = useState("");
  const [selectedBackend, setSelectedBackend] = useState("");

  useEffect(() => {
    let cancelled = false;
    api.get<BackendItem[]>("/v1/backends")
      .then((data) => {
        if (cancelled) return;
        setBackends(data);
        const first = data.find((b) => b.available);
        if (first) setSelectedBackend(first.name);
        setIsFetchingBackends(false);
      })
      .catch(() => {
        if (cancelled) return;
        setBackends([{ name: "keychain", display_name: "macOS Keychain", available: true }]);
        setSelectedBackend("keychain");
        setIsFetchingBackends(false);
      });
    return () => { cancelled = true; };
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
      <h2 className="text-xl font-semibold text-foreground">
        Choose a Credential Backend
      </h2>
      <p className="text-muted-foreground">
        Where should Keylatch store your secrets?
      </p>



      {/* Fix #10: show a loading indicator while fetching backends. */}
      {isFetchingBackends ? (
        <p role="status" aria-live="polite" className="text-sm text-muted-foreground">
          Loading backends…
        </p>
      ) : (
        <>
          <div className="space-y-2">
            {backends.map((b) => (
              <div key={b.name} className="space-y-1">
                <button
                  type="button"
                  className="w-full flex items-center justify-between rounded-lg border border-border px-4 py-3.5 text-left text-sm font-medium text-foreground transition-colors hover:bg-accent hover:border-primary/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-40 disabled:pointer-events-none"
                  onClick={() => { if (b.available) { setSelectedBackend(b.name); bootstrap(b.name); } }}
                  disabled={!b.available || bootstrapStatus === "loading"}
                >
                  <span>
                    {b.display_name}
                    {!b.available && <span className="ml-1.5 text-xs font-normal text-muted-foreground">(not installed)</span>}
                  </span>
                  {bootstrapStatus === "loading" && selectedBackend === b.name ? (
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-primary" />
                  ) : (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted-foreground shrink-0" aria-hidden="true">
                      <path d="m9 18 6-6-6-6" />
                    </svg>
                  )}
                </button>
                {!b.available && b.install_hint && (
                  <p className="pl-1 text-xs text-muted-foreground">{b.install_hint}</p>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {bootstrapStatus === "loading" && (
        <p role="status" aria-live="polite" className="text-sm text-muted-foreground">
          Setting up...
        </p>
      )}
      {bootstrapStatus === "error" && (
        <p
          className="rounded-md bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/50 px-3 py-2 text-sm text-red-700 dark:text-red-300"
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
  const navigate = useNavigate();

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <CheckCircle2 size={28} strokeWidth={1.5} className="text-emerald-500 shrink-0" aria-hidden="true" />
        <h2 className="text-xl font-semibold text-foreground">You're all set!</h2>
      </div>

      <p className="text-sm text-muted-foreground">
        Your credentials are locked in the vault. Agents will request access through Keylatch — raw API keys never leave your machine.
      </p>

      {/* Optional CLI install nudge */}
      <StepInstallCLI />

      <div className="pt-2">
        <Button type="button" className="w-full" onClick={() => navigate('/')}>
          Go to Dashboard
        </Button>
      </div>
    </div>
  );
}

// Re-export step components for testing / lazy-loading.
export { StepConnect } from "./StepConnect";
export { StepRun } from "./StepRun";
export { StepInstallCLI } from "./StepInstallCLI";
