// StepInstallCLI — optional CLI tools installation step.
import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";

export function StepInstallCLI() {
  const [status, setStatus] = useState<
    "idle" | "installing" | "ok" | "error" | "skipped"
  >("idle");
  const [error, setError] = useState("");

  const install = async () => {
    setStatus("installing");
    try {
      await invoke("install_cli");
      setStatus("ok");
    } catch (e) {
      setStatus("error");
      setError(String(e));
    }
  };

  if (status === "ok") {
    return (
      <p className="rounded-md bg-[var(--color-success-light)] px-3 py-2 text-sm text-[var(--color-success-dark)]">
        CLI tools installed. Run <code className="font-mono font-semibold">keylatch --help</code> in your terminal.
      </p>
    );
  }

  if (status === "skipped") {
    return (
      <p className="text-sm text-[var(--color-text-secondary)]">
        Skipped. You can install later at{" "}
        <a
          href="https://keylatch.dev/install"
          target="_blank"
          rel="noreferrer"
          className="underline underline-offset-2 hover:text-[var(--color-text-primary)]"
        >
          keylatch.dev/install
        </a>
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
        Install CLI tools (optional)
      </h3>
      <p className="text-sm text-[var(--color-text-secondary)]">
        Adds <code className="font-mono font-semibold">keylatch</code> to your terminal. Not required to use the
        app.
      </p>
      <div className="flex gap-2">
        <Button
          type="button"
          onClick={install}
          disabled={status === "installing"}
        >
          {status === "installing" ? "Installing..." : "Install"}
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={() => setStatus("skipped")}
        >
          Skip for now
        </Button>
      </div>
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
