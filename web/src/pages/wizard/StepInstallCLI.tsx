// StepInstallCLI — optional CLI install nudge, no competing buttons.
import { useState } from "react";
import { safeInvoke as invoke } from "@/lib/tauri";

export function StepInstallCLI() {
  const [status, setStatus] = useState<"idle" | "installing" | "ok" | "error">("idle");

  const install = async (e: React.MouseEvent) => {
    e.preventDefault();
    setStatus("installing");
    try {
      await invoke("install_cli");
      setStatus("ok");
    } catch {
      setStatus("error");
    }
  };

  if (status === "ok") {
    return (
      <p className="text-sm text-muted-foreground">
        CLI installed — run <code className="font-mono text-foreground">keylatch --help</code> to get started.
      </p>
    );
  }

  return (
    <p className="text-sm text-muted-foreground">
      Want the CLI?{" "}
      <a
        href="#"
        onClick={install}
        className="text-foreground underline underline-offset-2 hover:opacity-70 transition-opacity"
      >
        {status === "installing" ? "Installing…" : "Install keylatch CLI"}
      </a>
      {status === "error" && (
        <span className="ml-2 text-destructive">Failed — try again later.</span>
      )}
    </p>
  );
}
