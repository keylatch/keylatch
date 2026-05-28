// src/wizard.rs — Tauri IPC commands for the first-run wizard (Epic 42).
//
// All commands talk to the keylatchd sidecar at http://127.0.0.1:7890.
// They are registered in main.rs via tauri::Builder::invoke_handler.
//
// Security: these commands accept only plain strings from the frontend.
// No credential values are written to disk or logs.

use tauri::command;

const DAEMON_BASE: &str = "http://127.0.0.1:7890";

/// bootstrap initialises a credential backend (e.g. "keychain").
/// Called by the wizard Backend step.
#[command]
pub async fn bootstrap(backend: String) -> Result<serde_json::Value, String> {
    let url = format!("{}/v1/bootstrap", DAEMON_BASE);
    let body = serde_json::json!({ "backend": backend });

    match ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(&body)
    {
        Ok(_) => Ok(serde_json::json!({ "ok": true })),
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            Ok(serde_json::json!({ "ok": false, "error": format!("HTTP {code}: {text}") }))
        }
        Err(e) => Ok(serde_json::json!({ "ok": false, "error": e.to_string() })),
    }
}

/// connect_provider stores and verifies a provider API key.
/// Called by the wizard Connect step.
/// Posts to /v1/connect (the canonical wizard endpoint) with provider, api_key, and backend.
#[command]
pub async fn connect_provider(
    provider: String,
    key: String,
    backend: Option<String>,
) -> Result<serde_json::Value, String> {
    let url = format!("{}/v1/connect", DAEMON_BASE);
    let body = serde_json::json!({
        "provider": provider,
        "api_key": key,
        "backend": backend.unwrap_or_else(|| "keychain".to_string()),
    });

    match ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(&body)
    {
        Ok(resp) => match resp.into_json::<serde_json::Value>() {
            Ok(val) => {
                let ok = val.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                if ok {
                    Ok(serde_json::json!({ "verified": true }))
                } else {
                    let msg = val.get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("connect failed")
                        .to_string();
                    Ok(serde_json::json!({ "verified": false, "error": msg }))
                }
            }
            Err(e) => Ok(serde_json::json!({
                "verified": false,
                "error": format!("invalid response: {e}")
            })),
        },
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            Ok(serde_json::json!({
                "verified": false,
                "error": format!("HTTP {code}: {text}")
            }))
        }
        Err(e) => Ok(serde_json::json!({
            "verified": false,
            "error": e.to_string()
        })),
    }
}

/// run_agent runs a shell command through the keylatch broker and returns
/// the exit code and stdout. Called by the wizard Try It step.
#[command]
pub async fn run_agent(
    provider: String,
    command: String,
) -> Result<serde_json::Value, String> {
    let output = tokio::process::Command::new("keylatch")
        .args(["run", &provider, "--", "sh", "-c", &command])
        .output()
        .await
        .map_err(|e| format!("run_agent: {e}"))?;

    Ok(serde_json::json!({
        "exit_code": output.status.code().unwrap_or(-1),
        "stdout": String::from_utf8_lossy(&output.stdout),
    }))
}

/// install_cli copies the keylatch binary to ~/bin/keylatch and updates
/// shell RC files. Called by the wizard Done step (optional).
#[command]
pub async fn install_cli() -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|e| format!("install_cli: HOME: {e}"))?;
    let bin_dir = std::path::PathBuf::from(&home).join("bin");
    std::fs::create_dir_all(&bin_dir)
        .map_err(|e| format!("install_cli: create ~/bin: {e}"))?;

    // Copy the current executable as "keylatch".
    let src = std::env::current_exe()
        .map_err(|e| format!("install_cli: current_exe: {e}"))?;
    let dst = bin_dir.join("keylatch");
    std::fs::copy(&src, &dst)
        .map_err(|e| format!("install_cli: copy binary: {e}"))?;

    // Append PATH export to shell RC files if not already present.
    let export_line = "export PATH=\"$HOME/bin:$PATH\"";
    for rc in &[".zshrc", ".bashrc"] {
        let rc_path = std::path::PathBuf::from(&home).join(rc);
        if rc_path.exists() {
            let contents = std::fs::read_to_string(&rc_path).unwrap_or_default();
            if !contents.contains(export_line) {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&rc_path)
                    .map_err(|e| format!("install_cli: open {rc}: {e}"))?;
                use std::io::Write;
                writeln!(f, "\n# Added by Keylatch\n{export_line}")
                    .map_err(|e| format!("install_cli: write {rc}: {e}"))?;
            }
        }
    }
    Ok(())
}
