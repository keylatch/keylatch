mod redaction;
mod sidecar;
mod ipc;
mod webview;
mod session;
mod tray;
mod notify;
mod deeplink;
mod update;
mod launch;
mod approval_watcher;
mod wizard;

use std::sync::{Arc, Mutex};
use tauri::{Manager, RunEvent};

use redaction::redact;

pub fn run() {
    // Step 1: Register panic hook with redaction (FIND2-019 / S14-14).
    // This MUST be the very first statement.
    register_panic_hook();

    let app = tauri::Builder::default()
        // Step 3: single-instance plugin (S14-13).
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if is_llm_session() {
                return;
            }
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
            log::info!("single-instance: second launch argv={:?}", argv);
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        // M1: wrap every log message through redact() (S14-14).
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .format(|out, message, record| {
                    out.finish(format_args!(
                        "[{}] {}",
                        record.level(),
                        redact(&message.to_string())
                    ))
                })
                .build(),
        )
        .setup(|app| {
            // M2: IsLLMSession() MUST be the absolute first statement in setup (S14-7).
            if is_llm_session() {
                eprintln!("keylatch-app: LLM session detected — use the keylatch CLI instead");
                std::process::exit(0);
            }

            log::info!("keylatch-app: cold-start (version={})", env!("CARGO_PKG_VERSION"));

            // Step 5: SidecarSupervisor::start().
            let app_dir = app.path().app_data_dir().unwrap_or_else(|_| "/tmp/keylatch".into());
            let sidecar_path = app.path()
                .resource_dir()
                .unwrap_or_else(|_| ".".into())
                .join("binaries/keylatchd");
            let ipc_socket = app_dir.join("ipc.sock");

            let (mut supervisor, _status_rx) = sidecar::SidecarSupervisorImpl::new(
                sidecar_path.to_string_lossy().to_string(),
                ipc_socket.to_string_lossy().to_string(),
            );

            let localhost_url = match supervisor.start() {
                Ok(url) => url,
                Err(e) => {
                    log::error!("keylatch-app: sidecar failed to start: {}", redact(&e));
                    "tauri://localhost/error.html".to_string()
                }
            };

            let hmac_key = supervisor.hmac_key();

            // Step 6a: Wire IPC client.
            let ipc = ipc::IpcClient::new(
                ipc_socket.to_string_lossy().to_string(),
                hmac_key,
            );

            // Step 6a-ext: Wire TrayController and NotifierImpl.
            let tray_ctrl_opt = tray::TrayController::new(app.handle().clone())
                .map(Arc::new)
                .map_err(|e| {
                    log::warn!("keylatch-app: tray init failed (badge disabled): {e}");
                })
                .ok();
            let notifier = Arc::new(notify::NotifierImpl::new(app.handle().clone()));

            // Step 6b: Wire WebView host and NavigationGuard (C3 — FIND2-014).
            let port: u16 = localhost_url
                .split(':')
                .last()
                .and_then(|p| p.split('/').next())
                .and_then(|p| p.parse().ok())
                .unwrap_or(7890);
            let webview_host = Arc::new(webview::WebViewHost::new(port));
            let nav_guard = Arc::new(webview::NavigationGuard::new(webview_host.clone()));

            // Step 6c: Wire DesktopSession.
            let session = session::DesktopSession::new(ipc);

            // C3: Build the main window with the navigation hook wired (FIND2-014).
            let guard_for_nav = nav_guard.clone();
            let window = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("/".into()),
            )
            .title("Keylatch")
            .inner_size(1200.0, 800.0)
            .resizable(true)
            .visible(false)
            .on_navigation(move |url| {
                guard_for_nav.on_navigate(url.as_str())
            })
            .build()
            .map_err(|e| format!("build main window: {e}"))?;

            let _ = webview_host.assert_csp(&window);

            // Step 7: Bootstrap token + WebView navigation.
            if let Err(e) = session.navigate_with_bootstrap(&window, &localhost_url) {
                log::error!("keylatch-app: bootstrap navigation failed: {e}");
            }

            // Step 6a-ext2: Start approval watcher.
            if let Some(tray_ctrl) = tray_ctrl_opt {
                approval_watcher::start(
                    app.handle().clone(),
                    localhost_url.clone(),
                    tray_ctrl,
                    notifier.clone(),
                );
            } else {
                approval_watcher::start_notify_only(
                    app.handle().clone(),
                    localhost_url.clone(),
                    notifier.clone(),
                );
            }

            app.manage(Arc::new(Mutex::new(supervisor)));

            log::info!("keylatch-app: startup complete, URL={localhost_url}");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wizard::bootstrap,
            wizard::connect_provider,
            wizard::run_agent,
            wizard::install_cli,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        if let RunEvent::ExitRequested { .. } = event {
            log::info!("keylatch-app: exit requested — stopping sidecar");
            if let Some(sup) = app_handle.try_state::<Arc<Mutex<sidecar::SidecarSupervisorImpl>>>() {
                sup.lock().unwrap().stop();
            }
        }
    });
}

fn register_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("{info}");
        let redacted = redact(&msg);
        eprintln!("keylatch-app: PANIC (redacted): {redacted}");
    }));
}

fn is_llm_session() -> bool {
    let signals = [
        ("CLAUDE_CODE", None),
        ("CODEX_ENV", None),
        ("CREDENTIALS_LLM_SESSION", Some("1")),
    ];
    for (key, expected) in &signals {
        let val = std::env::var(key).unwrap_or_default();
        if val.is_empty() {
            continue;
        }
        match expected {
            None => return true,
            Some(e) if &val == e => return true,
            _ => {}
        }
    }
    false
}
