mod approval_watcher;
mod bundled;
mod csp;
mod deeplink;
mod desktop_http;
mod desktop_runtime;
mod ipc;
mod launch;
mod notify;
mod redaction;
mod session;
mod sidecar;
mod tray;
mod update;
mod webview;
mod wizard;

use std::sync::{Arc, Mutex};
use tauri::{Manager, RunEvent};

use redaction::redact;

pub fn run() {
    // Step 1: Register panic hook with redaction.
    // This MUST be the very first statement.
    register_panic_hook();

    let app = tauri::Builder::default()
        // Step 3: single-instance plugin.
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
        // Wrap every log message through redact().
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
            // IsLLMSession() MUST be the absolute first statement in setup.
            if is_llm_session() {
                eprintln!("keylatch-app: LLM session detected — use the keylatch CLI instead");
                std::process::exit(0);
            }

            log::info!(
                "keylatch-app: cold-start (version={})",
                env!("CARGO_PKG_VERSION")
            );

            // Step 5: SidecarSupervisor::start().
            let app_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&app_dir, std::fs::Permissions::from_mode(0o700))?;
            }
            let sidecar_path = bundled::sidecar(&tauri::utils::platform::current_exe()?)?;
            let ipc_socket = app_dir.join("ipc.sock");

            let (mut supervisor, _status_rx) = sidecar::SidecarSupervisorImpl::new(
                sidecar_path
                    .to_str()
                    .ok_or("sidecar path is not UTF-8")?
                    .to_string(),
                ipc_socket
                    .to_str()
                    .ok_or("IPC path is not UTF-8")?
                    .to_string(),
            );

            let localhost_url = match supervisor.start() {
                Ok(url) => {
                    if let Err(error) = csp::verify_sidecar(&url) {
                        supervisor.stop();
                        return Err(error.into());
                    }
                    url
                }
                Err(e) => {
                    log::error!("keylatch-app: sidecar failed to start: {}", redact(&e));
                    "tauri://localhost/error.html".to_string()
                }
            };

            // Step 6a-ext: Wire TrayController and NotifierImpl.
            let tray_ctrl_opt = tray::TrayController::new(app.handle().clone())
                .map(Arc::new)
                .map_err(|e| {
                    log::warn!("keylatch-app: tray init failed (badge disabled): {e}");
                })
                .ok();
            let notifier = Arc::new(notify::NotifierImpl::new(app.handle().clone()));

            // Step 6b: Wire WebView host and NavigationGuard.
            let port: u16 = localhost_url
                .split(':')
                .last()
                .and_then(|p| p.split('/').next())
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);
            let webview_host = Arc::new(webview::WebViewHost::new(port));
            let nav_guard = Arc::new(webview::NavigationGuard::new(webview_host.clone()));

            // Step 6c: Wire DesktopSession.
            let bootstrap_target = session::bootstrap_url(&localhost_url).ok();
            let initial_url = match &bootstrap_target {
                Some(url) => tauri::WebviewUrl::External(url.clone()),
                None => tauri::WebviewUrl::App("error.html".into()),
            };
            let active: desktop_runtime::ActiveConnection =
                Arc::new(Mutex::new(bootstrap_target.as_ref().map(|_| {
                    Arc::new(desktop_runtime::Connection {
                        base: localhost_url.clone(),
                        session: Arc::new(session::DesktopSession::new(supervisor.ipc_client())),
                    })
                })));
            let active_for_load = active.clone();

            // Build the main window with the navigation hook wired.
            let guard_for_nav = nav_guard.clone();
            let _window = tauri::WebviewWindowBuilder::new(app, "main", initial_url)
                .title("Keylatch")
                .inner_size(1200.0, 800.0)
                .resizable(true)
                .visible(false)
                .on_navigation(move |url| guard_for_nav.on_navigate(url.as_str()))
                .on_page_load(move |window, payload| {
                    if matches!(payload.event(), tauri::webview::PageLoadEvent::Finished) {
                        let current = active_for_load.lock().unwrap().clone();
                        if let Some(current) = current {
                            if session::bootstrap_url(&current.base).ok().as_ref()
                                == Some(payload.url())
                            {
                                if let Err(e) =
                                    current.session.complete_bootstrap(&window, &current.base)
                                {
                                    log::error!(
                                        "keylatch-app: bootstrap exchange failed: {}",
                                        redact(&e)
                                    );
                                }
                            }
                        }
                        let _ = window.show();
                    }
                })
                .build()
                .map_err(|e| format!("build main window: {e}"))?;

            let runtime = desktop_runtime::start(
                app.handle().clone(),
                supervisor,
                active,
                webview_host,
                tray_ctrl_opt,
                notifier,
            )?;
            app.manage(Mutex::new(runtime));

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
            if let Some(runtime) = app_handle.try_state::<Mutex<desktop_runtime::DesktopRuntime>>()
            {
                runtime.lock().unwrap().stop();
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
