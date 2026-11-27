use crate::notify::{Notification, NotifierImpl};
use crate::session::DesktopSession;
use crate::tray::{TrayController, TrayIconState};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, Runtime};

const POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize)]
struct ApprovalEntry {
    token: String,
    connection: String,
    actor: String,
    status: String,
    expires_at: String,
}

fn pending_at(approval: &ApprovalEntry, now: i64) -> bool {
    approval.status == "pending"
        && chrono::DateTime::parse_from_rfc3339(&approval.expires_at)
            .map(|expiry| expiry.timestamp() > now)
            .unwrap_or(false)
}

fn notification_body(approval: &ApprovalEntry) -> String {
    let actor: String = approval.actor.chars().take(8).collect();
    crate::redaction::redact(&format!(
        "{actor} requests access to {}",
        approval.connection
    ))
    .chars()
    .filter(|c| !c.is_control())
    .take(60)
    .collect()
}

pub struct ApprovalWatcher {
    stopped: Arc<AtomicBool>,
    wake: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl ApprovalWatcher {
    pub fn stop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.wake.send(());
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                log::error!("approval watcher stopped unexpectedly");
            }
        }
    }
}

impl Drop for ApprovalWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

fn show_error<R: Runtime>(
    app: &AppHandle<R>,
    tray: &Option<Arc<TrayController<R>>>,
    stopped: &Arc<AtomicBool>,
) {
    let tray = tray.clone();
    let stopped = stopped.clone();
    let _ = app.run_on_main_thread(move || {
        if !stopped.load(Ordering::Acquire) {
            if let Some(tray) = tray {
                tray.set_state(TrayIconState::IconError);
            }
        }
    });
}

pub fn start<R: Runtime + 'static>(
    app: AppHandle<R>,
    base_url: String,
    session: Arc<DesktopSession>,
    tray: Option<Arc<TrayController<R>>>,
    notifier: Arc<NotifierImpl<R>>,
) -> Result<ApprovalWatcher, std::io::Error> {
    let stopped = Arc::new(AtomicBool::new(false));
    let stopping = stopped.clone();
    let (wake, receiver) = mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("approval-watcher".into())
        .spawn(move || {
            let mut client = match session.native_http(&base_url) {
                Ok(client) => client,
                Err(_) => {
                    log::error!("approval watcher could not establish its native session");
                    show_error(&app, &tray, &stopping);
                    return;
                }
            };
            let mut known = HashSet::new();
            while !stopping.load(Ordering::Acquire) {
                match client.approvals::<Vec<ApprovalEntry>>() {
                    Ok(entries) => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        let pending: Vec<_> = entries
                            .into_iter()
                            .filter(|entry| pending_at(entry, now))
                            .collect();
                        let fresh: Vec<_> = pending
                            .iter()
                            .filter(|entry| !known.contains(&entry.token))
                            .cloned()
                            .collect();
                        known = pending.iter().map(|entry| entry.token.clone()).collect();
                        let count = pending.len() as u32;
                        let stopping = stopping.clone();
                        let tray = tray.clone();
                        let notifier = notifier.clone();
                        // Queue UI work so shutdown can join without blocking the GUI event loop.
                        let _ = app.run_on_main_thread(move || {
                            if stopping.load(Ordering::Acquire) {
                                return;
                            }
                            if let Some(tray) = tray {
                                tray.set_state(if count == 0 {
                                    TrayIconState::Idle
                                } else {
                                    TrayIconState::PendingApproval { count }
                                });
                            }
                            for approval in fresh {
                                notifier.show(
                                    Notification::new(
                                        format!("approval:{}", approval.token),
                                        "Keylatch: approval requested",
                                        notification_body(&approval),
                                    )
                                    .with_action_url("keylatch://approvals".to_string()),
                                );
                            }
                        });
                    }
                    Err(reason) => {
                        log::debug!("approval watcher: {reason}");
                        show_error(&app, &tray, &stopping);
                        if reason == crate::desktop_http::SESSION_EXPIRED
                            && !stopping.load(Ordering::Acquire)
                        {
                            match session.native_http(&base_url) {
                                Ok(renewed) => {
                                    client = renewed;
                                    let app_for_recovery = app.clone();
                                    let session = session.clone();
                                    let base = base_url.clone();
                                    let stopping = stopping.clone();
                                    let _ = app.run_on_main_thread(move || {
                                        if stopping.load(Ordering::Acquire) {
                                            return;
                                        }
                                        if let Some(window) =
                                            app_for_recovery.get_webview_window("main")
                                        {
                                            if session.rebootstrap(&window, &base).is_err() {
                                                log::error!("desktop session recovery failed");
                                            }
                                        }
                                    });
                                }
                                Err(_) => log::error!("native session renewal failed"),
                            }
                        }
                    }
                }
                if receiver.recv_timeout(POLL_INTERVAL) != Err(mpsc::RecvTimeoutError::Timeout) {
                    break;
                }
            }
        })?;
    Ok(ApprovalWatcher {
        stopped,
        wake,
        thread: Some(thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_array_filters_expired_resolved_and_malformed_requests() {
        let data = r#"[{"token":"one","actor":"robot","connection":"db","status":"pending","expires_at":"2030-01-01T00:00:00Z"}]"#;
        let mut entries: Vec<ApprovalEntry> = serde_json::from_str(data).unwrap();
        let entry = &mut entries[0];
        assert!(pending_at(entry, 1));
        assert!(!pending_at(entry, 1_893_456_000));
        entry.status = "approved".into();
        assert!(!pending_at(entry, 1));
        entry.status = "pending".into();
        entry.expires_at = "invalid".into();
        assert!(!pending_at(entry, 1));
    }

    #[test]
    fn unicode_notification_is_bounded_without_token_or_control_bytes() {
        let entry = ApprovalEntry {
            token: "never-show-this".into(),
            actor: "机器人🙂机器人🙂机器人🙂".into(),
            connection: format!("\n{}", "db".repeat(100)),
            status: "pending".into(),
            expires_at: "".into(),
        };
        let body = notification_body(&entry);
        assert!(body.starts_with("机器人🙂机器人🙂"));
        assert!(body.chars().count() <= 60);
        assert!(!body.contains(&entry.token));
        assert!(!body.contains('\n'));
    }

    #[test]
    fn stop_wakes_and_joins_worker_and_is_idempotent() {
        let stopped = Arc::new(AtomicBool::new(false));
        let observed = stopped.clone();
        let (wake, receiver) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            receiver.recv_timeout(Duration::from_secs(60)).unwrap();
            assert!(observed.load(Ordering::Acquire));
        });
        let mut watcher = ApprovalWatcher {
            stopped,
            wake,
            thread: Some(thread),
        };
        watcher.stop();
        assert!(watcher.thread.is_none());
        watcher.stop();
    }
}
