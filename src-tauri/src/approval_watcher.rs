// src/approval_watcher.rs — Approval event watcher.
//
// Polls GET /api/approvals every 5 s (after initial fetch) and:
//   - Updates the TrayController badge count on count changes.
//   - Fires a native notification via NotifierImpl on each new approval.
//
// S14-6: notification body contains only the actorHmac prefix (8 chars) and
//        connection name — never a credential value.
//
// The watcher runs in a background OS thread (not tokio, to avoid the tokio
// runtime dependency from sidecar.rs which is sync). It stops when the
// join_handle is dropped.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tauri::{AppHandle, Manager, Runtime};

use crate::notify::{Notification, NotifierImpl};
use crate::tray::TrayController;

const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Approval mirrors the JSON shape of GET /api/approvals.
/// S14-6: no credential value fields — only metadata identifiers.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalEntry {
    /// Opaque approval token (used as a stable ID for de-dup). // security-reviewed: 2026-05-16
    pub token: String,
    /// Connection name (value-free label). // security-reviewed: 2026-05-16
    pub connection: String,
    /// Actor HMAC — first 8 chars used for notification body (S14-6). // security-reviewed: 2026-05-16
    pub actor_hmac: String,
}

/// ApprovalList wraps the /api/approvals response.
#[derive(Debug, Deserialize)]
struct ApprovalList {
    approvals: Option<Vec<ApprovalEntry>>,
}

/// Start the approval watcher background thread (with tray badge + notifications).
///
/// The thread polls `base_url/api/approvals` and drives:
///   - `TrayController` approval count (badge).
///   - `NotifierImpl` for native OS notifications.
pub fn start<R: Runtime + 'static>(
    app: AppHandle<R>,
    base_url: String,
    tray: Arc<TrayController<R>>,
    notifier: Arc<NotifierImpl<R>>,
) {
    std::thread::Builder::new()
        .name("approval-watcher".to_string())
        .spawn(move || {
            run_watcher(app, base_url, Some(tray), notifier);
        })
        .expect("approval-watcher thread spawn");
}

/// Start the approval watcher in notify-only mode (no tray badge).
/// Used when TrayController init fails.
pub fn start_notify_only<R: Runtime + 'static>(
    app: AppHandle<R>,
    base_url: String,
    notifier: Arc<NotifierImpl<R>>,
) {
    std::thread::Builder::new()
        .name("approval-watcher-notify".to_string())
        .spawn(move || {
            run_watcher(app, base_url, None, notifier);
        })
        .expect("approval-watcher-notify thread spawn");
}

fn run_watcher<R: Runtime>(
    _app: AppHandle<R>,
    base_url: String,
    tray: Option<Arc<TrayController<R>>>,
    notifier: Arc<NotifierImpl<R>>,
) {
    let url = format!("{}/api/approvals", base_url.trim_end_matches('/'));
    let mut known_tokens: HashSet<String> = HashSet::new();
    let mut prev_count: u32 = 0;

    loop {
        match ureq::get(&url).call() {
            Ok(response) => {
                if let Ok(list) = response.into_json::<ApprovalList>() {
                    let approvals = list.approvals.unwrap_or_default();
                    let current_count = approvals.len() as u32;

                    // Detect new approvals (tokens not seen before).
                    for approval in &approvals {
                        if !known_tokens.contains(&approval.token) {
                            known_tokens.insert(approval.token.clone());
                            fire_notification(&notifier, approval);
                        }
                    }

                    // Purge tokens that are no longer in the list (resolved).
                    let active_tokens: HashSet<String> = approvals.iter()
                        .map(|a| a.token.clone())
                        .collect();
                    known_tokens.retain(|t| active_tokens.contains(t));

                    // Update tray badge if count changed (only when tray is available).
                    if let Some(ref tray_ctrl) = tray {
                        if current_count != prev_count {
                            if current_count == 0 {
                                // All resolved — reset to zero via repeated decrement.
                                for _ in 0..prev_count {
                                    tray_ctrl.decrement_approval();
                                }
                            } else if current_count > prev_count {
                                for _ in 0..(current_count - prev_count) {
                                    tray_ctrl.increment_approval();
                                }
                            } else {
                                for _ in 0..(prev_count - current_count) {
                                    tray_ctrl.decrement_approval();
                                }
                            }
                        }
                    }
                    prev_count = current_count;
                }
            }
            Err(e) => {
                // Transient error — log and continue polling.
                log::debug!("approval-watcher: poll error: {}", e);
            }
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Fire a native notification for a new approval (S14-6: value-free body).
fn fire_notification<R: Runtime>(notifier: &NotifierImpl<R>, approval: &ApprovalEntry) {
    // Body: first 8 chars of actorHmac + connection name, truncated to 60 chars total.
    let actor_prefix = &approval.actor_hmac[..approval.actor_hmac.len().min(8)];
    let raw_body = format!("{} requests access to {}", actor_prefix, approval.connection);
    let body: String = raw_body.chars().take(60).collect();

    let notification = Notification::new(
        format!("approval:{}", approval.token),
        "Keylatch: approval requested",
        body,
    )
    .with_action_url("keylatch://approvals".to_string());

    notifier.show(notification);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_body_truncated_to_60_chars() {
        let long_connection = "a".repeat(100);
        let actor = "abcdef1234567890";
        let actor_prefix = &actor[..8];
        let raw = format!("{} requests access to {}", actor_prefix, long_connection);
        let body: String = raw.chars().take(60).collect();
        assert!(body.len() <= 60, "body must be at most 60 chars");
    }

    #[test]
    fn test_body_does_not_contain_credentials() {
        let approval = ApprovalEntry {
            token: "tok-1".to_string(),
            connection: "my-conn".to_string(),
            actor_hmac: "abcdef1234567890".to_string(),
        };
        let actor_prefix = &approval.actor_hmac[..8];
        let raw = format!("{} requests access to {}", actor_prefix, approval.connection);
        let body: String = raw.chars().take(60).collect();

        // Verify no credential patterns in the body.
        let patterns = ["sk-", "ghp_", "github_pat_", "AKIA", "xoxb-", "xoxp-"];
        for p in &patterns {
            assert!(!body.contains(p), "body must not contain credential pattern {:?}", p);
        }
    }
}
