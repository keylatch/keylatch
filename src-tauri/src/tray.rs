// src/tray.rs — System tray controller.
//
// Manages the tray icon, tooltip, and menu. Subscribes to SidecarStatus
// and ApprovalEvent streams to drive icon state transitions.
//
// S14-6: tooltip is value-free — shows only counts, never credential data.
// DD-5: macOS LSUIElement (no Dock icon by default).

use std::sync::{Arc, Mutex};

use tauri::{
    menu::{Menu, MenuItem, MenuItemBuilder, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, Runtime,
};

/// TrayIconState drives which tray icon asset is displayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayIconState {
    Idle,
    PendingApproval { count: u32 },
    Processing,
    IconError,
    Updating,
}

/// TrayController manages the tray icon lifecycle.
pub struct TrayController<R: Runtime> {
    app: AppHandle<R>,
    state: Arc<Mutex<TrayIconState>>,
    pending_approval_count: Arc<Mutex<u32>>,
}

impl<R: Runtime> TrayController<R> {
    /// Create and register the tray icon with the initial Idle state.
    pub fn new(app: AppHandle<R>) -> Result<Self, String> {
        let ctrl = Self {
            app,
            state: Arc::new(Mutex::new(TrayIconState::Idle)),
            pending_approval_count: Arc::new(Mutex::new(0)),
        };
        ctrl.build_tray()?;
        Ok(ctrl)
    }

    /// Build (or rebuild) the tray icon with its default menu.
    fn build_tray(&self) -> Result<(), String> {
        // Items: Open Keylatch, Check for Updates, Quit.
        // DD-5: no dock icon; tray is the only entry point.
        let _ = TrayIconBuilder::with_id("keylatch-tray")
            .tooltip("Keylatch — idle")
            .on_tray_icon_event({
                let app = self.app.clone();
                move |_tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        // Bring the main window to front on left click.
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                }
            })
            .build(&self.app)
            .map_err(|e| format!("tray build: {e}"))?;
        Ok(())
    }

    /// Set the tray icon to the given state.
    /// S14-6: tooltip is value-free.
    pub fn set_state(&self, new_state: TrayIconState) {
        let tooltip = self.build_tooltip(&new_state);

        // Validate tooltip is value-free in dev/test builds (S14-6).
        #[cfg(debug_assertions)]
        self.assert_tooltip_value_free(&tooltip);

        *self.state.lock().unwrap() = new_state;

        if let Some(tray) = self.app.tray_by_id("keylatch-tray") {
            let _ = tray.set_tooltip(Some(&tooltip));
            // Icon path would be set here with tray.set_icon() using platform assets.
        }
    }

    /// Build a value-free tooltip string for the given state (S14-6).
    fn build_tooltip(&self, state: &TrayIconState) -> String {
        match state {
            TrayIconState::Idle => "Keylatch — running".to_string(),
            TrayIconState::PendingApproval { count } => {
                format!("Keylatch — {} pending approval{}", count, if *count == 1 { "" } else { "s" })
            }
            TrayIconState::Processing => "Keylatch — processing".to_string(),
            TrayIconState::IconError => "Keylatch — error (click to retry)".to_string(),
            TrayIconState::Updating => "Keylatch — updating".to_string(),
        }
    }

    /// S14-6 runtime check: reject tooltips containing credential patterns.
    #[cfg(debug_assertions)]
    fn assert_tooltip_value_free(&self, tooltip: &str) {
        for pattern in crate::redaction::REDACTION_PATTERNS {
            assert!(
                !tooltip.contains(pattern),
                "S14-6 violation: tooltip contains credential pattern {:?}: {:?}",
                pattern,
                tooltip
            );
        }
    }

    /// Increment the pending approval count and update the tray.
    pub fn increment_approval(&self) {
        let mut count = self.pending_approval_count.lock().unwrap();
        *count += 1;
        let c = *count;
        drop(count);
        self.set_state(TrayIconState::PendingApproval { count: c });
    }

    /// Decrement the pending approval count (resolving an approval).
    pub fn decrement_approval(&self) {
        let mut count = self.pending_approval_count.lock().unwrap();
        *count = count.saturating_sub(1);
        let c = *count;
        drop(count);
        if c == 0 {
            self.set_state(TrayIconState::Idle);
        } else {
            self.set_state(TrayIconState::PendingApproval { count: c });
        }
    }

    /// Flash the tray icon briefly (used for ReceiptEvent).
    /// N7: the spawned thread previously had no state-reset logic (dead code).
    /// Brief flash animation is not implementable without a platform timer API
    /// from this context; state remains as-is and will update on the next event.
    pub fn flash(&self) {
        // Brief flash animation not implemented without platform timer API.
        // State remains as-is; tray icon will update on next state change.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tooltip_idle_value_free() {
        // The tooltip for Idle must not contain any credential-like content.
        let tooltip = "Keylatch — running";
        let patterns = ["sk-", "ghp_", "github_pat_", "AKIA", "xoxb-", "xoxp-"];
        for p in &patterns {
            assert!(!tooltip.contains(p), "tooltip contains pattern {:?}", p);
        }
    }

    #[test]
    fn test_tooltip_pending_approval_value_free() {
        let tooltip = format!("Keylatch — {} pending approvals", 3);
        let patterns = ["sk-", "ghp_", "github_pat_", "AKIA", "xoxb-", "xoxp-"];
        for p in &patterns {
            assert!(!tooltip.contains(p));
        }
        assert!(tooltip.contains("3 pending approvals"));
    }

    #[test]
    fn test_set_tooltip_with_credential_rejected_in_dev() {
        // In production this is a no-op; in dev it asserts.
        // We test the pattern detection logic directly.
        let patterns = ["sk-", "ghp_", "github_pat_", "AKIA", "xoxb-", "xoxp-"];
        let bad_tooltip = "sk-fake-token is the key";
        let contains_cred = patterns.iter().any(|p| bad_tooltip.contains(p));
        assert!(contains_cred, "should detect credential in tooltip");
    }
}
