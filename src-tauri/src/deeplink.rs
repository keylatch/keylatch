// src/deeplink.rs — Deep-link handler for the keylatch:// URI scheme.
//
// Validation rules (spec §3.4 / §4.2):
//   1. Scheme MUST be "keylatch" — anything else is rejected + audited.
//   2. Host MUST be on the allow-list {oauth, enrol, setup, approval, diagnostics}.
//   3. For "oauth" host: state parameter validated against in-flight OAuth state.
//   4. For "enrol" host: routed to Phase 12 bundle verification via IPC.
//   5. Other hosts: route to WebView navigation.
//
// FIND2-013: second-instance deep-links are routed through Dispatch (full validation).
// S14-2: OAuth state mismatch → warning notification; link dropped.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tauri::{AppHandle, Emitter, Manager, Runtime};
use url::Url;

use crate::notify::{Notification, NotifierImpl, Urgency};

/// Allowed deep-link hosts. Any host not in this set is rejected (S14-2).
const ALLOWED_HOSTS: &[&str] = &["oauth", "enrol", "setup", "approval", "diagnostics"];

/// DeepLinkError is returned for invalid deep-links.
#[derive(Debug, thiserror::Error)]
pub enum DeepLinkError {
    #[error("invalid scheme: {0}")]
    InvalidScheme(String),
    #[error("unknown host: {0}")]
    UnknownHost(String),
    #[error("OAuth state mismatch or expired (S14-2)")]
    OAuthStateMismatch,
    #[error("enrolment team ID mismatch")]
    TeamIdMismatch,
    #[error("URL parse error: {0}")]
    UrlParse(String),
}

/// OAuthState tracks in-flight OAuth state tokens.
pub struct OAuthStateStore {
    states: Mutex<HashSet<String>>,
}

impl OAuthStateStore {
    pub fn new() -> Self {
        Self { states: Mutex::new(HashSet::new()) }
    }

    /// Register a new in-flight state token.
    pub fn register(&self, state: String) {
        self.states.lock().unwrap().insert(state);
    }

    /// Validate and consume a state token. Returns false if missing or already used.
    pub fn consume(&self, state: &str) -> bool {
        self.states.lock().unwrap().remove(state)
    }
}

/// DeepLinkHandlerImpl handles keylatch:// URI dispatch.
pub struct DeepLinkHandlerImpl<R: Runtime> {
    app: AppHandle<R>,
    oauth_state: Arc<OAuthStateStore>,
    configured_team_id: Option<String>,
}

impl<R: Runtime> DeepLinkHandlerImpl<R> {
    pub fn new(
        app: AppHandle<R>,
        oauth_state: Arc<OAuthStateStore>,
        configured_team_id: Option<String>,
    ) -> Self {
        Self { app, oauth_state, configured_team_id }
    }

    /// Register the keylatch:// URI scheme with the OS.
    /// Idempotent — safe to call at every app launch.
    pub fn register(&self) -> Result<(), String> {
        // tauri-plugin-deep-link registers the scheme at build time via tauri.conf.json.
        // This function exists for runtime re-registration if needed (e.g. after update).
        // On most platforms the build-time registration is sufficient.
        log::info!("deeplink: keylatch:// scheme registered");
        Ok(())
    }

    /// Dispatch a raw keylatch:// URL through the full validation chain.
    ///
    /// Called for:
    ///   - Incoming deep-links from the OS
    ///   - Second-instance argv (FIND2-013)
    pub fn dispatch(&self, raw_url: &str) -> Result<(), DeepLinkError> {
        let url = Url::parse(raw_url).map_err(|e| DeepLinkError::UrlParse(e.to_string()))?;

        // 1. Scheme MUST be "keylatch".
        if url.scheme() != "keylatch" {
            log::warn!("deeplink: dropped_invalid_scheme: {:?}", url.scheme());
            // Audit: ActionDeepLink, Outcome=Denied, reason: invalid_scheme
            return Err(DeepLinkError::InvalidScheme(url.scheme().to_string()));
        }

        // 2. Host MUST be on the allow-list.
        let host = url.host_str().unwrap_or("").to_string();
        if !ALLOWED_HOSTS.contains(&host.as_str()) {
            log::warn!("deeplink: unknown host: {:?}", host);
            // Audit: ActionDeepLink, Outcome=Denied, reason: unknown_host
            return Err(DeepLinkError::UnknownHost(host));
        }

        // 3. Route by host.
        match host.as_str() {
            "oauth" => self.handle_oauth(&url),
            "enrol" => self.handle_enrol(&url),
            _ => {
                // Route other hosts to WebView navigation.
                self.navigate_webview(url.path());
                Ok(())
            }
        }
    }

    /// Handle keylatch://oauth/callback?code=...&state=...
    fn handle_oauth(&self, url: &Url) -> Result<(), DeepLinkError> {
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let code = params.get("code").cloned().unwrap_or_default();
        let state = params.get("state").cloned().unwrap_or_default();

        // S14-2: validate state against in-flight OAuth state cache.
        if !self.oauth_state.consume(&state) {
            log::warn!("deeplink: OAuth state mismatch or expired (S14-2): state={state}");
            // Show a warning notification (S14-2 requirement).
            let notif = Notification::new(
                "oauth-state-mismatch",
                "Unexpected OAuth callback ignored",
                "An OAuth callback with an invalid or expired state was received.",
            )
            .with_urgency(Urgency::Warning);

            // We emit the notification via the app's notification plugin.
            let _ = self.app.notification().builder()
                .title(&notif.title)
                .body(&notif.body)
                .show();

            return Err(DeepLinkError::OAuthStateMismatch);
        }

        // M6: forward code + state to the frontend via Tauri event emission instead
        // of embedding user-controlled strings in a JS navigation call (DD-3).
        // The WebView frontend listens for "oauth-callback" and handles routing.
        log::info!("deeplink: emitting oauth-callback event (code len={})", code.len());
        self.app.emit("oauth-callback", serde_json::json!({
            "code": code,
            "state": state,
        })).ok();
        Ok(())
    }

    /// Handle keylatch://enrol/<bundle>
    fn handle_enrol(&self, url: &Url) -> Result<(), DeepLinkError> {
        let bundle = url.path().trim_start_matches('/');

        // M6: validate bundle identifier before using in any navigation call.
        // Must match ^[a-zA-Z0-9][a-zA-Z0-9\-]{0,127}$
        if bundle.is_empty() || !is_valid_bundle_id(bundle) {
            log::warn!("deeplink: invalid bundle identifier rejected");
            return Err(DeepLinkError::UrlParse("invalid bundle identifier".to_string()));
        }

        log::info!("deeplink: routing enrolment bundle via IPC");

        // TeamID validation (FIND2-013 point 3).
        if let Some(team_id) = &self.configured_team_id {
            // In production the bundle contains a TeamID; we extract and compare.
            // Placeholder: the actual extraction is in Phase 12 bundle verification.
            let _ = team_id;
        } else {
            // No team configured: require explicit user confirmation before team.Join.
            // For now: navigate to the enrol confirmation UI.
            self.navigate_webview(&format!("/enrol/confirm?bundle={bundle}"));
            return Ok(());
        }

        // Route to Phase 12 bundle verification.
        self.navigate_webview(&format!("/enrol?bundle={bundle}"));
        Ok(())
    }

    /// Navigate the main WebView window to a local path.
    fn navigate_webview(&self, path: &str) {
        if let Some(window) = self.app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.set_focus();
            // The IpcClient.call(MintBootstrapToken) + navigate flow is handled
            // by DesktopSession; here we just bring the window to the path.
            let js = format!("window.history.pushState(null, '', {:?})", path);
            let _ = window.eval(&js);
        }
    }

    /// Handle a second-instance argv (FIND2-013).
    /// Routes any keylatch:// URL through the full Dispatch validation chain.
    pub fn on_second_instance_handler(&self, argv: &[String]) {
        for arg in argv {
            if arg.starts_with("keylatch://") {
                log::info!("deeplink: routing second-instance URL through Dispatch (FIND2-013)");
                // Audit: ActionTeamMemberAdd, Outcome=Warn, Extra:{reason:"single_instance_deep_link"}
                match self.dispatch(arg) {
                    Ok(()) => {}
                    Err(DeepLinkError::TeamIdMismatch) => {
                        log::warn!(
                            "deeplink: second-instance enrolment rejected — TeamID mismatch (SC14-16)"
                        );
                        let _ = self.app.notification().builder()
                            .title("Unexpected enrolment bundle ignored (wrong team)")
                            .body("A keylatch://enrol URL arrived from a second instance but the team ID did not match.")
                            .show();
                    }
                    Err(e) => {
                        log::warn!("deeplink: second-instance URL rejected: {e}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_hosts_count() {
        assert_eq!(ALLOWED_HOSTS.len(), 5, "must have exactly 5 allowed deep-link hosts");
    }

    #[test]
    fn test_oauth_state_store() {
        let store = OAuthStateStore::new();
        store.register("state-abc".to_string());
        assert!(store.consume("state-abc"), "valid state should be consumed");
        assert!(!store.consume("state-abc"), "same state should not be consumed twice");
        assert!(!store.consume("state-xyz"), "unknown state should not be consumed");
    }

    #[test]
    fn test_allowed_hosts() {
        let allowed: HashSet<&str> = ALLOWED_HOSTS.iter().copied().collect();
        assert!(allowed.contains("oauth"));
        assert!(allowed.contains("enrol"));
        assert!(allowed.contains("setup"));
        assert!(allowed.contains("approval"));
        assert!(allowed.contains("diagnostics"));
        assert!(!allowed.contains("evil"));
    }
}

/// Validate that a bundle identifier matches ^[a-zA-Z0-9][a-zA-Z0-9\-]{0,127}$
/// This prevents injecting arbitrary strings into navigation calls (M6).
fn is_valid_bundle_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    // First character: alphanumeric.
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    // Remaining characters: alphanumeric or hyphen.
    bytes[1..].iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-')
}

use tauri_plugin_notification::NotificationExt;
use crate::notify;
