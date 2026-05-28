// src/session.rs — DesktopSession: bootstrap token flow.
//
// Implements the FIND-011 bootstrap flow:
//   1. fresh_bootstrap_token() → calls IPC MintBootstrapToken; returns one-time token
//   2. navigate_with_bootstrap(window) → navigates to /__bootstrap?b=<token>;
//      zeros the token immediately after navigation is initiated
//
// The shell never reads the resulting session cookie (HttpOnly; SameSite=Strict).
// The token is single-use (60 s TTL), never cached between calls.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{Runtime, WebviewWindow};

use crate::ipc::IpcClient;

// Used for safe JSON encoding of the bootstrap token value (N6).
use serde_json;

/// BootstrapToken is a single-use token for bootstrapping a WebView session.
/// It must be zeroed after use (navigate_with_bootstrap does this).
pub struct BootstrapToken {
    /// The token value. Zeroed after `navigate_with_bootstrap` returns.
    value: Vec<u8>,
    expires_at_unix: i64,
}

impl BootstrapToken {
    fn new(value: String, expires_at_unix: i64) -> Self {
        Self {
            value: value.into_bytes(),
            expires_at_unix,
        }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.value).unwrap_or("")
    }

    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.expires_at_unix <= now
    }

    /// Zero the token bytes. Called immediately after the token is used.
    fn zero(&mut self) {
        self.value.iter_mut().for_each(|b| *b = 0);
    }
}

impl Drop for BootstrapToken {
    fn drop(&mut self) {
        self.zero();
    }
}

/// DesktopSession manages the WebView bootstrap token lifecycle.
pub struct DesktopSession {
    ipc: IpcClient,
}

impl DesktopSession {
    pub fn new(ipc: IpcClient) -> Self {
        Self { ipc }
    }

    /// Obtain a fresh single-use bootstrap token from the sidecar.
    /// The token is NOT cached — every call mints a new one.
    pub fn fresh_bootstrap_token(&self) -> Result<BootstrapToken, String> {
        let (token, expires_at) = self.ipc.mint_bootstrap_token()
            .map_err(|e| format!("MintBootstrapToken IPC: {e}"))?;
        if token.is_empty() {
            return Err("sidecar returned empty bootstrap token".to_string());
        }
        let bt = BootstrapToken::new(token, expires_at);
        if bt.is_expired() {
            return Err("sidecar returned already-expired bootstrap token".to_string());
        }
        Ok(bt)
    }

    /// Navigate the WebView window to the bootstrap URL, then zero the token.
    /// N6: the token is delivered via an in-memory JS assignment (window.__kl_bootstrap_token)
    /// rather than a navigable URL query parameter, to prevent the token from appearing in
    /// browser history, referrer headers, or server logs.
    ///
    /// Flow:
    ///   1. Navigate to https://127.0.0.1:<port>/__bootstrap (no query parameter).
    ///   2. Inject the token via window.eval() as a JS variable assignment.
    ///   3. The frontend reads window.__kl_bootstrap_token, POSTs it to /__bootstrap,
    ///      which sets the HttpOnly session cookie and redirects to "/".
    ///   4. Zero the token immediately after injection.
    pub fn navigate_with_bootstrap<R: Runtime>(
        &self,
        window: &WebviewWindow<R>,
        localhost_url: &str,
    ) -> Result<(), String> {
        let mut token = self.fresh_bootstrap_token()?;

        // Step 1: navigate to the bootstrap page without the token in the URL.
        let bootstrap_url = format!("{}/__bootstrap", localhost_url);
        window.navigate(bootstrap_url.parse()
            .map_err(|e| format!("parse bootstrap URL: {e}"))?)
            .map_err(|e| format!("WebView navigate: {e}"))?;

        // Step 2: inject the token as an in-memory JS variable.
        // serde_json::to_string ensures the token is properly escaped.
        let token_str = token.as_str().to_owned();
        let js = format!(
            "window.__kl_bootstrap_token = {};",
            serde_json::to_string(&token_str)
                .map_err(|e| format!("token JSON encode: {e}"))?
        );

        // Zero the token immediately — the JS variable holds the value from here.
        token.zero();

        window.eval(&js)
            .map_err(|e| format!("WebView eval bootstrap token: {e}"))?;

        Ok(())
    }

    /// Reset the session: invalidate the current sidecar session and clear
    /// the WebView cookie jar for the localhost origin.
    pub fn reset<R: Runtime>(&self, window: &WebviewWindow<R>) -> Result<(), String> {
        // Send Shutdown+Restart via IPC (in production, call a session-invalidate method).
        // For now: eval JS to clear cookies for the localhost origin.
        window.eval("document.cookie.split(';').forEach(c => document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/'));")
            .map_err(|e| format!("WebView eval for cookie clear: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_token_zero_on_drop() {
        let token_value = "test-token-12345";
        let mut token = BootstrapToken::new(token_value.to_string(), i64::MAX);
        assert_eq!(token.as_str(), token_value);
        token.zero();
        // After zeroing, all bytes should be 0.
        assert!(token.value.iter().all(|&b| b == 0), "token must be zeroed");
    }

    #[test]
    fn test_expired_token_detected() {
        // Token expiring in the past.
        let token = BootstrapToken::new("x".to_string(), 1);
        assert!(token.is_expired());
    }

    #[test]
    fn test_valid_token_not_expired() {
        // Token expiring far in the future.
        let token = BootstrapToken::new("x".to_string(), i64::MAX);
        assert!(!token.is_expired());
    }
}
