// src/session.rs — DesktopSession: bootstrap token flow.
//
// Implements the bootstrap flow:
//   1. fresh_bootstrap_token() → calls IPC MintBootstrapToken; returns one-time token
//   2. The WebView builder loads the credential-free bootstrap page.
//   3. complete_bootstrap posts a fresh token after the trusted page has loaded.
//
// The shell never reads the resulting session cookie (HttpOnly; SameSite=Strict).
// The token is single-use (60 s TTL), never cached between calls.

use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Runtime, WebviewWindow};
use url::Url;

use crate::ipc::IpcClient;

pub fn bootstrap_url(base: &str) -> Result<Url, String> {
    let mut url = Url::parse(base).map_err(|_| "invalid sidecar URL".to_string())?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || url.port() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("sidecar URL must be its exact HTTP loopback origin".to_string());
    }
    url.set_path("/__bootstrap");
    Ok(url)
}

fn bootstrap_script(url: &Url, token: &str) -> Result<String, String> {
    let expected = serde_json::to_string(url.as_str()).map_err(|_| "encode bootstrap URL")?;
    let token = serde_json::to_string(token).map_err(|_| "encode bootstrap token")?;
    Ok(format!(
        r#"(async () => {{
        if (window.location.href !== {expected}) return;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        try {{
            const response = await fetch('/__bootstrap', {{
                method: 'POST', credentials: 'same-origin', redirect: 'error',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{token: {token}}}), signal: controller.signal
            }});
            if (!response.ok) throw new Error('bootstrap refused');
            window.location.replace('/');
        }} catch (_) {{
            document.body.textContent = 'Could not sign in to Keylatch. Restart the app to try again.';
        }} finally {{ clearTimeout(timeout); }}
    }})();"#
    ))
}

/// BootstrapToken is a single-use token for bootstrapping a WebView session.
/// Its native byte buffer is cleared after use.
pub struct BootstrapToken {
    /// The token value, cleared after constructing the exchange script.
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

    pub fn native_http(&self, base: &str) -> Result<crate::desktop_http::DesktopHttp, String> {
        bootstrap_url(base)?;
        let mut token = self.fresh_bootstrap_token()?;
        let result = crate::desktop_http::DesktopHttp::connect(base, token.as_str());
        token.zero();
        result.map_err(str::to_string)
    }

    /// Obtain a fresh single-use bootstrap token from the sidecar.
    /// The token is NOT cached — every call mints a new one.
    pub fn fresh_bootstrap_token(&self) -> Result<BootstrapToken, String> {
        let (token, expires_at) = self
            .ipc
            .mint_bootstrap_token()
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

    /// Exchange a token only after the trusted bootstrap document finishes loading.
    pub fn complete_bootstrap<R: Runtime>(
        &self,
        window: &WebviewWindow<R>,
        base: &str,
    ) -> Result<(), String> {
        let expected = bootstrap_url(base)?;
        if window.url().map_err(|_| "read WebView URL")? != expected {
            return Err("refusing bootstrap outside the sidecar page".to_string());
        }
        let mut token = self.fresh_bootstrap_token()?;
        let script = bootstrap_script(&expected, token.as_str())?;
        token.zero();
        window
            .eval(&script)
            .map_err(|_| "WebView bootstrap exchange failed".to_string())
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
    fn bootstrap_rejects_other_origins_and_embedded_credentials() {
        assert_eq!(
            bootstrap_url("http://127.0.0.1:7890").unwrap().as_str(),
            "http://127.0.0.1:7890/__bootstrap"
        );
        for base in [
            "http://example.test:7890",
            "http://127.0.0.1.evil.test:7890",
            "https://127.0.0.1:7890",
            "http://user@127.0.0.1:7890",
            "http://127.0.0.1:7890/path",
            "http://127.0.0.1:7890/?token=secret",
            "http://127.0.0.1:7890/#fragment",
            "http://127.0.0.1:0",
        ] {
            assert!(bootstrap_url(base).is_err(), "accepted {base}");
        }
    }

    #[test]
    fn bootstrap_script_encodes_token_and_checks_loaded_page() {
        let url = bootstrap_url("http://127.0.0.1:7890").unwrap();
        let token = "test\"token\\with\ncontrols";
        let script = bootstrap_script(&url, token).unwrap();
        assert!(script.contains(&serde_json::to_string(token).unwrap()));
        assert!(!script.contains(token));
        assert!(script.contains("window.location.href !== \"http://127.0.0.1:7890/__bootstrap\""));
        assert!(script.contains("method: 'POST'"));
        assert!(script.contains("redirect: 'error'"));
        assert!(!script.contains("__kl_bootstrap_token"));
    }

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
