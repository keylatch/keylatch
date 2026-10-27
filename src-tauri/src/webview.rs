// src/webview.rs — WebView host configuration.
//
// Implements the navigation policy hook that restricts the WebView to
// ONLY navigate to the active HTTP loopback sidecar or bundled assets.
// All other navigations are blocked and audited.
//
// The server CSP is verified separately before the window is created.

use std::sync::Arc;
use url::Url;

/// NavigationPolicy decides whether a navigation should proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigationPolicy {
    Allow,
    Block { reason: &'static str },
}

/// WebViewHost configures navigation policy for the main WebView window.
pub struct WebViewHost {
    active_port: u16,
}

impl WebViewHost {
    /// Create a new WebViewHost for the given sidecar port.
    pub fn new(active_port: u16) -> Self {
        Self { active_port }
    }

    /// Evaluate the navigation policy for a target URL.
    /// Allowed: http://127.0.0.1:<active_port>/* and bundled assets.
    /// Blocked: everything else.
    pub fn evaluate_navigation(&self, url: &str) -> NavigationPolicy {
        // Allow the bundled static error page.
        if url.starts_with("tauri://localhost/error.html") {
            return NavigationPolicy::Allow;
        }

        // Allow tauri:// scheme for asset loading.
        if url.starts_with("tauri://localhost/") {
            return NavigationPolicy::Allow;
        }

        match Url::parse(url) {
            Err(_) => NavigationPolicy::Block {
                reason: "malformed URL",
            },
            Ok(parsed) => {
                if parsed.scheme() == "http"
                    && parsed.host_str() == Some("tauri.localhost")
                    && parsed.path() == "/error.html"
                    && parsed.port().is_none()
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                {
                    return NavigationPolicy::Allow;
                }
                let scheme_ok = parsed.scheme() == "http";
                let host_ok = matches!(parsed.host_str(), Some("127.0.0.1"));
                let port_ok = parsed.port() == Some(self.active_port);
                if scheme_ok
                    && host_ok
                    && port_ok
                    && parsed.username().is_empty()
                    && parsed.password().is_none()
                {
                    NavigationPolicy::Allow
                } else {
                    NavigationPolicy::Block {
                        reason: "navigation target is not localhost sidecar",
                    }
                }
            }
        }
    }
}

/// NavigationGuard is a helper that wraps the WebViewHost policy and logs
/// blocked navigations to the audit log.
pub struct NavigationGuard {
    host: Arc<WebViewHost>,
}

impl NavigationGuard {
    pub fn new(host: Arc<WebViewHost>) -> Self {
        Self { host }
    }

    /// Called for every navigation attempt. Returns true to allow, false to block.
    pub fn on_navigate(&self, url: &str) -> bool {
        match self.host.evaluate_navigation(url) {
            NavigationPolicy::Allow => true,
            NavigationPolicy::Block { reason } => {
                // Audit: log blocked navigation with HMAC'd target host
                // (never the raw URL which might contain session tokens).
                let hmac_of_host = self.hmac_host(url);
                log::warn!(
                    "webview_redirect_blocked: reason={reason} target_host_hmac={hmac_of_host}"
                );
                false
            }
        }
    }

    /// Compute an HMAC-SHA256 label for the host of url.
    /// Only the host is included — not the full URL (which may contain tokens).
    fn hmac_host(&self, url: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        // Use a fixed label key for audit logging — the security value is
        // that credential material is never logged, not that the label is secret.
        let label_key = b"audit-label-key-v1";
        let host = Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "<unknown>".to_string());
        let mut mac = Hmac::<Sha256>::new_from_slice(label_key).unwrap();
        mac.update(host.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(port: u16) -> WebViewHost {
        WebViewHost::new(port)
    }

    #[test]
    fn test_allow_localhost() {
        let h = host(51842);
        assert_eq!(
            h.evaluate_navigation("http://127.0.0.1:51842/"),
            NavigationPolicy::Allow
        );
        assert_eq!(
            h.evaluate_navigation("http://127.0.0.1:51842/approvals/123"),
            NavigationPolicy::Allow
        );
    }

    #[test]
    fn test_block_external() {
        let h = host(51842);
        assert!(matches!(
            h.evaluate_navigation("https://attacker.example/exfil"),
            NavigationPolicy::Block { .. }
        ));
    }

    #[test]
    fn test_block_redirect_to_external() {
        // SC14-17: server-initiated redirect to external host is blocked.
        let h = host(51842);
        assert!(matches!(
            h.evaluate_navigation("https://attacker.example/exfil?token=secret"),
            NavigationPolicy::Block { .. }
        ));
    }

    #[test]
    fn test_allow_error_page() {
        let h = host(51842);
        assert_eq!(
            h.evaluate_navigation("tauri://localhost/error.html"),
            NavigationPolicy::Allow
        );
    }

    #[test]
    fn test_block_wrong_port() {
        let h = host(51842);
        assert!(matches!(
            h.evaluate_navigation("http://127.0.0.1:9999/"),
            NavigationPolicy::Block { .. }
        ));
    }

    #[test]
    fn test_block_wrong_scheme_and_embedded_credentials() {
        let h = host(51842);
        for url in [
            "https://127.0.0.1:51842/",
            "http://user@127.0.0.1:51842/",
            "http://127.0.0.1.evil.test:51842/",
        ] {
            assert!(matches!(
                h.evaluate_navigation(url),
                NavigationPolicy::Block { .. }
            ));
        }
    }
}

// Required for HMAC in NavigationGuard.
use hex;
use hmac;
use sha2;
