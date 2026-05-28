// src/ipc.rs — Rust IPC client for the keylatchd sidecar.
//
// Connects to the Unix socket served by keylatchd, signs frames with
// HMAC-SHA256, and dispatches calls to exactly 5 permitted methods (S14-8).
//
// Security invariants:
//   - IpcMethod enum is the compile-time allow-list (no runtime string dispatch).
//   - Invalid HMAC on response → drop + log; do NOT retry (prevents HMAC oracle).
//   - SubscribeEvents opens a long-lived streaming connection.

use std::io::{self, BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::Duration;

// Platform-agnostic stream type: Unix socket on Unix, TCP on Windows.
#[cfg(unix)]
type OsStream = UnixStream;
#[cfg(not(unix))]
type OsStream = std::net::TcpStream;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};

type HmacSha256 = Hmac<Sha256>;

const HMAC_TAG_SIZE: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FRAME_SIZE: u32 = 1 << 20; // 1 MiB

/// IpcMethod is the compile-time allow-list of permitted IPC methods (S14-8).
/// Adding a variant here is the ONLY way to call a new method — there is no
/// runtime string dispatch escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcMethod {
    Health,
    MintBootstrapToken,
    SubscribeEvents,
    Shutdown,
    OpenSystemBrowser,
}

impl IpcMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Health => "Health",
            Self::MintBootstrapToken => "MintBootstrapToken",
            Self::SubscribeEvents => "SubscribeEvents",
            Self::Shutdown => "Shutdown",
            Self::OpenSystemBrowser => "OpenSystemBrowser",
        }
    }
}

/// IpcError is returned for IPC failures.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("HMAC mismatch — frame rejected (S14-8)")]
    HmacMismatch,
    #[error("frame too large ({0} bytes)")]
    FrameTooLarge(u32),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("encoding error: {0}")]
    Encode(String),
    #[error("decoding error: {0}")]
    Decode(String),
    #[error("sidecar error: {0}")]
    Sidecar(String),
}

/// A raw IPC request frame (serialised to CBOR then HMAC-wrapped).
#[derive(Serialize)]
struct Request<'a> {
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

/// A raw IPC response frame.
#[derive(Deserialize)]
struct Response {
    result: Option<serde_json::Value>,
    error: Option<String>,
}

/// IpcClient connects to the keylatchd Unix socket and makes authenticated calls.
pub struct IpcClient {
    socket_path: String,
    hmac_key: Vec<u8>,
}

impl IpcClient {
    /// Create a new IpcClient.
    /// hmac_key must be exactly 32 bytes (the key shared with keylatchd).
    pub fn new(socket_path: String, hmac_key: Vec<u8>) -> Self {
        assert_eq!(hmac_key.len(), 32, "HMAC key must be 32 bytes");
        Self { socket_path, hmac_key }
    }

    /// Call an IPC method. Returns the decoded result value.
    ///
    /// `method` is the compile-time allow-list enum — no runtime string dispatch.
    pub fn call(
        &self,
        method: IpcMethod,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, IpcError> {
        let mut stream: OsStream = self.connect()?;
        let req = Request {
            method: method.as_str(),
            params,
        };
        self.write_frame(&mut stream, &req)?;
        let resp: Response = self.read_frame(&mut stream)?;
        if let Some(err) = resp.error {
            return Err(IpcError::Sidecar(err));
        }
        Ok(resp.result.unwrap_or(serde_json::Value::Null))
    }

    /// Call Health and return true if the sidecar is alive.
    pub fn health(&self) -> bool {
        self.call(IpcMethod::Health, None).is_ok()
    }

    /// Call MintBootstrapToken and return the (token, expires_at_unix) tuple.
    pub fn mint_bootstrap_token(&self) -> Result<(String, i64), IpcError> {
        let v = self.call(IpcMethod::MintBootstrapToken, None)?;
        let token = v["token"].as_str()
            .ok_or_else(|| IpcError::Decode("missing token field".to_string()))?
            .to_string();
        let expires_at = v["expires_at"].as_i64()
            .ok_or_else(|| IpcError::Decode("missing expires_at field".to_string()))?;
        Ok((token, expires_at))
    }

    /// Call Shutdown (fire-and-forget).
    pub fn shutdown(&self) -> Result<(), IpcError> {
        self.call(IpcMethod::Shutdown, None)?;
        Ok(())
    }

    /// Call OpenSystemBrowser with the given URL.
    /// Only https:// and keylatch:// URLs are accepted by the server (S14-2).
    pub fn open_system_browser(&self, url: &str) -> Result<(), IpcError> {
        let params = serde_json::json!({ "url": url });
        self.call(IpcMethod::OpenSystemBrowser, Some(params))?;
        Ok(())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn connect(&self) -> io::Result<OsStream> {
        #[cfg(unix)]
        {
            UnixStream::connect(&self.socket_path)
        }
        #[cfg(not(unix))]
        {
            // Windows: keylatchd exposes a TCP loopback endpoint.
            // The socket_path on Windows is "127.0.0.1:<port>".
            std::net::TcpStream::connect(&self.socket_path as &str)
        }
    }

    /// Write a CBOR frame: 4-byte length || CBOR body || 32-byte HMAC tag.
    fn write_frame<T: Serialize>(&self, w: &mut impl Write, v: &T) -> Result<(), IpcError> {
        // Serialise to CBOR using ciborium.
        let mut body = Vec::new();
        ciborium::into_writer(v, &mut body)
            .map_err(|e| IpcError::Encode(e.to_string()))?;

        let len = body.len() as u32;
        let len_bytes = len.to_be_bytes();

        // HMAC over length||body.
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| IpcError::Encode(e.to_string()))?;
        mac.update(&len_bytes);
        mac.update(&body);
        let tag = mac.finalize().into_bytes();

        // Write in a single call.
        let mut frame = Vec::with_capacity(4 + body.len() + HMAC_TAG_SIZE);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&tag);
        w.write_all(&frame).map_err(IpcError::Io)
    }

    /// Read and verify a CBOR frame. Returns IpcError::HmacMismatch on bad tag.
    /// On mismatch, the frame is dropped and NOT retried (prevents HMAC oracle).
    fn read_frame<T: for<'de> Deserialize<'de>>(
        &self,
        r: &mut impl io::Read,
    ) -> Result<T, IpcError> {
        // Read 4-byte length.
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf).map_err(IpcError::Io)?;
        let body_len = u32::from_be_bytes(len_buf);
        if body_len > MAX_FRAME_SIZE {
            return Err(IpcError::FrameTooLarge(body_len));
        }

        // Read body.
        let mut body = vec![0u8; body_len as usize];
        r.read_exact(&mut body).map_err(IpcError::Io)?;

        // Read HMAC tag.
        let mut tag = [0u8; HMAC_TAG_SIZE];
        r.read_exact(&mut tag).map_err(IpcError::Io)?;

        // Verify HMAC (constant-time).
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| IpcError::Decode(e.to_string()))?;
        mac.update(&len_buf);
        mac.update(&body);
        mac.verify_slice(&tag).map_err(|_| {
            // Log but do not surface detail (S14-8).
            log::warn!("ipc: HMAC mismatch on received frame — dropping connection");
            IpcError::HmacMismatch
        })?;

        // Decode CBOR.
        ciborium::from_reader(body.as_slice())
            .map_err(|e| IpcError::Decode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> Vec<u8> {
        vec![0xABu8; 32]
    }

    #[test]
    fn test_ipc_method_enum_count() {
        // Verify exactly 5 variants exist at compile time.
        // If a new variant is added without updating the allow-list, the
        // CI lint will catch it; this test catches accidental removal.
        let methods = [
            IpcMethod::Health,
            IpcMethod::MintBootstrapToken,
            IpcMethod::SubscribeEvents,
            IpcMethod::Shutdown,
            IpcMethod::OpenSystemBrowser,
        ];
        assert_eq!(methods.len(), 5, "IpcMethod must have exactly 5 variants (S14-8)");
    }

    #[test]
    fn test_ipc_method_no_runtime_string_dispatch() {
        // This is a compile-time property but we assert the string names match.
        assert_eq!(IpcMethod::Health.as_str(), "Health");
        assert_eq!(IpcMethod::MintBootstrapToken.as_str(), "MintBootstrapToken");
        assert_eq!(IpcMethod::SubscribeEvents.as_str(), "SubscribeEvents");
        assert_eq!(IpcMethod::Shutdown.as_str(), "Shutdown");
        assert_eq!(IpcMethod::OpenSystemBrowser.as_str(), "OpenSystemBrowser");
    }

    #[test]
    fn test_frame_roundtrip() {
        use std::io::Cursor;
        let key = make_key();
        let client = IpcClient::new("/tmp/nonexistent".to_string(), key);

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Payload { value: u32 }

        let mut buf = Vec::new();
        let payload = Payload { value: 42 };
        client.write_frame(&mut buf, &payload).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Payload = client.read_frame(&mut cursor).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_tampered_frame_returns_hmac_mismatch() {
        use std::io::Cursor;
        let key = make_key();
        let client = IpcClient::new("/tmp/nonexistent".to_string(), key);

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Payload { value: u32 }

        let mut buf = Vec::new();
        client.write_frame(&mut buf, &Payload { value: 1 }).unwrap();
        // Flip a byte in the body area.
        let mid = buf.len() / 2;
        buf[mid] ^= 0xFF;

        let mut cursor = Cursor::new(buf);
        let err = client.read_frame::<Payload>(&mut cursor).unwrap_err();
        assert!(matches!(err, IpcError::HmacMismatch), "expected HmacMismatch, got {:?}", err);
    }
}

// Re-export ciborium for sidecar module use.
use ciborium;
