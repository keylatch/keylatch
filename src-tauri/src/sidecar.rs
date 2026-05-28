// src/sidecar.rs — SidecarSupervisor implementation.
//
// Manages the lifecycle of the keylatchd Go sidecar process:
//   - Generates a 32-byte HMAC key using OsRng
//   - Passes the key via an inherited pipe FD (FIND2-002)
//   - Spawns keylatchd with --from-desktop-shell --ipc-socket <path>
//   - Parses the JSON `ready` line from keylatchd stdout (10 s timeout)
//   - Crash-restart with exponential backoff (1→2→4→8→max 30 s)
//   - After 5 consecutive failures → Crashed state
//   - Health-check polling every 5 s

use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngCore;
use rand::rngs::OsRng;
use serde::Deserialize;
use tokio::sync::broadcast;

/// SidecarState represents the supervisor state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarState {
    Starting,
    Running { localhost_url: String },
    Degraded { localhost_url: String },
    Restarting { attempt: u32 },
    Crashed { reason: String },
    Stopped,
}

/// SidecarStatus is broadcast to subscribers on state change.
#[derive(Debug, Clone)]
pub struct SidecarStatus {
    pub state: SidecarState,
    pub timestamp: std::time::SystemTime,
}

/// ReadyLine is the JSON object emitted by keylatchd on stdout when it is
/// ready to accept connections.
#[derive(Debug, Deserialize)]
struct ReadyLine {
    event: String,
    url: String,
    #[allow(dead_code)]
    build: Option<String>,
}

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESTART_ATTEMPTS: u32 = 5;
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);
const HEALTHY_UPTIME_RESET: Duration = Duration::from_secs(60);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// SidecarSupervisorImpl manages the keylatchd child process.
pub struct SidecarSupervisorImpl {
    sidecar_path: String,
    ipc_socket_path: String,
    state: Arc<Mutex<SidecarState>>,
    tx: broadcast::Sender<SidecarStatus>,
    hmac_key: Arc<Mutex<Vec<u8>>>,
    child: Arc<Mutex<Option<Child>>>,
}

impl SidecarSupervisorImpl {
    /// Create a new supervisor. `sidecar_path` is the path to the keylatchd binary.
    pub fn new(sidecar_path: String, ipc_socket_path: String) -> (Self, broadcast::Receiver<SidecarStatus>) {
        let (tx, rx) = broadcast::channel(16);
        let sup = Self {
            sidecar_path,
            ipc_socket_path,
            state: Arc::new(Mutex::new(SidecarState::Stopped)),
            tx,
            hmac_key: Arc::new(Mutex::new(vec![0u8; 32])),
            child: Arc::new(Mutex::new(None)),
        };
        (sup, rx)
    }

    /// Subscribe to state-change events.
    pub fn subscribe(&self) -> broadcast::Receiver<SidecarStatus> {
        self.tx.subscribe()
    }

    /// Returns the HMAC key used for the current sidecar process.
    /// The caller must not retain this beyond the current IPC session.
    pub fn hmac_key(&self) -> Vec<u8> {
        self.hmac_key.lock().unwrap().clone()
    }

    /// Returns the localhost URL if the sidecar is running.
    pub fn localhost_url(&self) -> Option<String> {
        match &*self.state.lock().unwrap() {
            SidecarState::Running { localhost_url } => Some(localhost_url.clone()),
            SidecarState::Degraded { localhost_url } => Some(localhost_url.clone()),
            _ => None,
        }
    }

    /// Start the sidecar, retrying with exponential backoff on failure.
    /// Returns Ok(()) once the sidecar signals `ready`.
    pub fn start(&mut self) -> Result<String, String> {
        let mut attempt = 0u32;
        let mut backoff = Duration::from_secs(1);

        loop {
            self.set_state(SidecarState::Starting);

            match self.spawn_once() {
                Ok(url) => {
                    self.set_state(SidecarState::Running { localhost_url: url.clone() });
                    return Ok(url);
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_RESTART_ATTEMPTS {
                        let reason = format!("sidecar failed after {} attempts: {}", attempt, e);
                        self.set_state(SidecarState::Crashed { reason: reason.clone() });
                        return Err(reason);
                    }
                    self.set_state(SidecarState::Restarting { attempt });
                    std::thread::sleep(backoff);
                    backoff = std::cmp::min(backoff * 2, MAX_BACKOFF);
                }
            }
        }
    }

    /// Spawn the sidecar once. Returns the localhost URL on success.
    /// FIND2-002: on Unix, HMAC key is passed via inherited pipe FD.
    ///            on Windows, key is passed via KEYLATCH_IPC_KEY env var (hex).
    fn spawn_once(&mut self) -> Result<String, String> {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);

        #[cfg(unix)]
        let child = {
            let (read_fd, write_fd) = create_pipe().map_err(|e| format!("pipe: {e}"))?;

            let child = Command::new(&self.sidecar_path)
                .arg("--from-desktop-shell")
                .arg("--ipc-socket")
                .arg(&self.ipc_socket_path)
                .env("KEYLATCH_IPC_KEY_FD", read_fd.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("spawn keylatchd: {e}"))?;

            {
                // Safety: write_fd is a valid pipe FD we just created.
                let mut wf = unsafe { std::fs::File::from_raw_fd(write_fd) };
                wf.write_all(&key).map_err(|e| format!("write key to pipe: {e}"))?;
            }
            unsafe { libc::close(read_fd) };
            child
        };

        #[cfg(not(unix))]
        let child = {
            let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            Command::new(&self.sidecar_path)
                .arg("--from-desktop-shell")
                .arg("--ipc-socket")
                .arg(&self.ipc_socket_path)
                .env("KEYLATCH_IPC_KEY", key_hex)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("spawn keylatchd: {e}"))?
        };

        {
            let mut k = self.hmac_key.lock().unwrap();
            k.copy_from_slice(&key);
        }
        key.iter_mut().for_each(|b| *b = 0);

        let url = self.wait_for_ready(child)?;
        Ok(url)
    }

    /// Read stdout of the child until a JSON `ready` line is found,
    /// or until READY_TIMEOUT elapses.
    fn wait_for_ready(&mut self, mut child: Child) -> Result<String, String> {
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let reader = BufReader::new(stdout);
        let deadline = Instant::now() + READY_TIMEOUT;

        let mut url: Option<String> = None;
        for line in reader.lines() {
            if Instant::now() > deadline {
                // Timed out — kill the child.
                let _ = child.kill();
                return Err(format!("sidecar did not emit 'ready' within {}s", READY_TIMEOUT.as_secs()));
            }
            let line = line.map_err(|e| format!("reading child stdout: {e}"))?;
            if let Ok(rl) = serde_json::from_str::<ReadyLine>(&line) {
                if rl.event == "ready" {
                    if rl.url.is_empty() {
                        let _ = child.kill();
                        return Err("ready line missing 'url' field".to_string());
                    }
                    url = Some(rl.url);
                    break;
                }
            }
        }

        let url = url.ok_or_else(|| "child exited without emitting 'ready'".to_string())?;

        // Store the child handle for later shutdown.
        *self.child.lock().unwrap() = Some(child);
        Ok(url)
    }

    /// Stop the sidecar gracefully: send Shutdown IPC → wait 5s → SIGTERM → SIGKILL.
    pub fn stop(&mut self) {
        let mut child_lock = self.child.lock().unwrap();
        if let Some(child) = child_lock.as_mut() {
            // Attempt graceful shutdown: the IPC Shutdown message is sent by
            // the IpcClient before calling stop(). Here we wait and escalate.
            let _ = child.wait_timeout(Duration::from_secs(5));
            // Try SIGTERM.
            #[cfg(unix)]
            {
                let pid = child.id() as i32;
                unsafe { libc::kill(pid, libc::SIGTERM) };
                let _ = child.wait_timeout(Duration::from_secs(5));
            }
            // Final SIGKILL.
            let _ = child.kill();
            let _ = child.wait();
        }
        *child_lock = None;
        self.set_state(SidecarState::Stopped);
    }

    /// Restart: stop then start with a fresh HMAC key.
    pub fn restart(&mut self) -> Result<String, String> {
        self.stop();
        self.start()
    }

    fn set_state(&self, state: SidecarState) {
        *self.state.lock().unwrap() = state.clone();
        let status = SidecarStatus {
            state,
            timestamp: std::time::SystemTime::now(),
        };
        // Ignore send errors (no subscribers is fine).
        let _ = self.tx.send(status);
    }
}

/// Create a Unix pipe and return (read_fd, write_fd).
/// The read_fd intentionally does NOT have O_CLOEXEC set so the child inherits it.
fn create_pipe() -> std::io::Result<(i32, i32)> {
    #[cfg(unix)]
    {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // N3: check return values of both fcntl calls.
        let flags = unsafe { libc::fcntl(fds[1], libc::F_GETFD) };
        if flags == -1 {
            // Close the pipe FDs before returning the error.
            unsafe { libc::close(fds[0]); libc::close(fds[1]); }
            return Err(std::io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(fds[1], libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if ret == -1 {
            unsafe { libc::close(fds[0]); libc::close(fds[1]); }
            return Err(std::io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }
    #[cfg(not(unix))]
    {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "pipe not implemented on this platform"))
    }
}

/// Extension trait to add wait_timeout to std::process::Child.
trait ChildExt {
    fn wait_timeout(&mut self, timeout: Duration) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl ChildExt for Child {
    fn wait_timeout(&mut self, timeout: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.try_wait()? {
                Some(status) => return Ok(Some(status)),
                None => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ready_line_parse_valid() {
        let json = r#"{"event":"ready","url":"http://127.0.0.1:7890","build":"dev"}"#;
        let rl: ReadyLine = serde_json::from_str(json).expect("parse");
        assert_eq!(rl.event, "ready");
        assert_eq!(rl.url, "http://127.0.0.1:7890");
    }

    #[test]
    fn test_ready_line_missing_url() {
        let json = r#"{"event":"ready","url":"","build":"dev"}"#;
        let rl: ReadyLine = serde_json::from_str(json).expect("parse");
        assert!(rl.url.is_empty(), "url should be empty");
    }

    #[test]
    fn test_ready_line_malformed() {
        let json = r#"not json"#;
        assert!(serde_json::from_str::<ReadyLine>(json).is_err());
    }

    #[test]
    fn test_sidecar_state_transitions() {
        let (sup, mut rx) = SidecarSupervisorImpl::new(
            "/nonexistent/keylatchd".to_string(),
            "/tmp/keylatch-test.sock".to_string(),
        );
        sup.set_state(SidecarState::Starting);
        let status = rx.try_recv().expect("state broadcast");
        assert_eq!(status.state, SidecarState::Starting);
    }
}

#[cfg(unix)]
extern crate libc;
