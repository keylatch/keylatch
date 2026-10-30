// src/sidecar.rs — SidecarSupervisor implementation.
//
// Manages the lifecycle of the keylatchd Go sidecar process:
//   - Generates a 32-byte HMAC key using OsRng
//   - Passes the key via an inherited pipe FD
//   - Spawns keylatchd with --from-desktop-shell --ipc-socket <path>
//   - Parses a bounded JSON `ready` line from keylatchd stdout (15 s timeout)
//   - Crash-restart with exponential backoff (1→2→4→8→max 30 s)
//   - After 5 consecutive failures → Crashed state
//   - Health-check polling every 5 s

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
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
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// SidecarSupervisorImpl manages the keylatchd child process.
pub struct SidecarSupervisorImpl {
    sidecar_path: String,
    ipc_socket_path: String,
    state: Arc<Mutex<SidecarState>>,
    tx: broadcast::Sender<SidecarStatus>,
    hmac_key: Arc<Mutex<Vec<u8>>>,
    child: Arc<Mutex<Option<Child>>>,
    #[cfg(test)]
    test_config_dir: Option<std::path::PathBuf>,
}

impl SidecarSupervisorImpl {
    /// Create a new supervisor. `sidecar_path` is the path to the keylatchd binary.
    pub fn new(
        sidecar_path: String,
        ipc_socket_path: String,
    ) -> (Self, broadcast::Receiver<SidecarStatus>) {
        let (tx, rx) = broadcast::channel(16);
        let sup = Self {
            sidecar_path,
            ipc_socket_path,
            state: Arc::new(Mutex::new(SidecarState::Stopped)),
            tx,
            hmac_key: Arc::new(Mutex::new(vec![0u8; 32])),
            child: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            test_config_dir: None,
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

    pub fn ipc_client(&self) -> crate::ipc::IpcClient {
        crate::ipc::IpcClient::new(self.ipc_socket_path.clone(), self.hmac_key())
    }

    pub fn healthy(&self) -> bool {
        let alive = self
            .child
            .lock()
            .unwrap()
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)));
        alive && self.ipc_client().health()
    }

    pub fn start_once(&mut self) -> Result<String, String> {
        self.set_state(SidecarState::Starting);
        let url = self.spawn_once()?;
        self.set_state(SidecarState::Running {
            localhost_url: url.clone(),
        });
        Ok(url)
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
                    self.set_state(SidecarState::Running {
                        localhost_url: url.clone(),
                    });
                    return Ok(url);
                }
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_RESTART_ATTEMPTS {
                        let reason = format!("sidecar failed after {} attempts: {}", attempt, e);
                        self.set_state(SidecarState::Crashed {
                            reason: reason.clone(),
                        });
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
    /// On Unix, the HMAC key is passed via an inherited pipe FD.
    /// On Windows, the key is written to the child's inherited stdin pipe.
    fn spawn_once(&mut self) -> Result<String, String> {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);

        let spawned = (|| -> Result<Child, String> {
            #[cfg(unix)]
            {
                let (read_fd, write_fd) = create_pipe().map_err(|e| format!("pipe: {e}"))?;
                let read_pipe = unsafe { std::fs::File::from_raw_fd(read_fd) };
                let mut write_pipe = unsafe { std::fs::File::from_raw_fd(write_fd) };

                let mut child = self
                    .command()
                    .env("KEYLATCH_IPC_KEY_FD", read_pipe.as_raw_fd().to_string())
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .map_err(|e| format!("spawn keylatchd: {e}"))?;

                drop(read_pipe);
                if let Err(error) = write_pipe.write_all(&key) {
                    kill_and_reap(&mut child);
                    return Err(format!("write IPC key pipe: {error}"));
                }
                Ok(child)
            }

            #[cfg(windows)]
            {
                let mut child = self
                    .command()
                    .env_remove("KEYLATCH_IPC_KEY")
                    .env_remove("KEYLATCH_IPC_KEY_FD")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .map_err(|e| format!("spawn keylatchd: {e}"))?;
                let Some(mut input) = child.stdin.take() else {
                    kill_and_reap(&mut child);
                    return Err("missing IPC key pipe".into());
                };
                if let Err(e) = input.write_all(&key) {
                    kill_and_reap(&mut child);
                    return Err(format!("write IPC key pipe: {e}"));
                }
                drop(input);
                Ok(child)
            }
        })();

        if spawned.is_ok() {
            let mut k = self.hmac_key.lock().unwrap();
            k.copy_from_slice(&key);
        }
        key.iter_mut().for_each(|b| *b = 0);

        let child = spawned?;
        let url = self.wait_for_ready(child)?;
        Ok(url)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.sidecar_path);
        command
            .arg("--from-desktop-shell")
            .arg("--ipc-socket")
            .arg(&self.ipc_socket_path)
            .args(["--port", "0"]);
        #[cfg(test)]
        if let Some(directory) = &self.test_config_dir {
            command.env("KEYLATCH_CONFIG_DIR", directory);
        }
        command
    }

    /// Read stdout of the child until a JSON `ready` line is found,
    /// or until READY_TIMEOUT elapses.
    fn wait_for_ready(&mut self, mut child: Child) -> Result<String, String> {
        let result = await_ready(&mut child, READY_TIMEOUT);
        match result {
            Ok(url) => {
                *self.child.lock().unwrap() = Some(child);
                Ok(url)
            }
            Err(error) => {
                self.hmac_key.lock().unwrap().fill(0);
                Err(error)
            }
        }
    }

    /// Stop the sidecar gracefully: send Shutdown IPC → wait 5s → SIGTERM → SIGKILL.
    pub fn stop(&mut self) {
        let child = self.child.lock().unwrap().take();
        if let Some(mut child) = child {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let ipc = crate::ipc::IpcClient::new(self.ipc_socket_path.clone(), self.hmac_key());
                let _ = ipc.shutdown();
                stop_child(&mut child, Duration::from_secs(5));
            }
        }
        self.hmac_key.lock().unwrap().fill(0);
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

impl Drop for SidecarSupervisorImpl {
    fn drop(&mut self) {
        self.stop();
    }
}

fn kill_and_reap(child: &mut Child) {
    if !matches!(child.try_wait(), Ok(Some(_))) {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn await_ready(child: &mut Child, timeout: Duration) -> Result<String, String> {
    let result = child
        .stdout
        .take()
        .ok_or_else(|| "missing sidecar stdout".to_string())
        .and_then(|mut stdout| read_ready(&mut stdout, timeout));
    if result.is_err() {
        kill_and_reap(child);
    }
    result
}

fn stop_child(child: &mut Child, grace: Duration) {
    if matches!(child.wait_timeout(grace), Ok(Some(_))) {
        return;
    }
    #[cfg(unix)]
    {
        // An unreaped child retains its PID until this owner observes its exit.
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        if matches!(child.wait_timeout(grace), Ok(Some(_))) {
            return;
        }
    }
    kill_and_reap(child);
}

fn read_ready(stdout: &mut ChildStdout, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let mut line = Vec::new();
    let mut total = 0usize;
    let mut buffer = [0u8; 4096];
    while Instant::now() < deadline {
        let size = match read_available(stdout, &mut buffer) {
            Ok(Some(0)) => return Err("child exited without emitting 'ready'".into()),
            Ok(Some(size)) => size,
            Ok(None) => continue,
            Err(error) => return Err(format!("reading sidecar stdout: {error}")),
        };
        total += size;
        if total > 65_536 {
            return Err("sidecar startup output exceeded limit".into());
        }
        for byte in &buffer[..size] {
            if *byte == b'\n' {
                if let Ok(ready) = serde_json::from_slice::<ReadyLine>(&line) {
                    if ready.event == "ready" {
                        crate::session::bootstrap_url(&ready.url)?;
                        return Ok(ready.url);
                    }
                }
                line.clear();
            } else {
                line.push(*byte);
            }
        }
    }
    Err("sidecar readiness timed out".into())
}

#[cfg(unix)]
fn read_available(stdout: &mut ChildStdout, buffer: &mut [u8]) -> std::io::Result<Option<usize>> {
    let mut fd = libc::pollfd {
        fd: stdout.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut fd, 1, 10) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::Interrupted {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if result == 0 {
        return Ok(None);
    }
    stdout.read(buffer).map(Some)
}

#[cfg(windows)]
fn read_available(stdout: &mut ChildStdout, buffer: &mut [u8]) -> std::io::Result<Option<usize>> {
    use std::os::windows::io::AsRawHandle;
    let mut available = 0u32;
    let result = unsafe {
        windows_sys::Win32::System::Pipes::PeekNamedPipe(
            stdout.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::BrokenPipe {
            Ok(Some(0))
        } else {
            Err(error)
        };
    }
    if available == 0 {
        std::thread::sleep(Duration::from_millis(10));
        return Ok(None);
    }
    let size = buffer.len().min(available as usize);
    stdout.read(&mut buffer[..size]).map(Some)
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
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(std::io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(fds[1], libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if ret == -1 {
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(std::io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }
    #[cfg(not(unix))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "pipe not implemented on this platform",
        ))
    }
}

/// Extension trait to add wait_timeout to std::process::Child.
trait ChildExt {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl ChildExt for Child {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
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
    fn lifecycle_fixture() {
        let Ok(mode) = std::env::var("KEYLATCH_TEST_SIDECAR_MODE") else {
            return;
        };
        match mode.as_str() {
            "ready" => println!("\n{{\"event\":\"ready\",\"url\":\"http://127.0.0.1:7890\"}}"),
            "invalid" => println!("\n{{\"event\":\"ready\",\"url\":\"http://example.test:7890\"}}"),
            "oversized" => println!("{}", "x".repeat(65_537)),
            "partial" => {
                print!("\n{{\"event\":\"ready\"");
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(60));
            }
            "silent" => std::thread::sleep(Duration::from_secs(60)),
            "eof" => (),
            _ => panic!("unknown fixture mode"),
        }
    }

    fn fixture(mode: &str) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sidecar::tests::lifecycle_fixture",
                "--nocapture",
            ])
            .env("KEYLATCH_TEST_SIDECAR_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn silent_and_partial_startup_obey_deadline() {
        for mode in ["silent", "partial"] {
            let mut child = fixture(mode);
            let started = Instant::now();
            let result = await_ready(&mut child, Duration::from_millis(150));
            let elapsed = started.elapsed();
            assert_eq!(result.unwrap_err(), "sidecar readiness timed out");
            assert!(
                elapsed < Duration::from_secs(2),
                "startup read blocked: {elapsed:?}"
            );
            assert!(child.try_wait().unwrap().is_some());
        }
    }

    #[test]
    fn startup_accepts_only_bounded_loopback_ready_output() {
        for (mode, expected) in [
            ("ready", None),
            (
                "invalid",
                Some("sidecar URL must be its exact HTTP loopback origin"),
            ),
            ("oversized", Some("sidecar startup output exceeded limit")),
            ("eof", Some("child exited without emitting 'ready'")),
        ] {
            let mut child = fixture(mode);
            let result = read_ready(child.stdout.as_mut().unwrap(), Duration::from_secs(5));
            kill_and_reap(&mut child);
            if let Some(expected) = expected {
                assert_eq!(result.unwrap_err(), expected);
            } else {
                assert_eq!(result.unwrap(), "http://127.0.0.1:7890");
            }
        }
    }

    #[test]
    fn shutdown_reaps_live_child_and_preserves_observed_exit() {
        let mut live = fixture("silent");
        stop_child(&mut live, Duration::from_millis(10));
        assert!(live.try_wait().unwrap().is_some());
        let mut exited = fixture("eof");
        let status = exited.wait().unwrap();
        let started = Instant::now();
        stop_child(&mut exited, Duration::from_secs(5));
        assert_eq!(exited.try_wait().unwrap(), Some(status));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

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

    #[test]
    #[ignore = "requires the real Go sidecar produced by the native CI build"]
    fn bundled_go_sidecar_bootstraps_and_rejects_old_ipc_after_restart() {
        let test_binary = std::env::current_exe().unwrap();
        let release_dir = test_binary.parent().unwrap().parent().unwrap();
        let binary = crate::bundled::sidecar(&release_dir.join("keylatch-app")).unwrap();
        #[cfg(unix)]
        let root = tempfile::Builder::new()
            .prefix("kl-")
            .tempdir_in("/tmp")
            .unwrap();
        #[cfg(windows)]
        let root = tempfile::Builder::new().prefix("kl-").tempdir().unwrap();
        let socket = root.path().join("i.sock");
        let (mut supervisor, _) = SidecarSupervisorImpl::new(
            binary.to_str().unwrap().to_string(),
            socket.to_str().unwrap().to_string(),
        );
        supervisor.test_config_dir = Some(root.path().join("config"));
        let base = supervisor.start().unwrap();
        crate::csp::verify_sidecar(&base).unwrap();
        let old_key = supervisor.hmac_key();
        let ipc = crate::ipc::IpcClient::new(socket.to_str().unwrap().into(), old_key.clone());
        assert!(ipc.health());
        let (token, _) = ipc.mint_bootstrap_token().unwrap();
        let client = crate::desktop_http::DesktopHttp::connect(&base, &token).unwrap();
        assert!(crate::desktop_http::DesktopHttp::connect(&base, &token).is_err());
        drop(client);
        assert!(supervisor.healthy());
        {
            let mut child = supervisor.child.lock().unwrap();
            kill_and_reap(child.as_mut().unwrap());
        }
        assert!(!supervisor.healthy());
        supervisor.stop();
        let new_base = supervisor.start_once().unwrap();
        assert!(supervisor.healthy());
        assert_ne!(supervisor.hmac_key(), old_key);
        assert!(!ipc.health());
        crate::csp::verify_sidecar(&new_base).unwrap();
        let new_ipc =
            crate::ipc::IpcClient::new(socket.to_str().unwrap().into(), supervisor.hmac_key());
        assert!(new_ipc.health());
        let (token, _) = new_ipc.mint_bootstrap_token().unwrap();
        crate::desktop_http::DesktopHttp::connect(&new_base, &token).unwrap();
        supervisor.stop();
        assert!(supervisor.child.lock().unwrap().is_none());
        assert!(supervisor.hmac_key().iter().all(|byte| *byte == 0));
        assert!(!new_ipc.health());
    }
}

#[cfg(unix)]
extern crate libc;
