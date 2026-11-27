use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, Runtime};

use crate::{
    approval_watcher,
    notify::NotifierImpl,
    session::DesktopSession,
    sidecar::SidecarSupervisorImpl,
    tray::{TrayController, TrayIconState},
    webview::WebViewHost,
};

pub struct Connection {
    pub base: String,
    pub session: Arc<DesktopSession>,
}

pub type ActiveConnection = Arc<Mutex<Option<Arc<Connection>>>>;

pub struct DesktopRuntime {
    stopped: Arc<AtomicBool>,
    wake: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl DesktopRuntime {
    pub fn stop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.wake.send(());
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                log::error!("desktop supervisor stopped unexpectedly");
            }
        }
    }
}

impl Drop for DesktopRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Default)]
struct RecoveryBudget {
    attempts: u32,
    healthy_since: Option<Instant>,
}

impl RecoveryBudget {
    fn healthy(&mut self, now: Instant) {
        let since = *self.healthy_since.get_or_insert(now);
        if now.duration_since(since) >= Duration::from_secs(60) {
            self.attempts = 0;
        }
    }

    fn next_delay(&mut self) -> Option<Duration> {
        self.healthy_since = None;
        if self.attempts >= 5 {
            return None;
        }
        let delay = Duration::from_secs(1 << self.attempts);
        self.attempts += 1;
        Some(delay)
    }
}

pub fn start<R: Runtime + 'static>(
    app: AppHandle<R>,
    mut supervisor: SidecarSupervisorImpl,
    active: ActiveConnection,
    host: Arc<WebViewHost>,
    tray: Option<Arc<TrayController<R>>>,
    notifier: Arc<NotifierImpl<R>>,
) -> Result<DesktopRuntime, std::io::Error> {
    let stopped = Arc::new(AtomicBool::new(false));
    let stopping = stopped.clone();
    let (wake, receiver) = mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("desktop-supervisor".into())
        .spawn(move || {
            let mut watcher = None;
            let mut budget = RecoveryBudget::default();
            let mut failures = 0;
            loop {
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                let current = active.lock().unwrap().clone();
                if let Some(connection) = current {
                    if supervisor.healthy() {
                        failures = 0;
                        budget.healthy(Instant::now());
                        if watcher.is_none() {
                            match approval_watcher::start(
                                app.clone(),
                                connection.base.clone(),
                                connection.session.clone(),
                                tray.clone(),
                                notifier.clone(),
                            ) {
                                Ok(started) => watcher = Some(started),
                                Err(_) => {
                                    log::error!("could not start approval watcher");
                                    break;
                                }
                            }
                        }
                        if receiver.recv_timeout(Duration::from_secs(5))
                            != Err(mpsc::RecvTimeoutError::Timeout)
                        {
                            break;
                        }
                        continue;
                    }
                    budget.healthy_since = None;
                    failures += 1;
                    if failures < 3 {
                        if receiver.recv_timeout(Duration::from_secs(5))
                            != Err(mpsc::RecvTimeoutError::Timeout)
                        {
                            break;
                        }
                        continue;
                    }
                }

                // Revoke callbacks and the old origin before starting another process.
                if let Some(mut old) = watcher.take() {
                    old.stop();
                }
                *active.lock().unwrap() = None;
                host.set_port(0);
                let error_app = app.clone();
                let error_active = active.clone();
                let error_stopping = stopping.clone();
                let error_tray = tray.clone();
                let _ = app.run_on_main_thread(move || {
                    if error_stopping.load(Ordering::Acquire)
                        || error_active.lock().unwrap().is_some()
                    {
                        return;
                    }
                    if let Some(tray) = error_tray {
                        tray.set_state(TrayIconState::IconError);
                    }
                    if let Some(window) = error_app.get_webview_window("main") {
                        let target = if cfg!(windows) {
                            "http://tauri.localhost/error.html"
                        } else {
                            "tauri://localhost/error.html"
                        };
                        if let Ok(url) = target.parse() {
                            let _ = window.navigate(url);
                        }
                    }
                });
                supervisor.stop();
                let Some(delay) = budget.next_delay() else {
                    log::error!("sidecar recovery exhausted; restart the desktop app");
                    break;
                };
                if receiver.recv_timeout(delay) != Err(mpsc::RecvTimeoutError::Timeout) {
                    break;
                }
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                let result = supervisor.start_once().and_then(|base| {
                    crate::csp::verify_sidecar(&base).map_err(str::to_string)?;
                    let session = Arc::new(DesktopSession::new(supervisor.ipc_client()));
                    session.native_http(&base)?;
                    Ok(Arc::new(Connection { base, session }))
                });
                match result {
                    Ok(connection) => {
                        if stopping.load(Ordering::Acquire) {
                            break;
                        }
                        let target = crate::session::bootstrap_url(&connection.base).unwrap();
                        host.set_port(target.port().unwrap());
                        *active.lock().unwrap() = Some(connection.clone());
                        failures = 0;
                        let navigate_app = app.clone();
                        let navigate_active = active.clone();
                        let navigate_stopping = stopping.clone();
                        let _ = app.run_on_main_thread(move || {
                            if navigate_stopping.load(Ordering::Acquire) {
                                return;
                            }
                            let current = navigate_active.lock().unwrap();
                            if !current
                                .as_ref()
                                .is_some_and(|current| Arc::ptr_eq(current, &connection))
                            {
                                return;
                            }
                            if let Some(window) = navigate_app.get_webview_window("main") {
                                if window.navigate(target).is_err() {
                                    log::error!("could not load recovered desktop session");
                                }
                            }
                        });
                    }
                    Err(_) => log::error!("sidecar recovery failed"),
                }
            }
            if let Some(mut watcher) = watcher {
                watcher.stop();
            }
            *active.lock().unwrap() = None;
            host.set_port(0);
            supervisor.stop();
        })?;
    Ok(DesktopRuntime {
        stopped,
        wake,
        thread: Some(thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_crashes_exhaust_budget_until_sustained_health() {
        let mut budget = RecoveryBudget::default();
        let now = Instant::now();
        for seconds in [1, 2, 4, 8, 16] {
            budget.healthy(now);
            assert_eq!(budget.next_delay(), Some(Duration::from_secs(seconds)));
        }
        assert_eq!(budget.next_delay(), None);
        budget.healthy(now);
        budget.healthy(now + Duration::from_secs(59));
        assert_eq!(budget.attempts, 5);
        budget.healthy(now + Duration::from_secs(60));
        assert_eq!(budget.next_delay(), Some(Duration::from_secs(1)));
    }

    #[test]
    fn shutdown_interrupts_backoff_and_joins_worker() {
        let stopped = Arc::new(AtomicBool::new(false));
        let observed = stopped.clone();
        let (wake, receiver) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            assert!(receiver.recv_timeout(Duration::from_secs(60)).is_ok());
            assert!(observed.load(Ordering::Acquire));
        });
        let mut runtime = DesktopRuntime {
            stopped,
            wake,
            thread: Some(thread),
        };
        runtime.stop();
        assert!(runtime.thread.is_none());
        runtime.stop();
    }
}
