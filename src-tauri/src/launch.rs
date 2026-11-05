// src/launch.rs — Per-OS launch-at-login registration.
//
// Implements DD-7: off by default; opt-in via first-run wizard.
// Per-user only, no admin elevation required.
//
// Platform implementations:
//   macOS 13+: SMAppService.mainApp.register() / .unregister()
//   macOS 12:  launchctl load/unload ~/Library/LaunchAgents/com.keylatch.app.plist
//   Windows:   HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Keylatch
//   Linux:     ~/.config/autostart/keylatch.desktop

use std::fs;
use std::path::PathBuf;

/// LaunchAtLogin manages per-user launch-at-login registration.
pub struct LaunchAtLogin {
    config_path: PathBuf,
    app_path: PathBuf,
    #[cfg(target_os = "windows")]
    run_key_path: String,
}

impl LaunchAtLogin {
    /// Create a new LaunchAtLogin manager.
    /// `config_path` is the path to app-config.json.
    /// `app_path` is the path to the keylatch-app binary (for XDG/registry).
    pub fn new(config_path: PathBuf, app_path: PathBuf) -> Self {
        Self {
            config_path,
            app_path,
            #[cfg(target_os = "windows")]
            run_key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
        }
    }

    /// Enable launch-at-login for the current user. Idempotent.
    pub fn enable(&self) -> Result<(), String> {
        self.platform_enable()?;
        self.write_config(true)
    }

    /// Disable launch-at-login for the current user. Idempotent.
    pub fn disable(&self) -> Result<(), String> {
        self.platform_disable()?;
        self.write_config(false)
    }

    /// Check if launch-at-login is currently enabled at the OS level.
    /// Reads OS state — not just the config file — to handle the case where
    /// the user removed it from System Preferences.
    pub fn is_enabled(&self) -> bool {
        self.platform_is_enabled()
    }

    // ── Platform implementations ──────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    fn platform_enable(&self) -> Result<(), String> {
        // macOS 13+: SMAppService.
        // For broad compatibility, use launchctl plist approach (works on 12+).
        let plist_path = self.launch_agents_plist();
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.keylatch.app</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>"#,
            self.app_path.display()
        );
        if let Some(parent) = plist_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(&plist_path, plist).map_err(|e| e.to_string())?;

        // Load the plist.
        std::process::Command::new("launchctl")
            .args(["load", "-w", &plist_path.to_string_lossy()])
            .status()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn platform_disable(&self) -> Result<(), String> {
        let plist_path = self.launch_agents_plist();
        if plist_path.exists() {
            std::process::Command::new("launchctl")
                .args(["unload", "-w", &plist_path.to_string_lossy()])
                .status()
                .map_err(|e| e.to_string())?;
            fs::remove_file(&plist_path).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn platform_is_enabled(&self) -> bool {
        self.launch_agents_plist().exists()
    }

    #[cfg(target_os = "macos")]
    fn launch_agents_plist(&self) -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("Library/LaunchAgents/com.keylatch.app.plist")
    }

    #[cfg(target_os = "linux")]
    fn platform_enable(&self) -> Result<(), String> {
        let desktop_path = self.autostart_desktop();
        if let Some(parent) = desktop_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let content = format!(
            "[Desktop Entry]\nType=Application\nName=Keylatch\nExec={}\nStartupNotify=false\nX-GNOME-Autostart-enabled=true\n",
            self.app_path.display()
        );
        fs::write(&desktop_path, content).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "linux")]
    fn platform_disable(&self) -> Result<(), String> {
        let path = self.autostart_desktop();
        if path.exists() {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn platform_is_enabled(&self) -> bool {
        self.autostart_desktop().exists()
    }

    #[cfg(target_os = "linux")]
    fn autostart_desktop(&self) -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("autostart/keylatch.desktop")
    }

    #[cfg(target_os = "windows")]
    fn platform_enable(&self) -> Result<(), String> {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let app = self
            .app_path
            .to_str()
            .ok_or("application path is not valid Unicode")?;
        if app.contains('"') || app.contains('\0') {
            return Err("application path contains an invalid character".to_string());
        }
        let (run_key, _) = hkcu
            .create_subkey_with_flags(&self.run_key_path, winreg::enums::KEY_SET_VALUE)
            .map_err(|e| e.to_string())?;
        run_key
            .set_value("Keylatch", &format!("\"{app}\""))
            .map_err(|e| e.to_string())
    }

    #[cfg(target_os = "windows")]
    fn platform_disable(&self) -> Result<(), String> {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run_key =
            match hkcu.open_subkey_with_flags(&self.run_key_path, winreg::enums::KEY_SET_VALUE) {
                Ok(key) => key,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.to_string()),
            };
        match run_key.delete_value("Keylatch") {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    #[cfg(target_os = "windows")]
    fn platform_is_enabled(&self) -> bool {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey(&self.run_key_path)
            .and_then(|k| k.get_value::<String, _>("Keylatch"))
            .is_ok()
    }

    // Fallback for unsupported platforms.
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    fn platform_enable(&self) -> Result<(), String> {
        Err("launch-at-login not supported on this platform".to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    fn platform_disable(&self) -> Result<(), String> {
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    fn platform_is_enabled(&self) -> bool {
        false
    }

    // ── Config helpers ────────────────────────────────────────────────────────

    fn write_config(&self, enabled: bool) -> Result<(), String> {
        // Read existing config or start fresh.
        let mut config: serde_json::Value = if self.config_path.exists() {
            let data = fs::read(&self.config_path).map_err(|e| e.to_string())?;
            serde_json::from_slice(&data).unwrap_or(serde_json::json!({}))
        } else {
            serde_json::json!({})
        };
        config["launch_at_login"] = serde_json::Value::Bool(enabled);
        let data = serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?;
        fs::write(&self.config_path, data).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_records_disabled_without_changing_os_registration() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("app-config.json");
        let app = PathBuf::from("/usr/local/bin/keylatch-app");
        let lal = LaunchAtLogin::new(config.clone(), app);
        lal.write_config(false).unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(config).unwrap()).unwrap();
        assert_eq!(saved["launch_at_login"], false);
    }

    #[test]
    fn repeated_config_updates_preserve_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("app-config.json");
        let app = dir.path().join("fake-keylatch-app");
        fs::write(&app, b"").unwrap();
        fs::write(&config, br#"{"theme":"dark"}"#).unwrap();
        let lal = LaunchAtLogin::new(config.clone(), app);
        lal.write_config(false).unwrap();
        lal.write_config(false).unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(config).unwrap()).unwrap();
        assert_eq!(saved["launch_at_login"], false);
        assert_eq!(saved["theme"], "dark");
    }

    #[cfg(target_os = "windows")]
    struct IsolatedRegistration {
        manager: LaunchAtLogin,
        _dir: tempfile::TempDir,
    }

    #[cfg(target_os = "windows")]
    impl Drop for IsolatedRegistration {
        fn drop(&mut self) {
            let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
            let _ = hkcu.delete_subkey_all(&self.manager.run_key_path);
        }
    }

    #[cfg(target_os = "windows")]
    fn isolated_registration() -> IsolatedRegistration {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = LaunchAtLogin::new(
            dir.path().join("app-config.json"),
            dir.path().join("App With Spaces").join("keylatch-app.exe"),
        );
        manager.run_key_path = format!(
            "Software\\Keylatch\\Tests\\{}",
            dir.path().file_name().unwrap().to_str().unwrap()
        );
        IsolatedRegistration { manager, _dir: dir }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_registration_handles_absent_key_and_value_idempotently() {
        let fixture = isolated_registration();
        let manager = &fixture.manager;
        assert!(!manager.is_enabled());
        manager.disable().unwrap();
        manager.disable().unwrap();
        manager.enable().unwrap();
        manager.enable().unwrap();
        assert!(manager.is_enabled());
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        let key = hkcu.open_subkey(&manager.run_key_path).unwrap();
        let command: String = key.get_value("Keylatch").unwrap();
        assert_eq!(command, format!("\"{}\"", manager.app_path.display()));
        drop(key);
        manager.disable().unwrap();
        manager.disable().unwrap();
        assert!(!manager.is_enabled());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_registration_rejects_embedded_command_quotes() {
        let mut fixture = isolated_registration();
        fixture.manager.app_path = PathBuf::from("bad\" --argument");
        assert!(fixture.manager.enable().is_err());
        assert!(!fixture.manager.is_enabled());
    }
}
