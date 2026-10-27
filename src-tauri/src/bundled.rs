use std::path::{Path, PathBuf};

/// Tauri installs external binaries beside the application executable.
pub fn sidecar(application: &Path) -> Result<PathBuf, &'static str> {
    if !application.is_absolute() {
        return Err("application executable path is not absolute");
    }
    let directory = application
        .parent()
        .ok_or("missing application directory")?;
    let name = if cfg!(windows) {
        "keylatchd.exe"
    } else {
        "keylatchd"
    };
    let path = directory.join(name);
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| "bundled sidecar is missing")?;
    if !metadata.file_type().is_file() {
        return Err("bundled sidecar must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("bundled sidecar is not executable");
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(directory: &Path) -> PathBuf {
        let name = if cfg!(windows) {
            "keylatchd.exe"
        } else {
            "keylatchd"
        };
        let file = directory.join(name);
        std::fs::write(&file, b"test executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        file
    }

    #[test]
    fn resolves_beside_application_without_searching_resources_or_path() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("Application with spaces");
        std::fs::create_dir(&directory).unwrap();
        let application = directory.join("keylatch-app");
        assert!(sidecar(&application).is_err());
        let resources = directory.join("resources").join("binaries");
        std::fs::create_dir_all(&resources).unwrap();
        fixture(&resources);
        assert!(sidecar(&application).is_err());
        let expected = fixture(&directory);
        assert_eq!(sidecar(&application).unwrap(), expected);
        assert!(sidecar(Path::new("keylatch-app")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_non_executable_and_symlink_sidecars() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let application = root.path().join("keylatch-app");
        let file = fixture(root.path());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(sidecar(&application).is_err());
        let target = root.path().join("other");
        std::fs::rename(&file, &target).unwrap();
        symlink(target, &file).unwrap();
        assert!(sidecar(&application).is_err());
    }
}
