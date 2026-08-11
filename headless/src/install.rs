use anyhow::{anyhow, bail, Context, Result};
use nix::unistd::Uid;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::storage::Storage;

pub const INSTALLED_BINARY: &str = "/usr/local/sbin/openfortivpn-manager-headless";
pub const INSTALLED_ENGINE: &str = "/usr/local/libexec/openfortivpn-manager-headless/openfortivpn";
pub const SYSTEMD_UNIT: &str = "/etc/systemd/system/openfortivpn-manager-headless.service";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

pub struct InstallResult {
    pub binary: PathBuf,
    pub engine: PathBuf,
    pub unit: PathBuf,
}

pub fn install(engine_source: Option<PathBuf>, start: bool, quiet: bool) -> Result<InstallResult> {
    require_root("install")?;
    let current_exe = std::env::current_exe().context("failed to locate current executable")?;
    let engine_source =
        match engine_source {
            Some(path) => path,
            None => find_repository_engine(&std::env::current_dir()?, &current_exe).ok_or_else(
                || anyhow!("cannot find a built openfortivpn engine; pass --engine PATH"),
            )?,
        };
    validate_source_file(&current_exe, "manager executable")?;
    validate_source_file(&engine_source, "openfortivpn engine")?;

    let storage = Storage::default();
    storage.ensure_layout()?;
    storage.load_or_create_token()?;
    let settings = storage.load_or_create_settings()?;
    storage.ensure_certificate(&settings.bind_address)?;

    install_file(&current_exe, Path::new(INSTALLED_BINARY), 0o755)?;
    install_file(&engine_source, Path::new(INSTALLED_ENGINE), 0o755)?;
    write_root_file(Path::new(SYSTEMD_UNIT), systemd_unit().as_bytes(), 0o644)?;

    if start {
        run_systemctl(["daemon-reload"], quiet)?;
        run_systemctl(
            ["enable", "--now", "openfortivpn-manager-headless.service"],
            quiet,
        )?;
    }

    Ok(InstallResult {
        binary: PathBuf::from(INSTALLED_BINARY),
        engine: PathBuf::from(INSTALLED_ENGINE),
        unit: PathBuf::from(SYSTEMD_UNIT),
    })
}

pub fn uninstall(purge: bool) -> Result<()> {
    require_root("uninstall")?;
    let _ = run_systemctl(
        ["disable", "--now", "openfortivpn-manager-headless.service"],
        false,
    );
    remove_file_if_exists(Path::new(SYSTEMD_UNIT))?;
    let _ = run_systemctl(["daemon-reload"], false);
    remove_file_if_exists(Path::new(INSTALLED_ENGINE))?;
    remove_file_if_exists(Path::new(INSTALLED_BINARY))?;
    remove_empty_parent(Path::new(INSTALLED_ENGINE))?;
    if purge {
        for path in [
            Path::new("/etc/openfortivpn-manager-headless"),
            Path::new("/var/lib/openfortivpn-manager-headless"),
            Path::new("/run/openfortivpn-manager-headless"),
        ] {
            remove_exact_directory(path)?;
        }
    }
    Ok(())
}

pub fn service_status(storage: &Storage) -> Result<String> {
    let service = Command::new(SYSTEMCTL)
        .args(["is-active", "openfortivpn-manager-headless.service"])
        .output();
    let service_state = match service {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => "systemd-unavailable".to_string(),
    };
    let profile_count = storage
        .load_profiles()
        .map(|profiles| profiles.len())
        .unwrap_or(0);
    Ok(format!(
        "service: {}\nprofiles: {}\nconfig: {}\nengine: {}",
        if service_state.is_empty() {
            "inactive"
        } else {
            &service_state
        },
        profile_count,
        storage.config_dir.display(),
        INSTALLED_ENGINE,
    ))
}

pub fn systemd_unit() -> String {
    format!(
        "[Unit]\nDescription=OpenFortiVPN Manager headless service\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={INSTALLED_BINARY} serve --engine {INSTALLED_ENGINE}\nRestart=on-failure\nRestartSec=5s\nUMask=0077\nRuntimeDirectory=openfortivpn-manager-headless\nRuntimeDirectoryMode=0700\nStateDirectory=openfortivpn-manager-headless\nStateDirectoryMode=0700\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nKillMode=mixed\nTimeoutStopSec=15s\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

fn require_root(operation: &str) -> Result<()> {
    if !Uid::effective().is_root() {
        bail!("{operation} must run as root; use sudo");
    }
    Ok(())
}

fn validate_source_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "{label} must be a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(())
}

fn install_file(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    if source == destination {
        fs::set_permissions(destination, fs::Permissions::from_mode(mode))?;
        return Ok(());
    }
    validate_source_file(source, "source")?;
    let contents = fs::read(source)?;
    write_root_file(destination, &contents, mode)
}

fn write_root_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent"))?;
    fs::create_dir_all(parent)?;
    reject_symlink(parent)?;
    let temporary = parent.join(format!(
        ".{}.install.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("refusing symlink destination: {}", path.display());
    }
    Ok(())
}

fn run_systemctl<const N: usize>(arguments: [&str; N], quiet: bool) -> Result<()> {
    let mut command = Command::new(SYSTEMCTL);
    command.args(arguments);
    if quiet {
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::null());
    }
    let status = command.status().context("failed to execute systemctl")?;
    if !status.success() {
        bail!("systemctl failed with {status}");
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn remove_empty_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        match fs::remove_dir(parent) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn remove_exact_directory(path: &Path) -> Result<()> {
    let allowed = [
        Path::new("/etc/openfortivpn-manager-headless"),
        Path::new("/var/lib/openfortivpn-manager-headless"),
        Path::new("/run/openfortivpn-manager-headless"),
    ];
    if !allowed.contains(&path) {
        bail!("refusing to purge unexpected path: {}", path.display());
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn find_repository_engine(current_dir: &Path, current_exe: &Path) -> Option<PathBuf> {
    let mut roots = Vec::new();
    roots.extend(current_dir.ancestors().map(Path::to_path_buf));
    if let Some(parent) = current_exe.parent() {
        roots.extend(parent.ancestors().map(Path::to_path_buf));
    }
    for root in roots {
        for relative in [
            "build/app-engine/openfortivpn",
            "build/cmake/openfortivpn",
            "build/openfortivpn",
            "app/src-tauri/resources/bin/openfortivpn",
        ] {
            let candidate = root.join(relative);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_has_security_and_restart_settings() {
        let unit = systemd_unit();
        assert_eq!(SYSTEMCTL, "/usr/bin/systemctl");
        assert!(Path::new(SYSTEMCTL).is_absolute());
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("UMask=0077"));
        assert!(unit.contains("RuntimeDirectoryMode=0700"));
        assert!(unit.contains(INSTALLED_ENGINE));
    }

    #[test]
    fn engine_discovery_finds_repository_build() {
        let root = tempfile::tempdir().unwrap();
        let engine = root.path().join("build/app-engine/openfortivpn");
        fs::create_dir_all(engine.parent().unwrap()).unwrap();
        fs::write(&engine, b"engine").unwrap();
        assert_eq!(
            find_repository_engine(
                root.path(),
                &root.path().join("headless/target/debug/manager")
            ),
            Some(engine)
        );
    }
}
