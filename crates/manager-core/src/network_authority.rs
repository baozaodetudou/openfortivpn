//! Cross-process exclusive authority for engines that still own global network
//! changes. Losing a process lock never proves that those changes were undone.
use crate::{ControlError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

pub const SYSTEM_DIRECTORY: &str = "/var/lib/openfortivpn-manager/network";

#[cfg(unix)]
pub fn system_directory() -> Result<PathBuf, ControlError> {
    use std::os::unix::fs::DirBuilderExt;
    if unsafe { libc::geteuid() } != 0 {
        return Err(ControlError::new(
            ErrorCode::RecoveryRequired,
            "system network authority requires the privileged launcher",
        ));
    }
    for path in ["/var/lib/openfortivpn-manager", SYSTEM_DIRECTORY] {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(recovery()),
        }
        crate::private_file::verify_directory(Path::new(path)).map_err(|_| recovery())?;
    }
    Ok(PathBuf::from(SYSTEM_DIRECTORY))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Owner {
    pub attempt_id: String,
    pub manager: String,
    pub uid: u32,
    /// Zero means spawn/identity capture has not completed. Never guess a PID.
    pub process_group: u32,
    /// Group zero is recoverable only when engine startup used LaunchGate.
    /// Older journals have no such proof and remain conservatively blocked.
    #[serde(default)]
    pub pre_spawn_gated: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schema_version: u32,
    owner: Owner,
}
fn recovery() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "system network authority requires recovery",
    )
}
fn validate(owner: &Owner) -> Result<(), ControlError> {
    if !matches!(owner.manager.as_str(), "headless" | "helper" | "desktop")
        || owner.attempt_id.is_empty()
        || owner.attempt_id.len() > 128
        || !owner
            .attempt_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || owner.process_group == 1
        || owner.process_group > i32::MAX as u32
    {
        return Err(recovery());
    }
    Ok(())
}
fn barrier(directory: &Path) -> Result<(), ControlError> {
    crate::private_file::verify_directory(directory).map_err(|_| recovery())?;
    #[cfg(unix)]
    File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|_| recovery())?;
    Ok(())
}
fn guard(directory: &Path) -> Result<File, ControlError> {
    barrier(directory)?;
    crate::private_file::try_lock(&directory.join(".authority.lock"), false).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            ControlError::new(
                ErrorCode::NetworkConflict,
                "another manager owns the system network",
            )
        } else {
            recovery()
        }
    })
}
pub struct MaintenanceGuard {
    // Release in reverse acquisition order: native first, machine second.
    _native: crate::network::LockedStore,
    _authority: File,
}
pub fn maintenance_guard(directory: &Path) -> Result<MaintenanceGuard, ControlError> {
    let lock = guard(directory)?;
    if inspect(directory)?.is_some() {
        return Err(recovery());
    }
    let native = crate::network::LockedStore::idle_guard(directory)?;
    Ok(MaintenanceGuard {
        _native: native,
        _authority: lock,
    })
}
pub fn inspect(directory: &Path) -> Result<Option<Owner>, ControlError> {
    barrier(directory)?;
    let bytes = match crate::private_file::read(&directory.join("active.json"), 4096) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(recovery()),
    };
    let record: Record = serde_json::from_slice(&bytes).map_err(|_| recovery())?;
    if !matches!(record.schema_version, 1 | 2)
        || (record.schema_version == 1 && record.owner.pre_spawn_gated)
    {
        return Err(recovery());
    }
    validate(&record.owner)?;
    Ok(Some(record.owner))
}
fn remove(directory: &Path) -> Result<(), ControlError> {
    std::fs::remove_file(directory.join("active.json")).map_err(|_| recovery())?;
    barrier(directory)
}
pub struct ExclusiveLease {
    directory: PathBuf,
    owner: Owner,
    _guard: File,
}
impl ExclusiveLease {
    pub fn acquire(directory: &Path, owner: Owner) -> Result<Self, ControlError> {
        validate(&owner)?;
        let lock = guard(directory)?;
        if inspect(directory)?.is_some() {
            return Err(recovery());
        }
        let _native = crate::network::LockedStore::idle_guard(directory)?;
        let bytes = serde_json::to_vec(&Record {
            schema_version: 2,
            owner: owner.clone(),
        })
        .map_err(|_| recovery())?;
        crate::atomic_file::write_private(&directory.join("active.json"), &bytes)
            .map_err(|_| recovery())?;
        Ok(Self {
            directory: directory.into(),
            owner,
            _guard: lock,
        })
    }
    pub fn bind_process_group(&mut self, group: u32) -> Result<(), ControlError> {
        if group <= 1 || group > i32::MAX as u32 {
            return Err(recovery());
        }
        self.owner.process_group = group;
        let bytes = serde_json::to_vec(&Record {
            schema_version: 2,
            owner: self.owner.clone(),
        })
        .map_err(|_| recovery())?;
        crate::atomic_file::write_private(&self.directory.join("active.json"), &bytes)
            .map_err(|_| recovery())
    }
    /// The adapter calls this only after wait/reap and output EOF/drain, and
    /// after the lifecycle has independently confirmed network cleanup.
    pub fn finish(self, reaped: bool, cleanup_confirmed: bool) -> Result<(), ControlError> {
        if !reaped || !cleanup_confirmed || inspect(&self.directory)?.as_ref() != Some(&self.owner)
        {
            return Err(recovery());
        }
        let _native = crate::network::LockedStore::idle_guard(&self.directory)?;
        remove(&self.directory)
    }
}
/// Only a trusted local recovery adapter may supply quiescence proof, including
/// any adapter descendants. API clients cannot acknowledge this journal.
pub fn acknowledge(
    directory: &Path,
    attempt: &str,
    uid: u32,
    quiescent: impl FnOnce() -> Result<bool, ControlError>,
) -> Result<(), ControlError> {
    let _guard = guard(directory)?;
    let owner = inspect(directory)?.ok_or_else(recovery)?;
    if owner.attempt_id != attempt || owner.uid != uid {
        return Err(recovery());
    }
    let _native = crate::network::LockedStore::idle_guard(directory)?;
    if !quiescent()? {
        return Err(recovery());
    }
    remove(directory)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }
    fn owner(id: &str) -> Owner {
        Owner {
            attempt_id: id.into(),
            manager: "headless".into(),
            uid: 501,
            process_group: 0,
            pre_spawn_gated: false,
        }
    }
    #[test]
    fn every_manager_is_excluded_until_reap_and_cleanup_are_confirmed() {
        let dir = directory();
        let lease = ExclusiveLease::acquire(dir.path(), owner("first")).unwrap();
        assert!(ExclusiveLease::acquire(dir.path(), owner("second")).is_err());
        assert!(lease.finish(false, true).is_err());
        assert!(ExclusiveLease::acquire(dir.path(), owner("second")).is_err());
        assert!(acknowledge(dir.path(), "first", 502, || Ok(true)).is_err());
        assert!(acknowledge(dir.path(), "first", 501, || Ok(false)).is_err());
        acknowledge(dir.path(), "first", 501, || Ok(true)).unwrap();
        ExclusiveLease::acquire(dir.path(), owner("second"))
            .unwrap()
            .finish(true, true)
            .unwrap();
        assert!(inspect(dir.path()).unwrap().is_none());
    }
    #[test]
    fn crashed_worker_or_failed_cleanup_keeps_the_durable_reservation() {
        let dir = directory();
        drop(ExclusiveLease::acquire(dir.path(), owner("before-spawn")).unwrap());
        assert_eq!(
            inspect(dir.path()).unwrap().unwrap().attempt_id,
            "before-spawn"
        );
        assert!(ExclusiveLease::acquire(dir.path(), owner("new")).is_err());
        acknowledge(dir.path(), "before-spawn", 501, || Ok(true)).unwrap();
        let lease = ExclusiveLease::acquire(dir.path(), owner("new")).unwrap();
        assert!(lease.finish(true, false).is_err());
        assert!(ExclusiveLease::acquire(dir.path(), owner("third")).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn invalid_records_and_symlinks_fail_closed_before_recovery_callback() {
        let dir = directory();
        let path = dir.path().join("active.json");
        crate::atomic_file::write_private(&path, b"{invalid").unwrap();
        assert!(acknowledge(dir.path(), "x", 501, || panic!("must not run")).is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();
        assert!(ExclusiveLease::acquire(dir.path(), owner("x")).is_err());
        assert!(acknowledge(dir.path(), "x", 501, || panic!("must not run")).is_err());
    }
    #[test]
    fn installer_and_process_binding_cannot_bypass_the_active_owner() {
        let dir = directory();
        let maintenance = maintenance_guard(dir.path()).unwrap();
        assert!(ExclusiveLease::acquire(dir.path(), owner("running")).is_err());
        assert!(crate::network::LockedStore::idle_guard(dir.path()).is_err());
        drop(maintenance);
        assert!(crate::network::LockedStore::idle_guard(dir.path()).is_ok());
        let mut lease = ExclusiveLease::acquire(dir.path(), owner("running")).unwrap();
        assert!(maintenance_guard(dir.path()).is_err());
        assert!(lease.bind_process_group(u32::MAX).is_err());
        lease.bind_process_group(321).unwrap();
        assert_eq!(inspect(dir.path()).unwrap().unwrap().process_group, 321);
        lease.finish(true, true).unwrap();
        assert!(maintenance_guard(dir.path()).is_ok());
    }
    #[test]
    fn older_records_never_gain_pre_spawn_gate_proof_during_migration() {
        let dir = directory();
        let path = dir.path().join("active.json");
        crate::atomic_file::write_private(&path, br#"{"schemaVersion":1,"owner":{"attemptId":"old","manager":"desktop","uid":501,"processGroup":0}}"#).unwrap();
        assert!(!inspect(dir.path()).unwrap().unwrap().pre_spawn_gated);
        crate::atomic_file::write_private(&path, br#"{"schemaVersion":1,"owner":{"attemptId":"old","manager":"desktop","uid":501,"processGroup":0,"preSpawnGated":true}}"#).unwrap();
        assert!(inspect(dir.path()).is_err());
    }

    fn pending_native(directory: &Path) {
        use crate::network::{Backend, BackendCapabilities, LockedStore, Plan, Resource};
        struct Empty;
        impl Backend for Empty {
            fn inspect(&mut self, _: &Resource) -> Result<Option<String>, ControlError> {
                Ok(None)
            }
            fn apply(&mut self, _: &Resource) -> Result<String, ControlError> {
                panic!("this test never changes a platform resource")
            }
            fn remove(&mut self, _: &Resource, _: &str) -> Result<(), ControlError> {
                panic!("this test never changes a platform resource")
            }
        }
        LockedStore::open(directory)
            .unwrap()
            .prepare(
                Plan {
                    attempt_id: "native".into(),
                    profile_id: "profile".into(),
                    generation: 1,
                    network_epoch: 0,
                    resources: vec![],
                },
                BackendCapabilities { split_dns: true },
                &mut Empty,
            )
            .unwrap();
    }

    #[test]
    fn native_journal_blocks_release_and_acknowledgement_before_destructive_callback() {
        let dir = directory();
        let lease = ExclusiveLease::acquire(dir.path(), owner("native")).unwrap();
        pending_native(dir.path());
        assert!(lease.finish(true, true).is_err());
        assert!(inspect(dir.path()).unwrap().is_some());
        assert!(acknowledge(dir.path(), "native", 501, || {
            panic!("native recovery must precede subordinate journal deletion")
        })
        .is_err());
        assert!(inspect(dir.path()).unwrap().is_some());
    }

    #[test]
    fn orphan_native_journal_and_binding_block_new_engines_and_maintenance() {
        let dir = directory();
        pending_native(dir.path());
        assert!(ExclusiveLease::acquire(dir.path(), owner("legacy")).is_err());
        assert!(maintenance_guard(dir.path()).is_err());
        assert!(inspect(dir.path()).unwrap().is_none());
        crate::network::Journal::save(
            &mut crate::network::FileJournal(dir.path().join("network.json")),
            &crate::network::Snapshot::default(),
        )
        .unwrap();
        let binding = dir.path().join("binding-native.json");
        crate::atomic_file::write_private(&binding, b"orphan recovery evidence").unwrap();
        assert!(ExclusiveLease::acquire(dir.path(), owner("legacy")).is_err());
        assert!(maintenance_guard(dir.path()).is_err());
        std::fs::remove_file(binding).unwrap();
        ExclusiveLease::acquire(dir.path(), owner("legacy"))
            .unwrap()
            .finish(true, true)
            .unwrap();
    }

    #[test]
    fn malformed_native_journal_never_becomes_cleanup_proof() {
        let dir = directory();
        drop(ExclusiveLease::acquire(dir.path(), owner("native")).unwrap());
        crate::atomic_file::write_private(&dir.path().join("network.json"), b"{invalid").unwrap();
        assert!(acknowledge(dir.path(), "native", 501, || panic!("must not run")).is_err());
        assert!(inspect(dir.path()).unwrap().is_some());
    }

    #[test]
    fn unfinished_native_worker_blocks_acknowledgement_without_waiting_or_deleting() {
        let dir = directory();
        drop(ExclusiveLease::acquire(dir.path(), owner("native")).unwrap());
        let worker = crate::network::LockedStore::open(dir.path()).unwrap();
        assert!(acknowledge(dir.path(), "native", 501, || panic!("must not run")).is_err());
        assert!(inspect(dir.path()).unwrap().is_some());
        drop(worker);
        acknowledge(dir.path(), "native", 501, || Ok(true)).unwrap();
        assert!(inspect(dir.path()).unwrap().is_none());
    }
}
