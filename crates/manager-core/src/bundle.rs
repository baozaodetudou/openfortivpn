//! Offline all-or-recoverable installation of a fixed, launcher-owned bundle.
//! The service must be stopped before this transaction is opened. An interrupted
//! replacement is rolled back before any new installation may begin.
use crate::{atomic_file, private_file, ControlError, ErrorCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
const MAX_PAYLOAD: u64 = 256 * 1024 * 1024;
#[derive(Clone)]
pub struct Target {
    pub name: String,
    pub path: PathBuf,
    pub mode: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    name: String,
    path: PathBuf,
    before: Option<String>,
    after: String,
    mode: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    entries: Vec<Entry>,
}
fn failed() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "bundle replacement requires offline recovery",
    )
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn current(path: &Path) -> Result<Option<Vec<u8>>, ControlError> {
    match fs::symlink_metadata(path) {
        Ok(_) => private_file::read_metadata(path, MAX_PAYLOAD)
            .map(Some)
            .map_err(|_| failed()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(failed()),
    }
}
pub struct Bundle {
    directory: PathBuf,
    targets: BTreeMap<String, Target>,
    _lock: fs::File,
}
impl Bundle {
    pub fn open(directory: &Path, targets: Vec<Target>) -> Result<Self, ControlError> {
        private_file::verify_directory(directory).map_err(|_| failed())?;
        if targets.is_empty() || targets.len() > 8 {
            return Err(failed());
        }
        let mut map = BTreeMap::new();
        let mut paths = std::collections::BTreeSet::new();
        for target in targets {
            if target.name.is_empty()
                || target.name.len() > 32
                || !target
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || !target.path.is_absolute()
                || !matches!(target.mode, 0o440 | 0o644 | 0o755)
                || !paths.insert(target.path.clone())
            {
                return Err(failed());
            }
            let parent = target.path.parent().ok_or_else(failed)?;
            if fs::canonicalize(parent).map_err(|_| failed())? != parent {
                return Err(failed());
            }
            let metadata = fs::symlink_metadata(parent).map_err(|_| failed())?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(failed());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
                    return Err(failed());
                }
            }
            if map.insert(target.name.clone(), target).is_some() {
                return Err(failed());
            }
        }
        let lock = private_file::lock(&directory.join(".bundle.lock")).map_err(|_| failed())?;
        Ok(Self {
            directory: directory.into(),
            targets: map,
            _lock: lock,
        })
    }
    fn load(&self, name: &str) -> Result<Option<Manifest>, ControlError> {
        let path = self.directory.join(name);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(failed()),
            Ok(_) => {}
        }
        let bytes = private_file::read(&path, 8192).map_err(|_| failed())?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| failed())?;
        let mut names = std::collections::BTreeSet::new();
        if manifest.schema_version != 2 || manifest.entries.len() != self.targets.len() {
            return Err(failed());
        }
        for entry in &manifest.entries {
            if !names.insert(&entry.name)
                || self
                    .targets
                    .get(&entry.name)
                    .is_none_or(|t| t.mode != entry.mode || t.path != entry.path)
                || std::iter::once(&entry.after)
                    .chain(entry.before.iter())
                    .any(|s| {
                        s.len() != 64
                            || !s
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
            {
                return Err(failed());
            }
        }
        Ok(Some(manifest))
    }
    fn save(&self, name: &str, manifest: &Manifest) -> Result<(), ControlError> {
        let bytes = serde_json::to_vec(manifest).map_err(|_| failed())?;
        atomic_file::write_private(&self.directory.join(name), &bytes).map_err(|_| failed())
    }
    fn blob(&self, hash: &str) -> Result<Vec<u8>, ControlError> {
        let bytes =
            private_file::read(&self.directory.join(hash), MAX_PAYLOAD).map_err(|_| failed())?;
        if digest(&bytes) != hash {
            return Err(failed());
        }
        Ok(bytes)
    }
    fn retain(&self, bytes: &[u8]) -> Result<String, ControlError> {
        if bytes.len() as u64 > MAX_PAYLOAD {
            return Err(failed());
        }
        let hash = digest(bytes);
        // Always replace, so a corrupt retained payload cannot survive by name.
        atomic_file::write_private(&self.directory.join(&hash), bytes).map_err(|_| failed())?;
        Ok(hash)
    }
    fn restore(&self, manifest: &Manifest) -> Result<(), ControlError> {
        // Validate every payload and every destination before the first write.
        let mut restore = Vec::new();
        for entry in &manifest.entries {
            let target = self.targets.get(&entry.name).ok_or_else(failed)?;
            let present = current(&target.path)?.map(|bytes| digest(&bytes));
            if present != entry.before && present.as_ref() != Some(&entry.after) {
                return Err(failed());
            }
            let bytes = entry
                .before
                .as_ref()
                .map(|hash| self.blob(hash))
                .transpose()?;
            restore.push((target, bytes));
        }
        for (target, bytes) in restore {
            if let Some(bytes) = bytes {
                atomic_file::write_mode(&target.path, &bytes, target.mode).map_err(|_| failed())?;
            } else if target.path.exists() {
                fs::remove_file(&target.path).map_err(|_| failed())?;
                fs::File::open(target.path.parent().ok_or_else(failed)?)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| failed())?;
            }
        }
        Ok(())
    }
    fn remove_marker(&self, name: &str) -> Result<(), ControlError> {
        fs::remove_file(self.directory.join(name)).map_err(|_| failed())?;
        fs::File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| failed())
    }
    pub fn recover(&mut self) -> Result<bool, ControlError> {
        let Some(manifest) = self.load("pending.json")? else {
            return Ok(false);
        };
        self.restore(&manifest)?;
        self.remove_marker("pending.json")?;
        self.gc()?;
        Ok(true)
    }
    pub fn install(&mut self, payloads: BTreeMap<String, Vec<u8>>) -> Result<(), ControlError> {
        self.install_inner(payloads, None)
    }
    fn install_inner(
        &mut self,
        payloads: BTreeMap<String, Vec<u8>>,
        fail_after: Option<usize>,
    ) -> Result<(), ControlError> {
        self.recover()?;
        if payloads.len() != self.targets.len()
            || payloads.keys().any(|name| !self.targets.contains_key(name))
        {
            return Err(failed());
        }
        let mut entries = Vec::new();
        for (name, target) in &self.targets {
            let before = current(&target.path)?
                .as_deref()
                .map(|b| self.retain(b))
                .transpose()?;
            let after = self.retain(&payloads[name])?;
            entries.push(Entry {
                name: name.clone(),
                path: target.path.clone(),
                before,
                after,
                mode: target.mode,
            });
        }
        let manifest = Manifest {
            schema_version: 2,
            entries,
        };
        self.save("pending.json", &manifest)?;
        let result = (|| {
            for (index, entry) in manifest.entries.iter().enumerate() {
                if fail_after == Some(index) {
                    return Err(failed());
                }
                let target = &self.targets[&entry.name];
                atomic_file::write_mode(&target.path, &payloads[&entry.name], target.mode)
                    .map_err(|_| failed())?;
            }
            // Retain the prior bundle for explicit rollback. The durable pending
            // marker remains authoritative until its final removal succeeds.
            self.save("previous.json", &manifest)?;
            self.remove_marker("pending.json")?;
            self.gc()
        })();
        if result.is_err() && fail_after.is_none() {
            let _ = self.recover();
        }
        result
    }
    pub fn rollback(&mut self) -> Result<(), ControlError> {
        self.recover()?;
        let manifest = self.load("previous.json")?.ok_or_else(failed)?;
        self.save("pending.json", &manifest)?;
        self.restore(&manifest)?;
        self.remove_marker("pending.json")?;
        self.remove_marker("previous.json")?;
        self.gc()
    }
    fn gc(&self) -> Result<(), ControlError> {
        let mut retained = std::collections::BTreeSet::new();
        for name in ["pending.json", "previous.json"] {
            if let Some(m) = self.load(name)? {
                for e in m.entries {
                    retained.insert(e.after);
                    retained.extend(e.before);
                }
            }
        }
        for entry in fs::read_dir(&self.directory).map_err(|_| failed())? {
            let entry = entry.map_err(|_| failed())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() == 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && !retained.contains(&name)
            {
                fs::remove_file(entry.path()).map_err(|_| failed())?;
            }
        }
        Ok(())
    }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> (tempfile::TempDir, Vec<Target>) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let targets = ["engine", "manager", "unit"]
            .map(|name| Target {
                name: name.into(),
                path: fs::canonicalize(dir.path()).unwrap().join(name),
                mode: if name == "unit" { 0o644 } else { 0o755 },
            })
            .to_vec();
        for target in &targets {
            atomic_file::write_mode(
                &target.path,
                format!("old-{}", target.name).as_bytes(),
                target.mode,
            )
            .unwrap();
        }
        (dir, targets)
    }
    fn new_payloads() -> BTreeMap<String, Vec<u8>> {
        ["engine", "manager", "unit"]
            .map(|name| (name.into(), format!("new-{name}").into_bytes()))
            .into()
    }
    #[test]
    fn interruption_at_each_replacement_boundary_restores_a_complete_old_bundle() {
        for boundary in 0..3 {
            let (dir, targets) = fixture();
            let mut bundle = Bundle::open(dir.path(), targets.clone()).unwrap();
            assert!(bundle
                .install_inner(new_payloads(), Some(boundary))
                .is_err());
            drop(bundle);
            let mut bundle = Bundle::open(dir.path(), targets.clone()).unwrap();
            assert!(bundle.recover().unwrap());
            assert!(!bundle.recover().unwrap());
            for target in targets {
                assert_eq!(
                    fs::read(target.path).unwrap(),
                    format!("old-{}", target.name).as_bytes()
                );
            }
        }
    }
    #[test]
    fn complete_bundle_rolls_back_and_preserves_executable_modes() {
        let (dir, targets) = fixture();
        let mut bundle = Bundle::open(dir.path(), targets.clone()).unwrap();
        bundle.install(new_payloads()).unwrap();
        for target in &targets {
            assert_eq!(
                fs::read(&target.path).unwrap(),
                format!("new-{}", target.name).as_bytes()
            );
            assert_eq!(
                fs::metadata(&target.path).unwrap().permissions().mode() & 0o777,
                target.mode
            );
        }
        bundle.rollback().unwrap();
        for target in targets {
            assert_eq!(
                fs::read(target.path).unwrap(),
                format!("old-{}", target.name).as_bytes()
            );
        }
        assert!(bundle.rollback().is_err());
    }
    #[test]
    fn pending_bundle_is_bound_to_exact_targets_and_sudoers_mode() {
        let (dir, mut targets) = fixture();
        targets[2].mode = 0o440;
        atomic_file::write_mode(&targets[2].path, b"old-unit", 0o440).unwrap();
        let mut bundle = Bundle::open(dir.path(), targets.clone()).unwrap();
        assert!(bundle.install_inner(new_payloads(), Some(1)).is_err());
        drop(bundle);
        let mut rebound = targets.clone();
        rebound[2].path = fs::canonicalize(dir.path())
            .unwrap()
            .join("other-user-sudoers");
        let mut wrong = Bundle::open(dir.path(), rebound.clone()).unwrap();
        assert!(wrong.recover().is_err());
        assert!(!rebound[2].path.exists());
        drop(wrong);
        let mut correct = Bundle::open(dir.path(), targets.clone()).unwrap();
        assert!(correct.recover().unwrap());
        assert_eq!(
            fs::metadata(&targets[2].path).unwrap().permissions().mode() & 0o777,
            0o440
        );
    }

    #[test]
    fn external_replacement_and_corrupt_retained_blob_block_recovery_before_writes() {
        for corrupt in [false, true] {
            let (dir, targets) = fixture();
            let mut bundle = Bundle::open(dir.path(), targets.clone()).unwrap();
            assert!(bundle.install_inner(new_payloads(), Some(1)).is_err());
            if corrupt {
                atomic_file::write_private(&dir.path().join(digest(b"old-unit")), b"corrupt")
                    .unwrap();
            } else {
                atomic_file::write_mode(&targets[0].path, b"external-engine", 0o755).unwrap();
            }
            let observed = targets
                .iter()
                .map(|t| fs::read(&t.path).unwrap())
                .collect::<Vec<_>>();
            assert!(bundle.recover().is_err());
            assert!(dir.path().join("pending.json").exists());
            assert_eq!(
                targets
                    .iter()
                    .map(|t| fs::read(&t.path).unwrap())
                    .collect::<Vec<_>>(),
                observed
            );
        }
    }
}
