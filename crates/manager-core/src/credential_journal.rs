//! Recovery for credentials stored outside the profile metadata transaction.
//! References are staged without overwriting the old secret; GC uses the
//! durable repository's live references, including later superseding saves.
use crate::{atomic_file, private_file, repository, ControlError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
const PREFIX: &str = ".credential-intent.";
const MAX_INTENTS: usize = 8192;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    pub profile_id: String,
    pub old_ref: Option<String>,
    pub new_ref: Option<String>,
    pub delete_profile: bool,
}
fn failed() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "credential repository requires recovery",
    )
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}
impl Intent {
    fn validate(&self) -> Result<(), ControlError> {
        if self.profile_id.is_empty()
            || self.profile_id.len() > 128
            || self.profile_id == "__remote_access_token"
            || self.profile_id.chars().any(|c| c.is_control())
            || (self.delete_profile && self.new_ref.is_some())
        {
            return Err(failed());
        }
        for reference in [&self.old_ref, &self.new_ref].into_iter().flatten() {
            if reference != &self.profile_id
                && reference
                    .strip_prefix("credential:")
                    .is_none_or(|id| !uuid(id))
            {
                return Err(failed());
            }
        }
        Ok(())
    }
}
fn entries(directory: &Path) -> Result<Vec<PathBuf>, ControlError> {
    private_file::verify_directory(directory).map_err(|_| failed())?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| failed())? {
        let entry = entry.map_err(|_| failed())?;
        if entry.file_name().to_string_lossy().starts_with(PREFIX) {
            if !entry.file_type().map_err(|_| failed())?.is_file() {
                return Err(failed());
            }
            paths.push(entry.path());
            if paths.len() >= MAX_INTENTS {
                return Err(failed());
            }
        }
    }
    paths.sort();
    Ok(paths)
}
pub fn begin(directory: &Path, intent: &Intent) -> Result<PathBuf, ControlError> {
    intent.validate()?;
    entries(directory)?;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| failed())?;
    let nonce: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let path = directory.join(format!("{PREFIX}{nonce}.json"));
    let bytes = serde_json::to_vec(intent).map_err(|_| failed())?;
    atomic_file::write_new_private(&path, &bytes).map_err(|_| failed())?;
    Ok(path)
}
/// Deleting a missing entry must succeed so interrupted GC is retryable.
pub fn collect(
    directory: &Path,
    path: &Path,
    intent: &Intent,
    active: &HashSet<String>,
    backup: &HashSet<String>,
    delete: &mut impl FnMut(&str) -> Result<(), ControlError>,
) -> Result<(), ControlError> {
    intent.validate()?;
    private_file::verify_directory(directory).map_err(|_| failed())?;
    if path.parent() != Some(directory)
        || !path
            .file_name()
            .is_some_and(|s| s.to_string_lossy().starts_with(PREFIX))
    {
        return Err(failed());
    }
    let gc = repository::credential_gc(
        [&intent.old_ref, &intent.new_ref]
            .into_iter()
            .flatten()
            .cloned(),
        active,
        backup,
    );
    for reference in gc.delete {
        delete(&reference)?;
    }
    if !gc.deferred_for_backup {
        fs::remove_file(path).map_err(|_| failed())?;
        #[cfg(unix)]
        fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| failed())?;
    }
    Ok(())
}
pub fn recover(
    directory: &Path,
    active: &HashSet<String>,
    backup: &HashSet<String>,
    mut delete: impl FnMut(&str) -> Result<(), ControlError>,
) -> Result<(), ControlError> {
    // Parse every record before deleting any credential. An unsupported intent
    // cannot trigger partial GC of otherwise valid records.
    let intents = entries(directory)?
        .into_iter()
        .map(|path| {
            let bytes = private_file::read(&path, 16 * 1024).map_err(|_| failed())?;
            let intent: Intent = serde_json::from_slice(&bytes).map_err(|_| failed())?;
            intent.validate()?;
            Ok((path, intent))
        })
        .collect::<Result<Vec<_>, ControlError>>()?;
    for (path, intent) in intents {
        collect(directory, &path, &intent, active, backup, &mut delete)?;
    }
    Ok(())
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const OLD: &str = "credential:00000000-0000-4000-8000-000000000001";
    const NEW: &str = "credential:00000000-0000-4000-8000-000000000002";
    const FUTURE: &str = "credential:00000000-0000-4000-8000-000000000003";
    fn intent() -> Intent {
        Intent {
            profile_id: "profile".into(),
            old_ref: Some(OLD.into()),
            new_ref: Some(NEW.into()),
            delete_profile: false,
        }
    }
    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }
    #[test]
    fn each_crash_boundary_and_later_save_recovers_against_the_durable_ref() {
        for step in 0..5 {
            let dir = fixture();
            let record = begin(dir.path(), &intent()).unwrap();
            let mut secrets = HashSet::from([OLD.to_string()]);
            if step >= 1 {
                secrets.insert(NEW.into());
            }
            let active = HashSet::from([if step >= 2 { NEW.into() } else { OLD.into() }]);
            if step == 3 {
                secrets.remove(OLD);
            }
            let active = if step == 4 {
                secrets.insert(FUTURE.into());
                HashSet::from([FUTURE.into()])
            } else {
                active
            };
            recover(dir.path(), &active, &HashSet::new(), |reference| {
                secrets.remove(reference);
                Ok(())
            })
            .unwrap();
            assert_eq!(secrets, active);
            assert!(!record.exists());
            recover(dir.path(), &active, &HashSet::new(), |_| {
                panic!("already collected")
            })
            .unwrap();
        }
    }
    #[test]
    fn credential_failure_retains_intent_and_backup_refs_until_retry() {
        let dir = fixture();
        let record = begin(dir.path(), &intent()).unwrap();
        let mut secrets = HashSet::from([OLD.to_string(), NEW.into()]);
        let active = HashSet::new();
        let mut calls = 0;
        assert!(recover(dir.path(), &active, &HashSet::new(), |reference| {
            calls += 1;
            if calls == 2 {
                return Err(failed());
            }
            secrets.remove(reference);
            Ok(())
        })
        .is_err());
        assert!(record.exists());
        recover(
            dir.path(),
            &active,
            &HashSet::from([NEW.into()]),
            |reference| {
                secrets.remove(reference);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(secrets, HashSet::from([NEW.into()]));
        assert!(record.exists());
        recover(dir.path(), &active, &HashSet::new(), |reference| {
            secrets.remove(reference);
            Ok(())
        })
        .unwrap();
        assert!(secrets.is_empty());
        assert!(!record.exists());
    }
    #[test]
    fn malformed_or_unsafe_journal_never_deletes_any_credential() {
        let dir = fixture();
        begin(dir.path(), &intent()).unwrap();
        let path = dir.path().join(format!("{PREFIX}bad.json"));
        atomic_file::write_private(&path, br#"{"profileId":"__remote_access_token","oldRef":"__remote_access_token","newRef":null,"deleteProfile":true}"#).unwrap();
        assert!(
            recover(dir.path(), &HashSet::new(), &HashSet::new(), |_| panic!(
                "invalid batch must not delete"
            ))
            .is_err()
        );
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(
            recover(dir.path(), &HashSet::new(), &HashSet::new(), |_| panic!(
                "symlink must not delete"
            ))
            .is_err()
        );
    }
}
