//! Profile use cases run inside an adapter-owned transaction. Adapters own the
//! durable lock/recovery and native storage; all transports use these policies.
use crate::{domain::*, repository, validation, ControlError, ErrorCode};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub type Catalog = BTreeMap<String, VpnProfile>;

pub enum SecretChange {
    Replace(Zeroizing<String>),
    Remove,
}

pub struct Mutation {
    pub profiles: Catalog,
    pub stored: BTreeMap<String, SecretChange>,
    pub session: BTreeMap<String, SecretChange>,
    pub clear_sessions: bool,
}

/// A repository is only exposed while its durable transaction lock is held.
/// A failed commit must keep its recovery anchor and must not expose stale
/// cached data as a successful write. Session changes follow the durable commit.
pub trait ProfileRepository {
    type Error: From<ControlError>;
    fn profiles(&self) -> &Catalog;
    fn has_stored_secret(&mut self, id: &str) -> Result<bool, Self::Error>;
    fn view(&self, id: &str) -> Result<ProfileView, Self::Error>;
    fn commit(&mut self, mutation: Mutation) -> Result<(), Self::Error>;
}

pub struct SaveRequest {
    pub profile: VpnProfile,
    pub password: Option<Zeroizing<String>>,
    pub remember_password: bool,
    pub expected_revision: Option<u64>,
}

/// Preserve the desktop's explicit credential-save contract and the headless
/// v1 contract allowing password-less profiles. Auto-connect always requires
/// a durable credential, regardless of transport.
#[derive(Clone, Copy)]
pub enum MissingPasswordPolicy {
    Allow,
    RequireWhenRemembering,
}

pub fn check_revision(expected: Option<u64>, actual: u64) -> Result<(), ControlError> {
    if expected.is_some_and(|expected| expected != actual) {
        return Err(ControlError::new(
            ErrorCode::RevisionConflict,
            "profile revision changed; reload before retrying",
        ));
    }
    Ok(())
}

pub fn check_delete(
    profile: &VpnProfile,
    expected: Option<u64>,
    active: bool,
    stop_first: bool,
) -> Result<(), ControlError> {
    check_revision(expected, profile.revision)?;
    if active && !stop_first {
        return Err(ControlError::new(
            ErrorCode::ProfileBusy,
            "profile is active; stopFirst=true is required",
        ));
    }
    Ok(())
}

pub fn save<R: ProfileRepository>(
    repository: &mut R,
    mut request: SaveRequest,
    missing: MissingPasswordPolicy,
) -> Result<ProfileView, R::Error> {
    validation::profile(&request.profile)?;
    request.profile.trusted_cert = validation::certificate_pin(&request.profile.trusted_cert)?;
    if let Some(password) = &request.password {
        validation::password(password)?;
    }
    let password = request.password.filter(|password| !password.is_empty());
    let id = request.profile.id.clone();
    let current = repository.profiles().get(&id);
    let existing = current.is_some();
    check_revision(request.expected_revision, current.map_or(0, |p| p.revision))?;
    request.profile.revision = current
        .map_or(0, |p| p.revision)
        .checked_add(1)
        .ok_or_else(|| {
            ControlError::new(ErrorCode::RecoveryRequired, "profile revision exhausted")
        })?;
    // Credential references are storage authority, never editable client data.
    request.profile.credential_ref = current.and_then(|p| p.credential_ref.clone());
    if current.is_none() && repository.profiles().len() >= repository::MAX_PROFILES {
        return Err(ControlError::new(ErrorCode::InvalidInput, "profile capacity reached").into());
    }
    let stored = request.remember_password
        && (password.is_some() || (existing && repository.has_stored_secret(&id)?));
    if (request.profile.auto_connect && !stored)
        || (request.remember_password
            && !stored
            && matches!(missing, MissingPasswordPolicy::RequireWhenRemembering))
    {
        return Err(ControlError::new(
            ErrorCode::InvalidInput,
            "a stored VPN password is required",
        )
        .into());
    }
    let mut mutation = Mutation {
        profiles: repository.profiles().clone(),
        stored: BTreeMap::new(),
        session: BTreeMap::new(),
        clear_sessions: false,
    };
    if request.remember_password {
        if let Some(password) = password {
            mutation
                .stored
                .insert(id.clone(), SecretChange::Replace(password));
        } else if !existing {
            // A v1 password-less create must not adopt an orphan whose key
            // happens to match the client-selected profile ID.
            mutation.stored.insert(id.clone(), SecretChange::Remove);
        }
        mutation.session.insert(id.clone(), SecretChange::Remove);
    } else {
        request.profile.credential_ref = None;
        mutation.stored.insert(id.clone(), SecretChange::Remove);
        if let Some(password) = password {
            mutation
                .session
                .insert(id.clone(), SecretChange::Replace(password));
        }
    }
    mutation.profiles.insert(id.clone(), request.profile);
    repository.commit(mutation)?;
    repository.view(&id)
}

pub fn delete<R: ProfileRepository>(
    repository: &mut R,
    id: &str,
    expected_revision: Option<u64>,
) -> Result<bool, R::Error> {
    let Some(current) = repository.profiles().get(id) else {
        return Ok(false);
    };
    check_revision(expected_revision, current.revision)?;
    let mut profiles = repository.profiles().clone();
    profiles.remove(id);
    repository.commit(Mutation {
        profiles,
        stored: BTreeMap::from([(id.into(), SecretChange::Remove)]),
        session: BTreeMap::from([(id.into(), SecretChange::Remove)]),
        clear_sessions: false,
    })?;
    Ok(true)
}

pub fn restore<R: ProfileRepository>(
    repository: &mut R,
    schema: u32,
    profiles: &[VpnProfile],
    secrets: &BTreeMap<String, Zeroizing<String>>,
) -> Result<(), R::Error> {
    repository::validate_portable_archive(
        schema,
        profiles,
        secrets
            .iter()
            .map(|(id, secret)| (id.as_str(), secret.as_str())),
    )?;
    let profiles = repository::prepare_restored_catalog(profiles, repository.profiles())?;
    let mut stored = repository
        .profiles()
        .keys()
        .chain(profiles.keys())
        .map(|id| (id.clone(), SecretChange::Remove))
        .collect::<BTreeMap<_, _>>();
    for (id, secret) in secrets {
        stored.insert(id.clone(), SecretChange::Replace(secret.clone()));
    }
    repository.commit(Mutation {
        profiles,
        stored,
        session: BTreeMap::new(),
        clear_sessions: true,
    })
}

#[derive(Clone, Default)]
pub struct ReferencedCatalog {
    pub profiles: Catalog,
    pub stored: BTreeSet<String>,
    pub unknown: BTreeSet<String>,
}

/// Native credential transaction port. New immutable refs and intents precede
/// metadata commit; failures leave the intent batch for reference-based recovery.
pub trait ReferenceBackend {
    type Error: From<ControlError>;
    type IntentHandle;
    fn allocate_reference(&mut self) -> String;
    fn begin(
        &mut self,
        intent: &crate::credential_journal::Intent,
    ) -> Result<Self::IntentHandle, Self::Error>;
    fn write_secret(&mut self, reference: &str, secret: &str) -> Result<(), Self::Error>;
    fn commit_metadata(&mut self, catalog: &ReferencedCatalog) -> Result<(), Self::Error>;
    fn collect(
        &mut self,
        handle: &Self::IntentHandle,
        intent: &crate::credential_journal::Intent,
    ) -> Result<(), Self::Error>;
}

pub struct ReferenceCommit {
    pub catalog: ReferencedCatalog,
    /// The metadata commit succeeded. Deferred GC retains its durable intents
    /// and must not turn this into a reported failed write that clients retry.
    pub deferred_gc: usize,
}

pub fn commit_referenced<B: ReferenceBackend>(
    backend: &mut B,
    current: &ReferencedCatalog,
    profiles: Catalog,
    changes: &BTreeMap<String, SecretChange>,
) -> Result<ReferenceCommit, B::Error> {
    if profiles.len() > repository::MAX_PROFILES {
        return Err(ControlError::new(ErrorCode::InvalidInput, "profile capacity reached").into());
    }
    for (id, profile) in &profiles {
        validation::profile(profile)?;
        if id != &profile.id {
            return Err(
                ControlError::new(ErrorCode::InvalidInput, "catalog identity mismatch").into(),
            );
        }
    }
    for (id, change) in changes {
        if let SecretChange::Replace(secret) = change {
            validation::password(secret)?;
            if !profiles.contains_key(id) {
                return Err(ControlError::new(
                    ErrorCode::InvalidInput,
                    "orphan credential mutation",
                )
                .into());
            }
        } else if !profiles.contains_key(id) && !current.profiles.contains_key(id) {
            return Err(
                ControlError::new(ErrorCode::InvalidInput, "unknown credential mutation").into(),
            );
        }
    }
    let mut next = ReferencedCatalog {
        profiles,
        stored: current.stored.clone(),
        unknown: current.unknown.clone(),
    };
    let mut intents = Vec::new();
    for (id, change) in changes {
        let old_ref = if current.stored.contains(id) || current.unknown.contains(id) {
            current
                .profiles
                .get(id)
                .map(|p| p.credential_ref.clone().unwrap_or_else(|| id.clone()))
        } else {
            None
        };
        let new_ref = match change {
            SecretChange::Replace(_) => Some(backend.allocate_reference()),
            SecretChange::Remove => None,
        };
        let intent = crate::credential_journal::Intent {
            profile_id: id.clone(),
            old_ref,
            new_ref: new_ref.clone(),
            delete_profile: !next.profiles.contains_key(id),
        };
        let handle = backend.begin(&intent)?;
        intents.push((handle, intent));
        next.unknown.remove(id);
        if let Some(profile) = next.profiles.get_mut(id) {
            profile.credential_ref = new_ref.clone();
        }
        match (change, new_ref) {
            (SecretChange::Replace(secret), Some(reference)) => {
                backend.write_secret(&reference, secret)?;
                next.stored.insert(id.clone());
            }
            _ => {
                next.stored.remove(id);
            }
        }
    }
    next.stored.retain(|id| next.profiles.contains_key(id));
    next.unknown.retain(|id| next.profiles.contains_key(id));
    backend.commit_metadata(&next)?;
    let deferred_gc = intents
        .iter()
        .filter(|(handle, intent)| backend.collect(handle, intent).is_err())
        .count();
    Ok(ReferenceCommit {
        catalog: next,
        deferred_gc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct MemoryRepository {
        profiles: Catalog,
        secrets: BTreeMap<String, Zeroizing<String>>,
        sessions: BTreeMap<String, Zeroizing<String>>,
        commits: usize,
        fail: bool,
    }
    impl ProfileRepository for MemoryRepository {
        type Error = ControlError;
        fn profiles(&self) -> &Catalog {
            &self.profiles
        }
        fn has_stored_secret(&mut self, id: &str) -> Result<bool, ControlError> {
            Ok(self.secrets.contains_key(id))
        }
        fn view(&self, id: &str) -> Result<ProfileView, ControlError> {
            Ok(ProfileView {
                profile: self.profiles[id].clone(),
                password_stored: self.secrets.contains_key(id),
                has_secret: self.secrets.contains_key(id) || self.sessions.contains_key(id),
            })
        }
        fn commit(&mut self, mutation: Mutation) -> Result<(), ControlError> {
            self.commits += 1;
            if self.fail {
                return Err(ControlError::new(
                    ErrorCode::RecoveryRequired,
                    "injected commit failure",
                ));
            }
            self.profiles = mutation.profiles;
            if mutation.clear_sessions {
                self.sessions.clear();
            }
            for (changes, target) in [
                (mutation.stored, &mut self.secrets),
                (mutation.session, &mut self.sessions),
            ] {
                for (id, change) in changes {
                    match change {
                        SecretChange::Replace(secret) => {
                            target.insert(id, secret);
                        }
                        SecretChange::Remove => {
                            target.remove(&id);
                        }
                    }
                }
            }
            Ok(())
        }
    }
    fn profile(id: &str) -> VpnProfile {
        serde_json::from_value(
            serde_json::json!({"id":id,"name":"Synthetic","host":"vpn.example.test"}),
        )
        .unwrap()
    }
    fn request(
        id: &str,
        secret: Option<&str>,
        remember: bool,
        revision: Option<u64>,
    ) -> SaveRequest {
        SaveRequest {
            profile: profile(id),
            password: secret.map(|s| Zeroizing::new(s.into())),
            remember_password: remember,
            expected_revision: revision,
        }
    }
    #[test]
    fn stale_revision_and_validation_fail_before_any_commit_or_credential_change() {
        let mut repo = MemoryRepository::default();
        save(
            &mut repo,
            request("one", Some("synthetic-old"), true, Some(0)),
            MissingPasswordPolicy::Allow,
        )
        .unwrap();
        let error = save(
            &mut repo,
            request("one", Some("synthetic-new"), true, Some(0)),
            MissingPasswordPolicy::Allow,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::RevisionConflict);
        assert!(delete(&mut repo, "one", Some(0)).is_err());
        let mut bad = request("one", Some("synthetic-new"), true, Some(1));
        bad.profile.host = "bad\nconfig".into();
        assert!(save(&mut repo, bad, MissingPasswordPolicy::Allow).is_err());
        assert_eq!(repo.commits, 1);
        assert_eq!(repo.secrets["one"].as_str(), "synthetic-old");
    }
    #[test]
    fn save_ignores_client_refs_normalizes_pins_and_moves_session_to_durable_storage() {
        let mut repo = MemoryRepository::default();
        let mut first = request("one", Some("synthetic-session"), false, Some(0));
        first.profile.credential_ref = Some("__remote_access_token".into());
        first.profile.trusted_cert = "AB".repeat(32);
        let view = save(&mut repo, first, MissingPasswordPolicy::Allow).unwrap();
        assert!(view.has_secret && !view.password_stored);
        assert!(view.profile.credential_ref.is_none());
        assert_eq!(view.profile.trusted_cert, "ab".repeat(32));
        save(
            &mut repo,
            request("one", Some("synthetic-stored"), true, Some(1)),
            MissingPasswordPolicy::Allow,
        )
        .unwrap();
        assert!(repo.sessions.is_empty());
        assert_eq!(repo.secrets["one"].as_str(), "synthetic-stored");
        let mut last = request("one", Some("synthetic-rejected"), false, Some(2));
        last.profile.auto_connect = true;
        assert!(save(&mut repo, last, MissingPasswordPolicy::Allow).is_err());
        assert_eq!(repo.profiles["one"].revision, 2);
    }
    #[test]
    fn failed_commit_keeps_session_and_restores_validate_entire_catalog_before_writes() {
        let mut repo = MemoryRepository::default();
        save(
            &mut repo,
            request("one", Some("synthetic-session"), false, None),
            MissingPasswordPolicy::Allow,
        )
        .unwrap();
        repo.fail = true;
        assert!(save(
            &mut repo,
            request("one", Some("synthetic-new"), true, None),
            MissingPasswordPolicy::Allow
        )
        .is_err());
        assert_eq!(repo.sessions["one"].as_str(), "synthetic-session");
        let mut overflow = profile("two");
        overflow.revision = u64::MAX;
        assert!(restore(&mut repo, 1, &[profile("one"), overflow], &BTreeMap::new()).is_err());
        assert_eq!(repo.commits, 2);
        repo.fail = false;
        restore(
            &mut repo,
            1,
            &[profile("two")],
            &BTreeMap::from([("two".into(), Zeroizing::new("synthetic-restored".into()))]),
        )
        .unwrap();
        assert!(repo.sessions.is_empty());
        assert!(!repo.profiles.contains_key("one"));
        assert_eq!(repo.secrets["two"].as_str(), "synthetic-restored");
        assert!(!delete(&mut repo, "absent", None).unwrap());
    }
    #[test]
    fn stop_first_revision_and_legacy_missing_password_contracts_are_explicit() {
        let profile = profile("one");
        assert_eq!(
            check_delete(&profile, Some(1), true, true)
                .unwrap_err()
                .code,
            ErrorCode::RevisionConflict
        );
        assert_eq!(
            check_delete(&profile, Some(0), true, false)
                .unwrap_err()
                .code,
            ErrorCode::ProfileBusy
        );
        assert!(check_delete(&profile, Some(0), true, true).is_ok());
        let mut repo = MemoryRepository::default();
        assert!(save(
            &mut repo,
            request("one", None, true, None),
            MissingPasswordPolicy::RequireWhenRemembering
        )
        .is_err());
        assert_eq!(repo.commits, 0);
        assert!(
            !save(
                &mut repo,
                request("one", None, true, None),
                MissingPasswordPolicy::Allow
            )
            .unwrap()
            .password_stored
        );
    }

    #[test]
    fn a_new_profile_never_adopts_a_native_reference_or_orphaned_secret_by_choosing_its_id() {
        let id = "credential:00000000-0000-4000-8000-000000000001";
        let mut repo = MemoryRepository::default();
        repo.secrets
            .insert(id.into(), Zeroizing::new("synthetic-other-profile".into()));
        let result = save(
            &mut repo,
            request(id, None, true, Some(0)),
            MissingPasswordPolicy::RequireWhenRemembering,
        );
        assert_eq!(result.unwrap_err().code, ErrorCode::InvalidInput);
        assert_eq!(repo.commits, 0);
        assert!(repo.profiles.is_empty());
        let view = save(
            &mut repo,
            request(id, None, true, Some(0)),
            MissingPasswordPolicy::Allow,
        )
        .unwrap();
        assert!(!view.password_stored);
        assert!(!repo.secrets.contains_key(id));
    }

    #[cfg(unix)]
    struct FaultBackend {
        root: tempfile::TempDir,
        durable: ReferencedCatalog,
        credentials: BTreeMap<String, String>,
        fail_at: usize,
        step: usize,
        serial: usize,
    }
    #[cfg(unix)]
    impl FaultBackend {
        fn boundary(&mut self) -> Result<(), ControlError> {
            self.step += 1;
            if self.step == self.fail_at {
                return Err(ControlError::new(
                    ErrorCode::RecoveryRequired,
                    "injected boundary failure",
                ));
            }
            Ok(())
        }
        fn recover(&mut self) {
            let active = self
                .durable
                .profiles
                .values()
                .filter(|p| self.durable.stored.contains(&p.id))
                .map(|p| p.credential_ref.clone().unwrap())
                .collect();
            crate::credential_journal::recover(
                self.root.path(),
                &active,
                &Default::default(),
                |reference| {
                    self.credentials.remove(reference);
                    Ok(())
                },
            )
            .unwrap();
        }
    }
    #[cfg(unix)]
    impl ReferenceBackend for FaultBackend {
        type Error = ControlError;
        type IntentHandle = std::path::PathBuf;
        fn allocate_reference(&mut self) -> String {
            self.serial += 1;
            format!("credential:00000000-0000-4000-8000-{:012}", self.serial)
        }
        fn begin(
            &mut self,
            intent: &crate::credential_journal::Intent,
        ) -> Result<Self::IntentHandle, ControlError> {
            self.boundary()?;
            crate::credential_journal::begin(self.root.path(), intent)
        }
        fn write_secret(&mut self, reference: &str, secret: &str) -> Result<(), ControlError> {
            // Native stores may commit then report an uncertain failure.
            self.credentials.insert(reference.into(), secret.into());
            self.boundary()
        }
        fn commit_metadata(&mut self, catalog: &ReferencedCatalog) -> Result<(), ControlError> {
            self.boundary()?;
            self.durable = catalog.clone();
            self.boundary()
        }
        fn collect(
            &mut self,
            handle: &Self::IntentHandle,
            intent: &crate::credential_journal::Intent,
        ) -> Result<(), ControlError> {
            self.boundary()?;
            let active = self
                .durable
                .profiles
                .values()
                .filter(|p| self.durable.stored.contains(&p.id))
                .map(|p| p.credential_ref.clone().unwrap())
                .collect();
            crate::credential_journal::collect(
                self.root.path(),
                handle,
                intent,
                &active,
                &Default::default(),
                &mut |reference| {
                    self.credentials.remove(reference);
                    Ok(())
                },
            )
        }
    }
    #[cfg(unix)]
    #[test]
    fn native_restore_faults_recover_every_prefix_without_deleting_live_credentials() {
        use std::os::unix::fs::PermissionsExt;
        // Two replacements and one removed profile exercise mid-batch failures,
        // uncertain secret writes, pre/post metadata commit and interrupted GC.
        for fail_at in 1..=11 {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut old = ReferencedCatalog::default();
            let mut credentials = BTreeMap::new();
            for (index, id) in ["one", "removed"].into_iter().enumerate() {
                let reference = format!("credential:00000000-0000-4000-8000-{:012}", 90 + index);
                let mut profile = profile(id);
                profile.credential_ref = Some(reference.clone());
                old.profiles.insert(id.into(), profile);
                old.stored.insert(id.into());
                credentials.insert(reference, format!("synthetic-{id}"));
            }
            let mut backend = FaultBackend {
                root,
                durable: old.clone(),
                credentials,
                fail_at,
                step: 0,
                serial: 0,
            };
            let profiles = BTreeMap::from([
                ("one".into(), profile("one")),
                ("two".into(), profile("two")),
            ]);
            let changes = BTreeMap::from([
                (
                    "one".into(),
                    SecretChange::Replace(Zeroizing::new("synthetic-new-one".into())),
                ),
                (
                    "two".into(),
                    SecretChange::Replace(Zeroizing::new("synthetic-new-two".into())),
                ),
                ("removed".into(), SecretChange::Remove),
            ]);
            let result = commit_referenced(&mut backend, &old, profiles, &changes);
            if let Ok(result) = result {
                assert_eq!(result.deferred_gc, usize::from((8..=10).contains(&fail_at)));
            }
            backend.recover();
            let live: BTreeSet<_> = backend
                .durable
                .profiles
                .values()
                .map(|p| p.credential_ref.as_ref().unwrap().clone())
                .collect();
            assert_eq!(
                backend.credentials.keys().cloned().collect::<BTreeSet<_>>(),
                live,
                "fault boundary {fail_at}"
            );
            assert!(backend
                .credentials
                .values()
                .all(|s| s.starts_with("synthetic-")));
            backend.recover();
        }
    }
}
