use super::*;
use openfortivpn_manager_core::profile_service::{
    self, ProfileRepository, ReferenceBackend, ReferencedCatalog, SecretChange,
};
use openfortivpn_manager_http::ApiError;

pub(super) fn acquire_ownership(directory: &std::path::Path) -> Result<fs::File, String> {
    openfortivpn_manager_core::private_file::verify_directory(directory)
        .map_err(|_| "配置目录所有者、权限或类型异常".to_string())?;
    openfortivpn_manager_core::private_file::try_lock(
        &directory.join(".repository-owner.lock"),
        false,
    )
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            "已有进程拥有此配置仓库，请先退出该进程".to_string()
        } else {
            "无法获得私有配置仓库锁，请检查权限和恢复状态".to_string()
        }
    })
}

/// The transaction guard spans snapshot, native staging, metadata replacement,
/// cache publication and GC. Lifecycle reservations are held by the caller.
pub(super) struct DesktopRepository {
    app: AppHandle,
    snapshot: ReferencedCatalog,
    _transaction: std::sync::MutexGuard<'static, ()>,
}
impl DesktopRepository {
    pub(super) fn new(app: &AppHandle) -> Result<Self, ApiError> {
        let transaction = CREDENTIAL_TRANSACTIONS
            .lock()
            .map_err(|_| "凭据事务状态已损坏")?;
        let state = app.state::<AppState>();
        let store = lock_store(&state)?;
        ensure_repository_ready(&store).map_err(|_| repository_api_error())?;
        Ok(Self {
            app: app.clone(),
            snapshot: ReferencedCatalog {
                profiles: store.profiles.clone(),
                stored: store.stored_secret_profiles.iter().cloned().collect(),
                unknown: store.unknown_secret_profiles.iter().cloned().collect(),
            },
            _transaction: transaction,
        })
    }
}
impl ProfileRepository for DesktopRepository {
    type Error = ApiError;
    fn profiles(&self) -> &profile_service::Catalog {
        &self.snapshot.profiles
    }
    fn has_stored_secret(&mut self, id: &str) -> Result<bool, ApiError> {
        if !self.snapshot.profiles.contains_key(id) {
            return Ok(false);
        }
        let reference = self
            .snapshot
            .profiles
            .get(id)
            .and_then(|p| p.credential_ref.as_deref())
            .unwrap_or(id);
        let password = read_stored_password(&self.app, reference)?.map(zeroize::Zeroizing::new);
        if let Some(password) = password {
            validate_password(&password)?;
            self.snapshot.stored.insert(id.into());
            self.snapshot.unknown.remove(id);
            Ok(true)
        } else {
            self.snapshot.stored.remove(id);
            self.snapshot.unknown.remove(id);
            Ok(false)
        }
    }
    fn view(&self, id: &str) -> Result<ProfileView, ApiError> {
        let state = self.app.state::<AppState>();
        let store = lock_store(&state)?;
        let profile = store.profiles.get(id).ok_or("找不到指定配置")?;
        let stored = store.stored_secret_profiles.contains(id);
        Ok(profile_view(
            profile,
            stored || store.secrets.contains_key(id),
            stored,
        ))
    }
    fn commit(&mut self, mutation: profile_service::Mutation) -> Result<(), ApiError> {
        if mutation.clear_sessions {
            backup::write_restore_backup(&self.app)?;
        }
        let current = self.snapshot.clone();
        let result = profile_service::commit_referenced(
            self,
            &current,
            mutation.profiles,
            &mutation.stored,
        )?;
        self.snapshot = result.catalog;
        let state = self.app.state::<AppState>();
        let mut store = lock_store(&state)?;
        if mutation.clear_sessions {
            for secret in store.secrets.values_mut() {
                secret.zeroize();
            }
            store.secrets.clear();
            store.reconnect_attempts.clear();
            store.reconnect_generations.clear();
            store.instances.clear();
        }
        for (id, change) in mutation.session {
            if let Some(mut old) = store.secrets.remove(&id) {
                old.zeroize();
            }
            if let SecretChange::Replace(secret) = change {
                store.secrets.insert(id, secret.to_string());
            }
        }
        if result.deferred_gc > 0 {
            eprintln!("Credential cleanup deferred; durable recovery intents retained");
        }
        Ok(())
    }
}
impl ReferenceBackend for DesktopRepository {
    type Error = ApiError;
    type IntentHandle = PathBuf;
    fn allocate_reference(&mut self) -> String {
        format!("credential:{}", Uuid::new_v4())
    }
    fn begin(&mut self, intent: &CredentialIntent) -> Result<PathBuf, ApiError> {
        Ok(begin_credential_intent(&self.app, intent)?)
    }
    fn write_secret(&mut self, reference: &str, secret: &str) -> Result<(), ApiError> {
        Ok(store_password(&self.app, reference, secret)?)
    }
    fn commit_metadata(&mut self, catalog: &ReferencedCatalog) -> Result<(), ApiError> {
        let stored = catalog.stored.iter().cloned().collect();
        let unknown = catalog.unknown.iter().cloned().collect();
        let state = self.app.state::<AppState>();
        let mut store = lock_store(&state)?;
        commit_profile_metadata(&mut store, || {
            persist_profiles(&self.app, &catalog.profiles, &stored, &unknown)
        })
        .map_err(|_| repository_api_error())?;
        store.profiles = catalog.profiles.clone();
        store.stored_secret_profiles = stored;
        store.unknown_secret_profiles = unknown;
        Ok(())
    }
    fn collect(&mut self, path: &PathBuf, intent: &CredentialIntent) -> Result<(), ApiError> {
        let loaded = load_profiles(&self.app)?;
        Ok(collect_credential_intent(&self.app, path, intent, &loaded)?)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use openfortivpn_manager_core::{credential_journal, ControlError, ErrorCode};
    struct FileBackend {
        directory: PathBuf,
        store: RuntimeStore,
        fail_at: usize,
        step: usize,
        serial: usize,
    }
    fn injected() -> ControlError {
        ControlError::new(ErrorCode::RecoveryRequired, "synthetic transaction fault")
    }
    #[test]
    fn repository_ownership_excludes_other_binaries_and_rejects_lock_symlinks() {
        let directory = env::temp_dir().join(format!("ofv-repository-owner-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = acquire_ownership(&directory).unwrap();
        assert!(acquire_ownership(&directory)
            .unwrap_err()
            .contains("已有进程"));
        drop(owner);
        drop(acquire_ownership(&directory).unwrap());
        let path = directory.join(".repository-owner.lock");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(acquire_ownership(&directory).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
    impl FileBackend {
        fn boundary(&mut self) -> Result<(), ControlError> {
            self.step += 1;
            if self.step == self.fail_at {
                Err(injected())
            } else {
                Ok(())
            }
        }
        fn loaded(&self) -> LoadedProfiles {
            let bytes = openfortivpn_manager_core::private_file::read_metadata(
                &self.directory.join("profiles.json"),
                16 * 1024 * 1024,
            )
            .unwrap();
            parse_profile_file(std::str::from_utf8(&bytes).unwrap()).unwrap()
        }
        fn delete_secret(&self, reference: &str) -> Result<(), ControlError> {
            let path = self.directory.join("credentials.json");
            let mut credentials = load_local_credentials_file(&path).map_err(|_| injected())?;
            if let Some(mut value) = credentials.remove(reference) {
                value.zeroize();
            }
            persist_local_credentials_file(&path, &credentials).map_err(|_| injected())
        }
    }
    impl ReferenceBackend for FileBackend {
        type Error = ControlError;
        type IntentHandle = PathBuf;
        fn allocate_reference(&mut self) -> String {
            self.serial += 1;
            format!("credential:00000000-0000-4000-8000-{:012}", self.serial)
        }
        fn begin(&mut self, intent: &CredentialIntent) -> Result<PathBuf, ControlError> {
            self.boundary()?;
            credential_journal::begin(&self.directory, intent)
        }
        fn write_secret(&mut self, reference: &str, secret: &str) -> Result<(), ControlError> {
            let path = self.directory.join("credentials.json");
            let mut credentials = load_local_credentials_file(&path).map_err(|_| injected())?;
            credentials.insert(reference.into(), secret.into());
            persist_local_credentials_file(&path, &credentials).map_err(|_| injected())?;
            // A native write can succeed before returning an uncertain error.
            self.boundary()
        }
        fn commit_metadata(&mut self, catalog: &ReferencedCatalog) -> Result<(), ControlError> {
            let stored = catalog.stored.iter().cloned().collect();
            let unknown = catalog.unknown.iter().cloned().collect();
            let bytes = serialize_profile_file(&catalog.profiles, &stored, &unknown)
                .map_err(|_| injected())?;
            let before = self.boundary();
            let after = self.boundary();
            commit_profile_metadata(&mut self.store, || {
                before.map_err(|e| e.to_string())?;
                openfortivpn_manager_core::atomic_file::write_private(
                    &self.directory.join("profiles.json"),
                    bytes.as_bytes(),
                )
                .map_err(|e| e.to_string())?;
                after.map_err(|e| e.to_string())
            })
            .map_err(|_| injected())?;
            self.store.profiles = catalog.profiles.clone();
            self.store.stored_secret_profiles = stored;
            self.store.unknown_secret_profiles = unknown;
            Ok(())
        }
        fn collect(
            &mut self,
            path: &PathBuf,
            intent: &CredentialIntent,
        ) -> Result<(), ControlError> {
            self.boundary()?;
            credential_journal::collect(
                &self.directory,
                path,
                intent,
                &credential_references(&self.loaded()),
                &HashSet::new(),
                &mut |reference| self.delete_secret(reference),
            )
        }
    }
    #[test]
    fn real_local_credential_and_metadata_files_recover_each_restore_fault_boundary() {
        for fail_at in 1..=11 {
            let directory = env::temp_dir().join(format!("ofv-native-restore-{}", Uuid::new_v4()));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let mut old = ReferencedCatalog::default();
            let mut credentials = BTreeMap::new();
            for id in ["one", "removed"] {
                let mut profile: VpnProfile = serde_json::from_value(serde_json::json!({ "id": id, "name": "Synthetic", "host": "vpn.example.test" })).unwrap();
                let reference = format!("credential:{}", Uuid::new_v4());
                profile.credential_ref = Some(reference.clone());
                credentials.insert(reference, "synthetic-old".into());
                old.stored.insert(id.into());
                old.profiles.insert(id.into(), profile);
            }
            persist_local_credentials_file(&directory.join("credentials.json"), &credentials)
                .unwrap();
            let bytes = serialize_profile_file(
                &old.profiles,
                &old.stored.iter().cloned().collect(),
                &HashSet::new(),
            )
            .unwrap();
            openfortivpn_manager_core::atomic_file::write_private(
                &directory.join("profiles.json"),
                bytes.as_bytes(),
            )
            .unwrap();
            let mut backend = FileBackend {
                directory: directory.clone(),
                store: RuntimeStore {
                    profiles: old.profiles.clone(),
                    stored_secret_profiles: old.stored.iter().cloned().collect(),
                    ..RuntimeStore::default()
                },
                fail_at,
                step: 0,
                serial: 0,
            };
            let mut profiles = old.profiles.clone();
            profiles.remove("removed");
            let mut second = profiles["one"].clone();
            second.id = "two".into();
            second.credential_ref = None;
            profiles.insert("two".into(), second);
            let changes = BTreeMap::from([
                (
                    "one".into(),
                    SecretChange::Replace(zeroize::Zeroizing::new("synthetic-new-one".into())),
                ),
                (
                    "two".into(),
                    SecretChange::Replace(zeroize::Zeroizing::new("synthetic-new-two".into())),
                ),
                ("removed".into(), SecretChange::Remove),
            ]);
            let result = profile_service::commit_referenced(&mut backend, &old, profiles, &changes);
            if (6..=7).contains(&fail_at) {
                assert!(result.is_err());
                assert!(ensure_repository_ready(&backend.store).is_err());
            }
            let loaded = backend.loaded();
            let active = credential_references(&loaded);
            credential_journal::recover(&directory, &active, &HashSet::new(), |reference| {
                backend.delete_secret(reference)
            })
            .unwrap();
            let credentials =
                load_local_credentials_file(&directory.join("credentials.json")).unwrap();
            assert_eq!(
                credentials.keys().cloned().collect::<HashSet<_>>(),
                active,
                "native file fault {fail_at}"
            );
            apply_recovered_profiles(&mut backend.store, loaded);
            assert!(ensure_repository_ready(&backend.store).is_ok());
            fs::remove_dir_all(directory).unwrap();
        }
    }
}
