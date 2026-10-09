use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openfortivpn_manager_core::profile_service::{self, ProfileRepository, SecretChange};
use openfortivpn_manager_core::repository;
use openfortivpn_manager_core::validation;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

use crate::model::{ProfileView, ServerSettings, VpnProfile};

struct SecretMap(HashMap<String, String>);

impl std::ops::Deref for SecretMap {
    type Target = HashMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for SecretMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for SecretMap {
    fn drop(&mut self) {
        for secret in self.0.values_mut() {
            secret.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileTransaction {
    #[serde(default = "profile_schema")]
    schema_version: u32,
    profiles: serde_json::Value,
    secrets: HashMap<String, String>,
}
fn profile_schema() -> u32 {
    repository::PROFILE_SCHEMA
}
impl Drop for ProfileTransaction {
    fn drop(&mut self) {
        for secret in self.secrets.values_mut() {
            secret.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileBackup {
    schema_version: u32,
    profiles: Vec<VpnProfile>,
    secrets: HashMap<String, String>,
}

impl Drop for ProfileBackup {
    fn drop(&mut self) {
        for secret in self.secrets.values_mut() {
            secret.zeroize();
        }
    }
}

#[derive(Clone, Debug)]
pub struct Storage {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    session_secrets: Arc<Mutex<HashMap<String, Zeroizing<String>>>>,
}

struct LockedProfileRepository<'a> {
    storage: &'a Storage,
    _lock: fs::File,
    profiles: profile_service::Catalog,
    secrets: SecretMap,
    session: std::sync::MutexGuard<'a, HashMap<String, Zeroizing<String>>>,
}

impl ProfileRepository for LockedProfileRepository<'_> {
    type Error = anyhow::Error;
    fn profiles(&self) -> &profile_service::Catalog {
        &self.profiles
    }
    fn has_stored_secret(&mut self, id: &str) -> Result<bool> {
        Ok(self.secrets.contains_key(id))
    }
    fn view(&self, id: &str) -> Result<ProfileView> {
        Ok(ProfileView {
            profile: self
                .profiles
                .get(id)
                .ok_or_else(|| anyhow!("profile disappeared after commit"))?
                .clone(),
            password_stored: self.secrets.contains_key(id),
            has_secret: self.secrets.contains_key(id) || self.session.contains_key(id),
        })
    }
    fn commit(&mut self, mut mutation: profile_service::Mutation) -> Result<()> {
        let mut secrets = SecretMap(self.secrets.0.clone());
        for (id, change) in mutation.stored {
            if let Some(mut old) = secrets.remove(&id) {
                old.zeroize();
            }
            if let SecretChange::Replace(secret) = change {
                secrets.insert(id, secret.to_string());
            }
        }
        // This adapter stores a paired ID-keyed redo document, not native refs.
        for profile in mutation.profiles.values_mut() {
            profile.credential_ref = None;
        }
        if mutation.clear_sessions {
            let rollback = ProfileBackup {
                schema_version: 1,
                profiles: self.profiles.values().cloned().collect(),
                secrets: self.secrets.0.clone(),
            };
            self.storage.write_json_private(
                &self
                    .storage
                    .config_dir
                    .join(format!(".restore-backup-{}.json", uuid::Uuid::new_v4())),
                &rollback,
            )?;
        }
        self.storage.commit_profiles(&mutation.profiles, &secrets)?;
        self.profiles = mutation.profiles;
        self.secrets = secrets;
        if mutation.clear_sessions {
            self.session.clear();
        }
        for (id, change) in mutation.session {
            self.session.remove(&id);
            if let SecretChange::Replace(secret) = change {
                self.session.insert(id, secret);
            }
        }
        Ok(())
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            config_dir: PathBuf::from("/etc/openfortivpn-manager-headless"),
            state_dir: PathBuf::from("/var/lib/openfortivpn-manager-headless"),
            runtime_dir: PathBuf::from("/run/openfortivpn-manager-headless"),
            session_secrets: Arc::default(),
        }
    }
}

impl Storage {
    pub fn new(config_dir: PathBuf, state_dir: PathBuf, runtime_dir: PathBuf) -> Self {
        Self {
            config_dir,
            state_dir,
            runtime_dir,
            session_secrets: Arc::default(),
        }
    }

    pub fn ensure_layout(&self) -> Result<()> {
        for directory in [&self.config_dir, &self.state_dir, &self.runtime_dir] {
            fs::create_dir_all(directory)
                .with_context(|| format!("failed to create {}", directory.display()))?;
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            {
                bail!(
                    "refusing directory with unexpected type or owner: {}",
                    directory.display()
                );
            }
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("failed to secure {}", directory.display()))?;
        }
        Ok(())
    }

    fn profiles_path(&self) -> PathBuf {
        self.config_dir.join("profiles.json")
    }

    fn secrets_path(&self) -> PathBuf {
        self.config_dir.join("secrets.json")
    }

    fn settings_path(&self) -> PathBuf {
        self.config_dir.join("server.json")
    }

    fn token_path(&self) -> PathBuf {
        self.config_dir.join("access-token")
    }

    pub fn certificate_path(&self) -> PathBuf {
        self.config_dir.join("certificate.pem")
    }

    pub fn private_key_path(&self) -> PathBuf {
        self.config_dir.join("private-key.pem")
    }

    fn transaction_lock(&self) -> Result<fs::File> {
        self.ensure_layout()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(self.config_dir.join(".storage.lock"))?;
        if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("failed to lock configuration");
        }
        self.recover_transaction()?;
        Ok(file)
    }

    fn profile_repository(&self) -> Result<LockedProfileRepository<'_>> {
        let lock = self.transaction_lock()?;
        Ok(LockedProfileRepository {
            storage: self,
            _lock: lock,
            profiles: self.load_profiles_unlocked()?,
            secrets: SecretMap(self.read_json_or_default(&self.secrets_path())?),
            session: self
                .session_secrets
                .lock()
                .map_err(|_| anyhow!("session credential lock poisoned"))?,
        })
    }

    pub fn service_lock(&self) -> Result<fs::File> {
        self.ensure_layout()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(self.config_dir.join(".service.lock"))?;
        if unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) }
            != 0
        {
            bail!("another manager owns the runtime directory");
        }
        Ok(file)
    }

    fn run_records_dir(&self) -> Result<PathBuf> {
        self.ensure_layout()?;
        let directory = self.state_dir.join("runs");
        fs::create_dir_all(&directory)?;
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.is_dir() || metadata.uid() != nix::unistd::Uid::effective().as_raw() {
            bail!("invalid run journal directory");
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn run_record_path(&self, attempt: &str) -> Result<PathBuf> {
        uuid::Uuid::parse_str(attempt).context("invalid run journal attempt ID")?;
        Ok(self.run_records_dir()?.join(format!("{attempt}.json")))
    }

    pub fn write_run_record<T: Serialize>(&self, attempt: &str, record: &T) -> Result<()> {
        self.write_json_private(&self.run_record_path(attempt)?, record)
    }

    pub fn run_records<T: DeserializeOwned>(&self) -> Result<Vec<T>> {
        let directory = self.run_records_dir()?;
        let mut records = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| anyhow!("invalid run journal filename"))?;
            // Atomic writer temporary files have never committed an attempt.
            if name.starts_with('.') {
                continue;
            }
            let attempt = name
                .strip_suffix(".json")
                .ok_or_else(|| anyhow!("invalid run journal filename"))?;
            self.run_record_path(attempt)?;
            let value: serde_json::Value = self.read_json(&entry.path())?;
            if value.get("attemptId").and_then(serde_json::Value::as_str) != Some(attempt) {
                bail!("run journal identity does not match its filename");
            }
            records.push(serde_json::from_value(value)?);
        }
        Ok(records)
    }

    pub fn remove_run_record(&self, attempt: &str) -> Result<()> {
        let path = self.run_record_path(attempt)?;
        match fs::remove_file(&path) {
            Ok(()) => fs::File::open(path.parent().unwrap())?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    /// A backup is one private consistent document; session credentials and
    /// server/token/TLS identity are intentionally separate administrative data.
    pub fn backup_profiles(&self, destination: &Path) -> Result<()> {
        let _lock = self.transaction_lock()?;
        if destination.exists() {
            bail!("backup destination already exists");
        }
        let backup = ProfileBackup {
            schema_version: 1,
            profiles: self.load_profiles_unlocked()?.into_values().collect(),
            secrets: self.read_json_or_default(&self.secrets_path())?,
        };
        // create_new prevents overwriting an existing file or symlink even if
        // one appears after the existence check; remove incomplete output.
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)?;
        use std::io::Write;
        let result = (|| -> Result<()> {
            serde_json::to_writer_pretty(&mut output, &backup)?;
            output.write_all(b"\n")?;
            output.sync_all()?;
            if let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(destination);
        }
        result
    }

    pub fn restore_profiles(&self, source: &Path) -> Result<()> {
        let _service = self.service_lock()?;
        let mut repository = self.profile_repository()?;
        if !self.run_records::<serde_json::Value>()?.is_empty() {
            bail!("unfinished engine attempts require recovery before restoring profiles");
        }
        let backup: ProfileBackup = self.read_json(source)?;
        let secrets = backup
            .secrets
            .iter()
            .map(|(id, secret)| (id.clone(), Zeroizing::new(secret.clone())))
            .collect();
        profile_service::restore(
            &mut repository,
            backup.schema_version,
            &backup.profiles,
            &secrets,
        )
    }
    /// Explicit offline preparation for a pre-schema binary rollback. Passwords
    /// stay paired with their current profile IDs; retain a private rollback copy.
    pub fn prepare_legacy_rollback(&self) -> Result<PathBuf> {
        let _service = self.service_lock()?;
        let _lock = self.transaction_lock()?;
        if !self.run_records::<serde_json::Value>()?.is_empty() {
            bail!("unfinished VPN attempts require recovery before schema downgrade");
        }
        let profiles = self
            .load_profiles_unlocked()?
            .into_values()
            .collect::<Vec<_>>();
        let backup = ProfileBackup {
            schema_version: 1,
            profiles: profiles.clone(),
            secrets: self.read_json_or_default(&self.secrets_path())?,
        };
        let path = self
            .config_dir
            .join(format!(".downgrade-backup-{}.json", uuid::Uuid::new_v4()));
        self.write_json_private(&path, &backup)?;
        // Schema 0 stored a raw metadata array and the same ID-keyed credential
        // map. Only metadata changes, under the existing cross-process lock.
        self.write_json_private(&self.profiles_path(), &profiles)?;
        Ok(path)
    }

    fn load_profiles_unlocked(&self) -> Result<BTreeMap<String, VpnProfile>> {
        if !self.profiles_path().exists() {
            return Ok(BTreeMap::new());
        }
        let values: Vec<VpnProfile> =
            repository::decode_value(self.read_json(&self.profiles_path())?)?.profiles;
        let mut profiles = BTreeMap::new();
        for mut profile in values {
            validate_profile(&profile)?;
            profile.trusted_cert = validation::certificate_pin(&profile.trusted_cert)?;
            if profiles.insert(profile.id.clone(), profile).is_some() {
                bail!("duplicate profile id in configuration");
            }
        }
        Ok(profiles)
    }

    pub fn load_profiles(&self) -> Result<BTreeMap<String, VpnProfile>> {
        let _lock = self.transaction_lock()?;
        self.load_profiles_unlocked()
    }

    pub fn load_secrets(&self) -> Result<HashMap<String, String>> {
        let _lock = self.transaction_lock()?;
        self.read_json_or_default(&self.secrets_path())
    }

    fn recover_transaction(&self) -> Result<()> {
        let path = self.config_dir.join(".profile-transaction.json");
        if path.exists() {
            let mut pending: ProfileTransaction = self.read_json(&path)?;
            if pending.schema_version != repository::PROFILE_SCHEMA {
                bail!("unsupported profile transaction schema");
            }
            let profiles: Vec<VpnProfile> =
                repository::decode_value(pending.profiles.clone())?.profiles;
            let mut ids = std::collections::HashSet::new();
            for profile in &profiles {
                validate_profile(profile)?;
                if !ids.insert(&profile.id) {
                    bail!("duplicate profile in transaction");
                }
            }
            for (id, secret) in &pending.secrets {
                if !ids.contains(id) {
                    bail!("orphan credential in transaction");
                }
                validation::password(secret)?;
            }
            self.backup_legacy_metadata()?;
            self.write_private(&self.profiles_path(), &repository::encode(profiles)?)?;
            self.write_json_private(&self.secrets_path(), &pending.secrets)?;
            for secret in pending.secrets.values_mut() {
                secret.zeroize();
            }
            fs::remove_file(path)?;
            fs::File::open(&self.config_dir)?.sync_all()?;
        }
        Ok(())
    }
    fn backup_legacy_metadata(&self) -> Result<()> {
        let path = self.profiles_path();
        if !path.exists() {
            return Ok(());
        }
        let bytes = openfortivpn_manager_core::private_file::read(
            &path,
            repository::MAX_PROFILE_BYTES as u64,
        )?;
        let decoded = repository::decode::<VpnProfile>(&bytes)?;
        if decoded.legacy {
            let pair_path = self.config_dir.join(".migration-backup-schema0.json");
            if !pair_path.exists() {
                let pair = ProfileBackup {
                    schema_version: 1,
                    profiles: decoded.profiles,
                    secrets: self.read_json_or_default(&self.secrets_path())?,
                };
                self.write_json_private(&pair_path, &pair)?;
            }
            let backup = self.config_dir.join(".profiles-schema0-backup.json");
            if !backup.exists() {
                self.write_private(&backup, &bytes)?;
            }
        }
        Ok(())
    }

    fn commit_profiles(
        &self,
        profiles: &BTreeMap<String, VpnProfile>,
        secrets: &HashMap<String, String>,
    ) -> Result<()> {
        let values: Vec<&VpnProfile> = profiles.values().collect();
        self.backup_legacy_metadata()?;
        let document: serde_json::Value = serde_json::from_slice(&repository::encode(values)?)?;
        // The private redo journal is the commit point. Every reader/writer
        // holds the same process-independent lock and finishes an interrupted pair.
        self.write_json_private(
            &self.config_dir.join(".profile-transaction.json"),
            &serde_json::json!({"schemaVersion":repository::PROFILE_SCHEMA,"profiles": document, "secrets": secrets}),
        )?;
        self.recover_transaction()
    }

    pub fn list_profile_views(&self) -> Result<Vec<ProfileView>> {
        let _lock = self.transaction_lock()?;
        let profiles = self.load_profiles_unlocked()?;
        let secrets: HashMap<String, String> = self.read_json_or_default(&self.secrets_path())?;
        let secrets = SecretMap(secrets);
        let session = self
            .session_secrets
            .lock()
            .map_err(|_| anyhow!("session credential lock poisoned"))?;
        Ok(profiles
            .into_values()
            .map(|profile| {
                let stored = secrets.contains_key(&profile.id);
                ProfileView {
                    has_secret: stored || session.contains_key(&profile.id),
                    password_stored: stored,
                    profile,
                }
            })
            .collect())
    }

    pub fn save_profile(
        &self,
        profile: VpnProfile,
        password: Option<String>,
        remember_password: bool,
    ) -> Result<ProfileView> {
        self.save_profile_expected(profile, password, remember_password, None)
    }

    pub fn save_profile_expected(
        &self,
        profile: VpnProfile,
        password: Option<String>,
        remember_password: bool,
        expected_revision: Option<u64>,
    ) -> Result<ProfileView> {
        let password = password.map(Zeroizing::new);
        let mut repository = self.profile_repository()?;
        profile_service::save(
            &mut repository,
            profile_service::SaveRequest {
                profile,
                password,
                remember_password,
                expected_revision,
            },
            profile_service::MissingPasswordPolicy::Allow,
        )
    }

    pub fn delete_profile(&self, profile_id: &str) -> Result<bool> {
        self.delete_profile_expected(profile_id, None)
    }

    pub fn delete_profile_expected(
        &self,
        profile_id: &str,
        expected_revision: Option<u64>,
    ) -> Result<bool> {
        profile_service::delete(
            &mut self.profile_repository()?,
            profile_id,
            expected_revision,
        )
    }

    pub fn profile_and_password(&self, profile_id: &str) -> Result<(VpnProfile, String)> {
        let _lock = self.transaction_lock()?;
        let profile = self
            .load_profiles_unlocked()?
            .remove(profile_id)
            .ok_or_else(|| {
                openfortivpn_manager_core::ControlError::new(
                    openfortivpn_manager_core::ErrorCode::ProfileNotFound,
                    "profile not found",
                )
            })?;
        let secrets: HashMap<String, String> = self.read_json_or_default(&self.secrets_path())?;
        let secrets = SecretMap(secrets);
        let session = self
            .session_secrets
            .lock()
            .map_err(|_| anyhow!("session credential lock poisoned"))?;
        let password = session
            .get(profile_id)
            .map(|value| value.to_string())
            .or_else(|| secrets.get(profile_id).cloned())
            .ok_or_else(|| {
                openfortivpn_manager_core::ControlError::new(
                    openfortivpn_manager_core::ErrorCode::InvalidInput,
                    "profile has no VPN password",
                )
            })?;
        validation::password(&password)?;
        Ok((profile, password))
    }

    pub fn load_or_create_settings(&self) -> Result<ServerSettings> {
        let _lock = self.transaction_lock()?;
        let path = self.settings_path();
        if path.exists() {
            return self.read_json(&path);
        }
        let settings = ServerSettings::default();
        self.write_json_private(&path, &settings)?;
        Ok(settings)
    }

    pub fn load_or_create_token(&self) -> Result<String> {
        let _lock = self.transaction_lock()?;
        let path = self.token_path();
        if path.exists() {
            secure_existing_file(&path)?;
            let token = fs::read_to_string(&path)?.trim().to_string();
            if token.len() < 32 {
                bail!("stored access token is invalid");
            }
            secure_existing_file(&path)?;
            return Ok(token);
        }
        self.rotate_token_unlocked()
    }

    pub fn read_access_token(&self) -> Result<Zeroizing<String>> {
        let path = self.token_path();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)?;
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > 1024
        {
            bail!("access token file has invalid type, owner, mode or size");
        }
        let mut contents = Zeroizing::new(String::new());
        file.take(1025).read_to_string(&mut contents)?;
        let token = Zeroizing::new(contents.trim().to_string());
        if token.len() < 32 {
            bail!("stored access token is invalid");
        }
        Ok(token)
    }

    pub fn rotate_token(&self) -> Result<String> {
        let _lock = self.transaction_lock()?;
        self.rotate_token_unlocked()
    }

    fn rotate_token_unlocked(&self) -> Result<String> {
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let token = URL_SAFE_NO_PAD.encode(bytes);
        self.write_private(&self.token_path(), format!("{token}\n").as_bytes())?;
        Ok(token)
    }

    pub fn ensure_certificate(&self, bind_address: &str) -> Result<(PathBuf, PathBuf)> {
        let _lock = self.transaction_lock()?;
        openfortivpn_manager_core::tls_identity::TlsIdentityStore::new(&self.config_dir)
            .ensure(bind_address)
            .context("failed to prepare HTTPS identity")
    }

    pub fn runtime_config_path(&self, instance_id: &str) -> PathBuf {
        self.runtime_dir.join(format!("{instance_id}.conf"))
    }

    pub fn write_runtime_config(
        &self,
        profile: &VpnProfile,
        password: &str,
        instance_id: &str,
    ) -> Result<PathBuf> {
        validate_profile(profile)?;
        validation::password(password)?;
        let mut config = Zeroizing::new(String::from(
            "# Generated by openfortivpn-manager. Do not edit.\n",
        ));
        push_line(&mut config, "host", profile.host.trim());
        push_line(&mut config, "port", &profile.port.to_string());
        push_line(&mut config, "username", &profile.username);
        push_line(&mut config, "password", password);
        push_line(&mut config, "realm", &profile.realm);
        push_line(&mut config, "trusted-cert", &profile.trusted_cert);
        push_line(&mut config, "set-routes", bool_value(profile.set_routes));
        push_line(&mut config, "set-dns", bool_value(profile.set_dns));
        push_line(
            &mut config,
            "pppd-use-peerdns",
            bool_value(profile.pppd_use_peerdns),
        );
        push_line(
            &mut config,
            "half-internet-routes",
            bool_value(profile.half_internet_routes),
        );
        let path = self.runtime_config_path(instance_id);
        self.write_private(&path, config.as_bytes())?;
        Ok(path)
    }

    fn read_json_or_default<T>(&self, path: &Path) -> Result<T>
    where
        T: DeserializeOwned + Default,
    {
        if !path.exists() {
            return Ok(T::default());
        }
        self.read_json(path)
    }

    fn read_json<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let contents = Zeroizing::new(openfortivpn_manager_core::private_file::read(
            path,
            repository::MAX_PROFILE_BYTES as u64,
        )?);
        serde_json::from_slice(&contents)
            .with_context(|| format!("invalid JSON in {}", path.display()))
    }

    fn write_json_private<T: Serialize + ?Sized>(&self, path: &Path, value: &T) -> Result<()> {
        let contents = Zeroizing::new(serde_json::to_vec_pretty(value)?);
        self.write_private(path, &contents)
    }

    fn write_private(&self, path: &Path, contents: &[u8]) -> Result<()> {
        let parent = path.parent().ok_or_else(|| anyhow!("path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        openfortivpn_manager_core::atomic_file::write_private(path, contents)
            .with_context(|| format!("failed to replace {}", path.display()))
    }
}

fn secure_existing_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("refusing insecure non-regular file: {}", path.display());
    }
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        bail!("file has unexpected owner: {}", path.display());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn validate_profile(profile: &VpnProfile) -> Result<()> {
    validation::profile(profile).map_err(Into::into)
}

fn push_line(buffer: &mut String, key: &str, value: &str) {
    if !value.is_empty() {
        buffer.push_str(key);
        buffer.push_str(" = ");
        buffer.push_str(value);
        buffer.push('\n');
    }
}

fn bool_value(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::os::unix::fs::PermissionsExt;

    fn profile() -> VpnProfile {
        VpnProfile {
            id: "office".into(),
            revision: 0,
            name: "Office".into(),
            host: "vpn.example.com".into(),
            port: 443,
            username: "alice".into(),
            realm: String::new(),
            trusted_cert: String::new(),
            credential_ref: None,
            set_routes: true,
            set_dns: true,
            pppd_use_peerdns: false,
            half_internet_routes: false,
            use_sudo: true,
            auto_connect: false,
            auto_reconnect: true,
        }
    }

    #[test]
    fn passwords_are_separate_and_private() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        storage.ensure_layout().unwrap();
        let view = storage
            .save_profile(profile(), Some("very-secret".into()), true)
            .unwrap();
        assert!(view.password_stored);
        let profiles = fs::read_to_string(storage.profiles_path()).unwrap();
        assert!(!profiles.contains("very-secret"));
        assert!(fs::read_to_string(storage.secrets_path())
            .unwrap()
            .contains("very-secret"));
        assert_eq!(
            fs::metadata(storage.secrets_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&storage.config_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn rejects_configuration_injection() {
        let mut unsafe_profile = profile();
        unsafe_profile.host = "vpn.example.com\npassword = stolen".into();
        assert!(validate_profile(&unsafe_profile).is_err());
    }

    #[test]
    fn runtime_config_is_private() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        storage.ensure_layout().unwrap();
        let path = storage
            .write_runtime_config(&profile(), "secret", "instance")
            .unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fn test_storage(root: &Path) -> Storage {
        Storage::new(root.join("etc"), root.join("state"), root.join("run"))
    }

    #[test]
    fn profile_save_cannot_adopt_a_client_supplied_credential_reference() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        let mut input = profile();
        input.credential_ref = Some("__remote_access_token".into());
        let view = storage
            .save_profile(input, Some("synthetic".into()), true)
            .unwrap();
        assert!(view.profile.credential_ref.is_none());
        assert!(storage.load_profiles().unwrap()["office"]
            .credential_ref
            .is_none());
    }

    #[test]
    fn concurrent_successful_saves_are_not_lost() {
        let root = tempfile::tempdir().unwrap();
        test_storage(root.path()).ensure_layout().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        std::thread::scope(|scope| {
            for index in 0..16 {
                let storage = test_storage(root.path());
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let mut value = profile();
                    value.id = format!("profile-{index}");
                    barrier.wait();
                    storage
                        .save_profile(value, Some("secret".into()), true)
                        .unwrap();
                });
            }
        });
        let storage = test_storage(root.path());
        assert_eq!(storage.load_profiles().unwrap().len(), 16);
        assert_eq!(storage.load_secrets().unwrap().len(), 16);
    }

    #[test]
    fn backup_restore_is_private_revisioned_and_refuses_online_restore() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        let old = storage
            .save_profile(profile(), Some("old-synthetic".into()), true)
            .unwrap();
        let backup = root.path().join("backup.json");
        storage.backup_profiles(&backup).unwrap();
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(storage.backup_profiles(&backup).is_err());
        let mut changed = old.profile;
        changed.name = "Changed".into();
        storage
            .save_profile(changed, Some("new-synthetic".into()), true)
            .unwrap();
        let lease = storage.service_lock().unwrap();
        assert!(storage.restore_profiles(&backup).is_err());
        drop(lease);
        storage.restore_profiles(&backup).unwrap();
        let (profile, password) = storage.profile_and_password("office").unwrap();
        assert_eq!(profile.name, "Office");
        assert_eq!(profile.revision, 3);
        assert_eq!(password, "old-synthetic");
        let copies: Vec<_> = fs::read_dir(&storage.config_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".restore-backup-")
            })
            .collect();
        assert_eq!(copies.len(), 1);
        let old: ProfileBackup = storage.read_json(&copies[0].path()).unwrap();
        assert_eq!(old.secrets["office"], "new-synthetic");
    }
    #[test]
    fn legacy_downgrade_is_offline_preserves_password_pair_and_keeps_a_private_backup() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        let saved = storage
            .save_profile(profile(), Some("synthetic-rollback".into()), true)
            .unwrap();
        let service = storage.service_lock().unwrap();
        assert!(storage.prepare_legacy_rollback().is_err());
        drop(service);
        let backup = storage.prepare_legacy_rollback().unwrap();
        assert_eq!(
            fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let profiles: Vec<VpnProfile> =
            serde_json::from_slice(&fs::read(storage.profiles_path()).unwrap()).unwrap();
        assert_eq!(profiles[0].revision, saved.profile.revision);
        assert_eq!(
            storage.profile_and_password(&saved.profile.id).unwrap().1,
            "synthetic-rollback"
        );
        storage
            .save_profile(profiles[0].clone(), None, true)
            .unwrap();
        assert!(
            !repository::decode::<VpnProfile>(&fs::read(storage.profiles_path()).unwrap())
                .unwrap()
                .legacy
        );
    }

    #[test]
    fn invalid_backup_never_changes_current_profile_or_secret() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage
            .save_profile(profile(), Some("current-synthetic".into()), true)
            .unwrap();
        let before = fs::read(storage.profiles_path()).unwrap();
        let source = root.path().join("bad.json");
        for document in [
            serde_json::json!({"schemaVersion":99,"profiles":[],"secrets":{}}),
            serde_json::json!({"schemaVersion":1,"profiles":[profile(),profile()],"secrets":{}}),
            serde_json::json!({"schemaVersion":1,"profiles":[profile()],"secrets":{"office":"injected\npassword"}}),
            serde_json::json!({"schemaVersion":1,"profiles":[],"secrets":{"orphan":"secret"}}),
        ] {
            storage.write_json_private(&source, &document).unwrap();
            assert!(storage.restore_profiles(&source).is_err());
            assert_eq!(fs::read(storage.profiles_path()).unwrap(), before);
            assert_eq!(
                storage.profile_and_password("office").unwrap().1,
                "current-synthetic"
            );
        }
    }

    #[test]
    fn session_password_is_connectable_but_not_persisted() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage.ensure_layout().unwrap();
        let view = storage
            .save_profile(profile(), Some("session-secret".into()), false)
            .unwrap();
        assert!(view.has_secret);
        assert!(!view.password_stored);
        assert_eq!(
            storage.profile_and_password("office").unwrap().1,
            "session-secret"
        );
        assert!(storage.load_secrets().unwrap().is_empty());
        assert!(test_storage(root.path())
            .profile_and_password("office")
            .is_err());
    }

    #[test]
    fn rejects_passwords_the_c_parser_cannot_preserve() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage.ensure_layout().unwrap();
        for password in [
            " leading".to_string(),
            "trailing ".into(),
            "nul\0byte".into(),
            "a".repeat(257),
        ] {
            assert!(storage
                .save_profile(profile(), Some(password), true)
                .is_err());
        }
    }

    #[test]
    fn bind_change_regenerates_the_certificate_identity() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage.ensure_layout().unwrap();
        let (cert, _) = storage.ensure_certificate("127.0.0.1").unwrap();
        let first = fs::read(&cert).unwrap();
        storage.ensure_certificate("192.0.2.1").unwrap();
        assert_ne!(first, fs::read(&cert).unwrap());
    }

    #[test]
    fn interrupted_profile_secret_pair_is_recovered_before_reading() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage.ensure_layout().unwrap();
        storage
            .save_profile(profile(), Some("old-secret".into()), true)
            .unwrap();
        let mut updated = profile();
        updated.name = "Committed update".into();
        storage
            .write_json_private(
                &storage.config_dir.join(".profile-transaction.json"),
                &serde_json::json!({"profiles":[updated],"secrets":{"office":"new-secret"}}),
            )
            .unwrap();
        // Simulate power loss after the first file replacement.
        storage
            .write_json_private(&storage.profiles_path(), &vec![profile()])
            .unwrap();
        let reopened = test_storage(root.path());
        let (profile, password) = reopened.profile_and_password("office").unwrap();
        assert_eq!(profile.name, "Committed update");
        assert_eq!(password, "new-secret");
        assert!(!storage
            .config_dir
            .join(".profile-transaction.json")
            .exists());
    }
    #[test]
    fn legacy_migration_keeps_a_private_consistent_pair_and_future_schema_is_not_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage.ensure_layout().unwrap();
        storage
            .write_json_private(&storage.profiles_path(), &vec![profile()])
            .unwrap();
        storage
            .write_json_private(
                &storage.secrets_path(),
                &serde_json::json!({"office":"synthetic-legacy-password"}),
            )
            .unwrap();
        storage
            .save_profile(profile(), Some("synthetic-current-password".into()), true)
            .unwrap();
        let document: serde_json::Value = storage.read_json(&storage.profiles_path()).unwrap();
        assert_eq!(document["schemaVersion"], repository::PROFILE_SCHEMA);
        let backup_path = storage.config_dir.join(".migration-backup-schema0.json");
        let pair: ProfileBackup = storage.read_json(&backup_path).unwrap();
        assert_eq!(pair.profiles[0].id, "office");
        assert_eq!(pair.secrets["office"], "synthetic-legacy-password");
        assert_eq!(
            fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        storage
            .write_json_private(
                &storage.profiles_path(),
                &serde_json::json!({"schemaVersion":99,"profiles":[]}),
            )
            .unwrap();
        let before = fs::read(storage.profiles_path()).unwrap();
        assert!(storage
            .save_profile(profile(), Some("must-not-be-committed".into()), true)
            .is_err());
        assert_eq!(fs::read(storage.profiles_path()).unwrap(), before);
        assert_eq!(
            storage.load_secrets().unwrap()["office"],
            "synthetic-current-password"
        );
    }

    #[test]
    fn secrets_symlink_is_rejected_before_reading() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage.ensure_layout().unwrap();
        let target = root.path().join("external");
        fs::write(&target, "{\"office\":\"external-secret\"}").unwrap();
        std::os::unix::fs::symlink(&target, storage.secrets_path()).unwrap();
        assert!(storage.load_secrets().is_err());
    }

    #[test]
    fn only_one_service_can_own_the_runtime_directory() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        let first = storage.service_lock().unwrap();
        assert!(test_storage(root.path()).service_lock().is_err());
        drop(first);
        assert!(storage.service_lock().is_ok());
    }

    #[test]
    fn operator_certificate_is_preserved_and_wrong_identity_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage.ensure_layout().unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["console.example.com".into()]).unwrap();
        storage
            .write_private(&storage.certificate_path(), cert.pem().as_bytes())
            .unwrap();
        storage
            .write_private(
                &storage.private_key_path(),
                signing_key.serialize_pem().as_bytes(),
            )
            .unwrap();
        let before = fs::read(storage.certificate_path()).unwrap();
        storage.ensure_certificate("console.example.com").unwrap();
        assert_eq!(before, fs::read(storage.certificate_path()).unwrap());
        assert!(storage.ensure_certificate("wrong.example.com").is_err());
        assert_eq!(before, fs::read(storage.certificate_path()).unwrap());
    }

    #[test]
    fn mismatched_operator_private_key_is_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let storage = test_storage(root.path());
        storage.ensure_layout().unwrap();
        let first = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let second = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        storage
            .write_private(&storage.certificate_path(), first.cert.pem().as_bytes())
            .unwrap();
        storage
            .write_private(
                &storage.private_key_path(),
                second.signing_key.serialize_pem().as_bytes(),
            )
            .unwrap();
        let before = fs::read(storage.private_key_path()).unwrap();
        assert!(storage.ensure_certificate("localhost").is_err());
        assert_eq!(before, fs::read(storage.private_key_path()).unwrap());
    }
}
