use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::model::{ProfileView, ServerSettings, VpnProfile};

#[derive(Clone, Debug)]
pub struct Storage {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            config_dir: PathBuf::from("/etc/openfortivpn-manager-headless"),
            state_dir: PathBuf::from("/var/lib/openfortivpn-manager-headless"),
            runtime_dir: PathBuf::from("/run/openfortivpn-manager-headless"),
        }
    }
}

impl Storage {
    pub fn new(config_dir: PathBuf, state_dir: PathBuf, runtime_dir: PathBuf) -> Self {
        Self {
            config_dir,
            state_dir,
            runtime_dir,
        }
    }

    pub fn ensure_layout(&self) -> Result<()> {
        for directory in [&self.config_dir, &self.state_dir, &self.runtime_dir] {
            fs::create_dir_all(directory)
                .with_context(|| format!("failed to create {}", directory.display()))?;
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

    pub fn load_profiles(&self) -> Result<BTreeMap<String, VpnProfile>> {
        let values: Vec<VpnProfile> = self.read_json_or_default(&self.profiles_path())?;
        Ok(values
            .into_iter()
            .map(|profile| (profile.id.clone(), profile))
            .collect())
    }

    pub fn save_profiles(&self, profiles: &BTreeMap<String, VpnProfile>) -> Result<()> {
        let values: Vec<&VpnProfile> = profiles.values().collect();
        self.write_json_private(&self.profiles_path(), &values)
    }

    pub fn load_secrets(&self) -> Result<HashMap<String, String>> {
        self.read_json_or_default(&self.secrets_path())
    }

    pub fn save_secrets(&self, secrets: &HashMap<String, String>) -> Result<()> {
        self.write_json_private(&self.secrets_path(), secrets)
    }

    pub fn list_profile_views(&self) -> Result<Vec<ProfileView>> {
        let profiles = self.load_profiles()?;
        let mut secrets = self.load_secrets()?;
        let views = profiles
            .into_values()
            .map(|profile| {
                let stored = secrets.contains_key(&profile.id);
                ProfileView {
                    profile,
                    has_secret: stored,
                    password_stored: stored,
                }
            })
            .collect();
        for secret in secrets.values_mut() {
            secret.zeroize();
        }
        Ok(views)
    }

    pub fn save_profile(
        &self,
        profile: VpnProfile,
        password: Option<String>,
        remember_password: bool,
    ) -> Result<ProfileView> {
        validate_profile(&profile)?;
        if password
            .as_deref()
            .is_some_and(|value| value.contains(['\n', '\r']))
        {
            bail!("password cannot contain a newline");
        }
        let mut profiles = self.load_profiles()?;
        let mut secrets = self.load_secrets()?;
        profiles.insert(profile.id.clone(), profile.clone());
        match (
            remember_password,
            password.filter(|value| !value.is_empty()),
        ) {
            (true, Some(value)) => {
                secrets.insert(profile.id.clone(), value);
            }
            (false, _) => {
                secrets.remove(&profile.id);
            }
            (true, None) => {}
        }
        self.save_profiles(&profiles)?;
        self.save_secrets(&secrets)?;
        let stored = secrets.contains_key(&profile.id);
        let view = ProfileView {
            profile,
            has_secret: stored,
            password_stored: stored,
        };
        for secret in secrets.values_mut() {
            secret.zeroize();
        }
        Ok(view)
    }

    pub fn delete_profile(&self, profile_id: &str) -> Result<bool> {
        let mut profiles = self.load_profiles()?;
        let mut secrets = self.load_secrets()?;
        let removed = profiles.remove(profile_id).is_some();
        secrets.remove(profile_id);
        self.save_profiles(&profiles)?;
        self.save_secrets(&secrets)?;
        for secret in secrets.values_mut() {
            secret.zeroize();
        }
        Ok(removed)
    }

    pub fn profile_and_password(&self, profile_id: &str) -> Result<(VpnProfile, String)> {
        let profile = self
            .load_profiles()?
            .remove(profile_id)
            .ok_or_else(|| anyhow!("profile not found: {profile_id}"))?;
        let mut secrets = self.load_secrets()?;
        let password = secrets
            .remove(profile_id)
            .ok_or_else(|| anyhow!("profile has no stored VPN password"))?;
        for secret in secrets.values_mut() {
            secret.zeroize();
        }
        Ok((profile, password))
    }

    pub fn load_or_create_settings(&self) -> Result<ServerSettings> {
        let path = self.settings_path();
        if path.exists() {
            return self.read_json(&path);
        }
        let settings = ServerSettings::default();
        self.write_json_private(&path, &settings)?;
        Ok(settings)
    }

    pub fn load_or_create_token(&self) -> Result<String> {
        let path = self.token_path();
        if path.exists() {
            let token = fs::read_to_string(&path)?.trim().to_string();
            if token.len() < 32 {
                bail!("stored access token is invalid");
            }
            secure_existing_file(&path)?;
            return Ok(token);
        }
        self.rotate_token()
    }

    pub fn rotate_token(&self) -> Result<String> {
        self.ensure_layout()?;
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let token = URL_SAFE_NO_PAD.encode(bytes);
        self.write_private(&self.token_path(), format!("{token}\n").as_bytes())?;
        Ok(token)
    }

    pub fn ensure_certificate(&self, bind_address: &str) -> Result<(PathBuf, PathBuf)> {
        let cert = self.certificate_path();
        let key = self.private_key_path();
        if cert.is_file() && key.is_file() {
            secure_existing_file(&cert)?;
            secure_existing_file(&key)?;
            return Ok((cert, key));
        }
        let mut names = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        if !bind_address.is_empty() && !names.iter().any(|name| name == bind_address) {
            names.push(bind_address.to_string());
        }
        let CertifiedKey {
            cert: generated,
            signing_key,
        } = generate_simple_self_signed(names)
            .context("failed to generate self-signed certificate")?;
        self.write_private(&key, signing_key.serialize_pem().as_bytes())?;
        self.write_private(&cert, generated.pem().as_bytes())?;
        Ok((cert, key))
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
        validate_line("password", password)?;
        let mut config = String::from("# Generated by openfortivpn-manager. Do not edit.\n");
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
        let contents =
            fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_slice(&contents)
            .with_context(|| format!("invalid JSON in {}", path.display()))
    }

    fn write_json_private<T: Serialize + ?Sized>(&self, path: &Path, value: &T) -> Result<()> {
        let contents = serde_json::to_vec_pretty(value)?;
        self.write_private(path, &contents)
    }

    fn write_private(&self, path: &Path, contents: &[u8]) -> Result<()> {
        let parent = path.parent().ok_or_else(|| anyhow!("path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name().unwrap().to_string_lossy(),
            Uuid::new_v4()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| format!("failed to replace {}", path.display()));
        }
        secure_existing_file(path)
    }
}

fn secure_existing_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("refusing insecure non-regular file: {}", path.display());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn validate_profile(profile: &VpnProfile) -> Result<()> {
    if profile.id.trim().is_empty()
        || profile.name.trim().is_empty()
        || profile.host.trim().is_empty()
    {
        bail!("profile id, name and host are required");
    }
    if profile.port == 0 {
        bail!("port must be between 1 and 65535");
    }
    for (label, value) in [
        ("id", profile.id.as_str()),
        ("name", profile.name.as_str()),
        ("host", profile.host.as_str()),
        ("username", profile.username.as_str()),
        ("realm", profile.realm.as_str()),
    ] {
        validate_line(label, value)?;
    }
    if !profile.trusted_cert.is_empty()
        && (profile.trusted_cert.len() != 64
            || !profile
                .trusted_cert
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
    {
        bail!("trustedCert must be a 64-character SHA-256 digest");
    }
    Ok(())
}

fn validate_line(label: &str, value: &str) -> Result<()> {
    if value.contains(['\n', '\r']) {
        bail!("{label} cannot contain a newline");
    }
    Ok(())
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
    use std::os::unix::fs::PermissionsExt;

    fn profile() -> VpnProfile {
        VpnProfile {
            id: "office".into(),
            name: "Office".into(),
            host: "vpn.example.com".into(),
            port: 443,
            username: "alice".into(),
            realm: String::new(),
            trusted_cert: String::new(),
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
}
