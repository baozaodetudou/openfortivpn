//! Local-only portable profile/credential export and transactional restore.
use super::*;
use zeroize::Zeroizing;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Archive {
    schema_version: u32,
    profiles: Vec<VpnProfile>,
    secrets: BTreeMap<String, String>,
}
impl Drop for Archive {
    fn drop(&mut self) {
        for secret in self.secrets.values_mut() {
            secret.zeroize();
        }
    }
}
fn validate(archive: &Archive) -> Result<(), String> {
    openfortivpn_manager_core::repository::validate_portable_archive(
        archive.schema_version,
        &archive.profiles,
        archive
            .secrets
            .iter()
            .map(|(id, secret)| (id.as_str(), secret.as_str())),
    )
    .map_err(|e| e.to_string())
}
fn capture(app: &AppHandle) -> Result<Archive, String> {
    let (profiles, stored, unknown) = {
        let state = app.state::<AppState>();
        let store = lock_store(&state)?;
        ensure_repository_ready(&store)?;
        (
            store.profiles.clone(),
            store.stored_secret_profiles.clone(),
            store.unknown_secret_profiles.clone(),
        )
    };
    let mut archive = Archive {
        schema_version: 1,
        profiles: Vec::new(),
        secrets: BTreeMap::new(),
    };
    for mut profile in profiles.into_values() {
        if stored.contains(&profile.id) || unknown.contains(&profile.id) {
            let reference = profile.credential_ref.as_deref().unwrap_or(&profile.id);
            let password = read_stored_password(app, reference)?
                .ok_or("备份无法读取某个配置的已保存密码，请先修复凭据")?;
            archive.secrets.insert(profile.id.clone(), password);
        }
        profile.credential_ref = None;
        archive.profiles.push(profile);
    }
    validate(&archive)?;
    Ok(archive)
}
fn export(app: &AppHandle, output: &std::path::Path) -> Result<(), String> {
    if !output.is_absolute() {
        return Err("请填写备份文件的完整路径".into());
    }
    let _transaction = CREDENTIAL_TRANSACTIONS
        .lock()
        .map_err(|_| "凭据事务不可用")?;
    let archive = capture(app)?;
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(&archive).map_err(|e| e.to_string())?);
    if bytes.len() > openfortivpn_manager_core::repository::MAX_PROFILE_BYTES {
        return Err("备份超过大小限制".into());
    }
    openfortivpn_manager_core::atomic_file::write_new_private(output, &bytes)
        .map_err(|_| "无法写入私有备份；目标必须不存在且目录可写".into())
}
pub(super) struct RestoreGuard(pub(super) AppHandle);
impl Drop for RestoreGuard {
    fn drop(&mut self) {
        if let Ok(mut store) = self.0.state::<AppState>().store.lock() {
            store.restoring_repository = false;
        }
    }
}
pub(super) fn write_restore_backup(app: &AppHandle) -> Result<(), String> {
    let before = capture(app)?;
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(&before).map_err(|e| e.to_string())?);
    openfortivpn_manager_core::atomic_file::write_new_private(
        &app_data_dir(app)?.join(format!(".restore-backup-{}.json", Uuid::new_v4())),
        &bytes,
    )
    .map_err(|e| e.to_string())
}
fn restore(app: &AppHandle, input: &std::path::Path) -> Result<(), String> {
    if !input.is_absolute() {
        return Err("请填写备份文件的完整路径".into());
    }
    let bytes = Zeroizing::new(
        openfortivpn_manager_core::private_file::read(
            input,
            openfortivpn_manager_core::repository::MAX_PROFILE_BYTES as u64,
        )
        .map_err(|_| "无法读取私有备份，请检查文件所有者和权限")?,
    );
    let archive: Archive = serde_json::from_slice(&bytes).map_err(|_| "备份格式无效")?;
    validate(&archive)?;
    {
        let state = app.state::<AppState>();
        let mut store = lock_store(&state)?;
        ensure_repository_ready(&store)?;
        if !repository_is_idle(&store) {
            return Err("请先停止所有连接、完成恢复和配置操作，再还原备份".into());
        }
        store.restoring_repository = true;
    }
    let _guard = RestoreGuard(app.clone());
    let mut repository = profile_repository::DesktopRepository::new(app).map_err(|e| e.message)?;
    let secrets = archive
        .secrets
        .iter()
        .map(|(id, secret)| (id.clone(), Zeroizing::new(secret.clone())))
        .collect();
    openfortivpn_manager_core::profile_service::restore(
        &mut repository,
        archive.schema_version,
        &archive.profiles,
        &secrets,
    )
    .map_err(|e| e.message)?;
    drop(repository);
    publish_privilege_status(app);
    schedule_tray_refresh(app);
    let state = app.state::<AppState>();
    if let Ok(profiles) = super::list_profiles(state) {
        let _ = app.emit("vpn-profiles-changed", profiles);
    }
    Ok(())
}
#[tauri::command]
pub(super) async fn backup_profiles(app: AppHandle, output: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || export(&app, &PathBuf::from(output)))
        .await
        .map_err(|_| "备份工作线程失败".to_string())?
}
#[tauri::command]
pub(super) async fn restore_profiles(app: AppHandle, input: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || restore(&app, &PathBuf::from(input)))
        .await
        .map_err(|_| "还原工作线程失败".to_string())?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn portable_archive_rejects_internal_refs_orphans_and_missing_autoconnect_secrets() {
        let mut profile = VpnProfile {
            id: Uuid::new_v4().to_string(),
            name: "Synthetic".into(),
            host: "vpn.example".into(),
            port: 443,
            username: "user".into(),
            realm: String::new(),
            trusted_cert: String::new(),
            set_routes: true,
            set_dns: true,
            pppd_use_peerdns: false,
            half_internet_routes: false,
            use_sudo: true,
            auto_connect: false,
            auto_reconnect: false,
            revision: 1,
            credential_ref: None,
        };
        let mut archive = Archive {
            schema_version: 1,
            profiles: vec![profile.clone()],
            secrets: BTreeMap::new(),
        };
        validate(&archive).unwrap();
        archive.secrets.insert("orphan".into(), "synthetic".into());
        assert!(validate(&archive).is_err());
        archive.secrets.clear();
        profile.auto_connect = true;
        archive.profiles[0] = profile.clone();
        assert!(validate(&archive).is_err());
        archive
            .secrets
            .insert(profile.id.clone(), "synthetic".into());
        validate(&archive).unwrap();
        archive.profiles[0].credential_ref = Some("credential:synthetic".into());
        assert!(validate(&archive).is_err());
        archive.profiles[0].credential_ref = None;
        archive.profiles.push(profile);
        assert!(validate(&archive).is_err());
    }
}
