use openfortivpn_manager_core::log_buffer::LogBuffer;
use openfortivpn_manager_core::protocol::{Line, LineDecoder};
use openfortivpn_manager_core::supervisor::{OwnedProcess, StreamWorker as StreamReader};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, Wry};
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;
use uuid::Uuid;
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_BREAK_EVENT,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;
use zeroize::Zeroize;

mod authentication;
mod backup;
mod profile_repository;
mod remote;

static CREDENTIAL_TRANSACTIONS: Mutex<()> = Mutex::new(());

type CredentialIntent = openfortivpn_manager_core::credential_journal::Intent;

#[cfg(unix)]
type SystemNetworkLease = openfortivpn_manager_core::network_authority::ExclusiveLease;
#[cfg(windows)]
type SystemNetworkLease = openfortivpn_manager_core::windows_network_authority::WindowsLease;

fn begin_credential_intent(app: &AppHandle, intent: &CredentialIntent) -> Result<PathBuf, String> {
    openfortivpn_manager_core::credential_journal::begin(&app_data_dir(app)?, intent)
        .map_err(|e| e.to_string())
}

fn credential_references(loaded: &LoadedProfiles) -> HashSet<String> {
    loaded
        .profiles
        .values()
        .filter(|profile| {
            loaded.stored_secret_profiles.contains(&profile.id)
                || loaded.unknown_secret_profiles.contains(&profile.id)
        })
        .map(|profile| {
            profile
                .credential_ref
                .clone()
                .unwrap_or_else(|| profile.id.clone())
        })
        .collect()
}
fn backup_credential_references(app: &AppHandle) -> Result<HashSet<String>, String> {
    let backup_path = app_data_dir(app)?.join(".profiles-schema0-backup.json");
    if !backup_path.exists() {
        return Ok(HashSet::new());
    }
    let bytes = openfortivpn_manager_core::private_file::read(
        &backup_path,
        openfortivpn_manager_core::repository::MAX_PROFILE_BYTES as u64,
    )
    .map_err(|e| e.to_string())?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "迁移备份编码错误")?;
    Ok(credential_references(&parse_profile_file(text)?))
}
fn credential_gc_delete(
    app: &AppHandle,
    reference: &str,
) -> Result<(), openfortivpn_manager_core::ControlError> {
    delete_stored_password(app, reference).map_err(|_| {
        openfortivpn_manager_core::ControlError::new(
            openfortivpn_manager_core::ErrorCode::RecoveryRequired,
            "无法回收旧凭据，请完成配置仓库恢复",
        )
    })
}
fn collect_credential_intent(
    app: &AppHandle,
    path: &std::path::Path,
    intent: &CredentialIntent,
    loaded: &LoadedProfiles,
) -> Result<(), String> {
    openfortivpn_manager_core::credential_journal::collect(
        &app_data_dir(app)?,
        path,
        intent,
        &credential_references(loaded),
        &backup_credential_references(app)?,
        &mut |reference| credential_gc_delete(app, reference),
    )
    .map_err(|e| e.to_string())
}
fn recover_credential_intents(app: &AppHandle, loaded: &LoadedProfiles) -> Result<(), String> {
    openfortivpn_manager_core::credential_journal::recover(
        &app_data_dir(app)?,
        &credential_references(loaded),
        &backup_credential_references(app)?,
        |reference| credential_gc_delete(app, reference),
    )
    .map_err(|e| e.to_string())
}

use openfortivpn_manager_core::domain::{
    EngineInfo, LogEvent, PrivilegeStatus, ProfileView, VpnProfile,
};
type InstanceView = openfortivpn_manager_core::domain::InstanceView<String>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveProfileInput {
    profile: VpnProfile,
    password: Option<String>,
    #[serde(default)]
    remember_password: bool,
    #[serde(default)]
    expected_revision: Option<u64>,
}

impl Drop for SaveProfileInput {
    fn drop(&mut self) {
        if let Some(password) = &mut self.password {
            password.zeroize();
        }
    }
}

struct ManagedInstance {
    view: InstanceView,
    source_profile: VpnProfile,
    child: OwnedProcess,
    input: Option<Arc<openfortivpn_manager_core::private_input::PrivateInput>>,
    process_running: bool,
    lifecycle: openfortivpn_manager_core::lifecycle::EngineLifecycle,
    user_requested_stop: bool,
    reconnect_blocked: bool,
    failure_message: Option<String>,
}

#[derive(Default)]
struct LoadedProfiles {
    profiles: BTreeMap<String, VpnProfile>,
    stored_secret_profiles: HashSet<String>,
    unknown_secret_profiles: HashSet<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedVpnProfile {
    #[serde(flatten)]
    profile: VpnProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_stored: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeProcessRecord {
    instance_id: String,
    profile_id: String,
    pid: u32,
    process_group_id: u32,
    engine_path: String,
    config_path: String,
    #[cfg(windows)]
    #[serde(default)]
    process_identity: Option<openfortivpn_manager_core::windows_process::WindowsProcessIdentity>,
}

#[derive(Default)]
struct RuntimeStore {
    profiles: BTreeMap<String, VpnProfile>,
    secrets: HashMap<String, String>,
    stored_secret_profiles: HashSet<String>,
    unknown_secret_profiles: HashSet<String>,
    instances: BTreeMap<String, ManagedInstance>,
    starting_profiles: HashSet<String>,
    mutating_profiles: HashSet<String>,
    restoring_repository: bool,
    repository_recovery_required: bool,
    reconnect_attempts: HashMap<String, u32>,
    reconnect_generations: HashMap<String, u64>,
    logs: LogBuffer,
    stale_processes: BTreeMap<String, RuntimeProcessRecord>,
    challenges: openfortivpn_manager_core::control::Challenges,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct DesktopPreferences {
    close_to_tray: bool,
    start_minimized: bool,
}

impl Default for DesktopPreferences {
    fn default() -> Self {
        Self {
            close_to_tray: true,
            start_minimized: true,
        }
    }
}

#[derive(Clone)]
enum TrayAction {
    Connect(String),
    Disconnect(String),
    Reconnect(String),
}

struct TrayUi {
    status_item: MenuItem<Wry>,
    window_item: MenuItem<Wry>,
    disconnect_all_item: MenuItem<Wry>,
    profiles_menu: Submenu<Wry>,
}

#[derive(Default)]
struct AppState {
    store: Mutex<RuntimeStore>,
    repository_guard: Mutex<Option<fs::File>>,
    commands: Arc<openfortivpn_manager_core::actor::ProfileActors>,
    engine_cache: Mutex<Option<(Instant, PathBuf, EngineInfo)>>,
    lifecycle: Mutex<()>,
    desktop_preferences: Mutex<DesktopPreferences>,
    tray_ui: Mutex<Option<TrayUi>>,
    tray_actions: Mutex<HashMap<String, TrayAction>>,
    privilege_ready: AtomicBool,
    shutting_down: AtomicBool,
    quit_requested: AtomicBool,
    exit_cleanup_complete: AtomicBool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineEvent {
    instance_id: String,
    profile_id: String,
    profile_revision: u64,
    host: String,
    port: u16,
    payload: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AutoConnectError {
    profile_id: String,
    profile_name: String,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppExitBlocked {
    message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayActionError {
    profile_id: Option<String>,
    message: String,
}

const KEYRING_SERVICE: &str = "com.baozaodetudou.openfortivpn";
const TRAY_ID: &str = "openfortivpn-manager-tray";
const TRAY_TOGGLE_WINDOW_ID: &str = "tray-toggle-window";
const TRAY_DISCONNECT_ALL_ID: &str = "tray-disconnect-all";
const TRAY_QUIT_ID: &str = "tray-quit";
#[cfg(test)]
const MAX_RETAINED_LOGS: usize = openfortivpn_manager_core::log_buffer::MAX_LOGS;
const REMOTE_TOKEN_PROFILE_ID: &str = "__remote_access_token";
static CREDENTIAL_ACCESS: Mutex<()> = Mutex::new(());

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn lock_store<'a>(
    state: &'a State<'_, AppState>,
) -> Result<std::sync::MutexGuard<'a, RuntimeStore>, String> {
    state
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let path = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法确定应用数据目录：{error}"))?;
    fs::create_dir_all(&path).map_err(|error| format!("无法创建应用数据目录：{error}"))?;
    let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("应用数据目录不能是符号链接或普通文件".into());
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("应用数据目录不属于当前用户".into());
    }
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("无法保护应用数据目录：{error}"))?;
    openfortivpn_manager_core::private_file::verify_directory(&path).map_err(|e| e.to_string())?;
    Ok(path)
}

fn profiles_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("profiles.json"))
}

fn desktop_preferences_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("desktop-preferences.json"))
}

fn parse_desktop_preferences(contents: &str) -> Result<DesktopPreferences, String> {
    serde_json::from_str(contents).map_err(|error| format!("桌面设置格式错误：{error}"))
}

fn load_desktop_preferences(app: &AppHandle) -> Result<DesktopPreferences, String> {
    let path = desktop_preferences_path(app)?;
    if !path.exists() {
        return Ok(DesktopPreferences::default());
    }
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取桌面设置 {}：{error}", path.display()))?;
    parse_desktop_preferences(&contents)
}

fn persist_desktop_preferences(
    app: &AppHandle,
    preferences: &DesktopPreferences,
) -> Result<(), String> {
    let path = desktop_preferences_path(app)?;
    let contents = serde_json::to_string_pretty(preferences)
        .map_err(|error| format!("无法序列化桌面设置：{error}"))?;
    #[cfg(unix)]
    {
        let temporary = path.with_file_name(format!(".desktop-preferences.{}.tmp", Uuid::new_v4()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| format!("无法创建临时桌面设置：{error}"))?;
        if let Err(error) = file
            .write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
        {
            let _ = fs::remove_file(&temporary);
            return Err(format!("无法保存临时桌面设置：{error}"));
        }
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(format!("无法保存桌面设置 {}：{error}", path.display()));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("无法设置桌面设置权限：{error}"))?;
    }
    #[cfg(not(unix))]
    fs::write(&path, contents)
        .map_err(|error| format!("无法保存桌面设置 {}：{error}", path.display()))?;
    Ok(())
}

fn should_hide_window_on_close(
    preferences: &DesktopPreferences,
    quit_requested: bool,
    shutting_down: bool,
) -> bool {
    preferences.close_to_tray && !quit_requested && !shutting_down
}

fn should_start_hidden(launched_from_autostart: bool, start_minimized: bool) -> bool {
    launched_from_autostart && start_minimized
}

fn tray_status_text(statuses: &[&str]) -> String {
    let connected = statuses
        .iter()
        .filter(|status| **status == "connected")
        .count();
    let connecting = statuses
        .iter()
        .filter(|status| matches!(**status, "starting" | "connecting" | "disconnecting"))
        .count();
    let failed = statuses.contains(&"failed");
    match (connected, connecting, failed) {
        (connected, connecting, _) if connected > 0 && connecting > 0 => {
            format!("已连接 {connected} 个 · 正在连接 {connecting} 个")
        }
        (connected, _, _) if connected > 0 => format!("已连接 {connected} 个 VPN"),
        (_, connecting, _) if connecting > 0 => format!("正在连接 {connecting} 个 VPN"),
        (_, _, true) => "VPN 未连接 · 最近连接失败".to_string(),
        _ => "VPN 未连接".to_string(),
    }
}

fn parse_profile_file(contents: &str) -> Result<LoadedProfiles, String> {
    let values: Vec<PersistedVpnProfile> =
        openfortivpn_manager_core::repository::decode(contents.as_bytes())
            .map_err(|error| error.to_string())?
            .profiles;
    let mut loaded = LoadedProfiles::default();
    let mut references = HashSet::new();
    for mut value in values {
        validate_profile(&value.profile)?;
        value.profile.trusted_cert =
            openfortivpn_manager_core::validation::certificate_pin(&value.profile.trusted_cert)
                .map_err(|e| e.to_string())?;
        let profile_id = value.profile.id.clone();
        if loaded.profiles.contains_key(&profile_id) {
            return Err("配置文件含重复 ID".into());
        }
        if let Some(reference) = &value.profile.credential_ref {
            if reference != &profile_id
                && reference
                    .strip_prefix("credential:")
                    .is_none_or(|id| Uuid::parse_str(id).is_err())
            {
                return Err("配置文件含无效凭据引用".into());
            }
            if !references.insert(reference.clone()) {
                return Err("多个配置使用相同凭据引用".into());
            }
        }
        match value.password_stored {
            Some(true) => {
                loaded.stored_secret_profiles.insert(profile_id.clone());
            }
            Some(false) => {}
            None => {
                loaded.unknown_secret_profiles.insert(profile_id.clone());
            }
        }
        loaded.profiles.insert(profile_id, value.profile);
    }
    Ok(loaded)
}

fn serialize_profile_file(
    profiles: &BTreeMap<String, VpnProfile>,
    stored_secret_profiles: &HashSet<String>,
    unknown_secret_profiles: &HashSet<String>,
) -> Result<String, String> {
    let values = profiles
        .values()
        .cloned()
        .map(|profile| PersistedVpnProfile {
            password_stored: if unknown_secret_profiles.contains(&profile.id) {
                None
            } else {
                Some(stored_secret_profiles.contains(&profile.id))
            },
            profile,
        })
        .collect::<Vec<_>>();
    let bytes =
        openfortivpn_manager_core::repository::encode(values).map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|_| "配置编码失败".into())
}

fn load_profiles(app: &AppHandle) -> Result<LoadedProfiles, String> {
    let path = profiles_path(app)?;
    if !path.exists() {
        return Ok(LoadedProfiles::default());
    }

    let contents = openfortivpn_manager_core::private_file::read_metadata(
        &path,
        openfortivpn_manager_core::repository::MAX_PROFILE_BYTES as u64,
    )
    .map_err(|error| format!("无法读取配置列表 {}：{error}", path.display()))?;
    let contents = std::str::from_utf8(&contents).map_err(|_| "配置必须是 UTF-8".to_string())?;
    parse_profile_file(contents)
}

fn persist_profiles(
    app: &AppHandle,
    profiles: &BTreeMap<String, VpnProfile>,
    stored_secret_profiles: &HashSet<String>,
    unknown_secret_profiles: &HashSet<String>,
) -> Result<(), String> {
    let path = profiles_path(app)?;
    let contents =
        serialize_profile_file(profiles, stored_secret_profiles, unknown_secret_profiles)?;
    if path.exists() {
        let old = openfortivpn_manager_core::private_file::read_metadata(
            &path,
            openfortivpn_manager_core::repository::MAX_PROFILE_BYTES as u64,
        )
        .map_err(|e| e.to_string())?;
        let decoded = openfortivpn_manager_core::repository::decode::<PersistedVpnProfile>(&old)
            .map_err(|e| e.to_string())?;
        if decoded.legacy {
            let backup = app_data_dir(app)?.join(".profiles-schema0-backup.json");
            if !backup.exists() {
                openfortivpn_manager_core::atomic_file::write_private(&backup, &old)
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    openfortivpn_manager_core::atomic_file::write_private(&path, contents.as_bytes())
        .map_err(|error| format!("无法原子保存配置列表：{error}"))?;

    Ok(())
}

const REPOSITORY_RECOVERY_MESSAGE: &str =
    "配置写入未能确认，请停止所有连接后在设置中重新读取并恢复配置仓库";

fn repository_api_error() -> openfortivpn_manager_http::ApiError {
    openfortivpn_manager_http::ApiError::new(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "RECOVERY_REQUIRED",
        REPOSITORY_RECOVERY_MESSAGE,
        false,
    )
}

fn ensure_repository_ready(store: &RuntimeStore) -> Result<(), String> {
    if store.repository_recovery_required {
        Err(REPOSITORY_RECOVERY_MESSAGE.into())
    } else {
        Ok(())
    }
}

// A failed replacement can already be visible on disk (e.g. parent fsync
// fails after rename). Keep the old cache for diagnostics, but never use it as
// the basis of another write or connection until a durable reload succeeds.
fn commit_profile_metadata(
    store: &mut RuntimeStore,
    write: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    ensure_repository_ready(store)?;
    if write().is_err() {
        store.repository_recovery_required = true;
        return Err(REPOSITORY_RECOVERY_MESSAGE.into());
    }
    Ok(())
}

#[tauri::command]
fn repository_recovery_required(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(lock_store(&state)?.repository_recovery_required)
}

fn repository_is_idle(store: &RuntimeStore) -> bool {
    !store.restoring_repository
        && store.mutating_profiles.is_empty()
        && store.starting_profiles.is_empty()
        && store.stale_processes.is_empty()
        && !store
            .instances
            .values()
            .any(|i| i.process_running || i.lifecycle.cleanup_failed())
}

fn apply_recovered_profiles(store: &mut RuntimeStore, loaded: LoadedProfiles) {
    for secret in store.secrets.values_mut() {
        secret.zeroize();
    }
    store.secrets.clear();
    store.profiles = loaded.profiles;
    store.stored_secret_profiles = loaded.stored_secret_profiles;
    store.unknown_secret_profiles = loaded.unknown_secret_profiles;
    store.reconnect_attempts.clear();
    store.reconnect_generations.clear();
    store.instances.clear();
    store.repository_recovery_required = false;
}

#[tauri::command]
async fn recover_profile_repository(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        {
            let state = app.state::<AppState>();
            let mut store = lock_store(&state)?;
            if !repository_is_idle(&store) {
                return Err("请先停止所有连接并完成正在进行的操作与进程恢复".into());
            }
            store.restoring_repository = true;
        }
        let _guard = backup::RestoreGuard(app.clone());
        let _transaction = CREDENTIAL_TRANSACTIONS
            .lock()
            .map_err(|_| "凭据事务不可用")?;
        let loaded = load_profiles(&app)?;
        // Retry the durability barrier before collecting either credential ref.
        let path = profiles_path(&app)?;
        if path.exists() {
            fs::File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|_| REPOSITORY_RECOVERY_MESSAGE)?;
        }
        #[cfg(unix)]
        fs::File::open(app_data_dir(&app)?)
            .and_then(|file| file.sync_all())
            .map_err(|_| REPOSITORY_RECOVERY_MESSAGE)?;
        recover_credential_intents(&app, &loaded)?;
        {
            let state = app.state::<AppState>();
            let mut store = lock_store(&state)?;
            apply_recovered_profiles(&mut store, loaded);
        }
        emit_profiles_changed(&app);
        Ok(())
    })
    .await
    .map_err(|_| "配置恢复工作线程失败".to_string())?
}

fn credential_entry(profile_id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, profile_id)
        .map_err(|error| format!("无法访问系统凭据库：{error}"))
}

fn lock_credential_access() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    CREDENTIAL_ACCESS
        .lock()
        .map_err(|_| "系统凭据访问状态已损坏".to_string())
}

#[cfg(not(target_os = "macos"))]
fn read_keychain_password(profile_id: &str) -> Result<Option<String>, String> {
    match credential_entry(profile_id)?.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("无法从系统凭据库读取密码：{error}")),
    }
}

#[cfg(not(target_os = "macos"))]
fn store_keychain_password(profile_id: &str, password: &str) -> Result<(), String> {
    credential_entry(profile_id)?
        .set_password(password)
        .map_err(|error| format!("无法将密码保存到系统凭据库：{error}"))
}

#[cfg(not(target_os = "macos"))]
fn delete_keychain_password(profile_id: &str) -> Result<(), String> {
    match credential_entry(profile_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!("无法从系统凭据库删除密码：{error}")),
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
struct LocalCredentials(BTreeMap<String, String>);
#[cfg(any(target_os = "macos", all(test, unix)))]
impl std::ops::Deref for LocalCredentials {
    type Target = BTreeMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(any(target_os = "macos", all(test, unix)))]
impl std::ops::DerefMut for LocalCredentials {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
#[cfg(any(target_os = "macos", all(test, unix)))]
impl Drop for LocalCredentials {
    fn drop(&mut self) {
        for secret in self.0.values_mut() {
            secret.zeroize();
        }
    }
}
#[cfg(any(target_os = "macos", all(test, unix)))]
fn load_local_credentials_file(path: &std::path::Path) -> Result<LocalCredentials, String> {
    if !path.exists() {
        return Ok(LocalCredentials(BTreeMap::new()));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("无法检查本机凭据文件 {}：{error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err("本机凭据文件必须由当前用户拥有、使用 0600 且不能是符号链接".to_string());
    }
    let contents = zeroize::Zeroizing::new(
        openfortivpn_manager_core::private_file::read(path, 16 * 1024 * 1024)
            .map_err(|error| format!("无法读取本机凭据文件 {}：{error}", path.display()))?,
    );
    let credentials = LocalCredentials(
        serde_json::from_slice(&contents)
            .map_err(|error| format!("本机凭据文件格式错误：{error}"))?,
    );
    for (profile_id, password) in credentials.iter() {
        if profile_id.trim().is_empty() || profile_id == REMOTE_TOKEN_PROFILE_ID {
            return Err("本机凭据文件包含无效的配置 ID".to_string());
        }
        validate_password(password)
            .map_err(|message| format!("本机凭据文件中的 VPN 密码无法使用：{message}"))?;
    }
    Ok(credentials)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn persist_local_credentials_file(
    path: &std::path::Path,
    credentials: &BTreeMap<String, String>,
) -> Result<(), String> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("无法检查本机凭据文件 {}：{error}", path.display()))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err("拒绝覆盖所有者、权限或文件类型异常的本机凭据文件".to_string());
        }
    }
    let contents = zeroize::Zeroizing::new(
        serde_json::to_vec_pretty(credentials)
            .map_err(|error| format!("无法序列化本机凭据：{error}"))?,
    );
    openfortivpn_manager_core::atomic_file::write_private(path, &contents)
        .map_err(|error| format!("无法持久保存本机凭据文件 {}：{error}", path.display()))
}

#[cfg(target_os = "macos")]
fn local_credentials_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("credentials.json"))
}

#[cfg(target_os = "macos")]
fn read_stored_password(app: &AppHandle, profile_id: &str) -> Result<Option<String>, String> {
    let _guard = lock_credential_access()?;
    let path = local_credentials_path(app)?;
    Ok(load_local_credentials_file(&path)?.get(profile_id).cloned())
}

#[cfg(not(target_os = "macos"))]
fn read_stored_password(_app: &AppHandle, profile_id: &str) -> Result<Option<String>, String> {
    let _guard = lock_credential_access()?;
    read_keychain_password(profile_id)
}

#[cfg(target_os = "macos")]
fn store_password(app: &AppHandle, profile_id: &str, password: &str) -> Result<(), String> {
    let _guard = lock_credential_access()?;
    let path = local_credentials_path(app)?;
    let mut credentials = load_local_credentials_file(&path)?;
    if let Some(mut old) = credentials.insert(profile_id.to_string(), password.to_string()) {
        old.zeroize();
    }
    persist_local_credentials_file(&path, &credentials)
}

#[cfg(not(target_os = "macos"))]
fn store_password(_app: &AppHandle, profile_id: &str, password: &str) -> Result<(), String> {
    let _guard = lock_credential_access()?;
    store_keychain_password(profile_id, password)
}

#[cfg(target_os = "macos")]
fn delete_stored_password(app: &AppHandle, profile_id: &str) -> Result<(), String> {
    let _guard = lock_credential_access()?;
    let path = local_credentials_path(app)?;
    let mut credentials = load_local_credentials_file(&path)?;
    if let Some(mut old) = credentials.remove(profile_id) {
        old.zeroize();
    }
    persist_local_credentials_file(&path, &credentials)
}

#[cfg(not(target_os = "macos"))]
fn delete_stored_password(_app: &AppHandle, profile_id: &str) -> Result<(), String> {
    let _guard = lock_credential_access()?;
    delete_keychain_password(profile_id)
}

fn validate_line_value(label: &str, value: &str) -> Result<(), String> {
    if value.contains(['\0', '\n', '\r']) {
        return Err(format!("{label} 不能包含换行符"));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    openfortivpn_manager_core::validation::password(password).map_err(|error| error.to_string())
}

fn read_usable_stored_password(
    app: &AppHandle,
    profile_id: &str,
) -> Result<Option<String>, String> {
    let reference = app
        .state::<AppState>()
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?
        .profiles
        .get(profile_id)
        .and_then(|p| p.credential_ref.clone())
        .unwrap_or_else(|| profile_id.to_string());
    read_stored_password(app, &reference)?
        .map(|password| {
            validate_password(&password)
                .map_err(|message| format!("已保存的 VPN 密码无法使用：{message}"))?;
            Ok(password)
        })
        .transpose()
}

fn validate_profile(profile: &VpnProfile) -> Result<(), String> {
    if profile.id == REMOTE_TOKEN_PROFILE_ID {
        return Err("配置 ID 使用了系统保留值".to_string());
    }
    if profile.name.trim().is_empty() {
        return Err("配置名称不能为空".to_string());
    }
    if profile.host.trim().is_empty() {
        return Err("VPN 服务器不能为空".to_string());
    }
    if profile.port == 0 {
        return Err("端口必须在 1 到 65535 之间".to_string());
    }

    use openfortivpn_manager_core::validation;
    validation::line("id", &profile.id).map_err(|e| e.to_string())?;
    validate_line_value("配置名称", &profile.name)?;
    validate_line_value("服务器", &profile.host)?;
    validate_line_value("用户名", &profile.username)?;
    validate_line_value("Realm", &profile.realm)?;
    validation::engine_field("host", &profile.host, validation::HOST_MAX_BYTES)
        .map_err(|e| e.to_string())?;
    validation::engine_field(
        "username",
        &profile.username,
        validation::USERNAME_MAX_BYTES,
    )
    .map_err(|e| e.to_string())?;
    validation::engine_field("realm", &profile.realm, validation::REALM_MAX_BYTES)
        .map_err(|e| e.to_string())?;

    if !profile.trusted_cert.is_empty()
        && (profile.trusted_cert.len() != 64
            || !profile
                .trusted_cert
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
    {
        return Err("受信任证书必须是 64 位 SHA-256 十六进制摘要".to_string());
    }

    validation::profile(profile).map_err(|error| error.to_string())
}

fn profile_view(profile: &VpnProfile, has_secret: bool, password_stored: bool) -> ProfileView {
    ProfileView {
        profile: profile.clone(),
        has_secret,
        password_stored,
    }
}

fn resolve_engine(app: &AppHandle) -> PathBuf {
    // Development builds may point at a locally-built engine. Release builds
    // deliberately ignore this environment variable because the engine can be
    // copied into a root-owned location during helper installation.
    #[cfg(debug_assertions)]
    if let Some(path) = env::var_os("OPENFORTIVPN_BIN") {
        return PathBuf::from(path);
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        #[cfg(windows)]
        let candidate = resource_dir.join("bin").join("openfortivpn.exe");
        #[cfg(not(windows))]
        let candidate = resource_dir.join("bin").join("openfortivpn");
        if candidate.exists() {
            return candidate;
        }
    }

    #[cfg(windows)]
    {
        if let Ok(executable) = env::current_exe() {
            if let Some(parent) = executable.parent() {
                let candidate = parent.join("openfortivpn.exe");
                if candidate.exists() {
                    return candidate;
                }
            }
        }
        PathBuf::from("openfortivpn.exe")
    }

    #[cfg(not(windows))]
    {
        for candidate in [
            "/opt/homebrew/bin/openfortivpn",
            "/usr/local/bin/openfortivpn",
            "/usr/bin/openfortivpn",
        ] {
            let path = PathBuf::from(candidate);
            if path.exists() {
                return path;
            }
        }
        PathBuf::from("openfortivpn")
    }
}

#[cfg(unix)]
fn resolve_bundled_helper(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .resource_dir()
        .map(|directory| directory.join("bin").join("openfortivpn-manager-helper"))
        .map_err(|error| format!("无法定位应用资源目录：{error}"))
}

#[cfg(unix)]
const SUDO_EXECUTABLE: &str = "/usr/bin/sudo";

#[cfg(unix)]
fn bundled_engine_for_install(app: &AppHandle) -> Result<PathBuf, String> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|error| format!("无法定位应用资源目录：{error}"))?;
    #[cfg(windows)]
    let candidate = resource_dir.join("bin").join("openfortivpn.exe");
    #[cfg(not(windows))]
    let candidate = resource_dir.join("bin").join("openfortivpn");
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|error| format!("应用包内缺少 VPN 引擎 {}：{error}", candidate.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "应用包内 VPN 引擎必须是普通文件且不能是符号链接：{}",
            candidate.display()
        ));
    }
    Ok(candidate)
}

#[cfg(target_os = "macos")]
fn verify_macos_app_signature() -> Result<(), String> {
    let executable = env::current_exe().map_err(|error| format!("无法定位当前应用：{error}"))?;
    let bundle = executable
        .ancestors()
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("app"))
        .ok_or_else(|| "当前程序不在 macOS .app 包内，拒绝安装系统 helper".to_string())?;
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("无法校验应用签名：{error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("应用签名校验失败，拒绝安装系统 helper；请重新安装可信发行包".to_string())
    }
}

#[cfg(unix)]
fn file_sha256(path: &std::path::Path) -> Result<[u8; 32], String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("无法读取系统组件 {}：{error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("无法校验系统组件 {}：{error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

#[cfg(unix)]
fn installed_payload_matches(bundled: &std::path::Path, installed: &std::path::Path) -> bool {
    let bundled_metadata = fs::symlink_metadata(bundled);
    let installed_metadata = fs::symlink_metadata(installed);
    let (Ok(bundled_metadata), Ok(installed_metadata)) = (bundled_metadata, installed_metadata)
    else {
        return false;
    };
    if bundled_metadata.file_type().is_symlink()
        || !bundled_metadata.is_file()
        || installed_metadata.file_type().is_symlink()
        || !installed_metadata.is_file()
        || installed_metadata.uid() != 0
        || installed_metadata.mode() & 0o022 != 0
        || bundled_metadata.len() != installed_metadata.len()
    {
        return false;
    }
    matches!(
        (file_sha256(bundled), file_sha256(installed)),
        (Ok(expected), Ok(actual)) if expected == actual
    )
}

#[cfg(unix)]
fn installed_components_match_bundle(app: &AppHandle) -> bool {
    let Ok(helper) = resolve_bundled_helper(app) else {
        return false;
    };
    let Ok(engine) = bundled_engine_for_install(app) else {
        return false;
    };
    installed_payload_matches(&helper, &installed_helper_path())
        && installed_payload_matches(&engine, &installed_engine_path())
}

#[cfg(all(unix, target_os = "macos"))]
fn installed_helper_path() -> PathBuf {
    PathBuf::from("/Library/PrivilegedHelperTools/com.baozaodetudou.openfortivpn.helper")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn installed_helper_path() -> PathBuf {
    PathBuf::from("/usr/local/libexec/openfortivpn-manager/helper")
}

#[cfg(all(unix, target_os = "macos"))]
fn installed_engine_path() -> PathBuf {
    PathBuf::from("/Library/PrivilegedHelperTools/com.baozaodetudou.openfortivpn.engine")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn installed_engine_path() -> PathBuf {
    PathBuf::from("/usr/local/libexec/openfortivpn-manager/openfortivpn")
}

fn make_adapter_name(profile: &VpnProfile, instance_id: &str) -> String {
    let mut base: String = profile
        .name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .take(18)
        .collect();
    if base.is_empty() {
        base = "vpn".to_string();
    }
    let suffix: String = instance_id.chars().filter(|c| *c != '-').take(8).collect();
    format!("ofv-{base}-{suffix}")
}

fn push_config_line(buffer: &mut String, key: &str, value: &str) {
    if !value.is_empty() {
        buffer.push_str(key);
        buffer.push_str(" = ");
        buffer.push_str(value);
        buffer.push('\n');
    }
}

fn render_runtime_config(
    profile: &VpnProfile,
    password: &str,
    adapter_name: &str,
) -> Result<String, String> {
    validate_password(password)?;
    openfortivpn_manager_core::validation::gateway_dns(&profile.gateway_dns)
        .map_err(|error| error.to_string())?;

    let mut config = String::from("# Generated by OpenFortiVPN Manager. Do not edit.\n");
    push_config_line(&mut config, "host", profile.host.trim());
    push_config_line(&mut config, "gateway-dns", &profile.gateway_dns);
    push_config_line(&mut config, "port", &profile.port.to_string());
    push_config_line(&mut config, "username", &profile.username);
    push_config_line(&mut config, "password", password);
    push_config_line(&mut config, "realm", &profile.realm);
    push_config_line(&mut config, "trusted-cert", &profile.trusted_cert);
    push_config_line(
        &mut config,
        "set-routes",
        if profile.set_routes { "1" } else { "0" },
    );
    push_config_line(
        &mut config,
        "set-dns",
        if profile.set_dns { "1" } else { "0" },
    );
    push_config_line(
        &mut config,
        "pppd-use-peerdns",
        if profile.pppd_use_peerdns { "1" } else { "0" },
    );
    push_config_line(
        &mut config,
        "half-internet-routes",
        if profile.half_internet_routes {
            "1"
        } else {
            "0"
        },
    );

    #[cfg(windows)]
    push_config_line(&mut config, "pppd-ifname", adapter_name);
    #[cfg(not(windows))]
    let _ = adapter_name;

    Ok(config)
}

fn write_runtime_config(
    app: &AppHandle,
    profile: &VpnProfile,
    password: &str,
    instance_id: &str,
    adapter_name: &str,
) -> Result<PathBuf, String> {
    let directory = runtime_directory(app)?;
    let path = directory.join(format!("{instance_id}.conf"));
    let config = render_runtime_config(profile, password, adapter_name)?;
    #[cfg(unix)]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("无法创建临时配置 {}：{error}", path.display()))?;
        if let Err(error) = file.write_all(config.as_bytes()) {
            let _ = fs::remove_file(&path);
            return Err(format!("无法写入临时配置 {}：{error}", path.display()));
        }
    }
    #[cfg(not(unix))]
    openfortivpn_manager_core::atomic_file::write_private(&path, config.as_bytes())
        .map_err(|error| format!("无法写入临时配置 {}：{error}", path.display()))?;

    Ok(path)
}

fn runtime_directory(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app_data_dir(app)?.join("runtime");
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建运行目录：{error}"))?;
    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("无法设置运行目录权限：{error}"))?;
    Ok(directory)
}

fn runtime_process_record_path(app: &AppHandle, instance_id: &str) -> Result<PathBuf, String> {
    Ok(runtime_directory(app)?.join(format!("{instance_id}.process.json")))
}

fn persist_runtime_process_record(
    app: &AppHandle,
    record: &RuntimeProcessRecord,
) -> Result<PathBuf, String> {
    let path = runtime_process_record_path(app, &record.instance_id)?;
    let contents = serde_json::to_string_pretty(record)
        .map_err(|error| format!("无法序列化 VPN 进程记录：{error}"))?;
    openfortivpn_manager_core::atomic_file::write_private(&path, contents.as_bytes())
        .map_err(|error| format!("无法持久保存 VPN 进程记录：{error}"))?;
    Ok(path)
}

#[cfg(unix)]
fn process_rows() -> Option<Vec<(u32, String)>> {
    let Ok(output) = Command::new("ps").args(["-axo", "pgid=,command="]).output() else {
        return None;
    };
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let (group, command) = line.split_once(char::is_whitespace)?;
                Some((group.parse::<u32>().ok()?, command.trim().to_string()))
            })
            .collect(),
    )
}

#[cfg(unix)]
fn process_group_commands(process_group_id: u32) -> Option<Vec<String>> {
    process_rows().map(|rows| {
        rows.into_iter()
            .filter_map(|(group, command)| (group == process_group_id).then_some(command))
            .collect()
    })
}

#[cfg(unix)]
fn find_record_process_group(record: &RuntimeProcessRecord, rows: &[(u32, String)]) -> Option<u32> {
    rows.iter().find_map(|(group, command)| {
        if !command.contains(&record.engine_path) {
            return None;
        }
        rows.iter()
            .any(|(candidate_group, candidate_command)| {
                candidate_group == group && candidate_command.contains(&record.config_path)
            })
            .then_some(*group)
    })
}

#[cfg(unix)]
fn process_group_matches_record(record: &RuntimeProcessRecord) -> bool {
    process_rows()
        .map(|rows| {
            find_record_process_group(record, &rows).is_some_and(|group| {
                record.process_group_id == 0 || group == record.process_group_id
            })
        })
        .unwrap_or(true)
}

#[cfg(unix)]
fn process_group_contains_engine(process_group_id: u32, engine: &std::path::Path) -> bool {
    let engine = engine.to_string_lossy();
    process_group_commands(process_group_id)
        .map(|commands| {
            commands
                .iter()
                .any(|command| command.contains(engine.as_ref()))
        })
        .unwrap_or(true)
}

fn remove_runtime_process_record(app: &AppHandle, record: &RuntimeProcessRecord) {
    if let Ok(directory) = runtime_directory(app) {
        // Used only when spawn failed before creating a child.
        let _ = fs::remove_file(directory.join(format!("{}.process.json", record.instance_id)));
        let _ = fs::remove_file(directory.join(format!("{}.conf", record.instance_id)));
        #[cfg(unix)]
        let _ = fs::File::open(directory).and_then(|dir| dir.sync_all());
    }
}

fn finish_unstarted_process(
    app: &AppHandle,
    record: &RuntimeProcessRecord,
    lease: &mut Option<SystemNetworkLease>,
) -> Result<(), String> {
    if let Some(lease) = lease.take() {
        if let Err(error) = lease.finish(true, true) {
            // Recovery needs this local anchor if global deletion/fsync failed.
            if let Ok(mut store) = app.state::<AppState>().store.lock() {
                store
                    .stale_processes
                    .insert(record.instance_id.clone(), record.clone());
            }
            return Err(error.to_string());
        }
    }
    remove_runtime_process_record(app, record);
    Ok(())
}

fn reap_unregistered_child(child: std::process::Child, wait_now: bool) {
    let owned = OwnedProcess::new(child);
    if wait_now {
        if let Ok(mut child) = owned.lock() {
            let _ = child.wait();
        }
    }
    // A failed wait leaves the exact handle with the shared retrying reaper.
    // The caller retains both recovery journals and network reservations.
}

fn load_stale_runtime_processes(
    app: &AppHandle,
) -> Result<BTreeMap<String, RuntimeProcessRecord>, String> {
    let mut stale = BTreeMap::new();
    for entry in fs::read_dir(runtime_directory(app)?)
        .map_err(|error| format!("无法扫描运行目录：{error}"))?
    {
        let entry = entry.map_err(|error| format!("无法读取运行目录条目：{error}"))?;
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".process.json"))
        {
            continue;
        }
        let instance_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".process.json"))
            .unwrap_or_default()
            .to_string();
        Uuid::parse_str(&instance_id).map_err(|_| "无效的运行记录 ID".to_string())?;
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("运行记录必须是普通文件".into());
        }
        #[cfg(unix)]
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o600 {
            return Err("运行记录必须是本用户拥有的私有普通文件".into());
        }
        let config_path = runtime_directory(app)?.join(format!("{instance_id}.conf"));
        let record: RuntimeProcessRecord =
            serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
                .map_err(|_| "运行记录损坏，请保留现场恢复".to_string())?;
        if record.instance_id != instance_id || record.config_path != config_path.to_string_lossy()
        {
            return Err("运行记录身份或配置路径不一致".into());
        }
        #[cfg(unix)]
        let record = {
            let mut record = record;
            let rows = process_rows();
            let discovered_group = rows
                .as_deref()
                .and_then(|rows| find_record_process_group(&record, rows));
            if let Some(group) = discovered_group {
                if record.process_group_id == 0 {
                    record.pid = group;
                    record.process_group_id = group;
                    let _ = persist_runtime_process_record(app, &record);
                }
            }
            record
        };
        // Process absence proves neither route nor DNS cleanup.
        stale.insert(record.instance_id.clone(), record);
    }

    for entry in fs::read_dir(runtime_directory(app)?)
        .map_err(|error| format!("无法扫描运行目录：{error}"))?
    {
        let entry = entry.map_err(|error| format!("无法读取运行目录条目：{error}"))?;
        let path = entry.path();
        let Some(instance_id) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".conf"))
        else {
            continue;
        };
        if !runtime_process_record_path(app, instance_id)?.exists() {
            let _ = fs::remove_file(path);
        }
    }
    Ok(stale)
}

#[cfg(unix)]
fn cleanup_stale_runtime_processes(app: &AppHandle) -> Result<(), String> {
    let records = app
        .state::<AppState>()
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?
        .stale_processes
        .values()
        .cloned()
        .collect::<Vec<_>>();

    if let Some(record) = records.into_iter().next() {
        if record.process_group_id == 0 {
            return Err("无法确定上次遗留 VPN 进程组，请保留现场并检查运行目录".to_string());
        }
        if process_group_matches_record(&record) {
            let status = Command::new(SUDO_EXECUTABLE)
                .arg("-n")
                .arg(installed_helper_path())
                .arg("stop")
                .arg(record.process_group_id.to_string())
                .status()
                .map_err(|error| format!("无法清理上次遗留的 VPN 进程：{error}"))?;
            if !status.success() {
                return Err("无法清理上次遗留的 VPN 进程，请重新安装系统 helper".to_string());
            }
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline && process_group_matches_record(&record) {
                thread::sleep(Duration::from_millis(100));
            }
            if process_group_matches_record(&record) {
                return Err("等待上次遗留的 VPN 进程退出超时".to_string());
            }
        }
        return Err("遗留进程已停止，但网络清理没有确认；请恢复网络后在恢复提示中确认".into());
    }
    Ok(())
}

fn emit_instance(app: &AppHandle, view: &InstanceView) {
    let _ = app.emit("vpn-instance-changed", view.clone());
    schedule_tray_refresh(app);
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryNotice {
    instance_id: String,
    profile_id: String,
    message: String,
}

#[tauri::command]
fn list_recovery_records(app: AppHandle) -> Result<Vec<RecoveryNotice>, String> {
    let state = app.state::<AppState>();
    let store = lock_store(&state)?;
    let mut records = BTreeMap::new();
    for record in store.stale_processes.values() {
        records.insert(
            record.instance_id.clone(),
            RecoveryNotice {
                instance_id: record.instance_id.clone(),
                profile_id: record.profile_id.clone(),
                message: "上次运行中断，网络清理未确认".into(),
            },
        );
    }
    for instance in store
        .instances
        .values()
        .filter(|i| i.lifecycle.cleanup_failed())
    {
        records.insert(
            instance.view.id.clone(),
            RecoveryNotice {
                instance_id: instance.view.id.clone(),
                profile_id: instance.view.profile_id.clone(),
                message: instance
                    .failure_message
                    .clone()
                    .unwrap_or_else(|| "网络清理未确认".into()),
            },
        );
    }
    Ok(records.into_values().collect())
}

#[tauri::command]
fn acknowledge_recovery(
    app: AppHandle,
    instance_id: String,
    network_restored: bool,
) -> Result<(), String> {
    if !network_restored {
        return Err("需要确认已停止遗留进程并恢复网络".into());
    }
    let state = app.state::<AppState>();
    let _lifecycle = state.lifecycle.lock().map_err(|_| "生命周期状态已损坏")?;
    let mut store = lock_store(&state)?;
    if store
        .instances
        .get(&instance_id)
        .is_some_and(|i| i.process_running)
    {
        return Err("引擎仍在运行，请先停止连接".into());
    }
    {
        Uuid::parse_str(&instance_id).map_err(|_| "无效的恢复 ID")?;
        let path = runtime_process_record_path(&app, &instance_id)?;
        let record = if let Some(record) = store.stale_processes.get(&instance_id) {
            record.clone()
        } else {
            serde_json::from_slice::<RuntimeProcessRecord>(
                &openfortivpn_manager_core::private_file::read(&path, 8192)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
        };
        if record.instance_id != instance_id {
            return Err("恢复记录与当前实例不一致".into());
        }
        #[cfg(unix)]
        {
            let rows = process_rows().ok_or("无法检查进程，不能确认恢复")?;
            if find_record_process_group(&record, &rows).is_some() {
                return Err("遗留引擎仍在运行，请先停止并恢复网络".into());
            }
        }
        #[cfg(windows)]
        {
            use openfortivpn_manager_core::windows_process::{engine_is_running, inspect};
            if let Some(identity) = record.process_identity.as_ref() {
                if inspect(identity.pid).map_err(|e| e.to_string())?.as_ref() == Some(identity) {
                    return Err("遗留引擎仍在运行，请先停止并恢复网络".into());
                }
            } else if engine_is_running(std::path::Path::new(&record.engine_path))
                .map_err(|e| e.to_string())?
            {
                return Err("引擎仍在运行，无法确认无身份记录的恢复".into());
            }
        }
        #[cfg(unix)]
        {
            if std::path::Path::new(&record.engine_path) == installed_engine_path() {
                let output = Command::new(SUDO_EXECUTABLE)
                    .arg("-n")
                    .arg(installed_helper_path())
                    .args(["recover-network", &instance_id, "--acknowledge-cleanup"])
                    .stdin(Stdio::null())
                    .output()
                    .map_err(|e| e.to_string())?;
                if !output.status.success() {
                    return Err(String::from_utf8_lossy(&output.stderr).into_owned());
                }
            } else if unsafe { libc::geteuid() } == 0 {
                use openfortivpn_manager_core::network_authority as authority;
                let directory = authority::system_directory().map_err(|e| e.to_string())?;
                if let Some(owner) = authority::inspect(&directory).map_err(|e| e.to_string())? {
                    if owner.manager == "desktop" && owner.attempt_id == instance_id {
                        authority::acknowledge(&directory, &instance_id, owner.uid, || {
                            let uncertain = if owner.process_group == 0 {
                                !owner.pre_spawn_gated
                            } else {
                                (unsafe { libc::kill(-(owner.process_group as i32), 0) }) == 0
                                    || std::io::Error::last_os_error().raw_os_error()
                                        != Some(libc::ESRCH)
                            };
                            if uncertain {
                                return Err(openfortivpn_manager_core::ControlError::new(
                                    openfortivpn_manager_core::ErrorCode::RecoveryRequired,
                                    "无法确认遗留 VPN 进程组不存在",
                                ));
                            }
                            Ok(true)
                        })
                        .map_err(|e| e.to_string())?;
                    }
                }
            }
        }
        #[cfg(windows)]
        {
            use openfortivpn_manager_core::windows_network_authority::{MachineAuthority, Owner};
            let authority = MachineAuthority::open_system().map_err(|e| e.to_string())?;
            if let Some(owner) = authority.inspect().map_err(|e| e.to_string())? {
                if owner.attempt_id == instance_id {
                    let current = Owner::new(
                        instance_id.clone(),
                        "desktop".into(),
                        record.engine_path.clone(),
                    )
                    .map_err(|e| e.to_string())?;
                    if owner.manager != "desktop"
                        || !openfortivpn_manager_core::windows_process::same_executable(
                            &owner.executable,
                            &record.engine_path,
                        )
                    {
                        return Err("系统网络恢复记录与本地引擎不一致".into());
                    }
                    authority
                        .acknowledge(&instance_id, &current.principal_sid, || {
                            // The local IPC already requires explicit network-restored
                            // confirmation and rejects running owned instances. The
                            // authority independently checks every matching engine.
                            Ok(network_restored)
                        })
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        // Derive deletion paths from the verified attempt, not persisted paths.
        fs::remove_file(path).map_err(|e| e.to_string())?;
        let config = runtime_directory(&app)?.join(format!("{instance_id}.conf"));
        if config.exists() {
            fs::remove_file(config).map_err(|e| e.to_string())?;
        }
        #[cfg(unix)]
        fs::File::open(runtime_directory(&app)?)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())?;
        store.stale_processes.remove(&instance_id);
    }
    if let Some(instance) = store.instances.get_mut(&instance_id) {
        instance.lifecycle.acknowledge_recovery();
        instance.view.status = "disconnected".into();
        instance.view.message = "操作者已确认网络恢复".into();
        instance.view.ended_at = Some(now_epoch());
        instance.view.revision = instance.view.revision.saturating_add(1);
    }
    drop(store);
    refresh_privilege_status(&app, false);
    Ok(())
}

fn prune_finished_instances(store: &mut RuntimeStore) {
    let keep = openfortivpn_manager_core::retention::terminal_ids_to_keep(
        store
            .instances
            .iter()
            .filter(|(_, i)| !i.process_running && !i.lifecycle.cleanup_failed())
            .filter_map(|(id, i)| i.view.ended_at.map(|ended| (id.clone(), ended))),
        now_epoch(),
    );
    store.instances.retain(|id, i| {
        i.process_running
            || i.lifecycle.cleanup_failed()
            || i.view.ended_at.is_none()
            || keep.contains(id)
    });
}

fn profile_has_running_instance(store: &RuntimeStore, profile_id: &str) -> bool {
    store.instances.values().any(|instance| {
        instance.view.profile_id == profile_id
            && (instance.process_running || instance.lifecycle.cleanup_failed())
    })
}

fn profile_connection_in_progress(store: &RuntimeStore, profile_id: &str) -> bool {
    store.starting_profiles.contains(profile_id) || profile_has_running_instance(store, profile_id)
}

fn automatic_retry_allowed(
    user_requested_stop: bool,
    reconnect_blocked: bool,
    auto_reconnect_enabled: bool,
) -> bool {
    !user_requested_stop && !reconnect_blocked && auto_reconnect_enabled
}

fn bump_reconnect_generation(store: &mut RuntimeStore, profile_id: &str) -> u64 {
    let generation = store
        .reconnect_generations
        .entry(profile_id.to_string())
        .or_default();
    *generation = generation.saturating_add(1);
    *generation
}

fn can_transition_instance(current: &str, next: &str) -> bool {
    match current {
        "starting" | "connecting" => matches!(
            next,
            "connecting" | "connected" | "disconnecting" | "disconnected" | "failed"
        ),
        "connected" => matches!(
            next,
            "connected" | "disconnecting" | "disconnected" | "failed"
        ),
        "disconnecting" => matches!(next, "disconnecting" | "disconnected" | "failed"),
        "disconnected" | "failed" => false,
        _ => false,
    }
}

fn apply_instance_update(view: &mut InstanceView, status: &str, message: String) -> bool {
    if !can_transition_instance(&view.status, status) {
        return false;
    }
    view.status = status.to_string();
    view.message = message;
    view.revision = view.revision.saturating_add(1);
    true
}

fn update_instance(app: &AppHandle, instance_id: &str, status: &str, message: String) {
    let view = {
        let state = app.state::<AppState>();
        let Ok(mut store) = state.store.lock() else {
            return;
        };
        let (view, profile_id) = {
            let Some(instance) = store.instances.get_mut(instance_id) else {
                return;
            };
            if !instance.process_running {
                return;
            }
            if !apply_instance_update(&mut instance.view, status, message) {
                return;
            }
            if status == "connected" {
                instance.failure_message = None;
                instance.reconnect_blocked = false;
            }
            (instance.view.clone(), instance.view.profile_id.clone())
        };
        if status == "connected" {
            store.reconnect_attempts.remove(&profile_id);
        }
        view
    };
    emit_instance(app, &view);
}

fn record_instance_failure(
    app: &AppHandle,
    instance_id: &str,
    message: String,
    block_reconnect: bool,
) {
    let view = {
        let state = app.state::<AppState>();
        let Ok(mut store) = state.store.lock() else {
            return;
        };
        let Some(instance) = store.instances.get_mut(instance_id) else {
            return;
        };
        instance.reconnect_blocked |= block_reconnect;
        instance.failure_message = Some(message.clone());
        instance.view.message = message;
        instance.view.revision = instance.view.revision.saturating_add(1);
        instance.view.clone()
    };
    emit_instance(app, &view);
}

fn restore_instance_after_stop_failure(
    app: &AppHandle,
    instance_id: &str,
    status: &str,
    message: String,
) {
    let view = {
        let state = app.state::<AppState>();
        let Ok(mut store) = state.store.lock() else {
            return;
        };
        let Some(instance) = store.instances.get_mut(instance_id) else {
            return;
        };
        if instance.view.status != "disconnecting" {
            return;
        }
        // A failed signal does not revoke the user's stop intent.
        instance.user_requested_stop = true;
        instance.view.status = status.to_string();
        instance.view.message = message;
        instance.view.revision = instance.view.revision.saturating_add(1);
        instance.view.clone()
    };
    emit_instance(app, &view);
}

fn cancel_reconnect_for_stopped_instance(
    app: &AppHandle,
    instance_id: &str,
) -> Result<Option<InstanceView>, String> {
    let state = app.state::<AppState>();
    let mut store = state
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?;
    let profile_id = {
        let instance = store
            .instances
            .get(instance_id)
            .ok_or_else(|| "找不到指定连接实例".to_string())?;
        if instance.process_running {
            return Ok(None);
        }
        instance.view.profile_id.clone()
    };
    bump_reconnect_generation(&mut store, &profile_id);
    let instance = store
        .instances
        .get_mut(instance_id)
        .ok_or_else(|| "找不到指定连接实例".to_string())?;
    instance.user_requested_stop = true;
    instance.view.message = "已断开，自动重连已取消".to_string();
    instance.view.revision = instance.view.revision.saturating_add(1);
    Ok(Some(instance.view.clone()))
}

fn status_for_engine_state(state: &str) -> &'static str {
    match state {
        "disconnecting" | "disconnected" | "down" => "disconnecting",
        _ => "connecting",
    }
}

fn fallback_status_from_log(line: &str) -> Option<(&'static str, &'static str)> {
    line.contains("Tunnel is up and running.")
        .then_some(("connected", "已连接"))
}

fn handle_engine_event(app: &AppHandle, instance_id: &str, payload: &Value) {
    let mut invalid = false;
    let source = if let Ok(mut store) = app.state::<AppState>().store.lock() {
        if let Some(instance) = store.instances.get_mut(instance_id) {
            match instance.lifecycle.observe(payload) {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    instance.reconnect_blocked = true;
                    instance.failure_message = Some(error.to_string());
                    invalid = true;
                }
            }
            instance.reconnect_blocked |= instance.lifecycle.retry_blocked();
            instance.source_profile.clone()
        } else {
            return;
        }
    } else {
        return;
    };
    if invalid {
        authentication::fail_control(app, instance_id);
        return;
    }

    let event_name = payload
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or_default();

    match event_name {
        "auth_challenge" | "auth_challenge_closed" | "network_plan" => {
            if authentication::handle_event(app, instance_id, payload).is_err() {
                authentication::fail_control(app, instance_id);
                return;
            }
        }
        "state_change" => {
            let state_name = payload
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or("connecting");
            let status = status_for_engine_state(state_name);
            update_instance(app, instance_id, status, state_name.to_string());
        }
        "tunnel_up" => {
            let ip = payload
                .get("local_ip")
                .and_then(Value::as_str)
                .unwrap_or_default();
            update_instance(app, instance_id, "connected", format!("已连接 · {ip}"));
        }
        "cleanup_result" => {
            if let Ok(mut store) = app.state::<AppState>().store.lock() {
                if let Some(instance) = store.instances.get_mut(instance_id) {
                    if instance.lifecycle.cleanup_failed() {
                        instance.reconnect_blocked = true;
                        instance.failure_message =
                            Some("网络清理失败，需要恢复后才能启动新连接".into());
                    }
                }
            }
        }
        "tunnel_down" => {
            update_instance(
                app,
                instance_id,
                "disconnecting",
                "隧道正在关闭".to_string(),
            );
        }
        "error" => {
            let message = payload
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("连接失败");
            let permanent = payload.get("retryable").and_then(Value::as_bool) == Some(false)
                || payload.get("category").and_then(Value::as_str) == Some("auth");
            record_instance_failure(app, instance_id, message.to_string(), permanent);
        }
        "cert_error" => {
            record_instance_failure(app, instance_id, "服务器证书验证失败".to_string(), true);
            show_main_window(app);
        }
        _ => {}
    }

    let _ = app.emit(
        "vpn-engine-event",
        EngineEvent {
            instance_id: instance_id.to_string(),
            profile_id: source.id,
            profile_revision: source.revision,
            host: source.host,
            port: source.port,
            payload: payload.clone(),
        },
    );
}

fn spawn_stream_reader<R>(
    reader: R,
    app: AppHandle,
    instance_id: String,
    stream: &str,
) -> StreamReader
where
    R: openfortivpn_manager_core::process_output::Pipe + Send + 'static,
{
    let stream = stream.to_string();
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    let join = thread::spawn(move || {
        let mut reader =
            openfortivpn_manager_core::process_output::CancellablePipe::new(reader, flag.clone());
        let mut decoder = LineDecoder::default();
        let mut buffer = [0u8; 4096];
        let mut complete = true;
        loop {
            let length = match reader.read(&mut buffer) {
                Ok(length) => length,
                Err(_) => return false,
            };
            let records = if length == 0 {
                decoder.eof().into_iter().collect()
            } else {
                decoder.feed(&buffer[..length])
            };
            for record in records {
                let line = match record {
                    Line::Text(line) => line,
                    Line::Oversized => {
                        complete = false;
                        record_instance_failure(
                            &app,
                            &instance_id,
                            "引擎事件超过长度限制".into(),
                            true,
                        );
                        continue;
                    }
                    Line::InvalidUtf8 => {
                        complete = false;
                        continue;
                    }
                };
                if let Ok(payload) = serde_json::from_str::<Value>(&line) {
                    if payload.get("event").is_some() {
                        handle_engine_event(&app, &instance_id, &payload);
                        continue;
                    }
                }
                if let Some((status, message)) = fallback_status_from_log(&line) {
                    let legacy = app
                        .state::<AppState>()
                        .store
                        .lock()
                        .ok()
                        .and_then(|store| {
                            store
                                .instances
                                .get(&instance_id)
                                .map(|i| i.lifecycle.accepts_legacy_readiness())
                        })
                        .unwrap_or(false);
                    if legacy {
                        update_instance(&app, &instance_id, status, message.to_string());
                    }
                }
                let event = LogEvent {
                    id: openfortivpn_manager_core::protocol::next_log_id(),
                    instance_id: instance_id.clone(),
                    stream: stream.clone(),
                    line: openfortivpn_manager_core::protocol::redact(&line),
                    timestamp: now_epoch(),
                };
                if let Ok(mut store) = app.state::<AppState>().store.lock() {
                    retain_log(&mut store.logs, event.clone());
                }
                let _ = app.emit("vpn-log", event);
            }
            if length == 0 {
                return complete && !flag.load(Ordering::Acquire);
            }
        }
    });
    StreamReader { join, cancelled }
}

fn drain_stream_readers(readers: Vec<StreamReader>) -> bool {
    openfortivpn_manager_core::supervisor::drain_streams(readers, Duration::from_secs(2))
}

fn retain_log(logs: &mut LogBuffer, event: LogEvent) {
    logs.push(event);
}

fn recent_logs(
    logs: &LogBuffer,
    instance_id: Option<&str>,
    limit: usize,
) -> openfortivpn_manager_core::domain::LogSnapshot {
    logs.recent(instance_id, limit)
}

fn auto_reconnect_delay_seconds(attempt: u32) -> u64 {
    openfortivpn_manager_core::lifecycle::retry_delay_seconds(attempt)
}

fn schedule_auto_reconnect(
    app: AppHandle,
    profile_id: String,
    profile_name: String,
    delay_seconds: u64,
    generation: u64,
) {
    thread::spawn(move || {
        let clock = Instant::now();
        let mut timer = openfortivpn_manager_core::lifecycle::RetryTimer::default();
        timer.schedule(generation, 0, delay_seconds.saturating_mul(1000));
        loop {
            let state = app.state::<AppState>();
            if state.shutting_down.load(Ordering::SeqCst) {
                return;
            }
            let current = state
                .store
                .lock()
                .ok()
                .and_then(|store| store.reconnect_generations.get(&profile_id).copied());
            if current != Some(generation) {
                timer.cancel();
                return;
            }
            if timer.take_due(
                generation,
                clock.elapsed().as_millis().min(u64::MAX as u128) as u64,
            ) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        let still_enabled = app
            .state::<AppState>()
            .store
            .lock()
            .map(|store| {
                store
                    .profiles
                    .get(&profile_id)
                    .is_some_and(|profile| profile.auto_reconnect)
                    && store.instances.values().any(|instance| {
                        instance.view.profile_id == profile_id
                            && !instance.user_requested_stop
                            && !instance.reconnect_blocked
                    })
                    && store
                        .reconnect_generations
                        .get(&profile_id)
                        .copied()
                        .unwrap_or_default()
                        == generation
                    && !profile_has_running_instance(&store, &profile_id)
            })
            .unwrap_or(false);
        if !still_enabled {
            return;
        }

        let queued_profile = profile_id.clone();
        let start = tauri::async_runtime::block_on(run_profile_command(
            app.clone(),
            profile_id.clone(),
            move |app| {
                start_profile_impl(app, queued_profile, StartOrigin::AutoReconnect(generation))
                    .map_err(Into::into)
            },
        ))
        .map_err(|e| e.message);
        if let Err(message) = start {
            if message == AUTO_RECONNECT_CANCELLED {
                return;
            }
            let _ = app.emit(
                "vpn-autoconnect-error",
                AutoConnectError {
                    profile_id: profile_id.clone(),
                    profile_name: profile_name.clone(),
                    message: format!("自动重连失败：{message}"),
                },
            );
            let retry = app
                .state::<AppState>()
                .store
                .lock()
                .ok()
                .and_then(|mut store| {
                    let current_generation = store
                        .reconnect_generations
                        .get(&profile_id)
                        .copied()
                        .unwrap_or_default();
                    let should_retry =
                        !app.state::<AppState>().shutting_down.load(Ordering::SeqCst)
                            && current_generation == generation
                            && store
                                .profiles
                                .get(&profile_id)
                                .is_some_and(|profile| profile.auto_reconnect)
                            && store.instances.values().any(|instance| {
                                instance.view.profile_id == profile_id
                                    && automatic_retry_allowed(
                                        instance.user_requested_stop,
                                        instance.reconnect_blocked,
                                        true,
                                    )
                            })
                            && !profile_has_running_instance(&store, &profile_id);
                    if !should_retry {
                        return None;
                    }
                    let attempt = store
                        .reconnect_attempts
                        .entry(profile_id.clone())
                        .and_modify(|attempt| *attempt = attempt.saturating_add(1))
                        .or_insert(1);
                    let delay = auto_reconnect_delay_seconds(*attempt);
                    Some((delay, current_generation))
                });
            if let Some((delay, generation)) = retry {
                schedule_auto_reconnect(app, profile_id, profile_name, delay, generation);
            }
        }
    });
}

struct ProcessResources {
    config_path: PathBuf,
    process_record_path: Option<PathBuf>,
    network_lease: Option<SystemNetworkLease>,
}
fn spawn_process_monitor(
    app: AppHandle,
    instance_id: String,
    child: OwnedProcess,
    resources: ProcessResources,
    readers: Vec<StreamReader>,
) {
    thread::spawn(move || {
        let ProcessResources {
            config_path,
            process_record_path,
            mut network_lease,
        } = resources;
        let mut readers = Some(readers);
        loop {
            let status = {
                let Ok(mut child) = child.lock() else {
                    update_instance(
                        &app,
                        &instance_id,
                        "failed",
                        "无法访问 VPN 进程".to_string(),
                    );
                    return;
                };
                child.try_wait()
            };

            match status {
                Ok(Some(exit_status)) => {
                    let output_complete = drain_stream_readers(readers.take().unwrap_or_default());
                    if !output_complete {
                        record_instance_failure(
                            &app,
                            &instance_id,
                            "引擎输出未完成，需要检查残留子进程".into(),
                            true,
                        );
                    }
                    let (view, reconnect) = {
                        let state = app.state::<AppState>();
                        let Ok(mut store) = state.store.lock() else {
                            return;
                        };
                        let Some(instance) = store.instances.get(&instance_id) else {
                            return;
                        };
                        let profile_id = instance.view.profile_id.clone();
                        let profile_name = instance.view.profile_name.clone();
                        #[cfg(unix)]
                        let forced = {
                            use std::os::unix::process::ExitStatusExt;
                            exit_status.signal() == Some(libc::SIGKILL)
                        };
                        #[cfg(not(unix))]
                        let forced = !exit_status.success() && instance.user_requested_stop;
                        if let Some(instance) = store.instances.get_mut(&instance_id) {
                            if !instance.lifecycle.reaped(output_complete, forced) {
                                instance.reconnect_blocked = true;
                                instance.failure_message =
                                    Some("进程已退出，但网络清理未确认，需要恢复".into());
                            }
                            if let Some(lease) = network_lease.take() {
                                if lease
                                    .finish(true, !instance.lifecycle.cleanup_failed())
                                    .is_err()
                                {
                                    instance.lifecycle.require_recovery();
                                    instance.reconnect_blocked = true;
                                    instance.failure_message =
                                        Some("系统网络占用恢复未确认，需要本地恢复".into());
                                }
                            }
                            if !openfortivpn_manager_core::lifecycle::exit_retryable(
                                exit_status.code(),
                            ) {
                                instance.reconnect_blocked = true;
                            }
                        }
                        let instance = store
                            .instances
                            .get(&instance_id)
                            .expect("instance remains registered");
                        let user_requested_stop = instance.user_requested_stop;
                        let cleanup_failed = instance.lifecycle.cleanup_failed();
                        let reconnect_blocked = instance.reconnect_blocked;
                        let failure_message = instance.failure_message.clone();
                        let auto_reconnect = automatic_retry_allowed(
                            user_requested_stop,
                            reconnect_blocked,
                            store
                                .profiles
                                .get(&profile_id)
                                .is_some_and(|profile| profile.auto_reconnect),
                        );
                        let delay_seconds = if auto_reconnect {
                            let attempt = store
                                .reconnect_attempts
                                .entry(profile_id.clone())
                                .and_modify(|attempt| *attempt = attempt.saturating_add(1))
                                .or_insert(1);
                            Some(auto_reconnect_delay_seconds(*attempt))
                        } else {
                            if user_requested_stop {
                                store.reconnect_attempts.remove(&profile_id);
                            }
                            None
                        };
                        let generation = store
                            .reconnect_generations
                            .get(&profile_id)
                            .copied()
                            .unwrap_or_default();

                        let Some(instance) = store.instances.get_mut(&instance_id) else {
                            return;
                        };
                        instance.process_running = false;
                        if let Some(input) = instance.input.take() {
                            input.cancel();
                        }
                        instance.view.status =
                            if !cleanup_failed && (user_requested_stop || exit_status.success()) {
                                "disconnected".to_string()
                            } else {
                                "failed".to_string()
                            };
                        instance.view.message = match delay_seconds {
                            Some(delay) => format!("连接已中断，{delay} 秒后自动重连"),
                            None => failure_message.unwrap_or_else(|| match exit_status.code() {
                                Some(code) => format!("进程已退出，代码 {code}"),
                                None => "进程已终止".to_string(),
                            }),
                        };
                        instance.view.exit_code = exit_status.code();
                        instance.view.ended_at = Some(now_epoch());
                        instance.view.revision = instance.view.revision.saturating_add(1);
                        let result = (
                            instance.view.clone(),
                            delay_seconds
                                .map(|delay| (profile_id, profile_name, delay, generation)),
                        );
                        store
                            .challenges
                            .cancel_attempt(&result.0.profile_id, &instance_id);
                        result
                    };
                    let _ = fs::remove_file(&config_path);
                    if !app
                        .state::<AppState>()
                        .store
                        .lock()
                        .ok()
                        .and_then(|store| {
                            store
                                .instances
                                .get(&instance_id)
                                .map(|i| i.lifecycle.cleanup_failed())
                        })
                        .unwrap_or(true)
                    {
                        if let Some(path) = process_record_path.as_ref() {
                            let _ = fs::remove_file(path);
                        }
                    }
                    emit_instance(&app, &view);
                    if let Some((profile_id, profile_name, delay_seconds, generation)) = reconnect {
                        schedule_auto_reconnect(
                            app.clone(),
                            profile_id,
                            profile_name,
                            delay_seconds,
                            generation,
                        );
                    }
                    return;
                }
                Ok(None) => thread::sleep(Duration::from_millis(250)),
                Err(error) => {
                    record_instance_failure(
                        &app,
                        &instance_id,
                        format!("无法检查 VPN 进程：{error}"),
                        false,
                    );
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    });
}

#[tauri::command]
fn list_profiles(state: State<'_, AppState>) -> Result<Vec<ProfileView>, String> {
    let store = lock_store(&state)?;
    ensure_repository_ready(&store)?;
    Ok(store
        .profiles
        .values()
        .map(|profile| {
            let password_stored = store.stored_secret_profiles.contains(&profile.id);
            profile_view(
                profile,
                store.secrets.contains_key(&profile.id) || password_stored,
                password_stored,
            )
        })
        .collect())
}

#[tauri::command]
fn get_desktop_preferences(state: State<'_, AppState>) -> Result<DesktopPreferences, String> {
    state
        .desktop_preferences
        .lock()
        .map(|preferences| preferences.clone())
        .map_err(|_| "桌面设置状态已损坏".to_string())
}

#[tauri::command]
fn update_desktop_preferences(
    app: AppHandle,
    preferences: DesktopPreferences,
) -> Result<DesktopPreferences, String> {
    persist_desktop_preferences(&app, &preferences)?;
    let state = app.state::<AppState>();
    let mut current = state
        .desktop_preferences
        .lock()
        .map_err(|_| "桌面设置状态已损坏".to_string())?;
    *current = preferences.clone();
    drop(current);
    schedule_tray_refresh(&app);
    Ok(preferences)
}

fn reserve_profile_mutation(
    app: &AppHandle,
    profile_id: &str,
) -> Result<(), openfortivpn_manager_http::ApiError> {
    let state = app.state::<AppState>();
    let mut store = state
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?;
    ensure_repository_ready(&store).map_err(|_| repository_api_error())?;
    if store.restoring_repository || store.mutating_profiles.contains(profile_id) {
        return Err(openfortivpn_manager_http::ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "PROFILE_BUSY",
            "该配置正在被其他操作修改，请稍后重试",
            true,
        ));
    }
    if profile_connection_in_progress(&store, profile_id) {
        return Err(openfortivpn_manager_http::ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "PROFILE_BUSY",
            "该配置正在连接，请先断开",
            true,
        ));
    }
    store.mutating_profiles.insert(profile_id.to_string());
    bump_reconnect_generation(&mut store, profile_id);
    Ok(())
}

fn release_profile_mutation(app: &AppHandle, profile_id: &str) {
    let state = app.state::<AppState>();
    if let Ok(mut store) = state.store.lock() {
        store.mutating_profiles.remove(profile_id);
    };
}

async fn run_profile_command<T: Send + 'static>(
    app: AppHandle,
    profile: String,
    command: impl FnOnce(AppHandle) -> Result<T, openfortivpn_manager_http::ApiError> + Send + 'static,
) -> Result<T, openfortivpn_manager_http::ApiError> {
    let actors = app.state::<AppState>().commands.clone();
    actors
        .dispatch(&profile, async move {
            tokio::task::spawn_blocking(move || command(app))
                .await
                .map_err(|_| {
                    openfortivpn_manager_http::ApiError::from_message(
                        "配置操作 worker 失败，请检查恢复状态".into(),
                    )
                })?
        })
        .await
        .map_err(|error| openfortivpn_manager_http::ApiError::from_error(error.into()))?
}

#[tauri::command]
async fn save_profile(app: AppHandle, mut input: SaveProfileInput) -> Result<ProfileView, String> {
    if input.profile.id.trim().is_empty() {
        input.profile.id = Uuid::new_v4().to_string();
    }
    run_profile_command(app, input.profile.id.clone(), move |app| {
        save_profile_service(app, input)
    })
    .await
    .map_err(|error| error.message)
}

fn save_profile_service(
    app: AppHandle,
    mut input: SaveProfileInput,
) -> Result<ProfileView, openfortivpn_manager_http::ApiError> {
    if input.profile.id.trim().is_empty() {
        input.profile.id = Uuid::new_v4().to_string();
    }
    validate_profile(&input.profile)?;
    let profile_id = input.profile.id.clone();
    reserve_profile_mutation(&app, &profile_id)?;
    let result = (|| -> Result<ProfileView, openfortivpn_manager_http::ApiError> {
        let mut repository = profile_repository::DesktopRepository::new(&app)?;
        let view = openfortivpn_manager_core::profile_service::save(
            &mut repository,
            openfortivpn_manager_core::profile_service::SaveRequest {
                profile: input.profile.clone(),
                password: input.password.take().map(zeroize::Zeroizing::new),
                remember_password: input.remember_password,
                expected_revision: input.expected_revision,
            },
            openfortivpn_manager_core::profile_service::MissingPasswordPolicy::RequireWhenRemembering,
        )?;
        drop(repository);
        publish_privilege_status(&app);
        Ok(view)
    })();
    release_profile_mutation(&app, &profile_id);
    result
}

#[tauri::command]
async fn delete_profile(
    app: AppHandle,
    profile_id: String,
    expected_revision: Option<u64>,
    stop_first: Option<bool>,
) -> Result<(), String> {
    run_profile_command(app, profile_id.clone(), move |app| {
        delete_profile_service(
            app,
            profile_id,
            expected_revision,
            stop_first.unwrap_or(true),
        )
    })
    .await
    .map_err(|error| error.message)
}

fn delete_profile_service(
    app: AppHandle,
    profile_id: String,
    expected_revision: Option<u64>,
    stop_first: bool,
) -> Result<(), openfortivpn_manager_http::ApiError> {
    {
        let state = app.state::<AppState>();
        let store = lock_store(&state)?;
        let profile = store.profiles.get(&profile_id).ok_or_else(|| {
            openfortivpn_manager_http::ApiError::new(
                axum::http::StatusCode::NOT_FOUND,
                "PROFILE_NOT_FOUND",
                "找不到指定配置",
                false,
            )
        })?;
        openfortivpn_manager_core::profile_service::check_delete(
            profile,
            expected_revision,
            profile_connection_in_progress(&store, &profile_id),
            stop_first,
        )?;
    }
    disconnect_profile_impl(app.clone(), profile_id.clone())?;
    wait_for_profile_to_stop(&app, &profile_id)?;
    reserve_profile_mutation(&app, &profile_id)?;
    let result = (|| -> Result<(), openfortivpn_manager_http::ApiError> {
        let mut repository = profile_repository::DesktopRepository::new(&app)?;
        openfortivpn_manager_core::profile_service::delete(
            &mut repository,
            &profile_id,
            expected_revision,
        )?;
        {
            let state = app.state::<AppState>();
            let mut store = lock_store(&state)?;
            remove_profile_runtime_state(&mut store, &profile_id);
        }
        drop(repository);
        publish_privilege_status(&app);
        Ok(())
    })();
    release_profile_mutation(&app, &profile_id);
    result
}

fn remove_profile_runtime_state(store: &mut RuntimeStore, profile_id: &str) {
    store.profiles.remove(profile_id);
    if let Some(mut secret) = store.secrets.remove(profile_id) {
        secret.zeroize();
    }
    store.stored_secret_profiles.remove(profile_id);
    store.unknown_secret_profiles.remove(profile_id);
    store.reconnect_attempts.remove(profile_id);
    store.reconnect_generations.remove(profile_id);
    store
        .instances
        .retain(|_, instance| instance.view.profile_id != profile_id);
}

#[tauri::command]
fn list_instances(state: State<'_, AppState>) -> Result<Vec<InstanceView>, String> {
    let mut store = lock_store(&state)?;
    prune_finished_instances(&mut store);
    let mut instances: Vec<InstanceView> = store
        .instances
        .values()
        .map(|instance| instance.view.clone())
        .collect();
    instances.sort_by_key(|instance| std::cmp::Reverse(instance.started_at));
    Ok(instances)
}

#[tauri::command]
fn list_logs(
    state: State<'_, AppState>,
    instance_id: Option<String>,
    limit: Option<usize>,
) -> Result<openfortivpn_manager_core::domain::LogSnapshot, String> {
    let store = lock_store(&state)?;
    Ok(recent_logs(
        &store.logs,
        instance_id.as_deref(),
        limit.unwrap_or(400),
    ))
}

#[tauri::command]
fn diagnostic_report(app: AppHandle) -> Result<Value, String> {
    let snapshot = serde_json::json!({
        "profiles": list_profiles(app.state())?,
        "instances": list_instances(app.state())?,
        "logs": list_logs(app.state(),None,Some(2000))?,
        "engine": engine_info(app.clone()),
        "privilege": privilege_status_value(&app,app.state::<AppState>().privilege_ready.load(Ordering::SeqCst)),
        "runJournal": list_recovery_records(app.clone())?,
    });
    let capabilities =
        serde_json::to_value(openfortivpn_manager_core::domain::Capabilities::default())
            .map_err(|e| e.to_string())?;
    Ok(openfortivpn_manager_core::diagnostics::report(
        &snapshot,
        &capabilities,
        now_epoch(),
    ))
}

#[tauri::command]
fn engine_info(app: AppHandle) -> EngineInfo {
    let path = resolve_engine(&app);
    let state = app.state::<AppState>();
    let mut cache = state
        .engine_cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((checked, cached_path, info)) = cache.as_ref() {
        if cached_path == &path && checked.elapsed() < Duration::from_secs(60) {
            return info.clone();
        }
    }
    let (available, version, event_protocol, manager_launch_gate) =
        match openfortivpn_manager_core::engine::probe(&path) {
            Ok(metadata) => (
                true,
                metadata.version,
                metadata.event_protocol,
                metadata.manager_launch_gate,
            ),
            Err(error) => (false, error.to_string(), None, false),
        };

    let info = EngineInfo {
        platform: env::consts::OS.to_string(),
        path: path.to_string_lossy().to_string(),
        available,
        version,
        event_protocol,
        manager_launch_gate,
        requires_elevation: true,
    };
    *cache = Some((Instant::now(), path, info.clone()));
    info
}

#[cfg(unix)]
fn has_sudo_profiles(app: &AppHandle) -> bool {
    let state = app.state::<AppState>();
    state
        .store
        .lock()
        .map(|store| {
            store.profiles.values().any(|profile| profile.use_sudo)
                || !store.stale_processes.is_empty()
        })
        .unwrap_or(false)
}

#[cfg(unix)]
fn sudo_engine_ready(app: &AppHandle) -> bool {
    if !installed_components_match_bundle(app) {
        return false;
    }
    matches!(
        Command::new(SUDO_EXECUTABLE)
            .arg("-n")
            .arg(installed_helper_path())
            .arg("check")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(status) if status.success()
    )
}

fn privilege_status_value(_app: &AppHandle, ready: bool) -> PrivilegeStatus {
    #[cfg(unix)]
    let required = has_sudo_profiles(_app);
    #[cfg(windows)]
    let required = false;

    PrivilegeStatus {
        required,
        ready: !required || ready,
        platform: env::consts::OS.to_string(),
    }
}

fn set_privilege_ready(app: &AppHandle, ready: bool, emit_change: bool) -> PrivilegeStatus {
    let state = app.state::<AppState>();
    let previous = state.privilege_ready.swap(ready, Ordering::SeqCst);
    let status = privilege_status_value(app, ready);
    if emit_change && previous != ready {
        let _ = app.emit("vpn-privilege-changed", status.clone());
    }
    status
}

fn refresh_privilege_status(app: &AppHandle, emit_change: bool) -> PrivilegeStatus {
    #[cfg(unix)]
    let ready = has_sudo_profiles(app)
        && sudo_engine_ready(app)
        && cleanup_stale_runtime_processes(app).is_ok();
    #[cfg(windows)]
    let ready = true;

    set_privilege_ready(app, ready, emit_change)
}

fn publish_privilege_status(app: &AppHandle) -> PrivilegeStatus {
    let status = refresh_privilege_status(app, false);
    let _ = app.emit("vpn-privilege-changed", status.clone());
    status
}

#[cfg(unix)]
fn install_privileged_helper(app: &AppHandle, password: &mut String) -> Result<(), String> {
    let helper = resolve_bundled_helper(app)?;
    let engine = bundled_engine_for_install(app)?;
    if !helper.is_file() {
        return Err(format!("应用包内缺少权限 helper：{}", helper.display()));
    }
    if fs::symlink_metadata(&helper)
        .map(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
        .unwrap_or(true)
    {
        return Err(format!(
            "应用包内权限 helper 必须是普通文件且不能是符号链接：{}",
            helper.display()
        ));
    }
    #[cfg(target_os = "macos")]
    verify_macos_app_signature()?;

    let mut child = Command::new(SUDO_EXECUTABLE)
        .args(["-S", "-p", ""])
        .arg(&helper)
        .arg("install")
        .arg("--engine")
        .arg(&engine)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("无法启动 sudo：{error}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "无法向 sudo 提交管理员密码".to_string())?;
    let write_result = stdin
        .write_all(password.as_bytes())
        .and_then(|()| stdin.write_all(b"\n"));
    password.zeroize();
    write_result.map_err(|error| format!("无法向 sudo 提交管理员密码：{error}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|error| format!("无法等待 helper 安装结果：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if detail.is_empty() {
            "管理员密码验证失败，或系统 helper 安装失败".to_string()
        } else {
            format!("系统 helper 安装失败：{detail}")
        })
    }
}

#[tauri::command]
fn privilege_status(app: AppHandle) -> PrivilegeStatus {
    refresh_privilege_status(&app, false)
}

#[tauri::command]
fn unlock_privileges(app: AppHandle, mut password: String) -> Result<PrivilegeStatus, String> {
    #[cfg(unix)]
    let result = if password.is_empty() {
        Err("请输入电脑管理员密码".to_string())
    } else {
        install_privileged_helper(&app, &mut password).and_then(|()| {
            if sudo_engine_ready(&app) {
                cleanup_stale_runtime_processes(&app)?;
                Ok(set_privilege_ready(&app, true, true))
            } else {
                Err("helper 已安装，但免密权限校验失败".to_string())
            }
        })
    };

    #[cfg(windows)]
    let result = Ok(set_privilege_ready(&app, true, true));

    password.zeroize();
    result
}

fn start_privilege_keepalive(app: AppHandle) {
    #[cfg(unix)]
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(60));
        let state = app.state::<AppState>();
        if !state.privilege_ready.load(Ordering::SeqCst) {
            continue;
        }

        let refreshed = sudo_engine_ready(&app);
        if !refreshed {
            set_privilege_ready(&app, false, true);
        }
    });

    #[cfg(windows)]
    let _ = app;
}

#[derive(Clone, Copy)]
enum StartOrigin {
    User,
    Startup,
    AutoReconnect(u64),
}

const AUTO_RECONNECT_CANCELLED: &str = "自动重连已取消";

fn reuse_running_instance_for_start(origin: StartOrigin) -> bool {
    matches!(origin, StartOrigin::User)
}

fn reserve_start_generation(
    store: &mut RuntimeStore,
    profile_id: &str,
    origin: StartOrigin,
) -> Result<u64, String> {
    match origin {
        StartOrigin::AutoReconnect(expected) => {
            let current = store
                .reconnect_generations
                .get(profile_id)
                .copied()
                .unwrap_or_default();
            if current != expected {
                return Err(AUTO_RECONNECT_CANCELLED.to_string());
            }
            // This value is a cancellation token, not an attempt counter. Keep
            // it stable across transient automatic-start failures so the retry
            // loop remains valid until a user action explicitly invalidates it.
            Ok(expected)
        }
        StartOrigin::User | StartOrigin::Startup => {
            Ok(bump_reconnect_generation(store, profile_id))
        }
    }
}

#[cfg(unix)]
fn terminate_unregistered_process_group(
    pid: u32,
    use_sudo: bool,
    engine: &std::path::Path,
) -> bool {
    let result = if use_sudo {
        Command::new(SUDO_EXECUTABLE)
            .arg("-n")
            .arg(installed_helper_path())
            .arg("stop")
            .arg(pid.to_string())
            .status()
    } else {
        let process_group = format!("-{pid}");
        Command::new("kill")
            .args(["-TERM", "--"])
            .arg(process_group)
            .status()
    };
    if !matches!(result, Ok(status) if status.success()) {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && process_group_contains_engine(pid, engine) {
        thread::sleep(Duration::from_millis(100));
    }
    !process_group_contains_engine(pid, engine)
}

fn spawn_profile_process(
    app: AppHandle,
    profile: VpnProfile,
    password: String,
    profile_generation: u64,
) -> Result<InstanceView, String> {
    let state = app.state::<AppState>();
    let _lifecycle_guard = state
        .lifecycle
        .lock()
        .map_err(|_| "连接生命周期状态已损坏".to_string())?;
    if state.shutting_down.load(Ordering::SeqCst) {
        return Err("应用正在退出，不能启动新的连接".to_string());
    }
    let generation_is_current = state
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?
        .reconnect_generations
        .get(&profile.id)
        .copied()
        .unwrap_or_default()
        == profile_generation;
    if !generation_is_current {
        return Err(AUTO_RECONNECT_CANCELLED.to_string());
    }

    #[cfg(unix)]
    if profile.use_sudo {
        if !sudo_engine_ready(&app) {
            set_privilege_ready(&app, false, true);
            return Err("系统 VPN helper 尚未安装或与当前版本不匹配，请在桌面端手动连接一次以完成安装或更新".to_string());
        }
        set_privilege_ready(&app, true, true);
    }

    let instance_id = Uuid::new_v4().to_string();
    let private_control = authentication::experimental_control();
    let adapter_name = make_adapter_name(&profile, &instance_id);
    #[cfg(unix)]
    let gated_launch = !profile.use_sudo && engine_info(app.clone()).manager_launch_gate;
    let config_path = write_runtime_config(&app, &profile, &password, &instance_id, &adapter_name)?;
    let bundled_engine = resolve_engine(&app);
    #[cfg(unix)]
    let process_engine = if profile.use_sudo {
        installed_engine_path()
    } else {
        bundled_engine.clone()
    };
    #[cfg(windows)]
    let process_engine = bundled_engine.clone();

    let mut runtime_record = RuntimeProcessRecord {
        instance_id: instance_id.clone(),
        profile_id: profile.id.clone(),
        pid: 0,
        process_group_id: 0,
        engine_path: process_engine.to_string_lossy().into_owned(),
        config_path: config_path.to_string_lossy().into_owned(),
        #[cfg(windows)]
        process_identity: None,
    };
    let process_record_path = match persist_runtime_process_record(&app, &runtime_record) {
        Ok(path) => Some(path),
        Err(message) => {
            let _ = fs::remove_file(&config_path);
            return Err(message);
        }
    };
    // Keep a local recovery path before the global write. An uncertain global
    // fsync can publish ownership even when acquire returns an error.
    #[cfg(unix)]
    let mut network_lease = if !profile.use_sudo {
        use openfortivpn_manager_core::network_authority as authority;
        let directory = match authority::system_directory() {
            Ok(directory) => directory,
            Err(error) => {
                remove_runtime_process_record(&app, &runtime_record);
                return Err(error.to_string());
            }
        };
        match authority::ExclusiveLease::acquire(
            &directory,
            authority::Owner {
                attempt_id: instance_id.clone(),
                manager: "desktop".into(),
                uid: unsafe { libc::geteuid() },
                process_group: 0,
                pre_spawn_gated: gated_launch,
            },
        ) {
            Ok(lease) => Some(lease),
            Err(error) => {
                let uncertain = match authority::inspect(&directory) {
                    Ok(Some(owner)) => owner.attempt_id == instance_id,
                    Ok(None) => false,
                    Err(_) => true,
                };
                if uncertain {
                    if let Ok(mut store) = state.store.lock() {
                        store
                            .stale_processes
                            .insert(instance_id.clone(), runtime_record.clone());
                    }
                } else {
                    remove_runtime_process_record(&app, &runtime_record);
                }
                return Err(error.to_string());
            }
        }
    } else {
        None
    };
    #[cfg(windows)]
    let mut network_lease = {
        use openfortivpn_manager_core::windows_network_authority::{MachineAuthority, Owner};
        let prepared = MachineAuthority::open_system().and_then(|authority| {
            Owner::new(
                instance_id.clone(),
                "desktop".into(),
                process_engine.to_string_lossy().into_owned(),
            )
            .map(|owner| (authority, owner))
        });
        let (authority, owner) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                remove_runtime_process_record(&app, &runtime_record);
                return Err(error.to_string());
            }
        };
        match authority.acquire(owner) {
            Ok(lease) => Some(lease),
            Err(error) => {
                let uncertain = match MachineAuthority::open_system()
                    .and_then(|authority| authority.inspect())
                {
                    Ok(Some(owner)) => owner.attempt_id == instance_id,
                    Ok(None) => false,
                    Err(_) => true,
                };
                if uncertain {
                    if let Ok(mut store) = state.store.lock() {
                        store
                            .stale_processes
                            .insert(instance_id.clone(), runtime_record.clone());
                    }
                } else {
                    remove_runtime_process_record(&app, &runtime_record);
                }
                return Err(error.to_string());
            }
        }
    };

    #[cfg(unix)]
    let mut command = if profile.use_sudo {
        let mut command = Command::new(SUDO_EXECUTABLE);
        command
            .arg("-n")
            .arg(installed_helper_path())
            .arg("run")
            .arg(&config_path)
            .arg(format!("--owner-attempt={instance_id}"));
        command
    } else {
        let mut command = Command::new(&bundled_engine);
        command.arg("--json-events").arg("-c").arg(&config_path);
        command
    };

    #[cfg(windows)]
    let mut command = {
        let mut command = Command::new(&bundled_engine);
        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
        command.arg("--json-events").arg("-c").arg(&config_path);
        command
    };

    command
        .stdin(if private_control {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !profile.gateway_dns.is_empty() && !profile.use_sudo {
        command.arg(format!("--gateway-dns={}", profile.gateway_dns));
    }
    #[cfg(windows)]
    if !profile.gateway_dns.is_empty() && profile.use_sudo {
        command.arg(format!("--gateway-dns={}", profile.gateway_dns));
    }
    if private_control {
        command.arg(format!("--manager-control={instance_id}"));
    }

    #[cfg(unix)]
    command.process_group(0);
    #[cfg(unix)]
    let launch_gate = if gated_launch {
        match openfortivpn_manager_core::supervisor::LaunchGate::prepare(&mut command) {
            Ok(gate) => Some(gate),
            Err(error) => {
                finish_unstarted_process(&app, &runtime_record, &mut network_lease)?;
                return Err(error.to_string());
            }
        }
    } else {
        None
    };

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            finish_unstarted_process(&app, &runtime_record, &mut network_lease)?;
            return Err(format!("无法启动 {}：{error}", bundled_engine.display()));
        }
    };
    let stdout = child.stdout.take();
    drop(command);
    let stderr = child.stderr.take();
    let pid = child.id();
    let input_result = child
        .stdin
        .take()
        .map(|pipe| openfortivpn_manager_core::private_input::PrivateInput::new(pipe).map(Arc::new))
        .transpose();
    let input = match input_result {
        Ok(input) => input,
        Err(error) => {
            runtime_record.pid = pid;
            runtime_record.process_group_id = pid;
            let _ = persist_runtime_process_record(&app, &runtime_record);
            #[cfg(unix)]
            let stopped =
                terminate_unregistered_process_group(pid, profile.use_sudo, &process_engine);
            #[cfg(windows)]
            let stopped = child.kill().is_ok();
            reap_unregistered_child(child, stopped);
            if let Ok(mut store) = state.store.lock() {
                store
                    .stale_processes
                    .insert(instance_id.clone(), runtime_record);
            }
            return Err(format!("无法建立私有引擎通道：{error}；恢复记录已保留"));
        }
    };

    #[cfg(unix)]
    {
        runtime_record.pid = pid;
        runtime_record.process_group_id = pid;
        let persisted = persist_runtime_process_record(&app, &runtime_record).and_then(|_| {
            if let Some(lease) = network_lease.as_mut() {
                lease.bind_process_group(pid).map_err(|e| e.to_string())?;
            }
            if let Some(gate) = launch_gate {
                gate.release().map_err(|e| e.to_string())?;
            }
            Ok(())
        });
        if let Err(message) = persisted {
            let stopped =
                terminate_unregistered_process_group(pid, profile.use_sudo, &process_engine);
            reap_unregistered_child(child, stopped);
            if let Ok(mut store) = app.state::<AppState>().store.lock() {
                store
                    .stale_processes
                    .insert(instance_id.clone(), runtime_record.clone());
            }
            return Err(format!(
                "{message}；{}",
                if stopped {
                    "已停止未登记的 VPN 进程"
                } else {
                    "无法确认 VPN 进程已停止，已保留恢复记录并阻止再次连接"
                }
            ));
        }
    }

    #[cfg(windows)]
    {
        runtime_record.pid = pid;
        runtime_record.process_group_id = pid;
        let captured =
            openfortivpn_manager_core::windows_process::inspect(pid).map_err(|e| e.to_string());
        let persisted = match captured {
            Ok(Some(identity)) => {
                runtime_record.process_identity = Some(identity.clone());
                persist_runtime_process_record(&app, &runtime_record)
                    .map(|_| ())
                    .and_then(|_| {
                        network_lease
                            .as_mut()
                            .ok_or_else(|| "系统网络占用未登记".to_string())?
                            .bind_process(identity)
                            .map_err(|error| error.to_string())
                    })
            }
            Ok(None) => Err("引擎在进程身份登记前已退出".into()),
            Err(error) => Err(error),
        };
        if let Err(message) = persisted {
            // The Child handle still binds this process even if its numeric
            // PID was reused. Never kill using the persisted PID here.
            let _ = child.kill();
            reap_unregistered_child(child, true);
            if let Ok(mut store) = app.state::<AppState>().store.lock() {
                store
                    .stale_processes
                    .insert(instance_id.clone(), runtime_record);
            }
            return Err(format!("{message}；运行记录已保留，需要确认网络恢复"));
        }
    }

    let child = OwnedProcess::new(child);
    let attempt_sequence = state
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏")?
        .instances
        .values()
        .filter(|instance| instance.view.profile_id == profile.id)
        .map(|instance| instance.view.attempt_sequence)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let view = InstanceView {
        id: instance_id.clone(),
        profile_generation,
        attempt_sequence,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        adapter_name,
        status: "starting".to_string(),
        message: "VPN 进程已启动".to_string(),
        pid,
        started_at: now_epoch(),
        ended_at: None,
        exit_code: None,
        revision: 0,
    };

    let cancelled_before_registration = {
        let state = app.state::<AppState>();
        let mut store = state
            .store
            .lock()
            .map_err(|_| "内部运行状态已损坏".to_string())?;
        let cancelled = state.shutting_down.load(Ordering::SeqCst)
            || store
                .reconnect_generations
                .get(&profile.id)
                .copied()
                .unwrap_or_default()
                != profile_generation;
        store
            .instances
            .retain(|_, instance| instance.view.profile_id != profile.id);
        store.instances.insert(
            instance_id.clone(),
            ManagedInstance {
                view: view.clone(),
                source_profile: profile.clone(),
                child: child.clone(),
                input,
                process_running: true,
                lifecycle: openfortivpn_manager_core::lifecycle::EngineLifecycle::for_attempt(
                    &instance_id,
                    private_control,
                ),
                user_requested_stop: false,
                reconnect_blocked: false,
                failure_message: None,
            },
        );
        prune_finished_instances(&mut store);
        cancelled
    };

    emit_instance(&app, &view);
    let mut readers = Vec::new();
    if let Some(stdout) = stdout {
        readers.push(spawn_stream_reader(
            stdout,
            app.clone(),
            instance_id.clone(),
            "stdout",
        ));
    }
    if let Some(stderr) = stderr {
        readers.push(spawn_stream_reader(
            stderr,
            app.clone(),
            instance_id.clone(),
            "stderr",
        ));
    }
    spawn_process_monitor(
        app.clone(),
        instance_id,
        child,
        ProcessResources {
            config_path,
            process_record_path,
            network_lease,
        },
        readers,
    );

    if cancelled_before_registration {
        stop_instance_impl(
            app.clone(),
            app.state::<AppState>(),
            view.id.clone(),
            Some(profile.id),
        )
        .map_err(|message| format!("{AUTO_RECONNECT_CANCELLED}，且停止新进程失败：{message}"))?;
        return Err(AUTO_RECONNECT_CANCELLED.to_string());
    }

    Ok(view)
}

fn emit_profiles_changed(app: &AppHandle) {
    if let Ok(profiles) = list_profiles(app.state()) {
        let _ = app.emit("vpn-profiles-changed", profiles);
    }
    schedule_tray_refresh(app);
}

fn clear_missing_stored_password(app: &AppHandle, profile_id: &str) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut store = state
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?;
    if !store.stored_secret_profiles.contains(profile_id) {
        return Ok(());
    }
    let mut stored_secret_profiles = store.stored_secret_profiles.clone();
    let mut unknown_secret_profiles = store.unknown_secret_profiles.clone();
    stored_secret_profiles.remove(profile_id);
    unknown_secret_profiles.remove(profile_id);
    let profiles = store.profiles.clone();
    commit_profile_metadata(&mut store, || {
        persist_profiles(
            app,
            &profiles,
            &stored_secret_profiles,
            &unknown_secret_profiles,
        )
    })?;
    store.stored_secret_profiles = stored_secret_profiles;
    store.unknown_secret_profiles = unknown_secret_profiles;
    store.secrets.remove(profile_id);
    drop(store);
    emit_profiles_changed(app);
    Ok(())
}

fn resolve_profile_password(
    app: &AppHandle,
    profile_id: &str,
    session_password: Option<String>,
    password_stored: bool,
) -> Result<String, String> {
    if let Some(password) = session_password {
        return Ok(password);
    }
    if !password_stored {
        return Err("当前没有可用的 VPN 密码，请输入密码后再连接".to_string());
    }

    let password = match read_usable_stored_password(app, profile_id)? {
        Some(password) => password,
        None => {
            clear_missing_stored_password(app, profile_id)?;
            return Err("本机凭据存储中的 VPN 密码已不存在，请重新输入并保存".to_string());
        }
    };
    let state = app.state::<AppState>();
    let mut store = state
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?;
    if !store.profiles.contains_key(profile_id)
        || !store.stored_secret_profiles.contains(profile_id)
    {
        return Err("VPN 配置或已保存密码在连接期间发生了变化，请重试".to_string());
    }
    store
        .secrets
        .insert(profile_id.to_string(), password.clone());
    Ok(password)
}

fn desktop_connect_admission(
    store: &RuntimeStore,
    profile_id: &str,
    shutting_down: bool,
    origin: StartOrigin,
) -> Result<Option<InstanceView>, openfortivpn_manager_core::ControlError> {
    use openfortivpn_manager_core::connection_service::{
        self, ConnectDecision, ConnectFacts, ConnectionOwner, OwnershipState,
    };
    use openfortivpn_manager_core::{ControlError, ErrorCode};
    let owners = store
        .starting_profiles
        .iter()
        .map(|id| ConnectionOwner {
            profile_id: id,
            instance_id: None,
            state: OwnershipState::StartingReservation,
        })
        .chain(store.instances.values().filter_map(|instance| {
            let state = if instance.lifecycle.cleanup_failed() {
                OwnershipState::RecoveryRequired
            } else if !instance.process_running {
                return None;
            } else if instance.user_requested_stop || instance.view.status == "disconnecting" {
                OwnershipState::Stopping
            } else {
                OwnershipState::Healthy
            };
            Some(ConnectionOwner {
                profile_id: &instance.view.profile_id,
                instance_id: Some(&instance.view.id),
                state,
            })
        }))
        .collect::<Vec<_>>();
    let origin = if reuse_running_instance_for_start(origin) {
        connection_service::StartOrigin::User
    } else {
        match origin {
            StartOrigin::Startup => connection_service::StartOrigin::Startup,
            _ => connection_service::StartOrigin::Automatic,
        }
    };
    let facts = ConnectFacts {
        profile_id,
        profile_exists: store.profiles.contains_key(profile_id),
        shutting_down,
        repository_recovery_required: store.repository_recovery_required,
        repository_restoring: store.restoring_repository,
        profile_mutating: store.mutating_profiles.contains(profile_id),
        orphaned_recovery: !store.stale_processes.is_empty(),
        owners: &owners,
    };
    match connection_service::admit(&facts, origin)? {
        ConnectDecision::Reserve => Ok(None),
        ConnectDecision::Reuse(id) => store
            .instances
            .values()
            .find(|instance| instance.view.id == id && instance.view.profile_id == profile_id)
            .map(|instance| Some(instance.view.clone()))
            .ok_or_else(|| {
                ControlError::new(
                    ErrorCode::RecoveryRequired,
                    "published connection ownership is inconsistent",
                )
            }),
    }
}

fn desktop_connect_error_message(error: openfortivpn_manager_core::ControlError) -> String {
    use openfortivpn_manager_core::ErrorCode;
    match error.code {
        ErrorCode::InvalidInput => "连接配置标识无效",
        ErrorCode::ShuttingDown => "应用正在退出，不能启动新的连接",
        ErrorCode::ProfileNotFound => "找不到指定配置",
        ErrorCode::ProfileBusy => "该配置正在连接、停止或修改，请稍后重试",
        ErrorCode::NetworkConflict => "网络资源正在被其他配置使用，请先断开该连接",
        ErrorCode::RecoveryRequired => "存在未确认清理的进程、网络资源或配置存储，请先完成恢复",
        _ => "连接准入失败，请检查配置及运行状态",
    }
    .to_string()
}

fn start_profile_impl(
    app: AppHandle,
    profile_id: String,
    origin: StartOrigin,
) -> Result<InstanceView, String> {
    let (profile, session_password, password_stored, profile_generation) = {
        let state = app.state::<AppState>();
        let mut store = state
            .store
            .lock()
            .map_err(|_| "内部运行状态已损坏".to_string())?;
        if let Some(instance) = desktop_connect_admission(
            &store,
            &profile_id,
            state.shutting_down.load(Ordering::SeqCst),
            origin,
        )
        .map_err(desktop_connect_error_message)?
        {
            return Ok(instance);
        }

        // The shared admission and this reservation hold the same runtime
        // lock; credential workers cannot start an unreserved connection.
        let profile = store
            .profiles
            .get(&profile_id)
            .cloned()
            .ok_or_else(|| "找不到指定配置".to_string())?;
        let session_password = store.secrets.get(&profile_id).cloned();
        let password_stored = store.stored_secret_profiles.contains(&profile_id);
        let profile_generation = reserve_start_generation(&mut store, &profile_id, origin)?;
        store.starting_profiles.insert(profile_id.clone());
        (
            profile,
            session_password,
            password_stored,
            profile_generation,
        )
    };

    let result = resolve_profile_password(&app, &profile_id, session_password, password_stored)
        .and_then(|password| {
            spawn_profile_process(app.clone(), profile, password, profile_generation)
        });
    if let Ok(mut store) = app.state::<AppState>().store.lock() {
        store.starting_profiles.remove(&profile_id);
    }
    result
}

#[tauri::command]
async fn start_profile(app: AppHandle, profile_id: String) -> Result<InstanceView, String> {
    run_profile_command(app, profile_id.clone(), move |app| {
        start_profile_impl(app, profile_id, StartOrigin::User).map_err(Into::into)
    })
    .await
    .map_err(|error| error.message)
}

#[tauri::command]
async fn stop_instance(
    app: AppHandle,
    instance_id: String,
    profile_id: Option<String>,
) -> Result<(), String> {
    let profile = {
        let state = app.state::<AppState>();
        let mut store = lock_store(&state)?;
        let profile = store
            .instances
            .get(&instance_id)
            .map(|i| i.view.profile_id.clone())
            .or(profile_id.clone())
            .ok_or("找不到指定连接实例")?;
        // Cancel intent immediately, including a credential worker that has
        // not registered its child yet. The mailbox still serializes effects.
        bump_reconnect_generation(&mut store, &profile);
        profile
    };
    run_profile_command(app, profile, move |app| {
        stop_instance_impl(app.clone(), app.state(), instance_id, profile_id).map_err(Into::into)
    })
    .await
    .map_err(|e| e.message)
}

fn stop_instance_impl(
    app: AppHandle,
    state: State<'_, AppState>,
    instance_id: String,
    profile_id: Option<String>,
) -> Result<(), String> {
    let instance_id = {
        let mut store = lock_store(&state)?;
        if store.instances.contains_key(&instance_id) {
            instance_id
        } else if let Some(profile_id) = profile_id {
            if let Some(instance) = store
                .instances
                .values()
                .find(|instance| instance.view.profile_id == profile_id)
            {
                instance.view.id.clone()
            } else if store.starting_profiles.contains(&profile_id) {
                bump_reconnect_generation(&mut store, &profile_id);
                return Ok(());
            } else {
                return Ok(());
            }
        } else {
            return Err("找不到指定连接实例".to_string());
        }
    };

    let already_stopped = {
        let store = lock_store(&state)?;
        !store
            .instances
            .get(&instance_id)
            .ok_or_else(|| "找不到指定连接实例".to_string())?
            .process_running
    };
    if already_stopped {
        if let Some(view) = cancel_reconnect_for_stopped_instance(&app, &instance_id)? {
            emit_instance(&app, &view);
        }
        return Ok(());
    }

    let (child, pid, use_sudo, previous_status) = {
        let store = lock_store(&state)?;
        let profile_id = store
            .instances
            .get(&instance_id)
            .map(|instance| instance.view.profile_id.clone())
            .ok_or_else(|| "找不到指定连接实例".to_string())?;
        let use_sudo = store
            .profiles
            .get(&profile_id)
            .map(|profile| profile.use_sudo)
            .unwrap_or(true);
        let instance = store
            .instances
            .get(&instance_id)
            .ok_or_else(|| "找不到指定连接实例".to_string())?;
        (
            instance.child.clone(),
            instance.view.pid,
            use_sudo,
            instance.view.status.clone(),
        )
    };

    {
        let mut store = lock_store(&state)?;
        if let Some(instance) = store.instances.get_mut(&instance_id) {
            instance.user_requested_stop = true;
            if let Some(input) = &instance.input {
                input.cancel();
            }
            let profile = instance.view.profile_id.clone();
            store.challenges.cancel_attempt(&profile, &instance_id);
        }
    }
    // Serialize against the monitor's wait/reap while sending a signal. A
    // reaped PID can be reused during output draining and must not be signalled.
    let mut owned_child = child.lock().map_err(|_| "进程所有权状态已损坏")?;
    if owned_child.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Ok(());
    }

    #[cfg(unix)]
    if use_sudo && !sudo_engine_ready(&app) {
        set_privilege_ready(&app, false, true);
        return Err("系统 helper 不可用，请重新安装后再断开连接".to_string());
    }

    let view = {
        let mut store = lock_store(&state)?;
        let profile_id = {
            let instance = store
                .instances
                .get(&instance_id)
                .ok_or_else(|| "找不到指定连接实例".to_string())?;
            if !instance.process_running {
                drop(store);
                if let Some(view) = cancel_reconnect_for_stopped_instance(&app, &instance_id)? {
                    emit_instance(&app, &view);
                }
                return Ok(());
            }
            instance.view.profile_id.clone()
        };
        bump_reconnect_generation(&mut store, &profile_id);
        let instance = store
            .instances
            .get_mut(&instance_id)
            .ok_or_else(|| "找不到指定连接实例".to_string())?;
        instance.user_requested_stop = true;
        instance.view.status = "disconnecting".to_string();
        instance.view.message = "正在断开连接".to_string();
        instance.view.revision = instance.view.revision.saturating_add(1);
        instance.view.clone()
    };
    emit_instance(&app, &view);

    #[cfg(unix)]
    {
        let result = if use_sudo {
            Command::new(SUDO_EXECUTABLE)
                .arg("-n")
                .arg(installed_helper_path())
                .arg("stop")
                .arg(pid.to_string())
                .status()
        } else {
            let process_group = format!("-{pid}");
            Command::new("kill")
                .args(["-TERM", "--"])
                .arg(&process_group)
                .status()
        };
        // The monitor must be able to reap before checking whether the process
        // group is gone. Keep ownership locked only through signal delivery.
        drop(owned_child);
        let signal_sent = matches!(&result, Ok(status) if status.success());
        if !signal_sent {
            let process_already_stopped = {
                let store = lock_store(&state)?;
                store
                    .instances
                    .get(&instance_id)
                    .is_none_or(|instance| !instance.process_running)
            };
            if process_already_stopped {
                return Ok(());
            }
            let detail = match result {
                Ok(status) => format!("kill 返回状态 {status}"),
                Err(error) => error.to_string(),
            };
            restore_instance_after_stop_failure(
                &app,
                &instance_id,
                &previous_status,
                format!("断开失败：{detail}"),
            );
            return Err(format!(
                "无法安全停止 VPN 进程组：{detail}；运行记录已保留以便恢复"
            ));
        }
        if signal_sent {
            let engine = if use_sudo {
                installed_engine_path()
            } else {
                resolve_engine(&app)
            };
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline && process_group_contains_engine(pid, &engine) {
                thread::sleep(Duration::from_millis(100));
            }
            if process_group_contains_engine(pid, &engine) {
                return Err("等待 VPN 进程组退出超时".to_string());
            }
        }
    }

    #[cfg(windows)]
    {
        let _ = use_sudo;
        let result = send_windows_ctrl_break(pid);
        drop(owned_child);
        if let Err(error) = result {
            let process_already_stopped = {
                let store = lock_store(&state)?;
                store
                    .instances
                    .get(&instance_id)
                    .is_none_or(|instance| !instance.process_running)
            };
            if process_already_stopped {
                return Ok(());
            }
            restore_instance_after_stop_failure(
                &app,
                &instance_id,
                &previous_status,
                format!("断开失败：{error}"),
            );
            return Err(format!("无法停止 VPN 进程：{error}"));
        }
    }

    Ok(())
}

fn profile_is_active_or_starting(app: &AppHandle, profile_id: &str) -> bool {
    app.state::<AppState>()
        .store
        .lock()
        .map(|store| profile_connection_in_progress(&store, profile_id))
        .unwrap_or(true)
}

#[tauri::command]
async fn await_profile_stopped(
    app: AppHandle,
    profile_id: String,
    instance_id: String,
) -> Result<InstanceView, String> {
    run_profile_command(app, profile_id.clone(), move |app| {
        wait_for_profile_to_stop(&app, &profile_id)?;
        let state = app.state::<AppState>();
        let store = lock_store(&state)?;
        let instance = store
            .instances
            .get(&instance_id)
            .ok_or("证书提示对应的连接已不存在")?;
        if instance.view.profile_id != profile_id
            || profile_connection_in_progress(&store, &profile_id)
        {
            return Err("证书提示对应的连接已改变或尚未完成清理".into());
        }
        Ok(instance.view.clone())
    })
    .await
    .map_err(|error| error.message)
}

fn wait_for_profile_to_stop(app: &AppHandle, profile_id: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if !profile_is_active_or_starting(app, profile_id) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("等待旧连接断开超时，请确认进程状态后重试".to_string())
}

fn disconnect_profile_impl(app: AppHandle, profile_id: String) -> Result<(), String> {
    let instance_id = app
        .state::<AppState>()
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?
        .instances
        .values()
        .filter(|instance| instance.view.profile_id == profile_id)
        .max_by_key(|instance| {
            (
                instance.process_running,
                instance.view.started_at,
                instance.view.revision,
            )
        })
        .map(|instance| instance.view.id.clone())
        .unwrap_or_default();
    stop_instance_impl(
        app.clone(),
        app.state::<AppState>(),
        instance_id,
        Some(profile_id),
    )
}

fn reconnect_profile_impl(app: AppHandle, profile_id: String) -> Result<InstanceView, String> {
    disconnect_profile_impl(app.clone(), profile_id.clone())?;
    wait_for_profile_to_stop(&app, &profile_id)?;
    start_profile_impl(app, profile_id, StartOrigin::User)
}

#[tauri::command]
async fn reconnect_profile(app: AppHandle, profile_id: String) -> Result<InstanceView, String> {
    run_profile_command(app, profile_id.clone(), move |app| {
        reconnect_profile_impl(app, profile_id).map_err(Into::into)
    })
    .await
    .map_err(|e| e.message)
}

#[tauri::command]
async fn disconnect_all(app: AppHandle) -> Result<(), String> {
    let profile_ids = app
        .state::<AppState>()
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?
        .profiles
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let mut errors = Vec::new();
    for profile_id in profile_ids {
        if profile_is_active_or_starting(&app, &profile_id) {
            if let Err(error) = run_profile_command(app.clone(), profile_id.clone(), move |app| {
                disconnect_profile_impl(app, profile_id).map_err(Into::into)
            })
            .await
            {
                errors.push(error.message);
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("部分连接无法断开：{}", errors.join("；")))
    }
}

#[cfg(windows)]
fn send_windows_ctrl_break(pid: u32) -> Result<(), String> {
    // The engine installs a CTRL_BREAK handler that leaves its I/O loop and
    // restores routes, DNS and the Wintun adapter before exiting.
    unsafe {
        let attached = AttachConsole(pid) != 0;
        if SetConsoleCtrlHandler(None, 1) == 0 {
            if attached {
                FreeConsole();
            }
            return Err(format!(
                "无法保护管理器进程免受控制台信号：{}",
                std::io::Error::last_os_error()
            ));
        }
        let sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) != 0;
        thread::sleep(Duration::from_millis(100));
        SetConsoleCtrlHandler(None, 0);
        if attached {
            FreeConsole();
        }
        if sent {
            Ok(())
        } else {
            Err(format!(
                "无法向 VPN 进程发送 CTRL_BREAK：{}",
                std::io::Error::last_os_error()
            ))
        }
    }
}

#[tauri::command]
fn export_profile_config(state: State<'_, AppState>, profile_id: String) -> Result<String, String> {
    let store = lock_store(&state)?;
    ensure_repository_ready(&store)?;
    let profile = store
        .profiles
        .get(&profile_id)
        .ok_or_else(|| "找不到指定配置".to_string())?;
    render_runtime_config(profile, "", "openfortivpn")
}

fn profile_has_active_instance(app: &AppHandle, profile_id: &str) -> bool {
    let state = app.state::<AppState>();
    state
        .store
        .lock()
        .map(|store| {
            store.mutating_profiles.contains(profile_id)
                || profile_connection_in_progress(&store, profile_id)
        })
        .unwrap_or(false)
}

fn attempt_auto_connect(app: &AppHandle, profile_id: String, profile_name: String) {
    if profile_has_active_instance(app, &profile_id) {
        return;
    }
    let queued_profile = profile_id.clone();
    let start = tauri::async_runtime::block_on(run_profile_command(
        app.clone(),
        profile_id.clone(),
        move |app| {
            start_profile_impl(app, queued_profile, StartOrigin::Startup).map_err(Into::into)
        },
    ))
    .map_err(|e| e.message);
    if let Err(message) = start {
        let _ = app.emit(
            "vpn-autoconnect-error",
            AutoConnectError {
                profile_id,
                profile_name,
                message,
            },
        );
    }
}

fn start_auto_connect_profiles(app: AppHandle, credential_errors: Vec<AutoConnectError>) {
    thread::spawn(move || {
        // Give the webview time to register event listeners before reporting startup failures.
        thread::sleep(Duration::from_millis(900));

        let credential_error_profiles = credential_errors
            .iter()
            .map(|error| error.profile_id.clone())
            .collect::<HashSet<_>>();
        for error in credential_errors {
            let _ = app.emit("vpn-autoconnect-error", error);
        }

        let profiles = {
            let state = app.state::<AppState>();
            let Ok(store) = state.store.lock() else {
                return;
            };
            store
                .profiles
                .values()
                .filter(|profile| {
                    profile.auto_connect && !credential_error_profiles.contains(&profile.id)
                })
                .map(|profile| (profile.id.clone(), profile.name.clone(), profile.use_sudo))
                .collect::<Vec<_>>()
        };

        let mut waiting_for_privilege = Vec::new();
        for (profile_id, profile_name, use_sudo) in profiles {
            if cfg!(unix)
                && use_sudo
                && !app
                    .state::<AppState>()
                    .privilege_ready
                    .load(Ordering::SeqCst)
            {
                let _ = app.emit(
                    "vpn-autoconnect-error",
                    AutoConnectError {
                        profile_id: profile_id.clone(),
                        profile_name: profile_name.clone(),
                        message: "系统 VPN Helper 尚未安装；请在桌面点击一次连接完成安装"
                            .to_string(),
                    },
                );
                waiting_for_privilege.push((profile_id, profile_name));
            } else {
                attempt_auto_connect(&app, profile_id, profile_name);
            }
        }

        while !waiting_for_privilege.is_empty() {
            thread::sleep(Duration::from_millis(250));
            if app.state::<AppState>().shutting_down.load(Ordering::SeqCst) {
                return;
            }
            if !app
                .state::<AppState>()
                .privilege_ready
                .load(Ordering::SeqCst)
            {
                continue;
            }

            for (profile_id, profile_name) in waiting_for_privilege.drain(..) {
                attempt_auto_connect(&app, profile_id, profile_name);
            }
        }
    });
}

fn startup_credential_result_is_current(
    store: &RuntimeStore,
    profile: &VpnProfile,
    was_unknown: bool,
    was_stored: bool,
) -> bool {
    store.profiles.get(&profile.id) == Some(profile)
        && if was_unknown {
            store.unknown_secret_profiles.contains(&profile.id)
        } else {
            was_stored && store.stored_secret_profiles.contains(&profile.id)
        }
}

fn load_startup_credentials(
    app: AppHandle,
    profiles: BTreeMap<String, VpnProfile>,
    stored_secret_profiles: HashSet<String>,
    unknown_secret_profiles: HashSet<String>,
) {
    thread::spawn(move || {
        let mut credential_errors = Vec::new();
        let mut results = Vec::new();
        for profile in profiles.values().cloned() {
            let was_unknown = unknown_secret_profiles.contains(&profile.id);
            let was_stored = stored_secret_profiles.contains(&profile.id);
            if was_unknown || (profile.auto_connect && was_stored) {
                results.push((
                    profile.clone(),
                    was_unknown,
                    read_usable_stored_password(&app, &profile.id),
                ));
            } else if profile.auto_connect && !was_stored {
                credential_errors.push(AutoConnectError {
                    profile_id: profile.id,
                    profile_name: profile.name,
                    message: "自动连接需要先保存 VPN 密码".to_string(),
                });
            }
        }

        if let Ok(mut store) = app.state::<AppState>().store.lock() {
            let mut metadata_changed = false;
            for (profile, was_unknown, result) in results {
                if store.repository_recovery_required || store.restoring_repository {
                    continue;
                }
                let was_stored = stored_secret_profiles.contains(&profile.id);
                if !startup_credential_result_is_current(&store, &profile, was_unknown, was_stored)
                {
                    continue;
                }
                match result {
                    Ok(Some(password)) => {
                        store.secrets.insert(profile.id.clone(), password);
                        metadata_changed |= store.stored_secret_profiles.insert(profile.id.clone());
                        metadata_changed |= store.unknown_secret_profiles.remove(&profile.id);
                    }
                    Ok(None) => {
                        metadata_changed |= store.stored_secret_profiles.remove(&profile.id);
                        metadata_changed |= store.unknown_secret_profiles.remove(&profile.id);
                        if profile.auto_connect {
                            credential_errors.push(AutoConnectError {
                                profile_id: profile.id,
                                profile_name: profile.name,
                                message: "本机凭据存储中的 VPN 密码已不存在，请重新输入并保存"
                                    .to_string(),
                            });
                        }
                    }
                    Err(message) if profile.auto_connect => {
                        if was_unknown {
                            metadata_changed |=
                                store.stored_secret_profiles.insert(profile.id.clone());
                            metadata_changed |= store.unknown_secret_profiles.remove(&profile.id);
                        }
                        credential_errors.push(AutoConnectError {
                            profile_id: profile.id,
                            profile_name: profile.name,
                            message,
                        });
                    }
                    Err(_) if was_unknown => {
                        // Preserve a legacy profile's storage intent after a transient
                        // credential-backend error; connection retries it on demand.
                        metadata_changed |= store.stored_secret_profiles.insert(profile.id.clone());
                        metadata_changed |= store.unknown_secret_profiles.remove(&profile.id);
                    }
                    Err(_) => {}
                }
            }
            if metadata_changed {
                let profiles = store.profiles.clone();
                let stored = store.stored_secret_profiles.clone();
                let unknown = store.unknown_secret_profiles.clone();
                let _ = commit_profile_metadata(&mut store, || {
                    persist_profiles(&app, &profiles, &stored, &unknown)
                });
            }
        }

        emit_profiles_changed(&app);
        start_auto_connect_profiles(app, credential_errors);
    });
}

fn start_remote_access(app: AppHandle) {
    thread::spawn(move || match remote::initialize(app.clone()) {
        Ok(()) => {
            if let Ok(status) = remote::remote_access_status(app.clone()) {
                let _ = app.emit("remote-access-changed", status);
            }
        }
        Err(message) => {
            let _ = app.emit("remote-access-error", remote::RemoteAccessError { message });
        }
    });
}

#[derive(Clone)]
struct TrayProfileSnapshot {
    id: String,
    name: String,
    status: String,
    active: bool,
    starting: bool,
}

fn menu_text(value: &str) -> String {
    value.replace('&', "&&")
}

fn show_main_window(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_dock_visibility(true);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    schedule_tray_refresh(app);
}

fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_dock_visibility(false);
    schedule_tray_refresh(app);
}

fn schedule_tray_refresh(app: &AppHandle) {
    let app = app.clone();
    thread::spawn(move || refresh_tray(&app));
}

fn tray_profile_snapshots(app: &AppHandle) -> Vec<TrayProfileSnapshot> {
    let state = app.state::<AppState>();
    let Ok(store) = state.store.lock() else {
        return Vec::new();
    };
    store
        .profiles
        .values()
        .map(|profile| {
            let instance = store
                .instances
                .values()
                .filter(|instance| instance.view.profile_id == profile.id)
                .max_by_key(|instance| {
                    (
                        instance.process_running,
                        instance.view.started_at,
                        instance.view.revision,
                    )
                });
            let active = instance.is_some_and(|instance| instance.process_running);
            let starting = store.starting_profiles.contains(&profile.id);
            let status = if starting && !active {
                "starting".to_string()
            } else {
                instance
                    .map(|instance| instance.view.status.clone())
                    .unwrap_or_else(|| "disconnected".to_string())
            };
            TrayProfileSnapshot {
                id: profile.id.clone(),
                name: profile.name.clone(),
                status,
                active,
                starting,
            }
        })
        .collect()
}

fn tray_profile_status_label(status: &str) -> &'static str {
    match status {
        "starting" => "正在准备连接",
        "connecting" => "正在连接",
        "connected" => "已连接",
        "disconnecting" => "正在断开",
        "failed" => "连接失败",
        _ => "未连接",
    }
}

fn tray_profile_title(profile: &TrayProfileSnapshot) -> String {
    let indicator = match profile.status.as_str() {
        "connected" => "●",
        "starting" | "connecting" | "disconnecting" => "◐",
        "failed" => "!",
        _ => "○",
    };
    format!("{indicator} {}", menu_text(&profile.name))
}

fn refresh_tray(app: &AppHandle) {
    let profiles = tray_profile_snapshots(app);
    let statuses = profiles
        .iter()
        .map(|profile| profile.status.as_str())
        .collect::<Vec<_>>();
    let status_text = tray_status_text(&statuses);
    let any_active = profiles
        .iter()
        .any(|profile| profile.active || profile.starting);
    let window_visible = app
        .get_webview_window("main")
        .and_then(|window| window.is_visible().ok())
        .unwrap_or(false);
    let mut actions = HashMap::new();

    let state = app.state::<AppState>();
    let Ok(mut tray_ui_guard) = state.tray_ui.lock() else {
        return;
    };
    let Some(tray_ui) = tray_ui_guard.as_mut() else {
        return;
    };

    let _ = tray_ui.status_item.set_text(format!("状态：{status_text}"));
    let _ = tray_ui.window_item.set_text(if window_visible {
        "隐藏管理器"
    } else {
        "打开管理器"
    });
    let _ = tray_ui.disconnect_all_item.set_enabled(any_active);
    while tray_ui
        .profiles_menu
        .items()
        .map(|items| !items.is_empty())
        .unwrap_or(false)
    {
        let _ = tray_ui.profiles_menu.remove_at(0);
    }

    if profiles.is_empty() {
        if let Ok(empty) = MenuItem::new(app, "尚无 VPN 配置", false, None::<&str>) {
            let _ = tray_ui.profiles_menu.append(&empty);
        }
    } else {
        for profile in &profiles {
            let Ok(profile_menu) = Submenu::new(app, tray_profile_title(profile), true) else {
                continue;
            };
            if let Ok(status) = MenuItem::new(
                app,
                format!("状态：{}", tray_profile_status_label(&profile.status)),
                false,
                None::<&str>,
            ) {
                let _ = profile_menu.append(&status);
            }
            if let Ok(separator) = PredefinedMenuItem::separator(app) {
                let _ = profile_menu.append(&separator);
            }

            let connect_id = format!("tray-action-{}", Uuid::new_v4());
            if let Ok(connect) = MenuItem::with_id(
                app,
                connect_id.clone(),
                "连接",
                !profile.active && !profile.starting,
                None::<&str>,
            ) {
                let _ = profile_menu.append(&connect);
                actions.insert(connect_id, TrayAction::Connect(profile.id.clone()));
            }

            let reconnect_id = format!("tray-action-{}", Uuid::new_v4());
            if let Ok(reconnect) = MenuItem::with_id(
                app,
                reconnect_id.clone(),
                "重新连接",
                profile.active && profile.status != "disconnecting",
                None::<&str>,
            ) {
                let _ = profile_menu.append(&reconnect);
                actions.insert(reconnect_id, TrayAction::Reconnect(profile.id.clone()));
            }

            let disconnect_id = format!("tray-action-{}", Uuid::new_v4());
            if let Ok(disconnect) = MenuItem::with_id(
                app,
                disconnect_id.clone(),
                "断开连接",
                (profile.active || profile.starting) && profile.status != "disconnecting",
                None::<&str>,
            ) {
                let _ = profile_menu.append(&disconnect);
                actions.insert(disconnect_id, TrayAction::Disconnect(profile.id.clone()));
            }
            let _ = tray_ui.profiles_menu.append(&profile_menu);
        }
    }
    drop(tray_ui_guard);
    if let Ok(mut current_actions) = state.tray_actions.lock() {
        *current_actions = actions;
    }

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(format!("OpenFortiVPN Manager · {status_text}")));
        let _ = tray.set_title(Some(""));
    }
}

fn emit_tray_action_error(app: &AppHandle, profile_id: Option<String>, message: String) {
    show_main_window(app);
    let _ = app.emit(
        "vpn-tray-action-error",
        TrayActionError {
            profile_id,
            message,
        },
    );
}

fn run_tray_profile_action(app: AppHandle, action: TrayAction) {
    tauri::async_runtime::spawn(async move {
        let (profile_id, result) = match action {
            TrayAction::Connect(profile_id) => {
                let result = start_profile(app.clone(), profile_id.clone())
                    .await
                    .map(|_| ());
                (profile_id, result)
            }
            TrayAction::Disconnect(profile_id) => {
                let profile = profile_id.clone();
                let result = run_profile_command(app.clone(), profile_id.clone(), move |app| {
                    disconnect_profile_impl(app, profile).map_err(Into::into)
                })
                .await
                .map_err(|e| e.message);
                (profile_id, result)
            }
            TrayAction::Reconnect(profile_id) => {
                let result = reconnect_profile(app.clone(), profile_id.clone())
                    .await
                    .map(|_| ());
                (profile_id, result)
            }
        };
        if let Err(message) = result {
            emit_tray_action_error(&app, Some(profile_id), message);
        } else {
            schedule_tray_refresh(&app);
        }
    });
}

fn request_app_quit(app: &AppHandle) {
    app.state::<AppState>()
        .quit_requested
        .store(true, Ordering::SeqCst);
    app.exit(0);
}

fn handle_tray_menu_event(app: &AppHandle, id: &str) {
    match id {
        TRAY_TOGGLE_WINDOW_ID => {
            let visible = app
                .get_webview_window("main")
                .and_then(|window| window.is_visible().ok())
                .unwrap_or(false);
            if visible {
                hide_main_window(app);
            } else {
                show_main_window(app);
            }
        }
        TRAY_DISCONNECT_ALL_ID => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(message) = disconnect_all(app.clone()).await {
                    emit_tray_action_error(&app, None, message);
                }
            });
        }
        TRAY_QUIT_ID => request_app_quit(app),
        dynamic_id => {
            let action = app
                .state::<AppState>()
                .tray_actions
                .lock()
                .ok()
                .and_then(|actions| actions.get(dynamic_id).cloned());
            if let Some(action) = action {
                run_tray_profile_action(app.clone(), action);
            }
        }
    }
}

fn setup_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let status_item = MenuItem::new(app, "状态：VPN 未连接", false, None::<&str>)?;
    let window_item =
        MenuItem::with_id(app, TRAY_TOGGLE_WINDOW_ID, "打开管理器", true, None::<&str>)?;
    let profiles_menu = Submenu::new(app, "VPN 配置", true)?;
    let disconnect_all_item = MenuItem::with_id(
        app,
        TRAY_DISCONNECT_ALL_ID,
        "断开全部连接",
        false,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(app, TRAY_QUIT_ID, "退出 OpenFortiVPN", true, None::<&str>)?;
    let menu = Menu::new(app)?;
    menu.append(&status_item)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&window_item)?;
    menu.append(&profiles_menu)?;
    menu.append(&disconnect_all_item)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&quit_item)?;

    let mut tray_builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip("OpenFortiVPN Manager · VPN 未连接")
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| handle_tray_menu_event(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::DoubleClick { .. } = event {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon().cloned() {
        tray_builder = tray_builder.icon(icon);
    }
    tray_builder.build(app)?;
    if let Ok(mut tray_ui) = app.state::<AppState>().tray_ui.lock() {
        *tray_ui = Some(TrayUi {
            status_item,
            window_item,
            disconnect_all_item,
            profiles_menu,
        });
    }
    schedule_tray_refresh(app.handle());
    Ok(())
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    request_app_quit(&app);
}

fn shutdown_connections(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let _lifecycle_guard = state
        .lifecycle
        .lock()
        .map_err(|_| "连接生命周期状态已损坏".to_string())?;
    let instance_ids = app
        .state::<AppState>()
        .store
        .lock()
        .map(|mut store| {
            let profile_ids = store.profiles.keys().cloned().collect::<Vec<_>>();
            for profile_id in profile_ids {
                bump_reconnect_generation(&mut store, &profile_id);
            }
            store.starting_profiles.clear();
            store
                .instances
                .values()
                .filter(|instance| instance.process_running)
                .map(|instance| instance.view.id.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut stop_errors = Vec::new();
    for instance_id in instance_ids {
        if let Err(message) =
            stop_instance_impl(app.clone(), app.state::<AppState>(), instance_id, None)
        {
            stop_errors.push(message);
        }
    }
    if !stop_errors.is_empty() {
        return Err(format!(
            "无法安全停止所有 VPN 连接：{}。应用保持运行，请重新安装系统 helper 后再次退出。",
            stop_errors.join("；")
        ));
    }

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let running = app
            .state::<AppState>()
            .store
            .lock()
            .map(|store| {
                store
                    .instances
                    .values()
                    .any(|instance| instance.process_running)
            })
            .unwrap_or(false);
        if !running {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("等待 VPN 连接清理超时。应用保持运行，请先手动断开连接后再次退出。".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !args.iter().any(|argument| argument == "--autostart") {
                show_main_window(app);
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            // The UI single-instance plugin is not the repository authority:
            // renamed/development binaries and offline tools share this lock.
            let guard = profile_repository::acquire_ownership(&app_data_dir(app.handle())?)
                .map_err(std::io::Error::other)?;
            *app.state::<AppState>()
                .repository_guard
                .lock()
                .map_err(|_| std::io::Error::other("配置目录锁状态已损坏"))? = Some(guard);
            let desktop_preferences =
                load_desktop_preferences(app.handle()).unwrap_or_else(|message| {
                    eprintln!("OpenFortiVPN desktop settings were reset: {message}");
                    DesktopPreferences::default()
                });
            let loaded_profiles = load_profiles(app.handle()).map_err(|message| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("拒绝忽略损坏的 VPN 配置：{message}"),
                )
            })?;
            recover_credential_intents(app.handle(), &loaded_profiles)
                .map_err(std::io::Error::other)?;
            let startup_profiles = loaded_profiles.profiles.clone();
            let startup_stored_secret_profiles = loaded_profiles.stored_secret_profiles.clone();
            let startup_unknown_secret_profiles = loaded_profiles.unknown_secret_profiles.clone();
            let stale_processes =
                load_stale_runtime_processes(app.handle()).map_err(std::io::Error::other)?;

            let state = app.state::<AppState>();
            if let Ok(mut preferences) = state.desktop_preferences.lock() {
                *preferences = desktop_preferences.clone();
            }
            if let Ok(mut store) = state.store.lock() {
                store.profiles = loaded_profiles.profiles;
                store.stored_secret_profiles = loaded_profiles.stored_secret_profiles;
                store.unknown_secret_profiles = loaded_profiles.unknown_secret_profiles;
                store.stale_processes = stale_processes;
            }
            setup_tray(app)?;
            refresh_privilege_status(app.handle(), false);
            start_privilege_keepalive(app.handle().clone());
            load_startup_credentials(
                app.handle().clone(),
                startup_profiles,
                startup_stored_secret_profiles,
                startup_unknown_secret_profiles,
            );
            start_remote_access(app.handle().clone());

            if app.autolaunch().is_enabled().unwrap_or(false) {
                if let Err(error) = app
                    .autolaunch()
                    .disable()
                    .and_then(|()| app.autolaunch().enable())
                {
                    eprintln!("OpenFortiVPN could not refresh its autostart entry: {error}");
                }
            }

            let launched_from_autostart = env::args().any(|argument| argument == "--autostart");
            if should_start_hidden(launched_from_autostart, desktop_preferences.start_minimized) {
                hide_main_window(app.handle());
            } else {
                show_main_window(app.handle());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_recovery_records,
            repository_recovery_required,
            recover_profile_repository,
            diagnostic_report,
            backup::backup_profiles,
            backup::restore_profiles,
            acknowledge_recovery,
            list_profiles,
            get_desktop_preferences,
            update_desktop_preferences,
            save_profile,
            delete_profile,
            list_instances,
            authentication::authentication_challenges,
            authentication::respond_to_authentication,
            list_logs,
            engine_info,
            privilege_status,
            unlock_privileges,
            start_profile,
            stop_instance,
            await_profile_stopped,
            reconnect_profile,
            disconnect_all,
            quit_app,
            export_profile_config,
            remote::remote_access_status,
            remote::configure_remote_access,
            remote::rotate_remote_access_token,
        ])
        .build(tauri::generate_context!())
        .expect("error while building OpenFortiVPN Manager");

    app.run(|app, event| match event {
        tauri::RunEvent::WindowEvent {
            label,
            event: tauri::WindowEvent::CloseRequested { api, .. },
            ..
        } if label == "main" => {
            let state = app.state::<AppState>();
            let shutting_down = state.shutting_down.load(Ordering::SeqCst);
            let quit_requested = state.quit_requested.load(Ordering::SeqCst);
            api.prevent_close();
            if shutting_down || quit_requested {
                return;
            }
            let preferences = state
                .desktop_preferences
                .lock()
                .map(|preferences| preferences.clone())
                .unwrap_or_default();
            if should_hide_window_on_close(&preferences, quit_requested, shutting_down) {
                hide_main_window(app);
            } else {
                hide_main_window(app);
                request_app_quit(app);
            }
        }
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen {
            has_visible_windows,
            ..
        } => {
            if !has_visible_windows {
                show_main_window(app);
            }
        }
        tauri::RunEvent::ExitRequested { api, code, .. } => {
            let state = app.state::<AppState>();
            if state.exit_cleanup_complete.load(Ordering::SeqCst) {
                return;
            }
            api.prevent_exit();
            state.quit_requested.store(true, Ordering::SeqCst);
            if state.shutting_down.swap(true, Ordering::SeqCst) {
                return;
            }
            let app = app.clone();
            thread::spawn(move || match shutdown_connections(&app) {
                Ok(()) => {
                    let _ = remote::shutdown();
                    app.state::<AppState>()
                        .exit_cleanup_complete
                        .store(true, Ordering::SeqCst);
                    app.exit(code.unwrap_or_default());
                }
                Err(message) => {
                    let state = app.state::<AppState>();
                    state.shutting_down.store(false, Ordering::SeqCst);
                    state.quit_requested.store(false, Ordering::SeqCst);
                    show_main_window(&app);
                    let _ = app.emit("vpn-exit-blocked", AppExitBlocked { message });
                }
            });
        }
        tauri::RunEvent::Exit => {
            // macOS can terminate the native event loop without first yielding
            // a preventable ExitRequested event (for example from the native
            // application menu). Run a synchronous last-chance cleanup while
            // the process is still alive so privileged children cannot outlive
            // the manager. The normal asynchronous path marks this complete
            // before calling app.exit(), making the fallback a no-op there.
            let state = app.state::<AppState>();
            if !state.exit_cleanup_complete.load(Ordering::SeqCst) {
                state.shutting_down.store(true, Ordering::SeqCst);
                if let Err(message) = shutdown_connections(app) {
                    eprintln!("OpenFortiVPN emergency exit cleanup failed: {message}");
                } else {
                    state.exit_cleanup_complete.store(true, Ordering::SeqCst);
                }
                let _ = remote::shutdown();
            }
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn reader_panic_or_io_failure_cannot_be_treated_as_clean_eof() {
        use super::{drain_stream_readers, StreamReader};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        for panic in [false, true] {
            let join = std::thread::spawn(move || {
                if panic {
                    panic!("injected reader panic");
                }
                false
            });
            assert!(!drain_stream_readers(vec![StreamReader {
                join,
                cancelled: Arc::new(AtomicBool::new(false))
            }]));
        }
    }
    use super::*;

    type ProfileMutator = fn(&mut VpnProfile);

    fn valid_profile() -> VpnProfile {
        VpnProfile {
            id: "profile-1".to_string(),
            revision: 0,
            name: "Office VPN".to_string(),
            host: "vpn.example.com".to_string(),
            gateway_dns: String::new(),
            port: 443,
            username: "alice".to_string(),
            realm: "employees".to_string(),
            trusted_cert: "aB".repeat(32),
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

    #[cfg(unix)]
    #[test]
    fn privileged_operations_use_the_fixed_system_sudo_binary() {
        assert_eq!(SUDO_EXECUTABLE, "/usr/bin/sudo");
        assert!(std::path::Path::new(SUDO_EXECUTABLE).is_absolute());
    }

    #[cfg(unix)]
    #[test]
    fn component_hash_detects_payload_changes() {
        let directory = env::temp_dir().join(format!("openfortivpn-hash-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let first = directory.join("first");
        let second = directory.join("second");
        fs::write(&first, b"trusted payload").unwrap();
        fs::write(&second, b"trusted payload").unwrap();
        assert_eq!(file_sha256(&first).unwrap(), file_sha256(&second).unwrap());
        fs::write(&second, b"changed payload").unwrap();
        assert_ne!(file_sha256(&first).unwrap(), file_sha256(&second).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn loads_legacy_profiles_with_auto_connect_disabled() {
        let mut value = serde_json::to_value(valid_profile()).expect("profile should serialize");
        value
            .as_object_mut()
            .expect("profile should be an object")
            .remove("autoConnect");
        value
            .as_object_mut()
            .expect("profile should be an object")
            .remove("autoReconnect");

        let profile: VpnProfile =
            serde_json::from_value(value).expect("legacy profile should deserialize");

        assert!(!profile.auto_connect);
        assert!(profile.auto_reconnect);
    }

    #[test]
    fn profile_file_persists_credential_metadata_without_the_password() {
        let mut profile = valid_profile();
        profile.trusted_cert = profile.trusted_cert.to_ascii_lowercase();
        let profiles = BTreeMap::from([(profile.id.clone(), profile.clone())]);
        let stored = HashSet::from([profile.id.clone()]);

        let contents = serialize_profile_file(&profiles, &stored, &HashSet::new())
            .expect("profile metadata should serialize");

        assert!(contents.contains("\"passwordStored\": true"));
        assert!(!contents.contains("secret"));

        let loaded = parse_profile_file(&contents).expect("profile metadata should load");
        assert_eq!(loaded.profiles.get(&profile.id), Some(&profile));
        assert!(loaded.stored_secret_profiles.contains(&profile.id));
        assert!(!loaded.unknown_secret_profiles.contains(&profile.id));
    }

    #[test]
    fn legacy_profile_file_marks_credential_state_for_one_time_migration() {
        let profile = valid_profile();
        let contents = serde_json::to_string(&vec![profile.clone()]).unwrap();

        let loaded = parse_profile_file(&contents).expect("legacy profiles should load");

        assert!(!loaded.stored_secret_profiles.contains(&profile.id));
        assert!(loaded.unknown_secret_profiles.contains(&profile.id));
    }

    #[test]
    fn malformed_profile_files_never_silently_replace_profiles_or_credentials() {
        let profile = valid_profile();
        assert!(parse_profile_file(
            &serde_json::to_string(&[profile.clone(), profile.clone()]).unwrap()
        )
        .is_err());
        let mut unsafe_profile = profile.clone();
        unsafe_profile.credential_ref = Some(REMOTE_TOKEN_PROFILE_ID.into());
        assert!(parse_profile_file(&serde_json::to_string(&[unsafe_profile]).unwrap()).is_err());
        let mut unsafe_profile = profile;
        unsafe_profile.username = "a".repeat(65);
        assert!(parse_profile_file(&serde_json::to_string(&[unsafe_profile]).unwrap()).is_err());
    }

    #[test]
    fn explicit_missing_credential_is_not_rechecked_on_every_startup() {
        let profile = valid_profile();
        let profiles = BTreeMap::from([(profile.id.clone(), profile.clone())]);
        let contents = serialize_profile_file(&profiles, &HashSet::new(), &HashSet::new())
            .expect("profile metadata should serialize");

        let loaded = parse_profile_file(&contents).expect("profile metadata should load");

        assert!(!loaded.stored_secret_profiles.contains(&profile.id));
        assert!(!loaded.unknown_secret_profiles.contains(&profile.id));
    }

    #[test]
    fn stale_startup_credential_reads_cannot_undo_a_user_change() {
        let profile = valid_profile();
        let mut store = RuntimeStore::default();
        store.profiles.insert(profile.id.clone(), profile.clone());
        store.unknown_secret_profiles.insert(profile.id.clone());

        assert!(startup_credential_result_is_current(
            &store, &profile, true, false
        ));

        store.unknown_secret_profiles.remove(&profile.id);
        assert!(!startup_credential_result_is_current(
            &store, &profile, true, false
        ));

        store.stored_secret_profiles.insert(profile.id.clone());
        assert!(startup_credential_result_is_current(
            &store, &profile, false, true
        ));

        store.stored_secret_profiles.remove(&profile.id);
        assert!(!startup_credential_result_is_current(
            &store, &profile, false, true
        ));
    }

    #[test]
    fn uncertain_metadata_commit_blocks_stale_cache_until_disk_reload() {
        let directory = std::env::temp_dir().join(format!("ofv-commit-test-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("profiles.json");
        let mut old = valid_profile();
        old.credential_ref = Some(format!("credential:{}", Uuid::new_v4()));
        old.revision = 1;
        let mut new = old.clone();
        new.credential_ref = Some(format!("credential:{}", Uuid::new_v4()));
        new.revision = 2;
        let stored = HashSet::from([old.id.clone()]);
        let mut store = RuntimeStore::default();
        store.profiles.insert(old.id.clone(), old.clone());
        store.stored_secret_profiles = stored.clone();
        store
            .secrets
            .insert(old.id.clone(), "synthetic-old-session".into());
        let new_profiles = BTreeMap::from([(new.id.clone(), new.clone())]);
        let bytes = serialize_profile_file(&new_profiles, &stored, &HashSet::new()).unwrap();
        assert!(commit_profile_metadata(&mut store, || {
            openfortivpn_manager_core::atomic_file::write_private(&path, bytes.as_bytes()).unwrap();
            Err("injected failure after replacement".into())
        })
        .is_err());
        assert_eq!(store.profiles[&old.id].revision, 1);
        assert!(ensure_repository_ready(&store).is_err());
        assert!(
            commit_profile_metadata(&mut store, || panic!("stale cache must never write")).is_err()
        );
        let loaded = parse_profile_file(&fs::read_to_string(&path).unwrap()).unwrap();
        let candidates = [
            old.credential_ref.clone().unwrap(),
            new.credential_ref.clone().unwrap(),
        ];
        let gc = openfortivpn_manager_core::repository::credential_gc(
            candidates.clone().into_iter(),
            &credential_references(&loaded),
            &HashSet::new(),
        );
        assert_eq!(
            gc.delete,
            std::collections::BTreeSet::from([candidates[0].clone()])
        );
        apply_recovered_profiles(&mut store, loaded);
        assert_eq!(store.profiles[&new.id].revision, 2);
        assert!(store.secrets.is_empty());
        assert!(ensure_repository_ready(&store).is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_precommit_write_keeps_repository_blocked_and_idle_recovery_preserves_old_ref() {
        let mut store = RuntimeStore::default();
        let old = valid_profile();
        store.profiles.insert(old.id.clone(), old.clone());
        assert!(commit_profile_metadata(&mut store, || Err("disk full".into())).is_err());
        assert!(repository_is_idle(&store));
        store.mutating_profiles.insert(old.id.clone());
        assert!(!repository_is_idle(&store));
        store.mutating_profiles.clear();
        store.starting_profiles.insert(old.id.clone());
        assert!(!repository_is_idle(&store));
        store.starting_profiles.clear();
        store.restoring_repository = true;
        assert!(!repository_is_idle(&store));
        store.restoring_repository = false;
        apply_recovered_profiles(
            &mut store,
            LoadedProfiles {
                profiles: BTreeMap::from([(old.id.clone(), old)]),
                stored_secret_profiles: HashSet::new(),
                unknown_secret_profiles: HashSet::new(),
            },
        );
        assert!(commit_profile_metadata(&mut store, || Ok(())).is_ok());
    }

    #[test]
    fn accepts_a_complete_valid_profile() {
        assert_eq!(validate_profile(&valid_profile()), Ok(()));
    }

    #[test]
    fn rejects_missing_required_profile_values() {
        let mut profile = valid_profile();
        profile.name = " \t ".to_string();
        assert_eq!(
            validate_profile(&profile),
            Err("配置名称不能为空".to_string())
        );

        let mut profile = valid_profile();
        profile.host = "  ".to_string();
        assert_eq!(
            validate_profile(&profile),
            Err("VPN 服务器不能为空".to_string())
        );

        let mut profile = valid_profile();
        profile.port = 0;
        assert_eq!(
            validate_profile(&profile),
            Err("端口必须在 1 到 65535 之间".to_string())
        );
    }

    #[test]
    fn rejects_profile_id_reserved_for_remote_access_token() {
        let mut profile = valid_profile();
        profile.id = REMOTE_TOKEN_PROFILE_ID.to_string();
        assert_eq!(
            validate_profile(&profile),
            Err("配置 ID 使用了系统保留值".to_string())
        );
    }

    #[test]
    fn rejects_line_break_injection_in_profile_fields() {
        let cases: [(&str, ProfileMutator); 4] = [
            ("配置名称", |profile: &mut VpnProfile| {
                profile.name = "Office\nset-dns = 0".to_string()
            }),
            ("服务器", |profile: &mut VpnProfile| {
                profile.host = "vpn.example.com\rport = 1".to_string()
            }),
            ("用户名", |profile: &mut VpnProfile| {
                profile.username = "alice\npassword = injected".to_string()
            }),
            ("Realm", |profile: &mut VpnProfile| {
                profile.realm = "employees\rset-routes = 0".to_string()
            }),
        ];

        for (label, mutate) in cases {
            let mut profile = valid_profile();
            mutate(&mut profile);
            assert_eq!(
                validate_profile(&profile),
                Err(format!("{label} 不能包含换行符"))
            );
        }
    }

    #[test]
    fn validates_trusted_certificate_sha256_digest() {
        let mut profile = valid_profile();
        profile.trusted_cert.clear();
        assert_eq!(validate_profile(&profile), Ok(()));

        profile.trusted_cert = "a".repeat(63);
        assert_eq!(
            validate_profile(&profile),
            Err("受信任证书必须是 64 位 SHA-256 十六进制摘要".to_string())
        );

        profile.trusted_cert = format!("{}g", "a".repeat(63));
        assert_eq!(
            validate_profile(&profile),
            Err("受信任证书必须是 64 位 SHA-256 十六进制摘要".to_string())
        );
    }

    #[test]
    fn renders_runtime_config_with_all_profile_options() {
        let mut profile = valid_profile();
        profile.gateway_dns = "223.5.5.5".into();
        profile.host = "  vpn.example.com  ".to_string();
        profile.pppd_use_peerdns = true;
        profile.half_internet_routes = true;

        let config = render_runtime_config(&profile, "secret", "ofv-office-12345678")
            .expect("valid profile should render");

        assert!(config.starts_with("# Generated by OpenFortiVPN Manager. Do not edit.\n"));
        assert!(config.contains("host = vpn.example.com\n"));
        assert!(config.contains("gateway-dns = 223.5.5.5\n"));
        assert!(config.contains("port = 443\n"));
        assert!(config.contains("username = alice\n"));
        assert!(config.contains("password = secret\n"));
        assert!(config.contains("realm = employees\n"));
        assert!(config.contains(&format!("trusted-cert = {}\n", "aB".repeat(32))));
        assert!(config.contains("set-routes = 1\n"));
        assert!(config.contains("set-dns = 1\n"));
        assert!(config.contains("pppd-use-peerdns = 1\n"));
        assert!(config.contains("half-internet-routes = 1\n"));

        #[cfg(windows)]
        assert!(config.contains("pppd-ifname = ofv-office-12345678\n"));
        #[cfg(not(windows))]
        assert!(!config.contains("pppd-ifname"));
    }

    #[test]
    fn renders_disabled_flags_and_omits_empty_optional_values() {
        let mut profile = valid_profile();
        profile.username.clear();
        profile.realm.clear();
        profile.trusted_cert.clear();
        profile.set_routes = false;
        profile.set_dns = false;

        let config = render_runtime_config(&profile, "", "ofv-office-12345678")
            .expect("empty optional values should be allowed");
        assert!(!config.contains("gateway-dns"));

        assert!(!config.contains("username ="));
        assert!(!config.contains("password ="));
        assert!(!config.contains("realm ="));
        assert!(!config.contains("trusted-cert ="));
        assert!(config.contains("set-routes = 0\n"));
        assert!(config.contains("set-dns = 0\n"));
        assert!(config.contains("pppd-use-peerdns = 0\n"));
        assert!(config.contains("half-internet-routes = 0\n"));
    }

    #[test]
    fn rejects_line_break_injection_in_runtime_password() {
        let error = render_runtime_config(
            &valid_profile(),
            "secret\nset-routes = 0",
            "ofv-office-12345678",
        )
        .expect_err("password line breaks must be rejected");

        assert!(error.contains("line breaks"));
    }

    #[test]
    fn rejects_passwords_the_engine_would_silently_change_or_truncate() {
        for password in [
            " secret".into(),
            "secret ".into(),
            "sec\0ret".into(),
            "x".repeat(257),
        ] {
            assert!(validate_password(&password).is_err());
        }
        assert_eq!(validate_password("correct horse battery staple"), Ok(()));
    }

    #[test]
    fn adapter_name_is_safe_bounded_and_deterministic() {
        let mut profile = valid_profile();
        profile.name = "Office_VPN ! 2026-Production-Long".to_string();

        let name = make_adapter_name(&profile, "12345678-abcd-ef00-1111-222233334444");

        assert_eq!(name, "ofv-OfficeVPN2026-Prod-12345678");
        assert!(name.len() <= 31);
        assert!(name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-'));
        assert_eq!(
            make_adapter_name(&profile, "12345678-abcd-ef00-1111-222233334444"),
            name
        );
    }

    #[test]
    fn adapter_name_falls_back_for_non_ascii_profile_name() {
        let mut profile = valid_profile();
        profile.name = "公司专线".to_string();

        assert_eq!(
            make_adapter_name(&profile, "abcdef12-3456-7890-abcd-ef1234567890"),
            "ofv-vpn-abcdef12"
        );
    }

    #[test]
    fn adapter_name_distinguishes_reconnections() {
        let profile = valid_profile();

        let first = make_adapter_name(&profile, "11111111-aaaa-bbbb-cccc-dddddddddddd");
        let second = make_adapter_name(&profile, "22222222-aaaa-bbbb-cccc-dddddddddddd");

        assert_ne!(first, second);
        assert!(first.starts_with("ofv-OfficeVPN-"));
        assert!(second.starts_with("ofv-OfficeVPN-"));
    }

    #[test]
    fn engine_event_includes_profile_mapping_for_fast_process_events() {
        let event = EngineEvent {
            instance_id: "instance-1".to_string(),
            profile_id: "profile-1".to_string(),
            profile_revision: 7,
            host: "vpn.example.test".into(),
            port: 443,
            payload: serde_json::json!({
                "event": "cert_error",
                "digest": "a".repeat(64),
            }),
        };

        let value = serde_json::to_value(event).expect("engine event should serialize");
        assert_eq!(value["instanceId"], "instance-1");
        assert_eq!(value["profileId"], "profile-1");
        assert_eq!(value["profileRevision"], 7);
        assert_eq!(value["host"], "vpn.example.test");
        assert_eq!(value["payload"]["event"], "cert_error");
    }

    #[test]
    fn engine_state_mapping_preserves_terminal_states() {
        assert_eq!(status_for_engine_state("resolving"), "connecting");
        assert_eq!(status_for_engine_state("connected"), "connecting");
        assert_eq!(status_for_engine_state("disconnecting"), "disconnecting");
        assert_eq!(status_for_engine_state("down"), "disconnecting");
    }

    fn instance_view_with_status(status: &str) -> InstanceView {
        InstanceView {
            id: "instance-1".to_string(),
            profile_generation: 1,
            attempt_sequence: 1,
            profile_id: "profile-1".to_string(),
            profile_name: "Office VPN".to_string(),
            adapter_name: "ofv-OfficeVPN-12345678".to_string(),
            status: status.to_string(),
            message: "initial".to_string(),
            pid: 123,
            started_at: 1,
            ended_at: None,
            exit_code: None,
            revision: 0,
        }
    }

    #[test]
    fn tunnel_up_is_the_only_event_that_finishes_connecting() {
        let mut view = instance_view_with_status("starting");

        assert!(apply_instance_update(
            &mut view,
            status_for_engine_state("connected"),
            "connected".to_string()
        ));
        assert_eq!(view.status, "connecting");
        assert!(apply_instance_update(
            &mut view,
            "connected",
            "已连接".to_string()
        ));
        assert_eq!(view.status, "connected");
        assert_eq!(view.revision, 2);
    }

    #[test]
    fn late_events_cannot_revive_stopping_or_terminal_instances() {
        let mut stopping = instance_view_with_status("disconnecting");
        assert!(!apply_instance_update(
            &mut stopping,
            "connected",
            "late tunnel_up".to_string()
        ));
        assert_eq!(stopping.status, "disconnecting");

        let mut failed = instance_view_with_status("failed");
        assert!(!apply_instance_update(
            &mut failed,
            "connected",
            "late log".to_string()
        ));
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.revision, 0);
    }

    #[test]
    fn auto_reconnect_uses_bounded_exponential_backoff() {
        assert_eq!(auto_reconnect_delay_seconds(1), 3);
        assert_eq!(auto_reconnect_delay_seconds(2), 6);
        assert_eq!(auto_reconnect_delay_seconds(3), 12);
        assert_eq!(auto_reconnect_delay_seconds(5), 30);
        assert_eq!(auto_reconnect_delay_seconds(u32::MAX), 30);
    }

    #[test]
    fn different_profiles_can_reserve_connections_concurrently() {
        let mut store = RuntimeStore::default();
        store.starting_profiles.insert("profile-a".to_string());

        assert!(profile_connection_in_progress(&store, "profile-a"));
        assert!(!profile_connection_in_progress(&store, "profile-b"));

        store.starting_profiles.insert("profile-b".to_string());
        assert!(profile_connection_in_progress(&store, "profile-a"));
        assert!(profile_connection_in_progress(&store, "profile-b"));
        assert_eq!(store.starting_profiles.len(), 2);
    }

    #[test]
    fn repeated_user_connect_reuses_the_running_instance() {
        assert!(reuse_running_instance_for_start(StartOrigin::User));
        assert!(!reuse_running_instance_for_start(StartOrigin::Startup));
        assert!(!reuse_running_instance_for_start(
            StartOrigin::AutoReconnect(7)
        ));
    }

    fn desktop_admission_store() -> RuntimeStore {
        let profile = valid_profile();
        let mut store = RuntimeStore::default();
        store.profiles.insert(profile.id.clone(), profile.clone());
        #[cfg(unix)]
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()
            .unwrap();
        child.wait().unwrap();
        let mut view = instance_view_with_status("connected");
        view.id = "admitted-attempt".into();
        view.profile_id = profile.id;
        store.instances.insert(
            view.id.clone(),
            ManagedInstance {
                view,
                source_profile: valid_profile(),
                child: OwnedProcess::new(child),
                input: None,
                process_running: true,
                lifecycle: Default::default(),
                user_requested_stop: false,
                reconnect_blocked: false,
                failure_message: None,
            },
        );
        store
    }

    #[test]
    fn desktop_connect_admission_never_reuses_stopping_or_recovery_owners() {
        use openfortivpn_manager_core::ErrorCode;
        for gate in ["stop-request", "disconnecting", "recovery"] {
            let mut store = desktop_admission_store();
            let instance = store.instances.get_mut("admitted-attempt").unwrap();
            let profile_id = instance.view.profile_id.clone();
            let expected = match gate {
                "stop-request" => {
                    instance.user_requested_stop = true;
                    ErrorCode::ProfileBusy
                }
                "disconnecting" => {
                    instance.view.status = "disconnecting".into();
                    ErrorCode::ProfileBusy
                }
                _ => {
                    instance.process_running = false;
                    instance.lifecycle.require_recovery();
                    ErrorCode::RecoveryRequired
                }
            };
            assert_eq!(
                desktop_connect_admission(&store, &profile_id, false, StartOrigin::User)
                    .unwrap_err()
                    .code,
                expected
            );
        }
    }

    #[test]
    fn desktop_connect_admission_applies_all_reservations_and_recovery_gates_before_reuse() {
        use openfortivpn_manager_core::ErrorCode;
        for gate in [
            "repository",
            "restore",
            "mutation",
            "stale-other",
            "duplicate",
            "pending-other",
        ] {
            let mut store = desktop_admission_store();
            let profile_id = store.instances["admitted-attempt"].view.profile_id.clone();
            let expected = match gate {
                "repository" => {
                    store.repository_recovery_required = true;
                    ErrorCode::RecoveryRequired
                }
                "restore" => {
                    store.restoring_repository = true;
                    ErrorCode::ProfileBusy
                }
                "mutation" => {
                    store.mutating_profiles.insert(profile_id.clone());
                    ErrorCode::ProfileBusy
                }
                "stale-other" => {
                    store.stale_processes.insert(
                        "old".into(),
                        RuntimeProcessRecord {
                            instance_id: "old".into(),
                            profile_id: "other".into(),
                            pid: 0,
                            process_group_id: 0,
                            engine_path: "synthetic-engine".into(),
                            config_path: String::new(),
                            #[cfg(windows)]
                            process_identity: None,
                        },
                    );
                    ErrorCode::RecoveryRequired
                }
                "duplicate" => {
                    store.starting_profiles.insert(profile_id.clone());
                    ErrorCode::RecoveryRequired
                }
                _ => {
                    store.starting_profiles.insert("other".into());
                    ErrorCode::NetworkConflict
                }
            };
            assert_eq!(
                desktop_connect_admission(&store, &profile_id, false, StartOrigin::User)
                    .unwrap_err()
                    .code,
                expected
            );
        }
    }

    #[test]
    fn desktop_connect_admission_only_reuses_healthy_user_intent() {
        use openfortivpn_manager_core::ErrorCode;
        let mut store = desktop_admission_store();
        let profile_id = store.instances["admitted-attempt"].view.profile_id.clone();
        assert_eq!(
            desktop_connect_admission(&store, &profile_id, false, StartOrigin::User)
                .unwrap()
                .unwrap()
                .id,
            "admitted-attempt"
        );
        for origin in [StartOrigin::Startup, StartOrigin::AutoReconnect(7)] {
            assert_eq!(
                desktop_connect_admission(&store, &profile_id, false, origin)
                    .unwrap_err()
                    .code,
                ErrorCode::ProfileBusy
            );
        }
        assert_eq!(
            desktop_connect_admission(&store, &profile_id, true, StartOrigin::User)
                .unwrap_err()
                .code,
            ErrorCode::ShuttingDown
        );
        store.instances.clear();
        store.starting_profiles.insert(profile_id.clone());
        assert_eq!(
            desktop_connect_admission(&store, &profile_id, false, StartOrigin::User)
                .unwrap_err()
                .code,
            ErrorCode::ProfileBusy
        );
        store.starting_profiles.clear();
        assert!(
            desktop_connect_admission(&store, &profile_id, false, StartOrigin::User)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            desktop_connect_admission(&store, "missing", false, StartOrigin::User)
                .unwrap_err()
                .code,
            ErrorCode::ProfileNotFound
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_vpn_credentials_are_private_and_round_trip() {
        let directory =
            env::temp_dir().join(format!("openfortivpn-credentials-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("credentials.json");
        let credentials = BTreeMap::from([
            ("profile-a".to_string(), "first secret".to_string()),
            ("profile-b".to_string(), "second secret".to_string()),
        ]);

        persist_local_credentials_file(&path, &credentials).unwrap();

        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(&*load_local_credentials_file(&path).unwrap(), &credentials);

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn local_vpn_credentials_reject_insecure_permissions_and_symlinks() {
        use std::os::unix::fs::symlink;

        let directory =
            env::temp_dir().join(format!("openfortivpn-credentials-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("credentials.json");
        fs::write(&path, r#"{"profile-a":"first secret"}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(load_local_credentials_file(&path).is_err());
        assert!(persist_local_credentials_file(&path, &BTreeMap::new()).is_err());

        fs::remove_file(&path).unwrap();
        let target = directory.join("target.json");
        fs::write(&target, r#"{"profile-a":"first secret"}"#).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();

        assert!(load_local_credentials_file(&path).is_err());
        assert!(persist_local_credentials_file(&path, &BTreeMap::new()).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn profile_removal_clears_credentials_instances_and_retry_state() {
        let profile = valid_profile();
        let profile_id = profile.id.clone();
        let mut store = RuntimeStore::default();
        store.profiles.insert(profile_id.clone(), profile);
        store
            .secrets
            .insert(profile_id.clone(), "session secret".to_string());
        store.stored_secret_profiles.insert(profile_id.clone());
        store.unknown_secret_profiles.insert(profile_id.clone());
        store.reconnect_attempts.insert(profile_id.clone(), 3);
        store.reconnect_generations.insert(profile_id.clone(), 8);
        #[cfg(unix)]
        let test_child = Command::new("/usr/bin/true").spawn().unwrap();
        #[cfg(windows)]
        let test_child = Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()
            .unwrap();
        store.instances.insert(
            "instance-1".to_string(),
            ManagedInstance {
                view: InstanceView {
                    id: "instance-1".to_string(),
                    profile_generation: 8,
                    attempt_sequence: 1,
                    profile_id: profile_id.clone(),
                    profile_name: "Office".to_string(),
                    adapter_name: "ofv-office".to_string(),
                    status: "failed".to_string(),
                    message: "failed".to_string(),
                    pid: 0,
                    started_at: 1,
                    ended_at: Some(2),
                    exit_code: Some(1),
                    revision: 1,
                },
                source_profile: valid_profile(),
                child: OwnedProcess::new(test_child),
                input: None,
                process_running: false,
                lifecycle: Default::default(),
                user_requested_stop: false,
                reconnect_blocked: true,
                failure_message: Some("failed".to_string()),
            },
        );

        remove_profile_runtime_state(&mut store, &profile_id);

        assert!(!store.profiles.contains_key(&profile_id));
        assert!(!store.secrets.contains_key(&profile_id));
        assert!(!store.stored_secret_profiles.contains(&profile_id));
        assert!(!store.unknown_secret_profiles.contains(&profile_id));
        assert!(!store.reconnect_attempts.contains_key(&profile_id));
        assert!(!store.reconnect_generations.contains_key(&profile_id));
        assert!(store.instances.is_empty());
    }

    #[test]
    fn automatic_retry_excludes_manual_and_fatal_disconnects() {
        assert!(automatic_retry_allowed(false, false, true));
        assert!(!automatic_retry_allowed(true, false, true));
        assert!(!automatic_retry_allowed(false, true, true));
        assert!(!automatic_retry_allowed(false, false, false));
    }

    #[test]
    fn desktop_preferences_default_to_background_residency() {
        let preferences = DesktopPreferences::default();
        assert!(preferences.close_to_tray);
        assert!(preferences.start_minimized);
        assert!(should_hide_window_on_close(&preferences, false, false));
        assert!(!should_hide_window_on_close(&preferences, true, false));
        assert!(!should_hide_window_on_close(&preferences, false, true));
    }

    #[test]
    fn desktop_preferences_load_missing_fields_with_safe_defaults() {
        let preferences: DesktopPreferences = serde_json::from_str("{}").unwrap();
        assert_eq!(preferences, DesktopPreferences::default());

        let preferences: DesktopPreferences =
            serde_json::from_str(r#"{"closeToTray":false}"#).unwrap();
        assert!(!preferences.close_to_tray);
        assert!(preferences.start_minimized);
    }

    #[test]
    fn startup_is_hidden_only_for_background_autostart() {
        assert!(should_start_hidden(true, true));
        assert!(!should_start_hidden(true, false));
        assert!(!should_start_hidden(false, true));
    }

    #[test]
    fn tray_status_summarizes_connection_lifecycle() {
        assert_eq!(
            tray_status_text(&["connected", "connecting", "failed"]),
            "已连接 1 个 · 正在连接 1 个"
        );
        assert_eq!(tray_status_text(&["connecting"]), "正在连接 1 个 VPN");
        assert_eq!(tray_status_text(&["failed"]), "VPN 未连接 · 最近连接失败");
        assert_eq!(tray_status_text(&[]), "VPN 未连接");
    }

    #[test]
    fn reconnect_generation_is_monotonic_and_serialized() {
        let mut store = RuntimeStore::default();
        assert_eq!(bump_reconnect_generation(&mut store, "profile-1"), 1);
        assert_eq!(bump_reconnect_generation(&mut store, "profile-1"), 2);

        let mut view = instance_view_with_status("starting");
        view.profile_generation = 2;
        let value = serde_json::to_value(view).expect("instance should serialize");
        assert_eq!(value["profileGeneration"], 2);
        assert_eq!(value["revision"], 0);
    }

    #[test]
    fn automatic_reconnect_reuses_its_cancellation_generation() {
        let mut store = RuntimeStore::default();
        let generation = bump_reconnect_generation(&mut store, "profile-1");

        assert_eq!(
            reserve_start_generation(
                &mut store,
                "profile-1",
                StartOrigin::AutoReconnect(generation),
            ),
            Ok(generation)
        );
        assert_eq!(
            store.reconnect_generations.get("profile-1"),
            Some(&generation)
        );

        assert_eq!(
            reserve_start_generation(&mut store, "profile-1", StartOrigin::User),
            Ok(generation + 1)
        );
    }

    #[test]
    fn retained_logs_are_bounded_filterable_and_chronological() {
        let mut logs = LogBuffer::default();
        for index in 0..=MAX_RETAINED_LOGS {
            retain_log(
                &mut logs,
                LogEvent {
                    id: openfortivpn_manager_core::protocol::next_log_id(),
                    instance_id: if index % 2 == 0 { "a" } else { "b" }.to_string(),
                    stream: "stdout".to_string(),
                    line: format!("line-{index}"),
                    timestamp: index as u64,
                },
            );
        }

        assert_eq!(logs.len(), MAX_RETAINED_LOGS);
        assert_eq!(
            logs.front().map(|event| event.line.as_str()),
            Some("line-1")
        );
        let selected = recent_logs(&logs, Some("a"), 3);
        assert_eq!(selected.len(), 3);
        assert!(selected
            .windows(2)
            .all(|pair| pair[0].timestamp < pair[1].timestamp));
        assert!(selected.iter().all(|event| event.instance_id == "a"));
    }

    #[test]
    fn legacy_engine_log_marks_tunnel_as_connected() {
        assert_eq!(
            fallback_status_from_log("INFO: Tunnel is up and running."),
            Some(("connected", "已连接"))
        );
        assert_eq!(fallback_status_from_log("INFO: Authenticated."), None);
    }

    #[test]
    fn privilege_status_uses_frontend_field_names() {
        let value = serde_json::to_value(PrivilegeStatus {
            required: true,
            ready: false,
            platform: "macos".to_string(),
        })
        .expect("privilege status should serialize");

        assert_eq!(value["required"], true);
        assert_eq!(value["ready"], false);
        assert_eq!(value["platform"], "macos");
    }
}
