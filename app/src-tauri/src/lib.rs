use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
#[cfg(unix)]
use std::io::Write;
use std::io::{BufRead, BufReader, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_BREAK_EVENT,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;
use zeroize::Zeroize;

mod remote;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct VpnProfile {
    id: String,
    name: String,
    host: String,
    port: u16,
    username: String,
    realm: String,
    trusted_cert: String,
    set_routes: bool,
    set_dns: bool,
    pppd_use_peerdns: bool,
    half_internet_routes: bool,
    use_sudo: bool,
    #[serde(default)]
    auto_connect: bool,
    #[serde(default = "default_auto_reconnect")]
    auto_reconnect: bool,
}

fn default_auto_reconnect() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveProfileInput {
    profile: VpnProfile,
    password: Option<String>,
    #[serde(default)]
    remember_password: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileView {
    profile: VpnProfile,
    has_secret: bool,
    password_stored: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstanceView {
    id: String,
    profile_generation: u64,
    profile_id: String,
    profile_name: String,
    adapter_name: String,
    status: String,
    message: String,
    pid: u32,
    started_at: u64,
    ended_at: Option<u64>,
    exit_code: Option<i32>,
    revision: u64,
}

struct ManagedInstance {
    view: InstanceView,
    child: Arc<Mutex<Child>>,
    process_running: bool,
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

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeProcessRecord {
    instance_id: String,
    profile_id: String,
    pid: u32,
    process_group_id: u32,
    engine_path: String,
    config_path: String,
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
    reconnect_attempts: HashMap<String, u32>,
    reconnect_generations: HashMap<String, u64>,
    logs: VecDeque<LogEvent>,
    #[cfg(unix)]
    stale_processes: BTreeMap<String, RuntimeProcessRecord>,
}

#[derive(Default)]
struct AppState {
    store: Mutex<RuntimeStore>,
    lifecycle: Mutex<()>,
    privilege_ready: AtomicBool,
    shutting_down: AtomicBool,
    exit_cleanup_complete: AtomicBool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineInfo {
    platform: String,
    path: String,
    available: bool,
    version: String,
    requires_elevation: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogEvent {
    instance_id: String,
    stream: String,
    line: String,
    timestamp: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineEvent {
    instance_id: String,
    profile_id: String,
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
struct PrivilegeStatus {
    required: bool,
    ready: bool,
    platform: String,
}

const KEYRING_SERVICE: &str = "com.baozaodetudou.openfortivpn";
const MAX_RETAINED_LOGS: usize = 2_000;
const REMOTE_TOKEN_PROFILE_ID: &str = "__remote_access_token";
const ENGINE_PASSWORD_MAX_BYTES: usize = 256;
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
    Ok(path)
}

fn profiles_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join("profiles.json"))
}

fn parse_profile_file(contents: &str) -> Result<LoadedProfiles, String> {
    let values: Vec<PersistedVpnProfile> =
        serde_json::from_str(contents).map_err(|error| format!("配置列表格式错误：{error}"))?;
    let mut loaded = LoadedProfiles::default();
    for value in values {
        let profile_id = value.profile.id.clone();
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
    serde_json::to_string_pretty(&values).map_err(|error| format!("无法序列化配置列表：{error}"))
}

fn load_profiles(app: &AppHandle) -> Result<LoadedProfiles, String> {
    let path = profiles_path(app)?;
    if !path.exists() {
        return Ok(LoadedProfiles::default());
    }

    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取配置列表 {}：{error}", path.display()))?;
    parse_profile_file(&contents)
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
    #[cfg(unix)]
    {
        let temporary = path.with_file_name(format!(".profiles.{}.tmp", Uuid::new_v4()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| format!("无法创建临时配置列表：{error}"))?;
        if let Err(error) = file
            .write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
        {
            let _ = fs::remove_file(&temporary);
            return Err(format!("无法保存临时配置列表：{error}"));
        }
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(format!("无法保存配置列表 {}：{error}", path.display()));
        }
    }
    #[cfg(not(unix))]
    fs::write(&path, contents)
        .map_err(|error| format!("无法保存配置列表 {}：{error}", path.display()))?;

    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("无法设置配置列表权限：{error}"))?;

    Ok(())
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

fn read_stored_password(profile_id: &str) -> Result<Option<String>, String> {
    let _guard = lock_credential_access()?;
    match credential_entry(profile_id)?.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("无法从系统凭据库读取密码：{error}")),
    }
}

fn store_password(profile_id: &str, password: &str) -> Result<(), String> {
    let _guard = lock_credential_access()?;
    credential_entry(profile_id)?
        .set_password(password)
        .map_err(|error| format!("无法将密码保存到系统凭据库：{error}"))
}

fn delete_stored_password(profile_id: &str) -> Result<(), String> {
    let _guard = lock_credential_access()?;
    match credential_entry(profile_id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!("无法从系统凭据库删除密码：{error}")),
    }
}

fn validate_line_value(label: &str, value: &str) -> Result<(), String> {
    if value.contains('\n') || value.contains('\r') {
        return Err(format!("{label} 不能包含换行符"));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), String> {
    validate_line_value("密码", password)?;
    if password.contains('\0') {
        return Err("VPN 密码不能包含 NUL 字符".to_string());
    }
    if password.len() > ENGINE_PASSWORD_MAX_BYTES {
        return Err(format!("VPN 密码不能超过 {ENGINE_PASSWORD_MAX_BYTES} 字节"));
    }
    if password
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_whitespace)
        || password
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_whitespace)
    {
        return Err("VPN 密码不能以空白字符开头或结尾".to_string());
    }
    Ok(())
}

fn read_usable_stored_password(profile_id: &str) -> Result<Option<String>, String> {
    read_stored_password(profile_id)?
        .map(|password| {
            validate_password(&password)
                .map_err(|message| format!("系统凭据库中的 VPN 密码无法使用：{message}"))?;
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

    validate_line_value("配置名称", &profile.name)?;
    validate_line_value("服务器", &profile.host)?;
    validate_line_value("用户名", &profile.username)?;
    validate_line_value("Realm", &profile.realm)?;

    if !profile.trusted_cert.is_empty()
        && (profile.trusted_cert.len() != 64
            || !profile
                .trusted_cert
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
    {
        return Err("受信任证书必须是 64 位 SHA-256 十六进制摘要".to_string());
    }

    Ok(())
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

    let mut config = String::from("# Generated by OpenFortiVPN Manager. Do not edit.\n");
    push_config_line(&mut config, "host", profile.host.trim());
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
    fs::write(&path, config)
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

#[cfg(unix)]
fn runtime_process_record_path(app: &AppHandle, instance_id: &str) -> Result<PathBuf, String> {
    Ok(runtime_directory(app)?.join(format!("{instance_id}.process.json")))
}

#[cfg(unix)]
fn persist_runtime_process_record(
    app: &AppHandle,
    record: &RuntimeProcessRecord,
) -> Result<PathBuf, String> {
    let path = runtime_process_record_path(app, &record.instance_id)?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("process-record"),
        Uuid::new_v4()
    ));
    let contents = serde_json::to_string_pretty(record)
        .map_err(|error| format!("无法序列化 VPN 进程记录：{error}"))?;
    fs::write(&temporary, contents).map_err(|error| format!("无法保存 VPN 进程记录：{error}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("无法设置 VPN 进程记录权限：{error}"))?;
    if let Err(error) = fs::rename(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("无法原子更新 VPN 进程记录：{error}"));
    }
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

#[cfg(unix)]
fn remove_runtime_process_record(app: &AppHandle, record: &RuntimeProcessRecord) {
    if let Ok(path) = runtime_process_record_path(app, &record.instance_id) {
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_file(&record.config_path);
}

#[cfg(unix)]
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
        let config_path = runtime_directory(app)?.join(format!("{instance_id}.conf"));
        let mut record = fs::read_to_string(&path)
            .ok()
            .and_then(|contents| serde_json::from_str::<RuntimeProcessRecord>(&contents).ok())
            .unwrap_or_else(|| RuntimeProcessRecord {
                instance_id: instance_id.clone(),
                profile_id: String::new(),
                pid: 0,
                process_group_id: 0,
                engine_path: resolve_engine(app).to_string_lossy().into_owned(),
                config_path: config_path.to_string_lossy().into_owned(),
            });
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
            stale.insert(record.instance_id.clone(), record);
        } else if rows.is_none() {
            // Preserve the record when process inspection itself failed.
            stale.insert(record.instance_id.clone(), record);
        } else {
            remove_runtime_process_record(app, &record);
        }
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

    for record in records {
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
        remove_runtime_process_record(app, &record);
        if let Ok(mut store) = app.state::<AppState>().store.lock() {
            store.stale_processes.remove(&record.instance_id);
        }
    }
    Ok(())
}

fn emit_instance(app: &AppHandle, view: &InstanceView) {
    let _ = app.emit("vpn-instance-changed", view.clone());
}

fn profile_has_running_instance(store: &RuntimeStore, profile_id: &str) -> bool {
    store
        .instances
        .values()
        .any(|instance| instance.view.profile_id == profile_id && instance.process_running)
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
        instance.user_requested_stop = false;
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
    let event_name = payload
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or_default();

    match event_name {
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
            record_instance_failure(app, instance_id, message.to_string(), false);
        }
        "cert_error" => {
            record_instance_failure(app, instance_id, "服务器证书验证失败".to_string(), true);
        }
        _ => {}
    }

    let profile_id = app
        .state::<AppState>()
        .store
        .lock()
        .ok()
        .and_then(|store| {
            store
                .instances
                .get(instance_id)
                .map(|instance| instance.view.profile_id.clone())
        })
        .unwrap_or_default();

    let _ = app.emit(
        "vpn-engine-event",
        EngineEvent {
            instance_id: instance_id.to_string(),
            profile_id,
            payload: payload.clone(),
        },
    );
}

fn spawn_stream_reader<R>(reader: R, app: AppHandle, instance_id: String, stream: &str)
where
    R: Read + Send + 'static,
{
    let stream = stream.to_string();
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else {
                break;
            };

            if let Ok(payload) = serde_json::from_str::<Value>(&line) {
                if payload.get("event").is_some() {
                    handle_engine_event(&app, &instance_id, &payload);
                    continue;
                }
            }

            if line.contains("Could not authenticate to gateway.") {
                record_instance_failure(
                    &app,
                    &instance_id,
                    "VPN 身份验证失败，请检查账号和密码".to_string(),
                    true,
                );
            }
            if let Some((status, message)) = fallback_status_from_log(&line) {
                update_instance(&app, &instance_id, status, message.to_string());
            }

            let event = LogEvent {
                instance_id: instance_id.clone(),
                stream: stream.clone(),
                line,
                timestamp: now_epoch(),
            };
            if let Ok(mut store) = app.state::<AppState>().store.lock() {
                retain_log(&mut store.logs, event.clone());
            }
            let _ = app.emit("vpn-log", event);
        }
    });
}

fn retain_log(logs: &mut VecDeque<LogEvent>, event: LogEvent) {
    logs.push_back(event);
    while logs.len() > MAX_RETAINED_LOGS {
        logs.pop_front();
    }
}

fn recent_logs(
    logs: &VecDeque<LogEvent>,
    instance_id: Option<&str>,
    limit: usize,
) -> Vec<LogEvent> {
    let mut selected = logs
        .iter()
        .rev()
        .filter(|event| instance_id.is_none_or(|id| event.instance_id == id))
        .take(limit.clamp(1, MAX_RETAINED_LOGS))
        .cloned()
        .collect::<Vec<_>>();
    selected.reverse();
    selected
}

fn auto_reconnect_delay_seconds(attempt: u32) -> u64 {
    let exponent = attempt.saturating_sub(1).min(4);
    (3_u64.saturating_mul(1_u64 << exponent)).min(30)
}

fn schedule_auto_reconnect(
    app: AppHandle,
    profile_id: String,
    profile_name: String,
    delay_seconds: u64,
    generation: u64,
) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(delay_seconds));

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

        if let Err(message) = start_profile_impl(
            app.clone(),
            profile_id.clone(),
            StartOrigin::AutoReconnect(generation),
        ) {
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

fn spawn_process_monitor(
    app: AppHandle,
    instance_id: String,
    child: Arc<Mutex<Child>>,
    config_path: PathBuf,
    process_record_path: Option<PathBuf>,
) {
    thread::spawn(move || loop {
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
                // Give stdout/stderr readers a brief chance to classify fatal
                // authentication or certificate errors before retry policy is decided.
                thread::sleep(Duration::from_millis(100));
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
                    let user_requested_stop = instance.user_requested_stop;
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
                    instance.view.status = if user_requested_stop || exit_status.success() {
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
                    (
                        instance.view.clone(),
                        delay_seconds.map(|delay| (profile_id, profile_name, delay, generation)),
                    )
                };
                let _ = fs::remove_file(&config_path);
                if let Some(path) = process_record_path.as_ref() {
                    let _ = fs::remove_file(path);
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
    });
}

#[tauri::command]
fn list_profiles(state: State<'_, AppState>) -> Result<Vec<ProfileView>, String> {
    let store = lock_store(&state)?;
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

fn reserve_profile_mutation(app: &AppHandle, profile_id: &str) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut store = state
        .store
        .lock()
        .map_err(|_| "内部运行状态已损坏".to_string())?;
    if store.mutating_profiles.contains(profile_id) {
        return Err("该配置正在被其他操作修改，请稍后重试".to_string());
    }
    if profile_connection_in_progress(&store, profile_id) {
        return Err("该配置正在连接，请先断开".to_string());
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

#[tauri::command]
fn save_profile(app: AppHandle, mut input: SaveProfileInput) -> Result<ProfileView, String> {
    if input.profile.id.trim().is_empty() {
        input.profile.id = Uuid::new_v4().to_string();
    }
    validate_profile(&input.profile)?;

    let password = input.password.filter(|password| !password.is_empty());
    if let Some(password) = password.as_deref() {
        validate_password(password)?;
    }

    if input.profile.auto_connect && !input.remember_password {
        return Err("自动连接需要将密码保存到系统凭据库".to_string());
    }

    let profile_id = input.profile.id.clone();
    reserve_profile_mutation(&app, &profile_id)?;
    let result = (|| -> Result<ProfileView, String> {
        let (was_stored, was_unknown) = {
            let state = app.state::<AppState>();
            let store = lock_store(&state)?;
            (
                store.stored_secret_profiles.contains(&profile_id),
                store.unknown_secret_profiles.contains(&profile_id),
            )
        };

        let mut password_from_keyring = None;
        if input.remember_password {
            if let Some(password) = password.as_deref() {
                store_password(&profile_id, password)?;
            } else if was_stored {
                // An empty password while editing means keep the existing credential.
            } else {
                password_from_keyring = read_usable_stored_password(&profile_id)?;
                if password_from_keyring.is_none() {
                    return Err("请先输入密码，再保存到系统凭据库".to_string());
                }
            }
        } else if was_stored || was_unknown {
            delete_stored_password(&profile_id)?;
        }

        let view = {
            let state = app.state::<AppState>();
            let mut store = lock_store(&state)?;
            let password = password.or(password_from_keyring);
            let mut profiles = store.profiles.clone();
            let mut stored_secret_profiles = store.stored_secret_profiles.clone();
            let mut unknown_secret_profiles = store.unknown_secret_profiles.clone();
            if input.remember_password {
                stored_secret_profiles.insert(profile_id.clone());
            } else {
                stored_secret_profiles.remove(&profile_id);
            }
            unknown_secret_profiles.remove(&profile_id);
            profiles.insert(profile_id.clone(), input.profile.clone());
            persist_profiles(
                &app,
                &profiles,
                &stored_secret_profiles,
                &unknown_secret_profiles,
            )?;
            store.profiles = profiles;
            store.stored_secret_profiles = stored_secret_profiles;
            store.unknown_secret_profiles = unknown_secret_profiles;
            if let Some(password) = password {
                store.secrets.insert(profile_id.clone(), password);
            }
            profile_view(
                &input.profile,
                store.secrets.contains_key(&profile_id) || input.remember_password,
                store.stored_secret_profiles.contains(&profile_id),
            )
        };

        publish_privilege_status(&app);
        Ok(view)
    })();
    release_profile_mutation(&app, &profile_id);
    result
}

#[tauri::command]
fn delete_profile(app: AppHandle, profile_id: String) -> Result<(), String> {
    reserve_profile_mutation(&app, &profile_id)?;
    let result = (|| -> Result<(), String> {
        let was_stored = {
            let state = app.state::<AppState>();
            let store = lock_store(&state)?;
            if !store.profiles.contains_key(&profile_id) {
                return Err("找不到指定配置".to_string());
            }
            store.stored_secret_profiles.contains(&profile_id)
                || store.unknown_secret_profiles.contains(&profile_id)
        };

        if was_stored {
            delete_stored_password(&profile_id)?;
        }

        let state = app.state::<AppState>();
        let mut store = lock_store(&state)?;
        store.profiles.remove(&profile_id);
        store.secrets.remove(&profile_id);
        store.stored_secret_profiles.remove(&profile_id);
        store.unknown_secret_profiles.remove(&profile_id);
        store.reconnect_attempts.remove(&profile_id);
        store.reconnect_generations.remove(&profile_id);
        store
            .instances
            .retain(|_, instance| instance.view.profile_id != profile_id);
        persist_profiles(
            &app,
            &store.profiles,
            &store.stored_secret_profiles,
            &store.unknown_secret_profiles,
        )?;
        drop(store);
        publish_privilege_status(&app);
        Ok(())
    })();
    release_profile_mutation(&app, &profile_id);
    result
}

#[tauri::command]
fn list_instances(state: State<'_, AppState>) -> Result<Vec<InstanceView>, String> {
    let store = lock_store(&state)?;
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
) -> Result<Vec<LogEvent>, String> {
    let store = lock_store(&state)?;
    Ok(recent_logs(
        &store.logs,
        instance_id.as_deref(),
        limit.unwrap_or(400),
    ))
}

#[tauri::command]
fn engine_info(app: AppHandle) -> EngineInfo {
    let path = resolve_engine(&app);
    let output = Command::new(&path).arg("--version").output();
    let (available, version) = match output {
        Ok(output) if output.status.success() => (
            true,
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ),
        Ok(output) => (
            false,
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ),
        Err(error) => (false, error.to_string()),
    };

    EngineInfo {
        platform: env::consts::OS.to_string(),
        path: path.to_string_lossy().to_string(),
        available,
        version,
        requires_elevation: true,
    }
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
            return Err("系统 VPN helper 尚未安装，请先完成一次安装".to_string());
        }
        set_privilege_ready(&app, true, true);
    }

    let instance_id = Uuid::new_v4().to_string();
    let adapter_name = make_adapter_name(&profile, &instance_id);
    let config_path = write_runtime_config(&app, &profile, &password, &instance_id, &adapter_name)?;
    let bundled_engine = resolve_engine(&app);
    #[cfg(unix)]
    let process_engine = if profile.use_sudo {
        installed_engine_path()
    } else {
        bundled_engine.clone()
    };

    #[cfg(unix)]
    let mut runtime_record = RuntimeProcessRecord {
        instance_id: instance_id.clone(),
        profile_id: profile.id.clone(),
        pid: 0,
        process_group_id: 0,
        engine_path: process_engine.to_string_lossy().into_owned(),
        config_path: config_path.to_string_lossy().into_owned(),
    };
    #[cfg(unix)]
    let process_record_path = match persist_runtime_process_record(&app, &runtime_record) {
        Ok(path) => Some(path),
        Err(message) => {
            let _ = fs::remove_file(&config_path);
            return Err(message);
        }
    };
    #[cfg(windows)]
    let process_record_path = None;

    #[cfg(unix)]
    let mut command = if profile.use_sudo {
        let mut command = Command::new(SUDO_EXECUTABLE);
        command
            .arg("-n")
            .arg(installed_helper_path())
            .arg("run")
            .arg(&config_path);
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    command.process_group(0);

    let mut child = command.spawn().map_err(|error| {
        #[cfg(unix)]
        remove_runtime_process_record(&app, &runtime_record);
        #[cfg(windows)]
        let _ = fs::remove_file(&config_path);
        format!("无法启动 {}：{error}", bundled_engine.display())
    })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pid = child.id();

    #[cfg(unix)]
    {
        runtime_record.pid = pid;
        runtime_record.process_group_id = pid;
        if let Err(message) = persist_runtime_process_record(&app, &runtime_record) {
            let stopped =
                terminate_unregistered_process_group(pid, profile.use_sudo, &process_engine);
            if stopped {
                remove_runtime_process_record(&app, &runtime_record);
            } else if let Ok(mut store) = app.state::<AppState>().store.lock() {
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

    let child = Arc::new(Mutex::new(child));
    let view = InstanceView {
        id: instance_id.clone(),
        profile_generation,
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
                child: child.clone(),
                process_running: true,
                user_requested_stop: false,
                reconnect_blocked: false,
                failure_message: None,
            },
        );
        cancelled
    };

    emit_instance(&app, &view);
    if let Some(stdout) = stdout {
        spawn_stream_reader(stdout, app.clone(), instance_id.clone(), "stdout");
    }
    if let Some(stderr) = stderr {
        spawn_stream_reader(stderr, app.clone(), instance_id.clone(), "stderr");
    }
    spawn_process_monitor(
        app.clone(),
        instance_id,
        child,
        config_path,
        process_record_path,
    );

    if cancelled_before_registration {
        stop_instance(
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
    persist_profiles(
        app,
        &store.profiles,
        &stored_secret_profiles,
        &unknown_secret_profiles,
    )?;
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

    let password = match read_usable_stored_password(profile_id)? {
        Some(password) => password,
        None => {
            clear_missing_stored_password(app, profile_id)?;
            return Err("系统凭据库中的 VPN 密码已不存在，请重新输入并保存".to_string());
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

fn start_profile_impl(
    app: AppHandle,
    profile_id: String,
    origin: StartOrigin,
) -> Result<InstanceView, String> {
    if app.state::<AppState>().shutting_down.load(Ordering::SeqCst) {
        return Err("应用正在退出，不能启动新的连接".to_string());
    }
    let (profile, session_password, password_stored, profile_generation) = {
        let state = app.state::<AppState>();
        let mut store = state
            .store
            .lock()
            .map_err(|_| "内部运行状态已损坏".to_string())?;
        if store.mutating_profiles.contains(&profile_id) {
            return Err("该配置正在编辑或删除，请稍后重试".to_string());
        }
        #[cfg(unix)]
        if store
            .stale_processes
            .values()
            .any(|record| record.profile_id.is_empty() || record.profile_id == profile_id)
        {
            return Err(
                "检测到上次异常退出遗留的 VPN 进程，请先安装系统 helper 完成清理".to_string(),
            );
        }
        if profile_connection_in_progress(&store, &profile_id) {
            return Err("该配置已有连接，请先断开后再连接".to_string());
        }
        let profile = store
            .profiles
            .get(&profile_id)
            .cloned()
            .ok_or_else(|| "找不到指定配置".to_string())?;
        let session_password = store.secrets.get(&profile_id).cloned();
        let password_stored = store.stored_secret_profiles.contains(&profile_id);
        let profile_generation = match origin {
            StartOrigin::AutoReconnect(expected) => {
                let current = store
                    .reconnect_generations
                    .get(&profile_id)
                    .copied()
                    .unwrap_or_default();
                if current != expected {
                    return Err(AUTO_RECONNECT_CANCELLED.to_string());
                }
                bump_reconnect_generation(&mut store, &profile_id)
            }
            StartOrigin::User | StartOrigin::Startup => {
                bump_reconnect_generation(&mut store, &profile_id)
            }
        };
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
fn start_profile(app: AppHandle, profile_id: String) -> Result<InstanceView, String> {
    start_profile_impl(app, profile_id, StartOrigin::User)
}

#[tauri::command]
fn stop_instance(
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

    let (_child, pid, use_sudo, previous_status) = {
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
        let _ = (_child, use_sudo);
        if let Err(error) = send_windows_ctrl_break(pid) {
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
    if let Err(message) = start_profile_impl(app.clone(), profile_id.clone(), StartOrigin::Startup)
    {
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
                    read_usable_stored_password(&profile.id),
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
                                message: "系统凭据库中的 VPN 密码已不存在，请重新输入并保存"
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
                        // A legacy profile may have a keychain item that currently requires
                        // user approval. Record the secure-storage intent so future launches
                        // do not prompt for every profile; connection retries it on demand.
                        metadata_changed |= store.stored_secret_profiles.insert(profile.id.clone());
                        metadata_changed |= store.unknown_secret_profiles.remove(&profile.id);
                    }
                    Err(_) => {}
                }
            }
            if metadata_changed {
                let _ = persist_profiles(
                    &app,
                    &store.profiles,
                    &store.stored_secret_profiles,
                    &store.unknown_secret_profiles,
                );
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
        if let Err(message) = stop_instance(app.clone(), app.state::<AppState>(), instance_id, None)
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
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            let loaded_profiles = load_profiles(app.handle()).map_err(|message| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("拒绝忽略损坏的 VPN 配置：{message}"),
                )
            })?;
            let startup_profiles = loaded_profiles.profiles.clone();
            let startup_stored_secret_profiles = loaded_profiles.stored_secret_profiles.clone();
            let startup_unknown_secret_profiles = loaded_profiles.unknown_secret_profiles.clone();
            #[cfg(unix)]
            let stale_processes = load_stale_runtime_processes(app.handle()).unwrap_or_default();

            let state = app.state::<AppState>();
            if let Ok(mut store) = state.store.lock() {
                store.profiles = loaded_profiles.profiles;
                store.stored_secret_profiles = loaded_profiles.stored_secret_profiles;
                store.unknown_secret_profiles = loaded_profiles.unknown_secret_profiles;
                #[cfg(unix)]
                {
                    store.stale_processes = stale_processes;
                }
            }
            refresh_privilege_status(app.handle(), false);
            start_privilege_keepalive(app.handle().clone());
            load_startup_credentials(
                app.handle().clone(),
                startup_profiles,
                startup_stored_secret_profiles,
                startup_unknown_secret_profiles,
            );
            start_remote_access(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            save_profile,
            delete_profile,
            list_instances,
            list_logs,
            engine_info,
            privilege_status,
            unlock_privileges,
            start_profile,
            stop_instance,
            export_profile_config,
            remote::remote_access_status,
            remote::configure_remote_access,
            remote::rotate_remote_access_token,
        ])
        .build(tauri::generate_context!())
        .expect("error while building OpenFortiVPN Manager");

    app.run(|app, event| match event {
        tauri::RunEvent::ExitRequested { api, code, .. } => {
            let state = app.state::<AppState>();
            if state.exit_cleanup_complete.load(Ordering::SeqCst) {
                return;
            }
            api.prevent_exit();
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
                    app.state::<AppState>()
                        .shutting_down
                        .store(false, Ordering::SeqCst);
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
    use super::*;

    type ProfileMutator = fn(&mut VpnProfile);

    fn valid_profile() -> VpnProfile {
        VpnProfile {
            id: "profile-1".to_string(),
            name: "Office VPN".to_string(),
            host: "vpn.example.com".to_string(),
            port: 443,
            username: "alice".to_string(),
            realm: "employees".to_string(),
            trusted_cert: "aB".repeat(32),
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
        let profile = valid_profile();
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
        profile.host = "  vpn.example.com  ".to_string();
        profile.pppd_use_peerdns = true;
        profile.half_internet_routes = true;

        let config = render_runtime_config(&profile, "secret", "ofv-office-12345678")
            .expect("valid profile should render");

        assert!(config.starts_with("# Generated by OpenFortiVPN Manager. Do not edit.\n"));
        assert!(config.contains("host = vpn.example.com\n"));
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

        assert_eq!(error, "密码 不能包含换行符");
    }

    #[test]
    fn rejects_passwords_the_engine_would_silently_change_or_truncate() {
        assert_eq!(
            validate_password(" secret"),
            Err("VPN 密码不能以空白字符开头或结尾".to_string())
        );
        assert_eq!(
            validate_password("secret "),
            Err("VPN 密码不能以空白字符开头或结尾".to_string())
        );
        assert_eq!(
            validate_password("sec\0ret"),
            Err("VPN 密码不能包含 NUL 字符".to_string())
        );
        assert_eq!(
            validate_password(&"x".repeat(ENGINE_PASSWORD_MAX_BYTES + 1)),
            Err(format!("VPN 密码不能超过 {ENGINE_PASSWORD_MAX_BYTES} 字节"))
        );
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
            payload: serde_json::json!({
                "event": "cert_error",
                "digest": "a".repeat(64),
            }),
        };

        let value = serde_json::to_value(event).expect("engine event should serialize");
        assert_eq!(value["instanceId"], "instance-1");
        assert_eq!(value["profileId"], "profile-1");
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
    fn automatic_retry_excludes_manual_and_fatal_disconnects() {
        assert!(automatic_retry_allowed(false, false, true));
        assert!(!automatic_retry_allowed(true, false, true));
        assert!(!automatic_retry_allowed(false, true, true));
        assert!(!automatic_retry_allowed(false, false, false));
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
    fn retained_logs_are_bounded_filterable_and_chronological() {
        let mut logs = VecDeque::new();
        for index in 0..=MAX_RETAINED_LOGS {
            retain_log(
                &mut logs,
                LogEvent {
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
