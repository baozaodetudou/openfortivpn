use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
#[cfg(unix)]
use std::io::Write;
use std::io::{BufRead, BufReader, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone, Debug, Deserialize, Serialize)]
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
struct RuntimeStore {
    profiles: BTreeMap<String, VpnProfile>,
    secrets: HashMap<String, String>,
    stored_secret_profiles: HashSet<String>,
    instances: BTreeMap<String, ManagedInstance>,
    starting_profiles: HashSet<String>,
    mutating_profiles: HashSet<String>,
    reconnect_attempts: HashMap<String, u32>,
    reconnect_generations: HashMap<String, u64>,
}

#[derive(Default)]
struct AppState {
    store: Mutex<RuntimeStore>,
    privilege_ready: AtomicBool,
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
struct PrivilegeStatus {
    required: bool,
    ready: bool,
    platform: String,
}

const KEYRING_SERVICE: &str = "com.baozaodetudou.openfortivpn";

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

fn load_profiles(app: &AppHandle) -> Result<BTreeMap<String, VpnProfile>, String> {
    let path = profiles_path(app)?;
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取配置列表 {}：{error}", path.display()))?;
    let profiles: Vec<VpnProfile> =
        serde_json::from_str(&contents).map_err(|error| format!("配置列表格式错误：{error}"))?;
    Ok(profiles
        .into_iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect())
}

fn persist_profiles(
    app: &AppHandle,
    profiles: &BTreeMap<String, VpnProfile>,
) -> Result<(), String> {
    let path = profiles_path(app)?;
    let values: Vec<&VpnProfile> = profiles.values().collect();
    let contents = serde_json::to_string_pretty(&values)
        .map_err(|error| format!("无法序列化配置列表：{error}"))?;
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

fn read_stored_password(profile_id: &str) -> Result<Option<String>, String> {
    match credential_entry(profile_id)?.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("无法从系统凭据库读取密码：{error}")),
    }
}

fn store_password(profile_id: &str, password: &str) -> Result<(), String> {
    credential_entry(profile_id)?
        .set_password(password)
        .map_err(|error| format!("无法将密码保存到系统凭据库：{error}"))
}

fn delete_stored_password(profile_id: &str) -> Result<(), String> {
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

fn validate_profile(profile: &VpnProfile) -> Result<(), String> {
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
    validate_line_value("密码", password)?;

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
    let directory = app_data_dir(app)?.join("runtime");
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建运行目录：{error}"))?;
    let path = directory.join(format!("{instance_id}.conf"));
    let config = render_runtime_config(profile, password, adapter_name)?;
    fs::write(&path, config)
        .map_err(|error| format!("无法写入临时配置 {}：{error}", path.display()))?;

    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("无法设置临时配置权限：{error}"))?;

    Ok(path)
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

            let _ = app.emit(
                "vpn-log",
                LogEvent {
                    instance_id: instance_id.clone(),
                    stream: stream.clone(),
                    line,
                    timestamp: now_epoch(),
                },
            );
        }
    });
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
                    profile_id,
                    profile_name,
                    message: format!("自动重连失败：{message}"),
                },
            );
        }
    });
}

fn spawn_process_monitor(
    app: AppHandle,
    instance_id: String,
    child: Arc<Mutex<Child>>,
    config_path: PathBuf,
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
                    let auto_reconnect = !user_requested_stop
                        && !reconnect_blocked
                        && store
                            .profiles
                            .get(&profile_id)
                            .is_some_and(|profile| profile.auto_reconnect);
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
            profile_view(
                profile,
                store.secrets.contains_key(&profile.id),
                store.stored_secret_profiles.contains(&profile.id),
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
    if store.starting_profiles.contains(profile_id)
        || profile_has_running_instance(&store, profile_id)
    {
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
        validate_line_value("密码", password)?;
    }

    if input.profile.auto_connect && !input.remember_password {
        return Err("自动连接需要将密码保存到系统凭据库".to_string());
    }

    let profile_id = input.profile.id.clone();
    reserve_profile_mutation(&app, &profile_id)?;
    let result = (|| -> Result<ProfileView, String> {
        let was_stored = {
            let state = app.state::<AppState>();
            let store = lock_store(&state)?;
            store.stored_secret_profiles.contains(&profile_id)
        };

        let mut password_from_keyring = None;
        if input.remember_password {
            if let Some(password) = password.as_deref() {
                store_password(&profile_id, password)?;
            } else if was_stored {
                // An empty password while editing means keep the existing credential.
            } else {
                password_from_keyring = read_stored_password(&profile_id)?;
                if password_from_keyring.is_none() {
                    return Err("请先输入密码，再保存到系统凭据库".to_string());
                }
            }
        } else if was_stored {
            delete_stored_password(&profile_id)?;
        }

        let view = {
            let state = app.state::<AppState>();
            let mut store = lock_store(&state)?;
            if let Some(password) = password.or(password_from_keyring) {
                store.secrets.insert(profile_id.clone(), password);
            }
            if input.remember_password {
                store.stored_secret_profiles.insert(profile_id.clone());
            } else {
                store.stored_secret_profiles.remove(&profile_id);
            }
            store
                .profiles
                .insert(profile_id.clone(), input.profile.clone());
            persist_profiles(&app, &store.profiles)?;
            profile_view(
                &input.profile,
                store.secrets.contains_key(&profile_id),
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
        };

        if was_stored {
            delete_stored_password(&profile_id)?;
        }

        let state = app.state::<AppState>();
        let mut store = lock_store(&state)?;
        store.profiles.remove(&profile_id);
        store.secrets.remove(&profile_id);
        store.stored_secret_profiles.remove(&profile_id);
        store.reconnect_attempts.remove(&profile_id);
        store.reconnect_generations.remove(&profile_id);
        store
            .instances
            .retain(|_, instance| instance.view.profile_id != profile_id);
        persist_profiles(&app, &store.profiles)?;
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
        .map(|store| store.profiles.values().any(|profile| profile.use_sudo))
        .unwrap_or(false)
}

#[cfg(unix)]
fn sudo_engine_ready(app: &AppHandle) -> bool {
    let engine = resolve_engine(app);
    matches!(
        Command::new("sudo")
            .arg("-n")
            .arg(engine)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(status) if status.success()
    )
}

fn privilege_status_value(app: &AppHandle, ready: bool) -> PrivilegeStatus {
    #[cfg(unix)]
    let required = has_sudo_profiles(app);
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
    let ready = has_sudo_profiles(app) && sudo_engine_ready(app);
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
fn authenticate_sudo(password: &mut String) -> Result<(), String> {
    // With no terminal attached, sudo scopes its timestamp to this app's parent
    // process ID. Later sudo children from the same app can reuse that session.
    let mut child = Command::new("sudo")
        .args(["-S", "-p", "", "-v"])
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
        .map_err(|error| format!("无法等待 sudo 验证结果：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err("管理员密码验证失败，或当前用户没有 sudo 权限".to_string())
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
        authenticate_sudo(&mut password).and_then(|()| {
            if sudo_engine_ready(&app) {
                Ok(set_privilege_ready(&app, true, true))
            } else {
                Err("sudo 已完成验证，但当前用户无权运行 openfortivpn".to_string())
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

        let refreshed = matches!(
            Command::new("sudo")
                .args(["-n", "-v"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
            Ok(status) if status.success()
        ) || sudo_engine_ready(&app);
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

fn spawn_profile_process(
    app: AppHandle,
    profile: VpnProfile,
    password: String,
    profile_generation: u64,
) -> Result<InstanceView, String> {
    #[cfg(unix)]
    if profile.use_sudo {
        if !sudo_engine_ready(&app) {
            set_privilege_ready(&app, false, true);
            return Err("管理员权限尚未解锁，请先输入电脑管理员密码".to_string());
        }
        set_privilege_ready(&app, true, true);
    }

    let instance_id = Uuid::new_v4().to_string();
    let adapter_name = make_adapter_name(&profile, &instance_id);
    let config_path = write_runtime_config(&app, &profile, &password, &instance_id, &adapter_name)?;
    let engine = resolve_engine(&app);

    #[cfg(unix)]
    let mut command = if profile.use_sudo {
        let mut command = Command::new("sudo");
        command.arg("-n").arg(&engine);
        command
    } else {
        Command::new(&engine)
    };

    #[cfg(windows)]
    let mut command = Command::new(&engine);

    command
        .arg("--json-events")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|error| {
        let _ = fs::remove_file(&config_path);
        format!("无法启动 {}：{error}", engine.display())
    })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pid = child.id();
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

    {
        let state = app.state::<AppState>();
        let mut store = state
            .store
            .lock()
            .map_err(|_| "内部运行状态已损坏".to_string())?;
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
    }

    emit_instance(&app, &view);
    if let Some(stdout) = stdout {
        spawn_stream_reader(stdout, app.clone(), instance_id.clone(), "stdout");
    }
    if let Some(stderr) = stderr {
        spawn_stream_reader(stderr, app.clone(), instance_id.clone(), "stderr");
    }
    spawn_process_monitor(app.clone(), instance_id, child, config_path);

    Ok(view)
}

fn start_profile_impl(
    app: AppHandle,
    profile_id: String,
    origin: StartOrigin,
) -> Result<InstanceView, String> {
    let (profile, password, profile_generation) = {
        let state = app.state::<AppState>();
        let mut store = state
            .store
            .lock()
            .map_err(|_| "内部运行状态已损坏".to_string())?;
        if store.mutating_profiles.contains(&profile_id) {
            return Err("该配置正在编辑或删除，请稍后重试".to_string());
        }
        if store.starting_profiles.contains(&profile_id)
            || profile_has_running_instance(&store, &profile_id)
        {
            return Err("该配置已有连接，请先断开后再连接".to_string());
        }
        let profile = store
            .profiles
            .get(&profile_id)
            .cloned()
            .ok_or_else(|| "找不到指定配置".to_string())?;
        let password = store
            .secrets
            .get(&profile_id)
            .cloned()
            .ok_or_else(|| "密码未保存在当前会话，请编辑配置并重新输入密码".to_string())?;
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
        (profile, password, profile_generation)
    };

    let result = spawn_profile_process(app.clone(), profile, password, profile_generation);
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
        let store = lock_store(&state)?;
        if store.instances.contains_key(&instance_id) {
            instance_id
        } else if let Some(profile_id) = profile_id {
            let Some(instance) = store
                .instances
                .values()
                .find(|instance| instance.view.profile_id == profile_id)
            else {
                return Ok(());
            };
            instance.view.id.clone()
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

    #[cfg(unix)]
    if use_sudo && !sudo_engine_ready(&app) {
        set_privilege_ready(&app, false, true);
        return Err("管理员权限已失效，请重新解锁后再断开连接".to_string());
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
            Command::new("sudo")
                .args(["-n", "kill", "-TERM"])
                .arg(pid.to_string())
                .status()
        } else {
            Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status()
        };
        if !matches!(result, Ok(status) if status.success()) {
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
            let fallback = child
                .lock()
                .map_err(|_| "无法访问 VPN 进程".to_string())?
                .kill();
            if let Err(error) = fallback {
                restore_instance_after_stop_failure(
                    &app,
                    &instance_id,
                    &previous_status,
                    format!("断开失败：{error}"),
                );
                return Err(format!("无法停止 VPN 进程：{error}"));
            }
        }
    }

    #[cfg(windows)]
    {
        let _ = (pid, use_sudo);
        let result = child
            .lock()
            .map_err(|_| "无法访问 VPN 进程".to_string())?
            .kill();
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
            store.starting_profiles.contains(profile_id)
                || store.mutating_profiles.contains(profile_id)
                || profile_has_running_instance(&store, profile_id)
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
                waiting_for_privilege.push((profile_id, profile_name));
            } else {
                attempt_auto_connect(&app, profile_id, profile_name);
            }
        }

        while !waiting_for_privilege.is_empty() {
            thread::sleep(Duration::from_millis(250));
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            let profiles = load_profiles(app.handle()).unwrap_or_default();
            let mut secrets = HashMap::new();
            let mut stored_secret_profiles = HashSet::new();
            let mut credential_errors = Vec::new();

            for profile in profiles.values() {
                match read_stored_password(&profile.id) {
                    Ok(Some(password)) => {
                        secrets.insert(profile.id.clone(), password);
                        stored_secret_profiles.insert(profile.id.clone());
                    }
                    Ok(None) => {}
                    Err(message) if profile.auto_connect => {
                        credential_errors.push(AutoConnectError {
                            profile_id: profile.id.clone(),
                            profile_name: profile.name.clone(),
                            message,
                        });
                    }
                    Err(_) => {}
                }
            }

            let state = app.state::<AppState>();
            if let Ok(mut store) = state.store.lock() {
                store.profiles = profiles;
                store.secrets = secrets;
                store.stored_secret_profiles = stored_secret_profiles;
            }
            refresh_privilege_status(app.handle(), false);
            start_privilege_keepalive(app.handle().clone());
            start_auto_connect_profiles(app.handle().clone(), credential_errors);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            save_profile,
            delete_profile,
            list_instances,
            engine_info,
            privilege_status,
            unlock_privileges,
            start_profile,
            stop_instance,
            export_profile_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running OpenFortiVPN Manager");
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
