use super::{
    app_data_dir, delete_profile, engine_info, list_instances, list_logs, list_profiles,
    privilege_status, save_profile, start_profile, stop_instance, AppState, EngineInfo,
    InstanceView, LogEvent, PrivilegeStatus, ProfileView, SaveProfileInput,
};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpListener};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path as FilePath, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Emitter, Manager};

const REMOTE_TOKEN_ACCOUNT: &str = "__remote_access_token";
const REMOTE_CONFIG_FILE: &str = "remote-access.json";
const REMOTE_CERT_FILE: &str = "certificate.pem";
const REMOTE_KEY_FILE: &str = "private-key.pem";
const REMOTE_CERT_NAMES_FILE: &str = "certificate-names.json";
const REMOTE_PAGE: &str = include_str!("remote.html");

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteAccessSettings {
    pub(crate) enabled: bool,
    pub(crate) bind_address: String,
    pub(crate) port: u16,
}

impl Default for RemoteAccessSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1".to_string(),
            port: 18_443,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigureRemoteAccessInput {
    pub(crate) enabled: bool,
    pub(crate) bind_address: String,
    pub(crate) port: u16,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteAccessStatus {
    pub(crate) enabled: bool,
    pub(crate) running: bool,
    pub(crate) bind_address: String,
    pub(crate) port: u16,
    pub(crate) url: String,
    pub(crate) certificate_fingerprint: String,
    pub(crate) token_configured: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteAccessUpdate {
    pub(crate) status: RemoteAccessStatus,
    pub(crate) token: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RemoteAccessError {
    pub(crate) message: String,
}

struct RemoteRuntime {
    handle: Handle<SocketAddr>,
    thread: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

static REMOTE_RUNTIME: OnceLock<Mutex<Option<RemoteRuntime>>> = OnceLock::new();
static REMOTE_TOKEN_CONFIGURED: AtomicBool = AtomicBool::new(false);

fn runtime_slot() -> &'static Mutex<Option<RemoteRuntime>> {
    REMOTE_RUNTIME.get_or_init(|| Mutex::new(None))
}

fn remote_directory(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app_data_dir(app)?.join("remote-access");
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建远程访问目录：{error}"))?;
    set_private_permissions(&directory, true)?;
    Ok(directory)
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(REMOTE_CONFIG_FILE))
}

fn load_settings(app: &AppHandle) -> Result<RemoteAccessSettings, String> {
    let path = settings_path(app)?;
    if !path.exists() {
        return Ok(RemoteAccessSettings::default());
    }
    let contents =
        fs::read_to_string(&path).map_err(|error| format!("无法读取远程访问配置：{error}"))?;
    let settings = serde_json::from_str(&contents)
        .map_err(|error| format!("远程访问配置格式错误：{error}"))?;
    validate_settings(&settings)?;
    Ok(settings)
}

fn persist_settings(app: &AppHandle, settings: &RemoteAccessSettings) -> Result<(), String> {
    validate_settings(settings)?;
    let path = settings_path(app)?;
    let contents = serde_json::to_string_pretty(settings)
        .map_err(|error| format!("无法序列化远程访问配置：{error}"))?;
    fs::write(&path, contents).map_err(|error| format!("无法保存远程访问配置：{error}"))?;
    set_private_permissions(&path, false)
}

fn validate_settings(settings: &RemoteAccessSettings) -> Result<SocketAddr, String> {
    let ip = settings
        .bind_address
        .parse::<IpAddr>()
        .map_err(|_| "监听地址必须是有效的 IPv4 或 IPv6 地址".to_string())?;
    if settings.port == 0 {
        return Err("远程访问端口必须在 1 到 65535 之间".to_string());
    }
    Ok(SocketAddr::new(ip, settings.port))
}

fn set_private_permissions(path: &FilePath, directory: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mode = if directory { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("无法限制 {} 的权限：{error}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, directory);
    Ok(())
}

fn token_entry() -> Result<keyring::Entry, String> {
    super::credential_entry(REMOTE_TOKEN_ACCOUNT)
}

fn read_remote_token() -> Result<Option<String>, String> {
    let _guard = super::lock_credential_access()?;
    match token_entry()?.get_password() {
        Ok(token) => {
            REMOTE_TOKEN_CONFIGURED.store(true, Ordering::SeqCst);
            Ok(Some(token))
        }
        Err(keyring::Error::NoEntry) => {
            REMOTE_TOKEN_CONFIGURED.store(false, Ordering::SeqCst);
            Ok(None)
        }
        Err(error) => Err(format!("无法读取远程访问令牌：{error}")),
    }
}

fn generate_remote_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn store_remote_token(token: &str) -> Result<(), String> {
    let _guard = super::lock_credential_access()?;
    token_entry()?
        .set_password(token)
        .map_err(|error| format!("无法保存远程访问令牌：{error}"))?;
    REMOTE_TOKEN_CONFIGURED.store(true, Ordering::SeqCst);
    Ok(())
}

fn create_remote_token() -> Result<String, String> {
    let token = generate_remote_token();
    store_remote_token(&token)?;
    Ok(token)
}

fn ensure_remote_token() -> Result<(String, bool), String> {
    if let Some(token) = read_remote_token()? {
        return Ok((token, false));
    }
    Ok((create_remote_token()?, true))
}

fn certificate_paths(app: &AppHandle) -> Result<(PathBuf, PathBuf), String> {
    let directory = remote_directory(app)?;
    Ok((
        directory.join(REMOTE_CERT_FILE),
        directory.join(REMOTE_KEY_FILE),
    ))
}

fn certificate_names_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(remote_directory(app)?.join(REMOTE_CERT_NAMES_FILE))
}

fn certificate_names(settings: &RemoteAccessSettings) -> Vec<String> {
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if !settings.bind_address.is_empty() && !names.contains(&settings.bind_address) {
        names.push(settings.bind_address.clone());
    }
    names.sort();
    names.dedup();
    names
}

fn write_private_file(path: &FilePath, contents: impl AsRef<[u8]>) -> Result<(), String> {
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("private-file"),
        rand::random::<u64>()
    ));
    fs::write(&temporary, contents)
        .map_err(|error| format!("无法写入临时文件 {}：{error}", temporary.display()))?;
    set_private_permissions(&temporary, false)?;
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("无法替换私有文件 {}：{error}", path.display()))?;
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("无法原子更新私有文件 {}：{error}", path.display()));
    }
    Ok(())
}

fn ensure_certificate(
    app: &AppHandle,
    settings: &RemoteAccessSettings,
) -> Result<(PathBuf, PathBuf), String> {
    let (cert_path, key_path) = certificate_paths(app)?;
    let names_path = certificate_names_path(app)?;
    let names = certificate_names(settings);
    let stored_names = fs::read_to_string(&names_path)
        .ok()
        .and_then(|contents| serde_json::from_str::<Vec<String>>(&contents).ok());
    if cert_path.exists() && key_path.exists() && stored_names.as_ref() == Some(&names) {
        set_private_permissions(&cert_path, false)?;
        set_private_permissions(&key_path, false)?;
        set_private_permissions(&names_path, false)?;
        return Ok((cert_path, key_path));
    }

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(names.clone())
        .map_err(|error| format!("无法生成 HTTPS 证书：{error}"))?;
    // The metadata file is the commit marker. If the app stops between these
    // writes, the next launch regenerates the complete matching set.
    let _ = fs::remove_file(&names_path);
    write_private_file(&key_path, signing_key.serialize_pem())?;
    write_private_file(&cert_path, cert.pem())?;
    write_private_file(
        &names_path,
        serde_json::to_string_pretty(&names)
            .map_err(|error| format!("无法序列化 HTTPS 证书名称：{error}"))?,
    )?;
    Ok((cert_path, key_path))
}

fn certificate_fingerprint(app: &AppHandle) -> Result<String, String> {
    let (cert_path, _) = certificate_paths(app)?;
    if !cert_path.exists() {
        return Ok(String::new());
    }
    let encoded = fs::read(&cert_path).map_err(|error| format!("无法读取 HTTPS 证书：{error}"))?;
    let certificate =
        pem::parse(encoded).map_err(|error| format!("HTTPS 证书格式错误：{error}"))?;
    let digest = Sha256::digest(certificate.contents());
    Ok(digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

#[derive(Clone)]
struct WebState {
    app: AppHandle,
    token: Arc<String>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "访问令牌无效".to_string(),
        }
    }

    fn from_message(message: String) -> Self {
        let status = if message.contains("找不到") {
            StatusCode::NOT_FOUND
        } else if message.contains("正在")
            || message.contains("已有连接")
            || message.contains("请先")
        {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        Self { status, message }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

fn authorize(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err(ApiError::unauthorized());
    };
    let Ok(value) = value.to_str() else {
        return Err(ApiError::unauthorized());
    };
    let Some(candidate) = value.strip_prefix("Bearer ") else {
        return Err(ApiError::unauthorized());
    };
    if candidate.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        ),
    );
    response
}

async fn index() -> Html<&'static str> {
    Html(REMOTE_PAGE)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "openfortivpn-manager",
        "version": env!("CARGO_PKG_VERSION"),
        "tls": true
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    profiles: Vec<ProfileView>,
    instances: Vec<InstanceView>,
    logs: Vec<LogEvent>,
    engine: EngineInfo,
    privilege: PrivilegeStatus,
}

async fn snapshot(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Json<Snapshot>, ApiError> {
    authorize(&headers, &state.token)?;
    let profiles = list_profiles(state.app.state()).map_err(ApiError::from_message)?;
    let instances = list_instances(state.app.state()).map_err(ApiError::from_message)?;
    let logs = list_logs(state.app.state(), None, Some(400)).map_err(ApiError::from_message)?;
    Ok(Json(Snapshot {
        profiles,
        instances,
        logs,
        engine: engine_info(state.app.clone()),
        privilege: privilege_status(state.app),
    }))
}

async fn profiles(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileView>>, ApiError> {
    authorize(&headers, &state.token)?;
    list_profiles(state.app.state())
        .map(Json)
        .map_err(ApiError::from_message)
}

async fn instances(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InstanceView>>, ApiError> {
    authorize(&headers, &state.token)?;
    list_instances(state.app.state())
        .map(Json)
        .map_err(ApiError::from_message)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogsQuery {
    instance_id: Option<String>,
    limit: Option<usize>,
}

async fn logs(
    State(state): State<WebState>,
    headers: HeaderMap,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Vec<LogEvent>>, ApiError> {
    authorize(&headers, &state.token)?;
    list_logs(state.app.state(), query.instance_id, query.limit)
        .map(Json)
        .map_err(ApiError::from_message)
}

async fn save_profile_api(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(input): Json<SaveProfileInput>,
) -> Result<Json<ProfileView>, ApiError> {
    authorize(&headers, &state.token)?;
    save_profile(state.app, input)
        .map(Json)
        .map_err(ApiError::from_message)
}

async fn connect_profile(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<InstanceView>, ApiError> {
    authorize(&headers, &state.token)?;
    start_profile(state.app, profile_id)
        .map(Json)
        .map_err(ApiError::from_message)
}

fn current_profile_instance(
    app: &AppHandle,
    profile_id: &str,
) -> Result<Option<InstanceView>, ApiError> {
    let instances = list_instances(app.state()).map_err(ApiError::from_message)?;
    Ok(instances
        .into_iter()
        .find(|instance| instance.profile_id == profile_id))
}

async fn disconnect_profile(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, &state.token)?;
    if let Some(instance) = current_profile_instance(&state.app, &profile_id)? {
        stop_instance(
            state.app.clone(),
            state.app.state::<AppState>(),
            instance.id,
            Some(profile_id),
        )
        .map_err(ApiError::from_message)?;
    }
    Ok(StatusCode::ACCEPTED)
}

async fn reconnect_profile(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<InstanceView>, ApiError> {
    authorize(&headers, &state.token)?;
    if let Some(instance) = current_profile_instance(&state.app, &profile_id)? {
        stop_instance(
            state.app.clone(),
            state.app.state::<AppState>(),
            instance.id,
            Some(profile_id.clone()),
        )
        .map_err(ApiError::from_message)?;
        for _ in 0..60 {
            if !super::profile_has_active_instance(&state.app, &profile_id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if super::profile_has_active_instance(&state.app, &profile_id) {
            return Err(ApiError::from_message("等待旧连接断开超时".to_string()));
        }
    }
    start_profile(state.app, profile_id)
        .map(Json)
        .map_err(ApiError::from_message)
}

async fn delete_profile_api(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, &state.token)?;
    delete_profile(state.app, profile_id).map_err(ApiError::from_message)?;
    Ok(StatusCode::NO_CONTENT)
}

fn web_router(state: WebState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/profiles", get(profiles).post(save_profile_api))
        .route("/api/v1/instances", get(instances))
        .route("/api/v1/logs", get(logs))
        .route(
            "/api/v1/profiles/{profile_id}/connect",
            post(connect_profile),
        )
        .route(
            "/api/v1/profiles/{profile_id}/disconnect",
            post(disconnect_profile),
        )
        .route(
            "/api/v1/profiles/{profile_id}/reconnect",
            post(reconnect_profile),
        )
        .route("/api/v1/profiles/{profile_id}", delete(delete_profile_api))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

fn stop_running_server() -> Result<(), String> {
    let runtime = runtime_slot()
        .lock()
        .map_err(|_| "远程访问运行状态已损坏".to_string())?
        .take();
    if let Some(mut runtime) = runtime {
        runtime
            .handle
            .graceful_shutdown(Some(Duration::from_secs(5)));
        if let Some(thread) = runtime.thread.take() {
            thread
                .join()
                .map_err(|_| "远程访问服务线程异常退出".to_string())?;
        }
    }
    Ok(())
}

pub(crate) fn shutdown() -> Result<(), String> {
    stop_running_server()
}

fn start_server(
    app: AppHandle,
    settings: &RemoteAccessSettings,
    token: String,
) -> Result<(), String> {
    stop_running_server()?;
    let address = validate_settings(settings)?;
    let (cert_path, key_path) = ensure_certificate(&app, settings)?;
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("无法监听远程访问地址 {address}：{error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("无法配置远程访问监听器：{error}"))?;
    let handle = Handle::new();
    let thread_handle = handle.clone();
    let running = Arc::new(AtomicBool::new(true));
    let thread_running = running.clone();
    let server_app = app.clone();
    let thread = thread::spawn(move || {
        let web_app = server_app.clone();
        let result = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("无法创建远程访问运行时：{error}"))
            .and_then(|runtime| {
                runtime.block_on(async move {
                    let tls = RustlsConfig::from_pem_file(cert_path, key_path)
                        .await
                        .map_err(|error| format!("无法加载远程访问 HTTPS 证书：{error}"))?;
                    let server = axum_server::from_tcp_rustls(listener, tls)
                        .map_err(|error| format!("无法创建远程访问 HTTPS 服务：{error}"))?;
                    server
                        .handle(thread_handle)
                        .serve(
                            web_router(WebState {
                                app: web_app,
                                token: Arc::new(token),
                            })
                            .into_make_service(),
                        )
                        .await
                        .map_err(|error| format!("远程访问 HTTPS 服务异常：{error}"))
                })
            });
        thread_running.store(false, Ordering::SeqCst);
        if let Err(message) = result {
            let _ = server_app.emit("remote-access-error", RemoteAccessError { message });
        }
    });

    *runtime_slot()
        .lock()
        .map_err(|_| "远程访问运行状态已损坏".to_string())? = Some(RemoteRuntime {
        handle,
        thread: Some(thread),
        running,
    });
    Ok(())
}

fn is_running() -> bool {
    runtime_slot()
        .lock()
        .ok()
        .and_then(|runtime| {
            runtime
                .as_ref()
                .map(|runtime| runtime.running.load(Ordering::SeqCst))
        })
        .unwrap_or(false)
}

fn make_status(
    app: &AppHandle,
    settings: RemoteAccessSettings,
) -> Result<RemoteAccessStatus, String> {
    let address = validate_settings(&settings)?.ip();
    let display_address = match address {
        IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".to_string(),
        IpAddr::V6(ip) if ip.is_unspecified() => "::1".to_string(),
        _ => settings.bind_address.clone(),
    };
    let host = if display_address.contains(':') {
        format!("[{display_address}]")
    } else {
        display_address
    };
    Ok(RemoteAccessStatus {
        enabled: settings.enabled,
        running: is_running(),
        bind_address: settings.bind_address,
        port: settings.port,
        url: format!("https://{host}:{}", settings.port),
        certificate_fingerprint: certificate_fingerprint(app)?,
        token_configured: REMOTE_TOKEN_CONFIGURED.load(Ordering::SeqCst),
    })
}

pub(crate) fn initialize(app: AppHandle) -> Result<(), String> {
    let settings = load_settings(&app)?;
    if settings.enabled {
        let (token, _) = ensure_remote_token()?;
        start_server(app, &settings, token)?;
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn remote_access_status(app: AppHandle) -> Result<RemoteAccessStatus, String> {
    make_status(&app, load_settings(&app)?)
}

#[tauri::command]
pub(crate) fn configure_remote_access(
    app: AppHandle,
    input: ConfigureRemoteAccessInput,
) -> Result<RemoteAccessUpdate, String> {
    let settings = RemoteAccessSettings {
        enabled: input.enabled,
        bind_address: input.bind_address.trim().to_string(),
        port: input.port,
    };
    validate_settings(&settings)?;
    let previous_settings = load_settings(&app)?;

    let mut revealed_token = None;
    let token = if settings.enabled {
        let (token, created) = ensure_remote_token()?;
        ensure_certificate(&app, &settings)?;
        if created {
            revealed_token = Some(token.clone());
        }
        Some(token)
    } else {
        None
    };

    persist_settings(&app, &settings)?;
    let apply_result = match token {
        Some(token) => start_server(app.clone(), &settings, token),
        None => stop_running_server(),
    };
    if let Err(message) = apply_result {
        let config_rollback = persist_settings(&app, &previous_settings);
        let runtime_rollback = if previous_settings.enabled {
            ensure_remote_token()
                .and_then(|(token, _)| start_server(app.clone(), &previous_settings, token))
        } else {
            stop_running_server()
        };
        let rollback_message = match (config_rollback, runtime_rollback) {
            (Ok(()), Ok(())) => "已恢复之前的远程访问设置".to_string(),
            (config, runtime) => format!(
                "回滚不完整（配置：{}；服务：{}）",
                config.err().unwrap_or_else(|| "正常".to_string()),
                runtime.err().unwrap_or_else(|| "正常".to_string())
            ),
        };
        return Err(format!("{message}；{rollback_message}"));
    }
    Ok(RemoteAccessUpdate {
        status: make_status(&app, settings)?,
        token: revealed_token,
    })
}

#[tauri::command]
pub(crate) fn rotate_remote_access_token(app: AppHandle) -> Result<RemoteAccessUpdate, String> {
    let settings = load_settings(&app)?;
    let previous_token = read_remote_token()?;
    let token = generate_remote_token();
    store_remote_token(&token)?;
    if settings.enabled {
        if let Err(message) = start_server(app.clone(), &settings, token.clone()) {
            if let Some(previous_token) = previous_token {
                store_remote_token(&previous_token)?;
                start_server(app.clone(), &settings, previous_token)
                    .map_err(|rollback| format!("{message}；恢复旧令牌和服务失败：{rollback}"))?;
            }
            return Err(message);
        }
    }
    Ok(RemoteAccessUpdate {
        status: make_status(&app, settings)?,
        token: Some(token),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_loopback_only_and_disabled() {
        let settings = RemoteAccessSettings::default();
        assert!(!settings.enabled);
        assert_eq!(settings.bind_address, "127.0.0.1");
        assert_eq!(settings.port, 18_443);
        assert!(validate_settings(&settings).is_ok());
    }

    #[test]
    fn rejects_hostnames_and_zero_port() {
        let mut settings = RemoteAccessSettings {
            bind_address: "example.com".to_string(),
            ..RemoteAccessSettings::default()
        };
        assert!(validate_settings(&settings).is_err());
        settings.bind_address = "127.0.0.1".to_string();
        settings.port = 0;
        assert!(validate_settings(&settings).is_err());
    }

    #[test]
    fn certificate_names_follow_the_configured_bind_address() {
        let defaults = certificate_names(&RemoteAccessSettings::default());
        assert_eq!(defaults, vec!["127.0.0.1", "::1", "localhost"]);

        let settings = RemoteAccessSettings {
            bind_address: "10.10.0.8".to_string(),
            ..RemoteAccessSettings::default()
        };
        let names = certificate_names(&settings);
        assert!(names.iter().any(|name| name == "10.10.0.8"));
    }

    #[test]
    fn bearer_comparison_requires_exact_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer exact-secret"),
        );
        assert!(authorize(&headers, "exact-secret").is_ok());
        assert!(authorize(&headers, "other-secret").is_err());
    }

    #[test]
    fn generated_tokens_have_256_bits_of_random_input() {
        let first = generate_remote_token();
        let second = generate_remote_token();
        assert_eq!(first.len(), 43);
        assert_eq!(second.len(), 43);
        assert_ne!(first, second);
        assert!(first
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_')));
    }
}
