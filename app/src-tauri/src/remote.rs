use super::{
    app_data_dir, engine_info, list_instances, list_logs, list_profiles, privilege_status_value,
    AppState, EngineInfo, InstanceView, PrivilegeStatus, ProfileView, SaveProfileInput,
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
use tauri::{AppHandle, Emitter, Manager};

const REMOTE_TOKEN_ACCOUNT: &str = "__remote_access_token";
const REMOTE_CONFIG_FILE: &str = "remote-access.json";
const REMOTE_CERT_FILE: &str = "certificate.pem";
const REMOTE_KEY_FILE: &str = "private-key.pem";
const REMOTE_PAGE: &str = include_str!("remote.html");
const CLIENT: &str = include_str!("../../../web/remote-client.js");

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
    token: Arc<openfortivpn_manager_http::AccessToken>,
    handle: Handle<SocketAddr>,
    thread: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

static REMOTE_ADMIN: Mutex<()> = Mutex::new(());

static REMOTE_RUNTIME: OnceLock<Mutex<Option<RemoteRuntime>>> = OnceLock::new();
static REMOTE_TOKEN_CONFIGURED: AtomicBool = AtomicBool::new(false);

fn runtime_slot() -> &'static Mutex<Option<RemoteRuntime>> {
    REMOTE_RUNTIME.get_or_init(|| Mutex::new(None))
}

fn remote_directory(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app_data_dir(app)?.join("remote-access");
    fs::create_dir_all(&directory).map_err(|error| format!("无法创建远程访问目录：{error}"))?;
    // Reject links before tightening permissions; chmod on a link would alter
    // an unrelated directory and reading it could expose a private key.
    let metadata = fs::symlink_metadata(&directory).map_err(|_| "无法检查远程访问目录")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("远程访问目录不能是符号链接".into());
    }
    set_private_permissions(&directory, true)?;
    openfortivpn_manager_core::private_file::verify_directory(&directory)
        .map_err(|_| "远程访问目录权限不安全")?;
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
    openfortivpn_manager_core::atomic_file::write_private(&path, contents.as_bytes())
        .map_err(|error| format!("无法保存远程访问配置：{error}"))?;
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

#[cfg(test)]
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

fn ensure_certificate(
    app: &AppHandle,
    settings: &RemoteAccessSettings,
) -> Result<(PathBuf, PathBuf), String> {
    openfortivpn_manager_core::tls_identity::TlsIdentityStore::new(remote_directory(app)?)
        .ensure(&settings.bind_address)
        .map_err(|error| format!("无法准备 HTTPS 证书与私钥：{error}"))
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
    token: Arc<openfortivpn_manager_http::AccessToken>,
}

#[cfg(test)]
use openfortivpn_manager_http::authorize;
use openfortivpn_manager_http::ApiError;

#[derive(Clone, Copy)]
enum ProfileOperation {
    Edit,
    Start,
    StopOrDelete,
}

fn preflight_profile(
    app: &AppHandle,
    profile_id: &str,
    operation: ProfileOperation,
) -> Result<(), ApiError> {
    let state = app.state::<AppState>();
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::from_message("内部运行状态已损坏".into()))?;
    if !matches!(operation, ProfileOperation::StopOrDelete) && store.repository_recovery_required {
        return Err(super::repository_api_error());
    }
    if !matches!(operation, ProfileOperation::Edit) && !store.profiles.contains_key(profile_id) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "PROFILE_NOT_FOUND",
            "找不到指定配置",
            false,
        ));
    }
    if store.mutating_profiles.contains(profile_id)
        || (matches!(operation, ProfileOperation::Edit)
            && super::profile_connection_in_progress(&store, profile_id))
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "PROFILE_BUSY",
            "配置正在运行或修改，请稍后重试",
            true,
        ));
    }
    if matches!(operation, ProfileOperation::Start) {
        if state
            .shutting_down
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "SHUTTING_DOWN",
                "应用正在关闭",
                true,
            ));
        }
        if store.starting_profiles.iter().any(|id| id != profile_id)
            || store.instances.values().any(|i| {
                i.view.profile_id != profile_id
                    && (i.process_running || i.lifecycle.cleanup_failed())
            })
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "NETWORK_CONFLICT",
                "网络资源由另一个配置持有，请先断开",
                true,
            ));
        }
        if store.instances.values().any(|i| {
            i.view.profile_id == profile_id
                && (i.lifecycle.cleanup_failed()
                    || (i.process_running && i.view.status == "disconnecting"))
        }) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "PROFILE_BUSY",
                "连接正在停止或等待恢复",
                true,
            ));
        }
    }
    Ok(())
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
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'",
        ),
    );
    response
}

async fn index() -> Html<&'static str> {
    Html(REMOTE_PAGE)
}

async fn client() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        CLIENT,
    )
}

async fn capabilities(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Json<openfortivpn_manager_core::domain::Capabilities>, ApiError> {
    state.token.authorize(&headers)?;
    let capabilities = openfortivpn_manager_core::domain::Capabilities {
        privilege_setup: cfg!(unix),
        ..Default::default()
    };
    Ok(Json(capabilities))
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
    logs: openfortivpn_manager_core::domain::LogSnapshot,
    engine: EngineInfo,
    privilege: PrivilegeStatus,
}

async fn snapshot(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Json<Snapshot>, ApiError> {
    state.token.authorize(&headers)?;
    let profiles = list_profiles(state.app.state()).map_err(ApiError::from_message)?;
    let instances = list_instances(state.app.state()).map_err(ApiError::from_message)?;
    let logs = list_logs(state.app.state(), None, Some(400)).map_err(ApiError::from_message)?;
    Ok(Json(Snapshot {
        profiles,
        instances,
        logs,
        engine: engine_info(state.app.clone()),
        privilege: privilege_status_value(
            &state.app,
            state
                .app
                .state::<AppState>()
                .privilege_ready
                .load(std::sync::atomic::Ordering::SeqCst),
        ),
    }))
}

async fn profiles(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileView>>, ApiError> {
    state.token.authorize(&headers)?;
    list_profiles(state.app.state())
        .map(Json)
        .map_err(ApiError::from_message)
}

async fn instances(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InstanceView>>, ApiError> {
    state.token.authorize(&headers)?;
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
) -> Result<axum::response::Response, ApiError> {
    state.token.authorize(&headers)?;
    let logs = list_logs(state.app.state(), query.instance_id, query.limit)
        .map_err(ApiError::from_message)?;
    openfortivpn_manager_http::logs_response(logs)
}

async fn save_profile_api(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(mut input): Json<SaveProfileInput>,
) -> Result<Json<ProfileView>, ApiError> {
    state.token.authorize(&headers)?;
    if input.profile.id.trim().is_empty() {
        input.profile.id = uuid::Uuid::new_v4().to_string();
    }
    super::validate_profile(&input.profile).map_err(|message| {
        ApiError::new(StatusCode::BAD_REQUEST, "INVALID_INPUT", message, false)
    })?;
    if let Some(password) = &input.password {
        super::validate_password(password).map_err(|message| {
            ApiError::new(StatusCode::BAD_REQUEST, "INVALID_INPUT", message, false)
        })?;
    }
    if input.profile.auto_connect && !input.remember_password {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
            "自动连接需要保存密码",
            false,
        ));
    }
    super::run_profile_command(state.app, input.profile.id.clone(), move |app| {
        preflight_profile(&app, &input.profile.id, ProfileOperation::Edit)?;
        super::save_profile_service(app, input)
    })
    .await
    .map(Json)
}

async fn connect_profile(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<InstanceView>, ApiError> {
    state.token.authorize(&headers)?;
    super::run_profile_command(state.app, profile_id.clone(), move |app| {
        preflight_profile(&app, &profile_id, ProfileOperation::Start)?;
        super::start_profile_impl(app, profile_id, super::StartOrigin::User)
            .map_err(ApiError::from_message)
    })
    .await
    .map(Json)
}

async fn disconnect_profile(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.token.authorize(&headers)?;
    super::run_profile_command(state.app, profile_id.clone(), move |app| {
        preflight_profile(&app, &profile_id, ProfileOperation::StopOrDelete)?;
        super::disconnect_profile_impl(app, profile_id).map_err(ApiError::from_message)
    })
    .await?;
    Ok(StatusCode::ACCEPTED)
}

async fn reconnect_profile(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<InstanceView>, ApiError> {
    state.token.authorize(&headers)?;
    super::run_profile_command(state.app, profile_id.clone(), move |app| {
        preflight_profile(&app, &profile_id, ProfileOperation::StopOrDelete)?;
        super::reconnect_profile_impl(app, profile_id).map_err(ApiError::from_message)
    })
    .await
    .map(Json)
}

async fn delete_profile_api(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.token.authorize(&headers)?;
    super::run_profile_command(state.app, profile_id.clone(), move |app| {
        preflight_profile(&app, &profile_id, ProfileOperation::StopOrDelete)?;
        super::delete_profile_service(app, profile_id, None, true)
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn web_router(state: WebState) -> Router {
    let v2 = openfortivpn_manager_http::v2::router(Arc::new(state.clone()));
    Router::new()
        .route("/", get(index))
        .route("/remote-client.js", get(client))
        .route("/health", get(health))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/capabilities", get(capabilities))
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
        .with_state(state)
        .nest("/api/v2", v2)
        .layer(middleware::from_fn(security_headers))
}

impl openfortivpn_manager_http::v2::ControlService for WebState {
    fn capabilities(&self) -> openfortivpn_manager_core::domain::Capabilities {
        openfortivpn_manager_core::domain::Capabilities {
            privilege_setup: cfg!(unix),
            ..Default::default()
        }
    }
    fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        self.token.authorize(headers)
    }
    async fn snapshot(&self) -> Result<serde_json::Value, ApiError> {
        let app = self.app.clone();
        tokio::task::spawn_blocking(move || {
            let profiles = list_profiles(app.state()).map_err(ApiError::from_message)?;
            let instances = list_instances(app.state()).map_err(ApiError::from_message)?;
            let logs = list_logs(app.state(), None, Some(400)).map_err(ApiError::from_message)?;
            let recovery = super::list_recovery_records(app.clone()).map_err(ApiError::from_message)?;
            Ok(json!({"profiles":profiles,"instances":instances,"logs":logs,"runJournal":recovery,"engine":engine_info(app.clone()),"privilege":privilege_status_value(&app, app.state::<AppState>().privilege_ready.load(Ordering::SeqCst))}))
        }).await.map_err(|e| ApiError::from_message(e.to_string()))?
    }
    async fn save(
        &self,
        mut input: openfortivpn_manager_core::domain::SaveProfileInput,
    ) -> Result<serde_json::Value, ApiError> {
        super::run_profile_command(self.app.clone(), input.profile.id.clone(), move |app| {
            super::validate_profile(&input.profile).map_err(|message| {
                ApiError::new(StatusCode::BAD_REQUEST, "INVALID_INPUT", message, false)
            })?;
            if let Some(password) = &input.password {
                super::validate_password(password).map_err(|message| {
                    ApiError::new(StatusCode::BAD_REQUEST, "INVALID_INPUT", message, false)
                })?;
            }
            preflight_profile(&app, &input.profile.id, ProfileOperation::Edit)?;
            let view = super::save_profile_service(
                app,
                SaveProfileInput {
                    profile: input.profile.clone(),
                    password: input.password.take(),
                    remember_password: input.remember_password,
                    expected_revision: input.expected_revision,
                },
            )?;
            serde_json::to_value(view).map_err(|e| ApiError::from_message(e.to_string()))
        })
        .await
    }
    async fn execute(
        &self,
        profile: String,
        action: openfortivpn_manager_http::v2::Action,
    ) -> Result<serde_json::Value, ApiError> {
        use openfortivpn_manager_http::v2::Action;
        super::run_profile_command(self.app.clone(), profile.clone(), move |app| {
            preflight_profile(
                &app,
                &profile,
                if action == Action::Connect {
                    ProfileOperation::Start
                } else {
                    ProfileOperation::StopOrDelete
                },
            )?;
            if action != Action::Connect {
                super::disconnect_profile_impl(app.clone(), profile.clone())
                    .map_err(ApiError::from_message)?;
                super::wait_for_profile_to_stop(&app, &profile).map_err(ApiError::from_message)?;
            }
            if action == Action::Disconnect {
                return Ok(json!({"disconnected":true}));
            }
            let instance = super::start_profile_impl(app, profile, super::StartOrigin::User)
                .map_err(ApiError::from_message)?;
            serde_json::to_value(instance).map_err(|e| ApiError::from_message(e.to_string()))
        })
        .await
    }
    async fn delete(
        &self,
        profile: String,
        expected_revision: u64,
        stop_first: bool,
    ) -> Result<(), ApiError> {
        super::run_profile_command(self.app.clone(), profile.clone(), move |app| {
            preflight_profile(&app, &profile, ProfileOperation::StopOrDelete)?;
            super::delete_profile_service(app, profile, Some(expected_revision), stop_first)
        })
        .await
    }
    async fn logs(&self) -> Result<openfortivpn_manager_core::domain::LogSnapshot, ApiError> {
        list_logs(self.app.state(), None, Some(2000)).map_err(ApiError::from_message)
    }
    async fn authentication_challenges(
        &self,
    ) -> Result<Vec<openfortivpn_manager_core::control::Challenge>, ApiError> {
        super::authentication::authentication_challenges(self.app.state())
            .map_err(ApiError::from_message)
    }
    async fn respond_to_authentication(
        &self,
        response: openfortivpn_manager_core::control::AuthResponse,
    ) -> Result<(), ApiError> {
        super::run_profile_command(self.app.clone(), response.profile_id.clone(), move |app| {
            super::authentication::respond(app, response)
        })
        .await
    }
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
    let _admin = REMOTE_ADMIN.lock().map_err(|_| "远程访问管理状态已损坏")?;
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
    let token = Arc::new(openfortivpn_manager_http::AccessToken::new(token));
    let server_token = token.clone();
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
                                token: server_token,
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
        token,
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
    let _admin = REMOTE_ADMIN.lock().map_err(|_| "远程访问管理状态已损坏")?;
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
    let _admin = REMOTE_ADMIN.lock().map_err(|_| "远程访问管理状态已损坏")?;
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
    let _admin = REMOTE_ADMIN.lock().map_err(|_| "远程访问管理状态已损坏")?;
    let settings = load_settings(&app)?;
    let token = generate_remote_token();
    // Persist first; a failed credential write must keep the old token valid.
    store_remote_token(&token)?;
    let runtime = runtime_slot()
        .lock()
        .map_err(|_| "远程访问运行状态已损坏")?;
    if let Some(runtime) = runtime.as_ref() {
        runtime
            .token
            .replace(token.clone())
            .map_err(|_| "无法更新运行中的访问令牌")?;
    }
    drop(runtime);
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
