//! One HTTP contract for desktop and headless; platform adapters implement the
//! operations, not routing, idempotency, error envelopes or cursor semantics.
use crate::ApiError;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use openfortivpn_manager_core::domain::{Capabilities, SaveProfileInput};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub trait ControlService: Send + Sync + 'static {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
    fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError>;
    fn snapshot(&self) -> impl Future<Output = Result<Value, ApiError>> + Send;
    fn save(&self, input: SaveProfileInput)
        -> impl Future<Output = Result<Value, ApiError>> + Send;
    fn execute(
        &self,
        profile: String,
        action: Action,
    ) -> impl Future<Output = Result<Value, ApiError>> + Send;
    fn delete(
        &self,
        profile: String,
        expected_revision: u64,
        stop_first: bool,
    ) -> impl Future<Output = Result<(), ApiError>> + Send;
    fn logs(
        &self,
    ) -> impl Future<Output = Result<openfortivpn_manager_core::domain::LogSnapshot, ApiError>> + Send;
    fn authentication_challenges(
        &self,
    ) -> impl Future<Output = Result<Vec<openfortivpn_manager_core::control::Challenge>, ApiError>> + Send
    {
        async { Ok(Vec::new()) }
    }
    fn respond_to_authentication(
        &self,
        _input: openfortivpn_manager_core::control::AuthResponse,
    ) -> impl Future<Output = Result<(), ApiError>> + Send {
        async {
            Err(ApiError::new(
                StatusCode::NOT_IMPLEMENTED,
                "AUTH_CHANNEL_UNAVAILABLE",
                "manager authentication channel is unavailable",
                false,
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Connect,
    Disconnect,
    Reconnect,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Operation {
    operation_id: String,
    profile_id: String,
    action: Action,
    status: &'static str,
    result: Option<Value>,
    error: Option<Value>,
    #[serde(skip)]
    key: String,
    #[serde(skip)]
    created: Instant,
}

struct ApiState<T> {
    service: Arc<T>,
    session: String,
    operations: Mutex<BTreeMap<String, Operation>>,
}

struct V2Error(ApiError);
impl From<ApiError> for V2Error {
    fn from(error: ApiError) -> Self {
        Self(error)
    }
}
impl IntoResponse for V2Error {
    fn into_response(self) -> Response {
        self.0.into_v2_response()
    }
}

pub fn router<T: ControlService>(service: Arc<T>) -> Router {
    let state = Arc::new(ApiState {
        service,
        session: uuid::Uuid::new_v4().to_string(),
        operations: Mutex::default(),
    });
    Router::new()
        .route("/snapshot", get(snapshot::<T>))
        .route("/capabilities", get(capabilities::<T>))
        .route("/profiles", post(save::<T>))
        .route("/profiles/{profile}", axum::routing::delete(delete::<T>))
        .route("/profiles/{profile}/connect", post(connect::<T>))
        .route("/profiles/{profile}/disconnect", post(disconnect::<T>))
        .route("/profiles/{profile}/reconnect", post(reconnect::<T>))
        .route("/operations/{operation}", get(operation::<T>))
        .route("/logs", get(logs::<T>))
        .route("/diagnostics", get(diagnostics::<T>))
        .route(
            "/authentication/challenges",
            get(authentication_challenges::<T>),
        )
        .route(
            "/authentication/response",
            post(authentication_response::<T>),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), guard::<T>))
        .with_state(state)
}

async fn guard<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if let Err(error) = state.service.authorize(request.headers()) {
        return error.into_v2_response();
    }
    let response = next.run(request).await;
    // Axum's extraction rejections must obey the same public error contract;
    // never include malformed request contents (potentially credentials).
    if matches!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
    ) || (response.status() == StatusCode::BAD_REQUEST
        && response
            .headers()
            .get("content-type")
            .is_none_or(|v| v != "application/json"))
    {
        return ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
            "invalid or oversized request",
            false,
        )
        .into_v2_response();
    }
    response
}

async fn capabilities<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
) -> Json<Capabilities> {
    let mut capabilities = state.service.capabilities();
    capabilities.api_versions = vec![1, 2];
    Json(capabilities)
}

async fn snapshot<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
) -> Result<Json<Value>, V2Error> {
    let snapshot = state.service.snapshot().await?;
    let revision = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&snapshot).map_err(|e| ApiError::from_message(e.to_string()))?
        )
    );
    Ok(Json(
        json!({"sessionId":state.session,"revision":revision,"snapshot":snapshot}),
    ))
}

async fn diagnostics<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
) -> Result<Json<Value>, V2Error> {
    let snapshot = state.service.snapshot().await?;
    let capabilities = serde_json::to_value(state.service.capabilities())
        .map_err(|_| ApiError::from_message("capability serialization failed".into()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(Json(openfortivpn_manager_core::diagnostics::report(
        &snapshot,
        &capabilities,
        now,
    )))
}

async fn authentication_challenges<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
) -> Result<Json<Value>, V2Error> {
    let challenges = state.service.authentication_challenges().await?;
    Ok(Json(json!({"challenges":challenges})))
}
async fn authentication_response<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    input: Result<
        Json<openfortivpn_manager_core::control::AuthResponse>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<Value>, V2Error> {
    let Json(input) = input.map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
            "malformed authentication response",
            false,
        )
    })?;
    state.service.respond_to_authentication(input).await?;
    Ok(Json(json!({"submitted":true})))
}

async fn save<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    Json(input): Json<SaveProfileInput>,
) -> Result<Json<Value>, V2Error> {
    if input.expected_revision.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
            "expectedRevision is required (0 for a new profile)",
            false,
        )
        .into());
    }
    Ok(Json(state.service.save(input).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteQuery {
    expected_revision: u64,
    #[serde(default)]
    stop_first: bool,
}
async fn delete<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    Path(profile): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<StatusCode, V2Error> {
    state
        .service
        .delete(profile, query.expected_revision, query.stop_first)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn connect<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    Path(profile): Path<String>,
    headers: HeaderMap,
) -> Result<Response, V2Error> {
    enqueue(state, profile, Action::Connect, headers).await
}
async fn disconnect<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    Path(profile): Path<String>,
    headers: HeaderMap,
) -> Result<Response, V2Error> {
    enqueue(state, profile, Action::Disconnect, headers).await
}
async fn reconnect<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    Path(profile): Path<String>,
    headers: HeaderMap,
) -> Result<Response, V2Error> {
    enqueue(state, profile, Action::Reconnect, headers).await
}

async fn enqueue<T: ControlService>(
    state: Arc<ApiState<T>>,
    profile: String,
    action: Action,
    headers: HeaderMap,
) -> Result<Response, V2Error> {
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .filter(|key| {
            !key.is_empty() && key.len() <= 128 && key.bytes().all(|b| b.is_ascii_graphic())
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "INVALID_INPUT",
                "Idempotency-Key is required (1–128 visible ASCII bytes)",
                false,
            )
        })?
        .to_string();
    if profile.len() > 128 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
            "profile ID too long",
            false,
        )
        .into());
    }
    let mut operations = state.operations.lock().await;
    operations.retain(|_, op| {
        matches!(op.status, "queued" | "running") || op.created.elapsed() < Duration::from_secs(600)
    });
    if let Some(previous) = operations.values().find(|op| op.key == key) {
        if previous.profile_id != profile || previous.action != action {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "IDEMPOTENCY_CONFLICT",
                "key already belongs to a different operation",
                false,
            )
            .into());
        }
        return Ok((StatusCode::ACCEPTED, Json(previous.clone())).into_response());
    }
    if operations.len() >= 512 {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "OPERATION_CAPACITY",
            "operation capacity reached; retry later",
            true,
        )
        .into());
    }
    let operation = Operation {
        operation_id: uuid::Uuid::new_v4().to_string(),
        profile_id: profile.clone(),
        action,
        status: "queued",
        result: None,
        error: None,
        key,
        created: Instant::now(),
    };
    operations.insert(operation.operation_id.clone(), operation.clone());
    drop(operations);
    let id = operation.operation_id.clone();
    tokio::spawn(async move {
        if let Some(op) = state.operations.lock().await.get_mut(&id) {
            op.status = "running";
        }
        let service = state.service.clone();
        let result = tokio::spawn(async move { service.execute(profile, action).await })
            .await
            .unwrap_or_else(|_| Err(ApiError::from_message("operation worker failed".into())));
        if let Some(op) = state.operations.lock().await.get_mut(&id) {
            match result {
                Ok(value) => {
                    op.status = "succeeded";
                    op.result = Some(value);
                }
                Err(error) => {
                    op.status = "failed";
                    op.error = Some(
                        json!({"code":error.code,"message":error.message,"retryable":error.retryable,"requestId":uuid::Uuid::new_v4().to_string()}),
                    );
                }
            }
        }
    });
    Ok((StatusCode::ACCEPTED, Json(operation)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn authentication_routes_authorize_and_never_echo_malformed_secrets() {
        use tower::ServiceExt;
        let app = router(Arc::new(Service::default()));
        let unauthorized = axum::http::Request::builder()
            .method("POST")
            .uri("/authentication/response")
            .header("content-type", "application/json")
            .body(axum::body::Body::from("synthetic-secret"))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(unauthorized).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let mut malformed = request("POST", "/authentication/response", None);
        malformed.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        *malformed.body_mut() =
            axum::body::Body::from(r#"{"synthetic-secret":"synthetic-secret"}"#);
        let response = app.oneshot(malformed).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!value(response)
            .await
            .to_string()
            .contains("synthetic-secret"));
    }
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    #[derive(Default)]
    struct Service {
        calls: AtomicUsize,
    }
    impl ControlService for Service {
        fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError> {
            crate::authorize(headers, "synthetic-token")
        }
        async fn snapshot(&self) -> Result<Value, ApiError> {
            Ok(json!({"profiles":[],"instances":[]}))
        }
        async fn save(&self, _: SaveProfileInput) -> Result<Value, ApiError> {
            Ok(json!({"saved":true}))
        }
        async fn execute(&self, _: String, _: Action) -> Result<Value, ApiError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"instanceId":"attempt"}))
        }
        async fn delete(&self, _: String, _: u64, _: bool) -> Result<(), ApiError> {
            Ok(())
        }
        async fn logs(&self) -> Result<openfortivpn_manager_core::domain::LogSnapshot, ApiError> {
            Ok((10..=12)
                .map(|id| {
                    std::sync::Arc::new(openfortivpn_manager_core::domain::LogEvent {
                        id,
                        instance_id: "attempt".into(),
                        stream: "stdout".into(),
                        line: "safe".into(),
                        timestamp: 0,
                    })
                })
                .collect())
        }
    }
    fn request(method: &str, path: &str, key: Option<&str>) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer synthetic-token");
        if let Some(key) = key {
            request = request.header("idempotency-key", key);
        }
        request.body(Body::empty()).unwrap()
    }
    async fn value(response: Response) -> Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn duplicate_commands_execute_once_and_scope_conflicts_are_explicit() {
        let service = Arc::new(Service::default());
        let app = router(service.clone());
        let one = app
            .clone()
            .oneshot(request("POST", "/profiles/a/connect", Some("same")))
            .await
            .unwrap();
        assert_eq!(one.status(), StatusCode::ACCEPTED);
        let one = value(one).await;
        let two = value(
            app.clone()
                .oneshot(request("POST", "/profiles/a/connect", Some("same")))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(one["operationId"], two["operationId"]);
        let conflict = app
            .clone()
            .oneshot(request("POST", "/profiles/b/connect", Some("same")))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(
            value(conflict).await["error"]["code"],
            "IDEMPOTENCY_CONFLICT"
        );
        let path = format!("/operations/{}", one["operationId"].as_str().unwrap());
        for _ in 0..100 {
            let operation = value(
                app.clone()
                    .oneshot(request("GET", &path, None))
                    .await
                    .unwrap(),
            )
            .await;
            if operation["status"] == "succeeded" {
                assert_eq!(service.calls.load(Ordering::SeqCst), 1);
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("operation did not settle");
    }

    #[tokio::test]
    async fn authentication_precedes_parsing_and_bad_bodies_never_echo_secrets() {
        let app = router(Arc::new(Service::default()));
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/profiles")
                    .body(Body::from("synthetic-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(value(unauthorized).await["error"]["code"], "UNAUTHORIZED");
        let invalid = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/profiles")
                    .header("authorization", "Bearer synthetic-token")
                    .header("content-type", "application/json")
                    .body(Body::from("synthetic-password"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let invalid = value(invalid).await;
        assert_eq!(invalid["error"]["code"], "INVALID_INPUT");
        assert!(!invalid.to_string().contains("synthetic-password"));
    }

    #[tokio::test]
    async fn logs_report_truncation_and_reject_a_previous_server_session() {
        let app = router(Arc::new(Service::default()));
        let page = value(
            app.clone()
                .oneshot(request("GET", "/logs?afterId=3&limit=2", None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(page["truncated"], true);
        assert_eq!(page["nextId"], 11);
        assert_eq!(page["logs"].as_array().unwrap().len(), 2);
        let contiguous = value(
            app.clone()
                .oneshot(request("GET", "/logs?afterId=9", None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(contiguous["truncated"], false);
        let next = format!(
            "/logs?afterId=11&sessionId={}",
            page["sessionId"].as_str().unwrap()
        );
        let next = value(
            app.clone()
                .oneshot(request("GET", &next, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(next["logs"].as_array().unwrap().len(), 1);
        let old = app
            .oneshot(request("GET", "/logs?sessionId=old", None))
            .await
            .unwrap();
        assert_eq!(old.status(), StatusCode::CONFLICT);
        assert_eq!(value(old).await["error"]["code"], "CURSOR_RESET");
    }

    #[tokio::test]
    async fn diagnostics_are_authenticated_and_have_a_versioned_allowlist() {
        let app = router(Arc::new(Service::default()));
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/diagnostics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let report = value(
            app.oneshot(request("GET", "/diagnostics", None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(report["schemaVersion"], 1);
        assert!(report.get("logs").is_some());
        assert!(report.get("snapshot").is_none());
    }
}

async fn operation<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    Path(id): Path<String>,
) -> Result<Json<Operation>, V2Error> {
    let operations = state.operations.lock().await;
    let operation = operations
        .get(&id)
        .filter(|op| {
            matches!(op.status, "queued" | "running")
                || op.created.elapsed() < Duration::from_secs(600)
        })
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "OPERATION_NOT_FOUND",
                "operation not found or expired",
                false,
            )
        })?;
    Ok(Json(operation))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogsQuery {
    session_id: Option<String>,
    #[serde(default)]
    after_id: u64,
    limit: Option<usize>,
}
async fn logs<T: ControlService>(
    State(state): State<Arc<ApiState<T>>>,
    Query(query): Query<LogsQuery>,
) -> Result<Response, V2Error> {
    if query
        .session_id
        .as_ref()
        .is_some_and(|session| session != &state.session)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "CURSOR_RESET",
            "server session changed; reload snapshot",
            false,
        )
        .into());
    }
    let all = state.service.logs().await?;
    let first = all.first().map_or(0, |log| log.id);
    let last = all.last().map_or(0, |log| log.id);
    if query.after_id > last {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "CURSOR_RESET",
            "cursor is ahead of retained logs",
            false,
        )
        .into());
    }
    let logs: Vec<_> = all
        .into_iter()
        .filter(|log| log.id > query.after_id)
        .take(query.limit.unwrap_or(400).clamp(1, 2000))
        .collect();
    let next = logs.last().map_or(query.after_id, |log| log.id);
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Page<'a> {
        session_id: &'a str,
        next_id: u64,
        truncated: bool,
        logs: openfortivpn_manager_core::domain::LogSnapshot,
    }
    let capacity = openfortivpn_manager_core::log_buffer::json_capacity(&logs) + 512;
    crate::log_json_response(
        &Page {
            session_id: &state.session,
            next_id: next,
            truncated: query.after_id > 0 && query.after_id.saturating_add(1) < first,
            logs,
        },
        capacity,
    )
    .map_err(Into::into)
}
