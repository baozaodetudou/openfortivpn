use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::manager::VpnManager;
use crate::model::{InstanceView, LogEvent, ProfileView, SaveProfileInput, Snapshot};

const INDEX: &str = include_str!("../../app/src-tauri/src/remote.html");

#[derive(Clone)]
pub struct ApiState {
    pub manager: Arc<VpnManager>,
    pub token: Arc<String>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "missing or invalid Bearer token".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "message": self.message }))).into_response()
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/profiles", get(profiles).post(save_profile))
        .route("/api/v1/instances", get(instances))
        .route("/api/v1/logs", get(logs))
        .route("/api/v1/profiles/{profile_id}/connect", post(connect))
        .route("/api/v1/profiles/{profile_id}/disconnect", post(disconnect))
        .route("/api/v1/profiles/{profile_id}/reconnect", post(reconnect))
        .route("/api/v1/profiles/{profile_id}", delete(delete_profile))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "openfortivpn-manager-headless",
        "version": crate::VERSION,
        "tls": true
    }))
}

async fn snapshot(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Snapshot>, ApiError> {
    authorize(&headers, &state.token)?;
    state
        .manager
        .snapshot()
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}

async fn profiles(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileView>>, ApiError> {
    authorize(&headers, &state.token)?;
    state
        .manager
        .profile_views()
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}

async fn save_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<SaveProfileInput>,
) -> Result<Json<ProfileView>, ApiError> {
    authorize(&headers, &state.token)?;
    state
        .manager
        .save_profile(input)
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}

async fn instances(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InstanceView>>, ApiError> {
    authorize(&headers, &state.token)?;
    Ok(Json(state.manager.instances().await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogsQuery {
    instance_id: Option<String>,
    limit: Option<usize>,
}

async fn logs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Vec<LogEvent>>, ApiError> {
    authorize(&headers, &state.token)?;
    Ok(Json(
        state
            .manager
            .logs(query.instance_id.as_deref(), query.limit.unwrap_or(400))
            .await,
    ))
}

async fn connect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<InstanceView>, ApiError> {
    authorize(&headers, &state.token)?;
    state
        .manager
        .connect(&profile_id)
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}

async fn disconnect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, &state.token)?;
    state
        .manager
        .disconnect(&profile_id)
        .await
        .map_err(ApiError::bad_request)?;
    Ok(StatusCode::ACCEPTED)
}

async fn reconnect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<InstanceView>, ApiError> {
    authorize(&headers, &state.token)?;
    state
        .manager
        .reconnect(&profile_id)
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}

async fn delete_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize(&headers, &state.token)?;
    if state
        .manager
        .delete_profile(&profile_id)
        .await
        .map_err(ApiError::bad_request)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "profile not found".to_string(),
        })
    }
}

fn authorize(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    let valid =
        presented.len() == expected.len() && presented.as_bytes().ct_eq(expected.as_bytes()).into();
    if valid {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        ),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn test_app() -> (Router, TempDir) {
        let root = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        storage.ensure_layout().unwrap();
        let manager = Arc::new(VpnManager::new(storage, root.path().join("engine")));
        (
            router(ApiState {
                manager,
                token: Arc::new("01234567890123456789012345678901".into()),
            }),
            root,
        )
    }

    #[tokio::test]
    async fn health_is_public_but_api_requires_bearer_token() {
        let (app, _root) = test_app();
        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/profiles")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/profiles")
                    .header(
                        header::AUTHORIZATION,
                        "Bearer 01234567890123456789012345678901",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let body = allowed.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"[]");
    }

    #[tokio::test]
    async fn root_serves_the_token_login_web_console() {
        let (app, _root) = test_app();
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("访问令牌"));
        assert!(body.contains("/api/v1/snapshot"));
        assert!(body.contains("sessionStorage"));
    }

    #[tokio::test]
    async fn profile_api_never_returns_vpn_password() {
        let (app, _root) = test_app();
        let request = json!({
            "profile": {
                "id": "office",
                "name": "Office",
                "host": "vpn.example.com",
                "port": 443,
                "username": "alice",
                "realm": "",
                "trustedCert": "",
                "setRoutes": true,
                "setDns": true,
                "pppdUsePeerdns": false,
                "halfInternetRoutes": false,
                "useSudo": true,
                "autoConnect": false,
                "autoReconnect": true
            },
            "password": "never-return-this",
            "rememberPassword": true
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/profiles")
                    .header(
                        header::AUTHORIZATION,
                        "Bearer 01234567890123456789012345678901",
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("never-return-this"));
        assert!(!body.contains("password\":"));
        assert!(body.contains("\"passwordStored\":true"));
    }
}
