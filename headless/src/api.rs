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

use crate::manager::VpnManager;
use crate::model::{InstanceView, ProfileView, SaveProfileInput, Snapshot};

const CLIENT: &str = include_str!("../../web/remote-client.js");
const INDEX: &str = include_str!("../../app/src-tauri/src/remote.html");

#[derive(Clone)]
pub struct ApiState {
    pub manager: Arc<VpnManager>,
    pub token: Arc<String>,
    pub auth_storage: Option<crate::storage::Storage>,
}

use openfortivpn_manager_http::{authorize, ApiError};

fn authorize_state(headers: &HeaderMap, state: &ApiState) -> Result<(), ApiError> {
    if let Some(storage) = &state.auth_storage {
        let token = storage
            .read_access_token()
            .map_err(|_| ApiError::unauthorized())?;
        authorize(headers, &token)
    } else {
        authorize(headers, &state.token)
    }
}

pub fn router(state: ApiState) -> Router {
    let v2 = openfortivpn_manager_http::v2::router(Arc::new(state.clone()));
    Router::new()
        .route("/", get(index))
        .route("/remote-client.js", get(client))
        .route("/health", get(health))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/profiles", get(profiles).post(save_profile))
        .route("/api/v1/instances", get(instances))
        .route("/api/v1/logs", get(logs))
        .route("/api/v1/profiles/{profile_id}/connect", post(connect))
        .route("/api/v1/profiles/{profile_id}/disconnect", post(disconnect))
        .route("/api/v1/profiles/{profile_id}/reconnect", post(reconnect))
        .route("/api/v1/profiles/{profile_id}", delete(delete_profile))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
        .nest("/api/v2", v2)
        .layer(middleware::from_fn(security_headers))
}

impl openfortivpn_manager_http::v2::ControlService for ApiState {
    fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        authorize_state(headers, self)
    }
    async fn snapshot(&self) -> Result<serde_json::Value, ApiError> {
        let mut snapshot = serde_json::to_value(
            self.manager
                .snapshot()
                .await
                .map_err(ApiError::from_error)?,
        )
        .map_err(|e| ApiError::from_message(e.to_string()))?;
        snapshot["runJournal"] = serde_json::to_value(
            self.manager
                .recovery_records()
                .map_err(ApiError::from_error)?,
        )
        .map_err(|e| ApiError::from_message(e.to_string()))?;
        Ok(snapshot)
    }
    async fn save(&self, input: SaveProfileInput) -> Result<serde_json::Value, ApiError> {
        let profile = self
            .manager
            .save_profile(input)
            .await
            .map_err(ApiError::from_error)?;
        serde_json::to_value(profile).map_err(|e| ApiError::from_message(e.to_string()))
    }
    async fn execute(
        &self,
        profile: String,
        action: openfortivpn_manager_http::v2::Action,
    ) -> Result<serde_json::Value, ApiError> {
        use openfortivpn_manager_http::v2::Action;
        if !self
            .manager
            .profile_views()
            .await
            .map_err(ApiError::from_error)?
            .iter()
            .any(|p| p.profile.id == profile)
        {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "PROFILE_NOT_FOUND",
                "profile not found",
                false,
            ));
        }
        let result = match action {
            Action::Connect => serde_json::to_value(
                self.manager
                    .connect(&profile)
                    .await
                    .map_err(ApiError::from_error)?,
            ),
            Action::Reconnect => serde_json::to_value(
                self.manager
                    .reconnect(&profile)
                    .await
                    .map_err(ApiError::from_error)?,
            ),
            Action::Disconnect => {
                self.manager
                    .disconnect(&profile)
                    .await
                    .map_err(ApiError::from_error)?;
                Ok(json!({"disconnected":true}))
            }
        };
        result.map_err(|e| ApiError::from_message(e.to_string()))
    }
    async fn delete(
        &self,
        profile: String,
        expected_revision: u64,
        stop_first: bool,
    ) -> Result<(), ApiError> {
        if self
            .manager
            .delete_profile_expected(&profile, Some(expected_revision), stop_first)
            .await
            .map_err(ApiError::from_error)?
        {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "PROFILE_NOT_FOUND",
                "profile not found",
                false,
            ))
        }
    }
    async fn logs(&self) -> Result<openfortivpn_manager_core::domain::LogSnapshot, ApiError> {
        Ok(self.manager.logs(None, 2000).await)
    }
    async fn authentication_challenges(
        &self,
    ) -> Result<Vec<openfortivpn_manager_core::control::Challenge>, ApiError> {
        Ok(self.manager.authentication_challenges().await)
    }
    async fn respond_to_authentication(
        &self,
        input: openfortivpn_manager_core::control::AuthResponse,
    ) -> Result<(), ApiError> {
        self.manager
            .respond_to_authentication(input)
            .await
            .map_err(ApiError::from_error)
    }
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn client() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        CLIENT,
    )
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
    authorize_state(&headers, &state)?;
    state
        .manager
        .snapshot()
        .await
        .map(Json)
        .map_err(ApiError::from_error)
}

async fn capabilities(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<openfortivpn_manager_core::domain::Capabilities>, ApiError> {
    authorize_state(&headers, &state)?;
    Ok(Json(
        openfortivpn_manager_core::domain::Capabilities::default(),
    ))
}

async fn profiles(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileView>>, ApiError> {
    authorize_state(&headers, &state)?;
    state
        .manager
        .profile_views()
        .await
        .map(Json)
        .map_err(ApiError::from_error)
}

async fn save_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<SaveProfileInput>,
) -> Result<Json<ProfileView>, ApiError> {
    authorize_state(&headers, &state)?;
    state
        .manager
        .save_profile(input)
        .await
        .map(Json)
        .map_err(ApiError::from_error)
}

async fn instances(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InstanceView>>, ApiError> {
    authorize_state(&headers, &state)?;
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
) -> Result<axum::response::Response, ApiError> {
    authorize_state(&headers, &state)?;
    openfortivpn_manager_http::logs_response(
        state
            .manager
            .logs(query.instance_id.as_deref(), query.limit.unwrap_or(400))
            .await,
    )
}

async fn connect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<InstanceView>, ApiError> {
    authorize_state(&headers, &state)?;
    state
        .manager
        .connect(&profile_id)
        .await
        .map(Json)
        .map_err(ApiError::from_error)
}

async fn disconnect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize_state(&headers, &state)?;
    state
        .manager
        .disconnect(&profile_id)
        .await
        .map_err(ApiError::from_error)?;
    Ok(StatusCode::ACCEPTED)
}

async fn reconnect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<Json<InstanceView>, ApiError> {
    authorize_state(&headers, &state)?;
    state
        .manager
        .reconnect(&profile_id)
        .await
        .map(Json)
        .map_err(ApiError::from_error)
}

async fn delete_profile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize_state(&headers, &state)?;
    if state
        .manager
        .delete_profile(&profile_id)
        .await
        .map_err(ApiError::from_error)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "PROFILE_NOT_FOUND",
            "profile not found",
            false,
        ))
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
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'",
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
                auth_storage: None,
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
        assert!(body.contains("/remote-client.js"));
        assert!(CLIENT.contains("/api/v1/snapshot"));
        assert!(CLIENT.contains("sessionStorage"));
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

    #[tokio::test]
    async fn disk_token_rotation_invalidates_old_token_without_stopping_manager() {
        let root = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        let old_token = storage.rotate_token().unwrap();
        let manager = Arc::new(VpnManager::new(storage.clone(), root.path().join("engine")));
        let app = router(ApiState {
            manager: manager.clone(),
            token: Arc::new(old_token.clone()),
            auth_storage: Some(storage.clone()),
        });
        let request = |token: &str| {
            Request::builder()
                .uri("/api/v1/profiles")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(request(&old_token))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let new_token = storage.rotate_token().unwrap();
        assert_eq!(
            app.clone()
                .oneshot(request(&old_token))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.oneshot(request(&new_token)).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(manager.instances().await.is_empty());
    }

    #[tokio::test]
    async fn invalid_profile_uses_a_typed_400_envelope() {
        let (app, _root) = test_app();
        let response = app.oneshot(Request::builder().method("POST").uri("/api/v1/profiles")
            .header(header::AUTHORIZATION, "Bearer 01234567890123456789012345678901")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"profile":{"id":"bad","name":"Bad","host":"vpn.example.com","username":"a".repeat(65)}}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["code"], "INVALID_INPUT");
        assert_eq!(value["error"], value["message"]);
    }

    #[tokio::test]
    async fn v2_revisions_survive_restart_and_reject_stale_changes() {
        let (app, root) = test_app();
        let request = |revision, name| {
            Request::builder().method("POST").uri("/api/v2/profiles")
            .header(header::AUTHORIZATION, "Bearer 01234567890123456789012345678901")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"profile":{"id":"office","name":name,"host":"vpn.example.com","username":"test"},"password":"synthetic-secret","expectedRevision":revision}).to_string())).unwrap()
        };
        let first = app.clone().oneshot(request(0, "Initial")).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first: serde_json::Value =
            serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(first["profile"]["revision"], 1);
        assert_eq!(
            app.clone()
                .oneshot(request(1, "New"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let stale = app.oneshot(request(1, "Stale")).await.unwrap();
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let stale: serde_json::Value =
            serde_json::from_slice(&stale.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(stale["error"]["code"], "REVISION_CONFLICT");
        let storage = crate::storage::Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        let loaded = storage.load_profiles().unwrap();
        assert_eq!(loaded["office"].name, "New");
        assert_eq!(loaded["office"].revision, 2);
    }
}
