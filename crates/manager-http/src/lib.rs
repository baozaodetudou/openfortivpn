use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use openfortivpn_manager_core::{ControlError, ErrorCode};
use serde_json::json;
use subtle::ConstantTimeEq;
pub mod v2;

/// JSON responses for bounded log payloads avoid intermediate Value copies and
/// geometric buffer growth; the bytes are owned by the HTTP response.
pub fn log_json_response<T: serde::Serialize>(
    value: &T,
    capacity: usize,
) -> Result<Response, ApiError> {
    let lease = openfortivpn_manager_core::json_buffer::log_buffers()
        .encode(value, capacity)
        .map_err(|_| ApiError::from_message("log response serialization failed".into()))?;
    let bytes = bytes::Bytes::from_owner(lease);
    Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}
pub fn logs_response(
    logs: openfortivpn_manager_core::domain::LogSnapshot,
) -> Result<Response, ApiError> {
    let capacity = openfortivpn_manager_core::log_buffer::json_capacity(&logs);
    log_json_response(&logs, capacity)
}

/// The running server shares this value with the local administration adapter.
/// Rotation affects the next authorization without restarting HTTP or VPNs.
#[derive(Default)]
pub struct AccessToken(std::sync::RwLock<zeroize::Zeroizing<String>>);
impl AccessToken {
    pub fn new(token: String) -> Self {
        Self(std::sync::RwLock::new(zeroize::Zeroizing::new(token)))
    }
    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let expected = self.0.read().map_err(|_| ApiError::unauthorized())?;
        authorize(headers, &expected)
    }
    pub fn replace(&self, token: String) -> Result<(), ApiError> {
        let token = zeroize::Zeroizing::new(token);
        if token.is_empty() {
            return Err(ApiError::unauthorized());
        }
        *self.0.write().map_err(|_| ApiError::unauthorized())? = token;
        Ok(())
    }
}

pub fn authorize(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !expected.is_empty()
        && presented.len() == expected.len()
        && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
    {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

#[derive(Clone, Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
}

impl From<String> for ApiError {
    fn from(message: String) -> Self {
        Self::from_message(message)
    }
}
impl From<&str> for ApiError {
    fn from(message: &str) -> Self {
        Self::from_message(message.into())
    }
}

impl From<ControlError> for ApiError {
    fn from(error: ControlError) -> Self {
        Self::from_error(error.into())
    }
}

impl ApiError {
    pub fn from_message(message: String) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            message,
            false,
        )
    }
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "missing or invalid Bearer token",
            false,
        )
    }
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retryable,
        }
    }
    pub fn from_error(error: anyhow::Error) -> Self {
        let (status, code, retryable) = error
            .downcast_ref::<ControlError>()
            .map(|error| match error.code {
                ErrorCode::InvalidInput => (StatusCode::BAD_REQUEST, "INVALID_INPUT", false),
                ErrorCode::ProfileNotFound => (StatusCode::NOT_FOUND, "PROFILE_NOT_FOUND", false),
                ErrorCode::ProfileBusy => (StatusCode::CONFLICT, "PROFILE_BUSY", true),
                ErrorCode::NetworkConflict => (StatusCode::CONFLICT, "NETWORK_CONFLICT", true),
                ErrorCode::RevisionConflict => (StatusCode::CONFLICT, "REVISION_CONFLICT", false),
                ErrorCode::ShuttingDown => (StatusCode::SERVICE_UNAVAILABLE, "SHUTTING_DOWN", true),
                ErrorCode::RecoveryRequired => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RECOVERY_REQUIRED",
                    false,
                ),
            })
            .unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", false));
        Self::new(status, code, error.to_string(), retryable)
    }
    pub fn into_v2_response(self) -> Response {
        (self.status, Json(json!({"error": {"code":self.code,"message":self.message,"retryable":self.retryable,"requestId":uuid::Uuid::new_v4().to_string()}}))).into_response()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Preserve both existing v1 spellings while adding stable metadata.
        (self.status, Json(json!({"error":self.message,"message":self.message,"code":self.code,"retryable":self.retryable,"requestId":uuid::Uuid::new_v4().to_string()}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn response_bytes_remain_owned_until_every_slow_reader_drops_them() {
        use http_body_util::BodyExt;
        use openfortivpn_manager_core::domain::LogEvent;
        let logs = |line: &str| {
            vec![std::sync::Arc::new(LogEvent {
                id: 1,
                instance_id: "attempt".into(),
                stream: "stdout".into(),
                line: line.into(),
                timestamp: 2,
            })]
        };
        let first = logs_response(logs("original")).unwrap();
        assert_eq!(first.headers()[header::CONTENT_TYPE], "application/json");
        let held = first.into_body().collect().await.unwrap().to_bytes();
        let slow_reader = held.clone();
        drop(held);
        for _ in 0..100 {
            let next = logs_response(logs("replacement")).unwrap();
            let bytes = next.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()[0]["line"],
                "replacement"
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&slow_reader).unwrap()[0]["line"],
                "original"
            );
        }
    }

    #[test]
    fn rotation_revokes_old_tokens_on_every_existing_server_clone() {
        let token = std::sync::Arc::new(AccessToken::new("synthetic-old".into()));
        let server = token.clone();
        let headers = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            headers
        };
        assert!(server.authorize(&headers("Bearer synthetic-old")).is_ok());
        token.replace("synthetic-new".into()).unwrap();
        assert!(server.authorize(&headers("Bearer synthetic-old")).is_err());
        assert!(server.authorize(&headers("Bearer synthetic-new")).is_ok());
        assert!(token.replace(String::new()).is_err());
        assert!(server.authorize(&headers("Bearer synthetic-new")).is_ok());
    }
    #[test]
    fn typed_conflicts_do_not_depend_on_message_language() {
        for message in ["停止中", "stopping", "arbitrary text"] {
            let error =
                ApiError::from_error(ControlError::new(ErrorCode::ProfileBusy, message).into());
            assert_eq!(error.status, StatusCode::CONFLICT);
            assert_eq!(error.code, "PROFILE_BUSY");
        }
        assert_eq!(
            ApiError::from_error(anyhow::anyhow!("internal failure")).status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
    #[test]
    fn empty_or_wrong_tokens_are_never_authorized() {
        let mut headers = HeaderMap::new();
        assert!(authorize(&headers, "").is_err());
        headers.insert(header::AUTHORIZATION, "Bearer synthetic".parse().unwrap());
        assert!(authorize(&headers, "synthetic").is_ok());
        assert!(authorize(&headers, "different").is_err());
    }
}
