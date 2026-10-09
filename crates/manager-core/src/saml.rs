//! One-shot browser callbacks. A legacy gateway redirect without the state in
//! this exact path cannot be accepted as a manager-associated SAML response.
use crate::{ControlError, ErrorCode};
use std::net::IpAddr;
use zeroize::Zeroizing;
pub struct SessionId(Zeroizing<String>);
impl SessionId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
pub struct CallbackBinding {
    attempt: String,
    generation: u64,
    path: String,
    expires_at_ms: u64,
    consumed: bool,
}
fn invalid() -> ControlError {
    ControlError::new(
        ErrorCode::InvalidInput,
        "SAML callback is invalid, expired or belongs to another attempt",
    )
}
impl CallbackBinding {
    /// State must come from a cryptographically secure random source in the
    /// trusted launcher. It is never supplied by an unauthenticated callback.
    pub fn new(
        attempt: &str,
        generation: u64,
        state: &str,
        now_ms: u64,
        timeout_ms: u64,
    ) -> Result<Self, ControlError> {
        if attempt.len() != 36
            || !attempt.bytes().enumerate().all(|(i, c)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    c == b'-'
                } else {
                    c.is_ascii_digit() || matches!(c, b'a'..=b'f')
                }
            })
            || state.len() != 64
            || !state
                .bytes()
                .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
            || timeout_ms == 0
            || timeout_ms > 180000
        {
            return Err(invalid());
        }
        Ok(Self {
            attempt: attempt.into(),
            generation,
            path: format!("/authentication/saml/{attempt}/{state}"),
            expires_at_ms: now_ms.saturating_add(timeout_ms),
            consumed: false,
        })
    }
    /// Put this path in a gateway-supported redirect URL, never in diagnostics.
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn cancel(&mut self) {
        self.consumed = true;
    }
    pub fn accept(
        &mut self,
        peer: IpAddr,
        method: &str,
        target: &str,
        active_attempt: &str,
        active_generation: u64,
        now_ms: u64,
    ) -> Result<SessionId, ControlError> {
        if self.consumed
            || now_ms >= self.expires_at_ms
            || !peer.is_loopback()
            || method != "GET"
            || target.len() > 1024
            || self.attempt != active_attempt
            || self.generation != active_generation
        {
            return Err(invalid());
        }
        let (path, query) = target.split_once('?').ok_or_else(invalid)?;
        let token = query.strip_prefix("id=").ok_or_else(invalid)?;
        if path != self.path
            || token.is_empty()
            || token.len() > 128
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(invalid());
        }
        self.consumed = true;
        Ok(SessionId(Zeroizing::new(token.into())))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const ATTEMPT: &str = "00000000-0000-4000-8000-000000000001";
    fn binding() -> CallbackBinding {
        CallbackBinding::new(ATTEMPT, 7, &"ab".repeat(32), 0, 120000).unwrap()
    }
    #[test]
    fn callbacks_require_loopback_exact_path_method_state_and_live_generation() {
        let mut binding = binding();
        let target = format!("{}?id=synthetic-session", binding.path());
        for (peer, method, path, attempt, generation) in [
            ("192.0.2.1", "GET", target.as_str(), ATTEMPT, 7),
            ("127.0.0.1", "POST", target.as_str(), ATTEMPT, 7),
            ("127.0.0.1", "GET", "/?id=synthetic-session", ATTEMPT, 7),
            ("127.0.0.1", "GET", target.as_str(), "old-attempt", 7),
            ("127.0.0.1", "GET", target.as_str(), ATTEMPT, 8),
        ] {
            assert!(binding
                .accept(peer.parse().unwrap(), method, path, attempt, generation, 1)
                .is_err());
        }
        let session = binding
            .accept("::1".parse().unwrap(), "GET", &target, ATTEMPT, 7, 1)
            .unwrap();
        assert_eq!(session.as_str(), "synthetic-session");
        assert!(binding
            .accept("127.0.0.1".parse().unwrap(), "GET", &target, ATTEMPT, 7, 2)
            .is_err());
    }
    #[test]
    fn expiry_cancellation_and_request_injection_never_yield_a_session() {
        for token in [
            "",
            "good&id=other",
            "bad%0a",
            "bad\n",
            "bad#fragment",
            "id=wrong",
        ] {
            let mut binding = binding();
            let target = format!("{}?id={token}", binding.path());
            assert!(binding
                .accept("127.0.0.1".parse().unwrap(), "GET", &target, ATTEMPT, 7, 1)
                .is_err());
        }
        let mut expired = binding();
        let target = format!("{}?id=synthetic", expired.path());
        assert!(expired
            .accept(
                "127.0.0.1".parse().unwrap(),
                "GET",
                &target,
                ATTEMPT,
                7,
                120000
            )
            .is_err());
        let mut cancelled = binding();
        cancelled.cancel();
        assert!(cancelled
            .accept("127.0.0.1".parse().unwrap(), "GET", &target, ATTEMPT, 7, 1)
            .is_err());
    }
}
