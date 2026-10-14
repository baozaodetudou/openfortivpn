//! Process-independent supervision rules. Platform adapters own the child and
//! only call `reaped` after wait and output draining have actually completed.
use crate::{protocol::EventCursor, ControlError};
use serde_json::Value;

#[derive(Default)]
pub struct EngineLifecycle {
    cursor: EventCursor,
    protocol_v2: bool,
    network_pending: bool,
    cleanup_failed: bool,
    permanent_failure: bool,
    attempt_id: Option<String>,
    require_identity: bool,
}

impl EngineLifecycle {
    pub fn for_attempt(attempt: &str, require_identity: bool) -> Self {
        Self {
            attempt_id: Some(attempt.into()),
            require_identity,
            ..Default::default()
        }
    }
    pub fn observe(&mut self, event: &Value) -> Result<bool, ControlError> {
        if self.attempt_id.as_ref().is_some_and(|expected| {
            event["attemptId"].as_str().is_some_and(|id| id != expected)
                || (self.require_identity && event["attemptId"].as_str() != Some(expected.as_str()))
        }) {
            self.require_recovery();
            return Err(ControlError::new(
                crate::ErrorCode::InvalidInput,
                "engine event belongs to another attempt",
            ));
        }
        let protocol = event["protocolVersion"].as_u64().unwrap_or(1);
        if self.require_identity && protocol != 2 {
            self.require_recovery();
            return Err(ControlError::new(
                crate::ErrorCode::InvalidInput,
                "private control requires event protocol v2",
            ));
        }
        match self.cursor.accept(protocol, event["seq"].as_u64()) {
            Ok(false) => return Ok(false),
            Err(error) => {
                self.require_recovery();
                return Err(error);
            }
            Ok(true) => {}
        }
        self.protocol_v2 |= protocol == 2;
        let name = event["event"].as_str().unwrap_or_default();
        let phase = event["state"].as_str().unwrap_or_default();
        if name == "tunnel_up"
            || matches!(
                phase,
                "configuring" | "creating_adapter" | "tunneling" | "negotiating" | "connected"
            )
        {
            self.network_pending = true;
        }
        if name == "cleanup_result" {
            // A failure is sticky for this attempt. A later success cannot
            // erase a failed rollback or an incomplete output stream.
            self.cleanup_failed |= event["success"].as_bool() != Some(true);
            self.network_pending = self.cleanup_failed;
        }
        self.permanent_failure |= name == "cert_error"
            || (name == "error"
                && (event["retryable"].as_bool() == Some(false)
                    || event["category"].as_str() == Some("auth")));
        Ok(true)
    }

    pub fn reaped(&mut self, output_complete: bool, forced: bool) -> bool {
        if !output_complete || forced || (self.protocol_v2 && self.network_pending) {
            self.require_recovery();
        }
        !self.cleanup_failed
    }

    pub fn cleanup_failed(&self) -> bool {
        self.cleanup_failed
    }
    pub fn accepts_legacy_readiness(&self) -> bool {
        !self.require_identity && !self.protocol_v2 && !self.retry_blocked()
    }

    pub fn retry_blocked(&self) -> bool {
        self.permanent_failure || self.cleanup_failed
    }

    pub fn require_recovery(&mut self) {
        self.cleanup_failed = true;
        self.permanent_failure = true;
    }

    /// Adapters must independently prove no owned child remains and require
    /// the operator's acknowledgement of legacy network recovery.
    pub fn acknowledge_recovery(&mut self) {
        self.cleanup_failed = false;
        self.network_pending = false;
    }
}

/// A monotonic retry deadline, independent of a real clock. Generations bind
/// deadlines to user intent, so stop/reconnect invalidate all old timers.
#[derive(Default)]
pub struct RetryTimer {
    deadline: Option<(u64, u64)>,
}

impl RetryTimer {
    pub fn schedule(&mut self, generation: u64, now_ms: u64, delay_ms: u64) {
        self.deadline = Some((generation, now_ms.saturating_add(delay_ms)));
    }
    pub fn cancel(&mut self) {
        self.deadline = None;
    }
    pub fn take_due(&mut self, generation: u64, now_ms: u64) -> bool {
        match self.deadline {
            Some((scheduled, _)) if scheduled != generation => {
                self.cancel();
                false
            }
            Some((_, deadline)) if now_ms >= deadline => {
                self.cancel();
                true
            }
            _ => false,
        }
    }
}

pub fn retry_delay_seconds(attempt: u32) -> u64 {
    (3_u64.saturating_mul(1_u64 << attempt.saturating_sub(1).min(4))).min(30)
}

pub fn exit_retryable(code: Option<i32>) -> bool {
    // Match the C engine's documented typed exit values; legacy failure 1
    // remains transient unless its event stream supplied a permanent reason.
    matches!(code, Some(1 | 10 | 11 | 41))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn private_events_must_match_the_bound_attempt_before_readiness_or_cleanup() {
        for id in [Some("obsolete"), None] {
            let mut state = EngineLifecycle::for_attempt("current", true);
            let mut event = json!({"protocolVersion":2,"seq":1,"event":"tunnel_up"});
            if let Some(id) = id {
                event["attemptId"] = json!(id);
            }
            assert!(state.observe(&event).is_err());
            assert!(state.cleanup_failed());
            assert!(state.retry_blocked());
        }
        let mut state = EngineLifecycle::for_attempt("current", true);
        assert!(state.observe(&json!({"protocolVersion":2,"attemptId":"current","seq":1,"event":"state_change","state":"authenticating"})).unwrap());
    }
    #[test]
    fn private_or_v2_attempt_never_accepts_text_readiness_or_protocol_downgrade() {
        let mut private = EngineLifecycle::for_attempt("current", true);
        assert!(!private.accepts_legacy_readiness());
        assert!(private
            .observe(&json!({"attemptId":"current","event":"tunnel_up"}))
            .is_err());
        let mut legacy = EngineLifecycle::default();
        assert!(legacy.accepts_legacy_readiness());
        legacy
            .observe(&json!({"protocolVersion":2,"seq":1,"event":"state_change"}))
            .unwrap();
        assert!(!legacy.accepts_legacy_readiness());
    }
    #[test]
    fn cleanup_must_finish_after_readiness_and_failures_are_sticky() {
        let mut state = EngineLifecycle::default();
        state
            .observe(
                &json!({"protocolVersion":2,"seq":1,"event":"state_change","state":"configuring"}),
            )
            .unwrap();
        state
            .observe(&json!({"protocolVersion":2,"seq":2,"event":"tunnel_up"}))
            .unwrap();
        assert!(!state.reaped(true, false));
        state
            .observe(&json!({"protocolVersion":2,"seq":3,"event":"cleanup_result","success":true}))
            .unwrap();
        assert!(!state.reaped(true, false));
        state.acknowledge_recovery();
        assert!(state.reaped(true, false));
    }
    #[test]
    fn successful_cleanup_and_partial_output_are_distinct() {
        let mut state = EngineLifecycle::default();
        state
            .observe(&json!({"protocolVersion":2,"seq":1,"event":"tunnel_up"}))
            .unwrap();
        state
            .observe(&json!({"protocolVersion":2,"seq":2,"event":"cleanup_result","success":true}))
            .unwrap();
        assert!(state.reaped(true, false));
        assert!(!state.reaped(false, false));
    }
    #[test]
    fn fake_clock_never_retries_cancelled_or_obsolete_intent() {
        let mut timer = RetryTimer::default();
        for generation in 1..=1000 {
            timer.schedule(generation, 100, 3000);
            assert!(!timer.take_due(generation, 3099));
            if generation % 2 == 0 {
                timer.cancel();
            } else {
                assert!(!timer.take_due(generation + 1, 3100));
            }
            assert!(!timer.take_due(generation, 100_000));
        }
        timer.schedule(1001, 100, 3000);
        assert!(timer.take_due(1001, 3100));
        assert!(!timer.take_due(1001, 3100));
    }
    #[test]
    fn auth_tls_config_and_network_mutation_errors_do_not_retry() {
        for code in [12, 13, 20, 21, 22, 23, 30, 40, 50, 60] {
            assert!(!exit_retryable(Some(code)));
        }
        for code in [1, 10, 11, 41] {
            assert!(exit_retryable(Some(code)));
        }
    }
}
