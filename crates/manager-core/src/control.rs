//! Private engine commands and attempt-bound authentication challenges.
//! Response frames live only in memory; they are not Debug/Serialize values.
use crate::{ControlError, ErrorCode};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn invalid(message: &str) -> ControlError {
    ControlError::new(ErrorCode::InvalidInput, message)
}
fn valid_attempt(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_digit() || matches!(c, b'a'..=b'f')
            }
        })
}
fn valid_request(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
}
pub enum Command {
    AuthResponse,
    AuthCancel,
    LeaseDecision,
    NetworkResult,
}
pub struct SecretFrame(Zeroizing<Vec<u8>>);
impl SecretFrame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
pub fn frame(
    attempt: &str,
    request: &str,
    command: Command,
    value: &str,
) -> Result<SecretFrame, ControlError> {
    if !valid_attempt(attempt)
        || !valid_request(request)
        || value.is_empty()
        || value.len() > 1024
        || value.bytes().any(|c| matches!(c, 0 | b'\n' | b'\r'))
    {
        return Err(invalid("invalid engine control frame"));
    }
    if matches!(command, Command::LeaseDecision)
        && !matches!(value, "grant" | "grant_native" | "deny")
    {
        return Err(invalid("invalid lease decision"));
    }
    if matches!(command, Command::NetworkResult)
        && !matches!(value, "applied" | "released" | "deny")
    {
        return Err(invalid("invalid network transaction result"));
    }
    let command = match command {
        Command::AuthResponse => "auth_response",
        Command::AuthCancel => "auth_cancel",
        Command::LeaseDecision => "lease_decision",
        Command::NetworkResult => "network_result",
    };
    let encoded = Zeroizing::new(STANDARD.encode(value));
    let mut result = Zeroizing::new(format!("OFV2 {attempt} {request} {command} ").into_bytes());
    result.extend_from_slice(encoded.as_bytes());
    result.push(b'\n');
    Ok(SecretFrame(result))
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub profile_id: String,
    pub attempt_id: String,
    pub request_id: String,
    pub prompt: String,
    pub expires_at_ms: u64,
    pub max_response_bytes: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthResponse {
    pub profile_id: String,
    pub attempt_id: String,
    pub request_id: String,
    pub response: String,
}
impl Drop for AuthResponse {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.response.zeroize();
    }
}
struct Pending {
    challenge: Challenge,
    generation: u64,
}
#[derive(Default)]
pub struct Challenges {
    pending: BTreeMap<String, Pending>,
    seen: BTreeMap<String, std::collections::BTreeSet<String>>,
}
impl Challenges {
    pub fn register(
        &mut self,
        challenge: Challenge,
        generation: u64,
        now_ms: u64,
    ) -> Result<(), ControlError> {
        self.expire(now_ms);
        if !valid_attempt(&challenge.attempt_id)
            || !valid_request(&challenge.request_id)
            || challenge.profile_id.is_empty()
            || challenge.profile_id.len() > 128
            || challenge.prompt.len() > 1024
            || challenge.prompt.chars().any(|c| c == '\0')
            || challenge.max_response_bytes == 0
            || challenge.max_response_bytes > 1024
            || challenge.expires_at_ms <= now_ms
            || challenge.expires_at_ms - now_ms > 120_000
        {
            return Err(invalid("invalid authentication challenge"));
        }
        if self.pending.len() >= 512 && !self.pending.contains_key(&challenge.profile_id) {
            return Err(invalid("authentication challenge capacity reached"));
        }
        if self.pending.contains_key(&challenge.profile_id) {
            return Err(ControlError::new(
                ErrorCode::ProfileBusy,
                "profile already has a pending challenge",
            ));
        }
        if self.seen.len() >= 512 && !self.seen.contains_key(&challenge.attempt_id) {
            return Err(invalid("authentication attempt capacity reached"));
        }
        let seen = self.seen.entry(challenge.attempt_id.clone()).or_default();
        if seen.len() >= 32 || !seen.insert(challenge.request_id.clone()) {
            return Err(invalid(
                "authentication challenge was already used or exceeds attempt budget",
            ));
        }
        self.pending.insert(
            challenge.profile_id.clone(),
            Pending {
                challenge,
                generation,
            },
        );
        Ok(())
    }
    pub fn list(&mut self, now_ms: u64) -> Vec<Challenge> {
        self.expire(now_ms);
        self.pending.values().map(|p| p.challenge.clone()).collect()
    }
    pub fn respond(
        &mut self,
        profile: &str,
        attempt: &str,
        generation: u64,
        request: &str,
        now_ms: u64,
        value: &str,
    ) -> Result<SecretFrame, ControlError> {
        self.expire(now_ms);
        let pending = self
            .pending
            .get(profile)
            .ok_or_else(|| invalid("authentication challenge expired or is no longer active"))?;
        if pending.generation != generation
            || pending.challenge.attempt_id != attempt
            || pending.challenge.request_id != request
        {
            return Err(invalid(
                "authentication response belongs to another attempt",
            ));
        }
        if value.len() > pending.challenge.max_response_bytes {
            return Err(invalid("authentication response exceeds challenge limit"));
        }
        let frame = frame(attempt, request, Command::AuthResponse, value)?;
        self.pending.remove(profile);
        Ok(frame)
    }
    pub fn close(&mut self, profile: &str, attempt: &str, request: &str) {
        if self
            .pending
            .get(profile)
            .is_some_and(|p| p.challenge.attempt_id == attempt && p.challenge.request_id == request)
        {
            self.pending.remove(profile);
        }
    }
    pub fn cancel_attempt(&mut self, profile: &str, attempt: &str) {
        if self
            .pending
            .get(profile)
            .is_some_and(|p| p.challenge.attempt_id == attempt)
        {
            self.pending.remove(profile);
        }
        self.seen.remove(attempt);
    }
    fn expire(&mut self, now_ms: u64) {
        self.pending
            .retain(|_, pending| pending.challenge.expires_at_ms > now_ms);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const ATTEMPT: &str = "00000000-0000-4000-8000-000000000001";
    const REQUEST: &str = "0123456789abcdef0123456789abcdef";
    fn challenge() -> Challenge {
        Challenge {
            profile_id: "one".into(),
            attempt_id: ATTEMPT.into(),
            request_id: REQUEST.into(),
            prompt: "Synthetic token prompt".into(),
            expires_at_ms: 120000,
            max_response_bytes: 64,
        }
    }
    #[test]
    fn responses_are_single_use_bound_to_attempt_generation_and_deadline() {
        let mut challenges = Challenges::default();
        challenges.register(challenge(), 7, 0).unwrap();
        assert!(challenges
            .respond("one", ATTEMPT, 8, REQUEST, 1, "synthetic-otp")
            .is_err());
        assert!(challenges
            .respond("one", ATTEMPT, 7, "different", 1, "synthetic-otp")
            .is_err());
        let bytes = challenges
            .respond("one", ATTEMPT, 7, REQUEST, 1, "synthetic-otp")
            .unwrap();
        assert_eq!(
            bytes.as_bytes(),
            format!("OFV2 {ATTEMPT} {REQUEST} auth_response c3ludGhldGljLW90cA==\n").as_bytes()
        );
        assert!(challenges
            .respond("one", ATTEMPT, 7, REQUEST, 2, "synthetic-otp")
            .is_err());
        assert!(challenges.register(challenge(), 8, 2).is_err());
        let mut later = challenge();
        later.request_id = "0123456789abcdef0123456789abcdee".into();
        challenges.register(later.clone(), 8, 2).unwrap();
        assert!(challenges
            .respond(
                "one",
                ATTEMPT,
                8,
                &later.request_id,
                120000,
                "synthetic-otp"
            )
            .is_err());
        assert!(challenges.list(120001).is_empty());
    }
    #[test]
    fn cancelling_one_profile_leaves_other_challenges_and_rejects_control_injection() {
        let mut challenges = Challenges::default();
        challenges.register(challenge(), 1, 0).unwrap();
        let mut other = challenge();
        other.profile_id = "two".into();
        other.attempt_id = "00000000-0000-4000-8000-000000000002".into();
        challenges.register(other, 1, 0).unwrap();
        challenges.cancel_attempt("one", ATTEMPT);
        assert_eq!(challenges.list(1).len(), 1);
        assert!(frame(ATTEMPT, REQUEST, Command::AuthResponse, "bad\nframe").is_err());
        assert!(frame(ATTEMPT, REQUEST, Command::LeaseDecision, "command").is_err());
        assert!(frame(ATTEMPT, "bad", Command::AuthResponse, "synthetic").is_err());
    }
}
