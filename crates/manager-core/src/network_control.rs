//! Bounded engine resource handshake. An engine supplies only resource specs;
//! the manager supplies profile, generation and epoch from its owned attempt.
use crate::{
    network::{BackendCapabilities, Plan, Resource},
    ControlError, ErrorCode,
};
use serde::Deserialize;
use serde_json::Value;
use std::net::Ipv4Addr;

fn invalid() -> ControlError {
    ControlError::new(ErrorCode::InvalidInput, "invalid native network handshake")
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterfaceBinding {
    pub interface: String,
    pub index: u32,
    pub local_address: Ipv4Addr,
    pub transport_address: Ipv4Addr,
}
pub struct Admission {
    attempt: String,
    profile: String,
    generation: u64,
    request: Option<String>,
    binding: Option<InterfaceBinding>,
    resources: Vec<Resource>,
    expected: usize,
    committed: bool,
}
impl Admission {
    pub fn started(&self) -> bool {
        self.request.is_some()
    }
    pub fn new(attempt: String, profile: String, generation: u64) -> Self {
        Self {
            attempt,
            profile,
            generation,
            request: None,
            binding: None,
            resources: Vec::new(),
            expected: 0,
            committed: false,
        }
    }
    /// Returns a complete plan only at the final frame. Duplicate, reordered,
    /// cross-request and post-commit frames fail before any native mutation.
    pub fn observe(
        &mut self,
        event: &Value,
        epoch: u64,
    ) -> Result<Option<(Plan, InterfaceBinding)>, ControlError> {
        if event["protocolVersion"].as_u64() != Some(2)
            || event["attemptId"].as_str() != Some(self.attempt.as_str())
            || self.committed
        {
            return Err(invalid());
        }
        let request = event["requestId"]
            .as_str()
            .filter(|id| {
                id.len() == 32
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
            })
            .ok_or_else(invalid)?;
        match event["event"].as_str() {
            Some("network_begin") => {
                if self.request.is_some() {
                    return Err(invalid());
                }
                let count = event["resourceCount"]
                    .as_u64()
                    .filter(|n| *n <= 128)
                    .ok_or_else(invalid)? as usize;
                let binding: InterfaceBinding =
                    serde_json::from_value(event["binding"].clone()).map_err(|_| invalid())?;
                if binding.interface.is_empty()
                    || binding.interface.len() > 31
                    || !binding
                        .interface
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
                    || binding.index == 0
                    || binding.index > i32::MAX as u32
                    || binding.local_address.is_unspecified()
                    || binding.transport_address.is_unspecified()
                {
                    return Err(invalid());
                }
                self.request = Some(request.into());
                self.binding = Some(binding);
                self.expected = count;
                Ok(None)
            }
            Some("network_resource") => {
                if self.request.as_deref() != Some(request)
                    || event["ordinal"].as_u64() != Some(self.resources.len() as u64)
                    || self.resources.len() >= self.expected
                {
                    return Err(invalid());
                }
                let resource: Resource =
                    serde_json::from_value(event["resource"].clone()).map_err(|_| invalid())?;
                self.resources.push(resource);
                Ok(None)
            }
            Some("network_commit") => {
                if self.request.as_deref() != Some(request) || self.resources.len() != self.expected
                {
                    return Err(invalid());
                }
                let binding = self.binding.clone().ok_or_else(invalid)?;
                let plan = Plan {
                    attempt_id: self.attempt.clone(),
                    profile_id: self.profile.clone(),
                    generation: self.generation,
                    network_epoch: epoch,
                    resources: self.resources.clone(),
                };
                plan.validate(BackendCapabilities { split_dns: true })?;
                for resource in &plan.resources {
                    match resource {
                        Resource::Route(route) => {
                            if route.interface != binding.interface
                                || route.gateway.is_some()
                                || route.gateway_exception
                                || route.metric != 0
                            {
                                return Err(invalid());
                            }
                            let (ip, bits) =
                                route.destination.split_once('/').ok_or_else(invalid)?;
                            let address: Ipv4Addr = ip.parse().map_err(|_| invalid())?;
                            let bits: u32 = bits.parse().map_err(|_| invalid())?;
                            let mask = if bits == 0 {
                                0
                            } else {
                                u32::MAX << (32 - bits)
                            };
                            // Default/full tunnel requires a separate pre-adapter
                            // physical gateway exception transaction. This version
                            // supports split routes that preserve the transport.
                            if bits == 0
                                || u32::from(binding.transport_address) & mask == u32::from(address)
                            {
                                return Err(invalid());
                            }
                        }
                        Resource::Dns(dns)
                            if dns.interface != binding.interface || dns.domains.is_empty() =>
                        {
                            return Err(invalid())
                        }
                        Resource::Dns(_) => {}
                    }
                }
                self.committed = true;
                Ok(Some((plan, binding)))
            }
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const A: &str = "00000000-0000-4000-8000-000000000001";
    const R: &str = "0123456789abcdef0123456789abcdef";
    fn event(name: &str) -> Value {
        json!({"protocolVersion":2,"attemptId":A,"requestId":R,"event":name})
    }
    fn begin(count: u64) -> Value {
        let mut e = event("network_begin");
        e["resourceCount"] = json!(count);
        e["binding"] = json!({"interface":"ppp0","index":12,"localAddress":"10.1.1.2","transportAddress":"192.0.2.9"});
        e
    }
    fn item(cidr: &str, ordinal: u64) -> Value {
        let mut e = event("network_resource");
        e["ordinal"] = json!(ordinal);
        e["resource"] = json!({"kind":"route","spec":{"destination":cidr,"gateway":null,"interface":"ppp0","metric":0,"gatewayException":false}});
        e
    }
    #[test]
    fn only_a_complete_bound_ordered_plan_can_reach_the_privileged_worker() {
        let mut a = Admission::new(A.into(), "profile-owned-by-manager".into(), 17);
        assert!(a.observe(&begin(2), 9).unwrap().is_none());
        assert!(a.observe(&item("10.0.0.0/8", 0), 9).unwrap().is_none());
        assert!(a.observe(&event("network_commit"), 9).is_err());
        assert!(a.observe(&item("172.16.0.0/12", 1), 9).unwrap().is_none());
        let (plan, binding) = a.observe(&event("network_commit"), 9).unwrap().unwrap();
        assert_eq!(plan.profile_id, "profile-owned-by-manager");
        assert_eq!(plan.generation, 17);
        assert_eq!(plan.network_epoch, 9);
        assert_eq!(binding.index, 12);
        assert!(a.observe(&event("network_commit"), 9).is_err());
    }
    #[test]
    fn malformed_cross_attempt_and_unsafe_transport_plans_are_rejected() {
        for cidr in ["0.0.0.0/0", "192.0.2.0/24", "10.0.0.1/8"] {
            let mut a = Admission::new(A.into(), "profile".into(), 1);
            a.observe(&begin(1), 0).unwrap();
            a.observe(&item(cidr, 0), 0).unwrap();
            assert!(a.observe(&event("network_commit"), 0).is_err());
        }
        let mut a = Admission::new(A.into(), "profile".into(), 1);
        assert!(a.observe(&begin(129), 0).is_err());
        a.observe(&begin(1), 0).unwrap();
        assert!(a.observe(&item("10.0.0.0/8", 1), 0).is_err());
        let mut wrong = item("10.0.0.0/8", 0);
        wrong["attemptId"] = json!("obsolete");
        assert!(a.observe(&wrong, 0).is_err());
        wrong = item("10.0.0.0/8", 0);
        wrong["requestId"] = json!("ffffffffffffffffffffffffffffffff");
        assert!(a.observe(&wrong, 0).is_err());
    }
}
