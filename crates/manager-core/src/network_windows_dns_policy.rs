//! Platform-independent NRPT policy checks. The command transport is Windows
//! only; these conflict/ownership checks run in the ordinary core test suite.
use crate::{network::Dns, ControlError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::Ipv4Addr};

pub(crate) const COMMENT: &str = "openfortivpn-manager scoped-dns v1";
pub(crate) fn recovery() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "Windows scoped DNS requires recovery",
    )
}
fn conflict() -> ControlError {
    ControlError::new(
        ErrorCode::NetworkConflict,
        "an existing NRPT policy overlaps the VPN DNS domains",
    )
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Desired {
    pub luid: u64,
    pub namespaces: Vec<String>,
    pub servers: Vec<String>,
    pub display_name: String,
    pub comment: String,
}
fn domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
pub(crate) fn desired(dns: &Dns, luid: u64) -> Result<Desired, ControlError> {
    if luid == 0
        || dns.domains.is_empty()
        || dns.domains.len() > 32
        || dns.servers.is_empty()
        || dns.servers.len() > 4
        || dns.domains.iter().any(|v| !domain(v))
        || dns.servers.iter().any(|v| {
            v.is_unspecified() || v.is_loopback() || v.is_multicast() || *v == Ipv4Addr::BROADCAST
        })
    {
        return Err(ControlError::new(
            ErrorCode::InvalidInput,
            "Windows DNS requires scoped suffixes and VPN name servers",
        ));
    }
    let mut namespaces: Vec<_> = dns.domains.iter().map(|v| format!(".{v}")).collect();
    namespaces.sort();
    namespaces.dedup();
    let mut servers: Vec<_> = dns.servers.iter().map(ToString::to_string).collect();
    servers.sort();
    servers.dedup();
    if namespaces.len() != dns.domains.len() || servers.len() != dns.servers.len() {
        return Err(recovery());
    }
    let identity = serde_json::to_vec(&(luid, &namespaces, &servers)).map_err(|_| recovery())?;
    Ok(Desired {
        luid,
        namespaces,
        servers,
        display_name: format!("OpenFortiVPN Manager {:x}", Sha256::digest(identity)),
        comment: COMMENT.into(),
    })
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Rule {
    pub name: String,
    pub namespaces: Vec<String>,
    pub servers: Vec<String>,
    pub display_name: String,
    pub comment: String,
    /// The system cmdlet supplies all CIM properties in ordinal key order.
    /// Retain the exact serialization, including fields this version does not
    /// understand, so external edits cannot disappear during cleanup.
    pub canonical: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Policy {
    pub local: Vec<Rule>,
    pub effective: Vec<Rule>,
}
fn overlap(namespace: &str, requested: &str) -> bool {
    let namespace = namespace.trim_start_matches('.').to_ascii_lowercase();
    let requested = requested.trim_start_matches('.');
    // A global, wildcard, IDN/unrecognized policy may influence any request.
    // Reject it rather than infer undocumented Windows matching semantics.
    !domain(&namespace)
        || namespace == requested
        || namespace.ends_with(&format!(".{requested}"))
        || requested.ends_with(&format!(".{namespace}"))
}
fn overlaps(rule: &Rule, wanted: &Desired) -> bool {
    rule.namespaces.is_empty()
        || rule.namespaces.iter().any(|existing| {
            wanted
                .namespaces
                .iter()
                .any(|wanted| overlap(existing, wanted))
        })
}
fn same_values(a: &[String], b: &[String]) -> bool {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort();
    b.sort();
    a == b
}
fn properties(rule: &Rule) -> Result<BTreeMap<String, Value>, ControlError> {
    if rule.canonical.len() > 32768
        || rule.name.len() > 128
        || rule.namespaces.len() > 64
        || rule.servers.len() > 64
    {
        return Err(recovery());
    }
    let properties: BTreeMap<String, Value> =
        serde_json::from_str(&rule.canonical).map_err(|_| recovery())?;
    if properties.len() > 64 {
        return Err(recovery());
    }
    Ok(properties)
}
fn validate_owned(rule: &Rule, wanted: &Desired) -> Result<(), ControlError> {
    if rule.name.is_empty()
        || rule.name.chars().any(char::is_control)
        || rule.display_name != wanted.display_name
        || rule.comment != wanted.comment
        || !same_values(&rule.namespaces, &wanted.namespaces)
        || !same_values(&rule.servers, &wanted.servers)
    {
        return Err(recovery());
    }
    let props = properties(rule)?;
    for (field, value) in [
        ("Name", &rule.name),
        ("DisplayName", &wanted.display_name),
        ("Comment", &wanted.comment),
    ] {
        if props.get(field).and_then(Value::as_str) != Some(value) {
            return Err(recovery());
        }
    }
    if props.get("NameEncoding").and_then(Value::as_str) != Some("Punycode")
        || props.get("DirectAccessEnabled") != Some(&Value::Bool(false))
        || props.get("DnsSecEnabled") != Some(&Value::Bool(false))
    {
        return Err(recovery());
    }
    let namespaces: Vec<String> =
        serde_json::from_value(props.get("Namespace").ok_or_else(recovery)?.clone())
            .map_err(|_| recovery())?;
    let servers = match props.get("NameServers").ok_or_else(recovery)? {
        Value::String(servers) => servers
            .split(|c: char| matches!(c, ',' | ';') || c.is_whitespace())
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        Value::Array(servers) => servers
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(recovery))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(recovery()),
    };
    if !same_values(&namespaces, &wanted.namespaces) || !same_values(&servers, &wanted.servers) {
        return Err(recovery());
    }
    // A basic nameserver rule must never silently become DirectAccess/DNSSEC.
    for field in [
        "DirectAccessEnabled",
        "DnsSecEnabled",
        "DnsSecValidationRequired",
        "DnsSecQueryIPsecRequired",
        "DirectAccessQueryIPsecRequired",
    ] {
        if props
            .get(field)
            .is_some_and(|v| !v.is_null() && *v != Value::Bool(false))
        {
            return Err(recovery());
        }
    }
    Ok(())
}
pub(crate) fn fingerprint(rule: &Rule, luid: u64) -> Result<String, ControlError> {
    let _ = properties(rule)?;
    Ok(format!(
        "nrpt-v1:{luid}:{:x}",
        Sha256::digest(rule.canonical.as_bytes())
    ))
}
pub(crate) fn expected_hash(value: &str, luid: u64) -> Result<&str, ControlError> {
    let prefix = format!("nrpt-v1:{luid}:");
    let hash = value.strip_prefix(&prefix).ok_or_else(recovery)?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(recovery());
    }
    Ok(hash)
}
pub(crate) fn inspect<'a>(
    policy: &'a Policy,
    wanted: &Desired,
) -> Result<Option<&'a Rule>, ControlError> {
    if policy.local.len() > 512 || policy.effective.len() > 512 {
        return Err(recovery());
    }
    let mut owned = None;
    for rule in &policy.local {
        if rule.display_name == wanted.display_name {
            if owned.is_some() {
                return Err(recovery());
            }
            validate_owned(rule, wanted)?;
            owned = Some(rule);
        } else if overlaps(rule, wanted) {
            return Err(conflict());
        }
    }
    // Effective rules do not expose local GUID/DisplayName. A match is accepted
    // only when the exact matching local rule is also present, with one policy
    // row per suffix and unchanged resolver/security settings.
    let mut seen = Vec::new();
    for rule in &policy.effective {
        if !overlaps(rule, wanted) {
            continue;
        }
        if owned.is_none()
            || !same_values(&rule.servers, &wanted.servers)
            || rule.namespaces.is_empty()
            || rule
                .namespaces
                .iter()
                .any(|v| !wanted.namespaces.contains(v))
        {
            return Err(conflict());
        }
        let props = properties(rule)?;
        for field in [
            "DirectAccessEnabled",
            "DnsSecValidationRequired",
            "DnsSecQueryIPsecRequired",
            "DirectAccessQueryIPsecRequired",
        ] {
            if props
                .get(field)
                .is_some_and(|v| !v.is_null() && *v != Value::Bool(false))
            {
                return Err(conflict());
            }
        }
        seen.extend(rule.namespaces.clone());
    }
    if owned.is_some() && !same_values(&seen, &wanted.namespaces) {
        return Err(recovery());
    }
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wanted() -> Desired {
        desired(
            &Dns {
                interface: "vpn".into(),
                servers: vec!["10.0.0.53".parse().unwrap()],
                domains: vec!["corp.example".into()],
            },
            42,
        )
        .unwrap()
    }
    fn rule(wanted: &Desired) -> Rule {
        let name = "{11111111-1111-1111-1111-111111111111}".to_owned();
        let canonical = serde_json::json!({
            "Name": name,
            "Namespace": wanted.namespaces,
            "NameServers": wanted.servers.join(";"),
            "DisplayName": wanted.display_name,
            "Comment": wanted.comment,
            "NameEncoding": "Punycode",
            "DirectAccessEnabled": false,
            "DnsSecEnabled": false,
            "DnsSecValidationRequired": false,
        })
        .to_string();
        Rule {
            name,
            namespaces: wanted.namespaces.clone(),
            servers: wanted.servers.clone(),
            display_name: wanted.display_name.clone(),
            comment: wanted.comment.clone(),
            canonical,
        }
    }
    #[test]
    fn rejects_global_invalid_duplicate_and_unusable_dns() {
        let mut dns = Dns {
            interface: "vpn".into(),
            servers: vec!["10.0.0.53".parse().unwrap()],
            domains: vec![],
        };
        assert!(desired(&dns, 42).is_err());
        dns.domains = vec!["Corp.Example".into()];
        assert!(desired(&dns, 42).is_err());
        dns.domains = vec!["corp.example".into(), "corp.example".into()];
        assert!(desired(&dns, 42).is_err());
        dns.domains.truncate(1);
        dns.servers = vec![Ipv4Addr::UNSPECIFIED];
        assert!(desired(&dns, 42).is_err());
        dns.servers = vec!["10.0.0.53".parse().unwrap()];
        assert!(desired(&dns, 0).is_err());
    }
    #[test]
    fn parent_child_exact_wildcard_and_foreign_rules_block_before_mutation() {
        let wanted = wanted();
        for namespace in [
            ".example",
            ".dev.corp.example",
            "corp.example",
            ".",
            "*",
            "*.other.example",
        ] {
            let mut foreign = rule(&wanted);
            foreign.display_name = "external".into();
            foreign.namespaces = vec![namespace.into()];
            assert!(inspect(
                &Policy {
                    local: vec![foreign],
                    effective: vec![]
                },
                &wanted
            )
            .is_err());
        }
        let mut unrelated = rule(&wanted);
        unrelated.display_name = "external".into();
        unrelated.namespaces = vec![".unrelated.example".into()];
        assert!(inspect(
            &Policy {
                local: vec![unrelated],
                effective: vec![]
            },
            &wanted
        )
        .unwrap()
        .is_none());
    }
    #[test]
    fn exact_effective_policy_and_unchanged_unknown_properties_are_required() {
        let wanted = wanted();
        let local = rule(&wanted);
        let effective = local.clone();
        let mut policy = Policy {
            local: vec![local],
            effective: vec![effective],
        };
        assert!(inspect(&policy, &wanted).unwrap().is_some());
        let original = fingerprint(&policy.local[0], 42).unwrap();
        let mut edited: Value = serde_json::from_str(&policy.local[0].canonical).unwrap();
        edited["UnknownFuturePolicy"] = Value::String("external-edit".into());
        policy.local[0].canonical = edited.to_string();
        assert_ne!(fingerprint(&policy.local[0], 42).unwrap(), original);
        assert!(expected_hash(&original, 43).is_err());
        policy.effective[0].servers = vec!["10.0.0.54".into()];
        assert!(inspect(&policy, &wanted).is_err());
        policy.effective.clear();
        assert!(inspect(&policy, &wanted).is_err());
    }
    #[test]
    fn duplicate_owned_rule_and_direct_access_changes_fail_closed() {
        let wanted = wanted();
        let mut local = rule(&wanted);
        assert!(inspect(
            &Policy {
                local: vec![local.clone(), local.clone()],
                effective: vec![local.clone()]
            },
            &wanted
        )
        .is_err());
        local.canonical = r#"{"DirectAccessEnabled":true}"#.into();
        assert!(inspect(
            &Policy {
                local: vec![local.clone()],
                effective: vec![local]
            },
            &wanted
        )
        .is_err());
    }
}
