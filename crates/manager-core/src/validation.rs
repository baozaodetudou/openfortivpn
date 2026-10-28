use crate::{ControlError, ErrorCode};

pub const HOST_MAX_BYTES: usize = 253;
pub const USERNAME_MAX_BYTES: usize = 64;
pub const REALM_MAX_BYTES: usize = 63;
pub const PASSWORD_MAX_BYTES: usize = 256;

pub fn line(label: &str, value: &str) -> Result<(), ControlError> {
    if value.contains(['\0', '\n', '\r']) {
        return Err(ControlError::new(
            ErrorCode::InvalidInput,
            format!("{label} cannot contain NUL or line breaks"),
        ));
    }
    Ok(())
}

/// Config.c strips ASCII whitespace and uses fixed byte buffers. Reject values
/// it would alter instead of silently changing authentication input.
pub fn engine_field(label: &str, value: &str, max_bytes: usize) -> Result<(), ControlError> {
    line(label, value)?;
    if value.len() > max_bytes {
        return Err(ControlError::new(
            ErrorCode::InvalidInput,
            format!("{label} exceeds {max_bytes} UTF-8 bytes"),
        ));
    }
    if value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_whitespace)
        || value.as_bytes().last().is_some_and(u8::is_ascii_whitespace)
    {
        return Err(ControlError::new(
            ErrorCode::InvalidInput,
            format!("{label} cannot start or end with ASCII whitespace"),
        ));
    }
    Ok(())
}

pub fn password(value: &str) -> Result<(), ControlError> {
    engine_field("password", value, PASSWORD_MAX_BYTES)
}

pub fn certificate_pin(value: &str) -> Result<String, ControlError> {
    if !value.is_empty() && (value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit())) {
        return Err(ControlError::new(
            ErrorCode::InvalidInput,
            "trustedCert must be a 64-character SHA-256 digest",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

pub fn gateway_dns(value: &str) -> Result<(), ControlError> {
    if value.is_empty() {
        return Ok(());
    }
    if value.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| {
        let first = ip.octets()[0];
        first != 0 && first < 224
    }) {
        return Ok(());
    }
    Err(ControlError::new(
        ErrorCode::InvalidInput,
        "网关 DNS 必须是 IPv4 地址，例如 223.5.5.5；留空使用系统 DNS",
    ))
}

pub fn profile(profile: &crate::domain::VpnProfile) -> Result<(), ControlError> {
    if profile.id.trim().is_empty()
        || profile.name.trim().is_empty()
        || profile.host.trim().is_empty()
        || profile.id == "__remote_access_token"
        || profile.id.len() > 128
        || profile.name.len() > 256
        || profile.port == 0
    {
        return Err(ControlError::new(
            ErrorCode::InvalidInput,
            "profile id, name, host or port is invalid",
        ));
    }
    line("id", &profile.id)?;
    line("name", &profile.name)?;
    engine_field("host", &profile.host, HOST_MAX_BYTES)?;
    gateway_dns(&profile.gateway_dns)?;
    engine_field("username", &profile.username, USERNAME_MAX_BYTES)?;
    engine_field("realm", &profile.realm, REALM_MAX_BYTES)?;
    certificate_pin(&profile.trusted_cert)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_bytes_without_trimming_secrets() {
        assert!(password(&"é".repeat(128)).is_ok());
        assert!(password(&"é".repeat(129)).is_err());
        for value in [" secret", "secret\t", "nul\0", "a\nb"] {
            assert!(password(value).is_err());
        }
        assert!(password("inner space").is_ok());
    }

    #[test]
    fn normalizes_pins() {
        assert_eq!(certificate_pin(&"AB".repeat(32)).unwrap(), "ab".repeat(32));
        assert!(certificate_pin(&"ab".repeat(31)).is_err());
    }

    #[test]
    fn explicit_gateway_dns_is_optional_validated_and_survives_serialization() {
        let mut value: crate::domain::VpnProfile = serde_json::from_value(serde_json::json!({
            "id":"synthetic", "name":"Office", "host":"vpn.example.test",
        }))
        .unwrap();
        assert!(value.gateway_dns.is_empty());
        for dns in [
            "",
            "223.5.5.5",
            "114.114.114.114",
            "192.168.1.1",
            "127.0.0.1",
        ] {
            value.gateway_dns = dns.into();
            assert!(profile(&value).is_ok());
            let copy: crate::domain::VpnProfile =
                serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(copy.gateway_dns, dns);
        }
        for dns in [
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "dns.test",
            "1.1.1.1\npassword=x",
            " 223.5.5.5",
        ] {
            value.gateway_dns = dns.into();
            assert!(profile(&value).is_err(), "{dns}");
        }
    }
    #[test]
    fn catalog_ids_and_names_have_one_bounded_policy_for_every_adapter() {
        let mut value: crate::domain::VpnProfile = serde_json::from_value(serde_json::json!({
            "id":"synthetic", "name":"Office", "host":"vpn.example.test",
        }))
        .unwrap();
        assert!(profile(&value).is_ok());
        for id in ["", "__remote_access_token", &"x".repeat(129)] {
            value.id = id.into();
            assert!(profile(&value).is_err());
        }
        value.id = "synthetic".into();
        value.name = "é".repeat(129);
        assert!(profile(&value).is_err());
        value.name = "é".repeat(128);
        assert!(profile(&value).is_ok());
    }
}
