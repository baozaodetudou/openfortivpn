//! Versioned metadata codec shared by both repositories. Unknown versions fail
//! before mutation; the legacy array remains readable for staged migration.
use crate::{ControlError, ErrorCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
pub const PROFILE_SCHEMA: u32 = 1;
pub const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROFILES: usize = 4096;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document<T> {
    schema_version: u32,
    profiles: Vec<T>,
}
pub struct Decoded<T> {
    pub profiles: Vec<T>,
    pub legacy: bool,
}
fn invalid() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "unsupported or invalid profile repository schema",
    )
}
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<Decoded<T>, ControlError> {
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(invalid());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    decode_value(value)
}
pub fn decode_value<T: DeserializeOwned>(
    value: serde_json::Value,
) -> Result<Decoded<T>, ControlError> {
    let (profiles, legacy) = if value.is_array() {
        (
            serde_json::from_value::<Vec<T>>(value).map_err(|_| invalid())?,
            true,
        )
    } else {
        let document: Document<T> = serde_json::from_value(value).map_err(|_| invalid())?;
        if document.schema_version != PROFILE_SCHEMA {
            return Err(invalid());
        }
        (document.profiles, false)
    };
    if profiles.len() > MAX_PROFILES {
        return Err(invalid());
    }
    Ok(Decoded { profiles, legacy })
}
pub fn encode<T: Serialize>(profiles: Vec<T>) -> Result<Vec<u8>, ControlError> {
    if profiles.len() > MAX_PROFILES {
        return Err(invalid());
    }
    let bytes = serde_json::to_vec_pretty(&Document {
        schema_version: PROFILE_SCHEMA,
        profiles,
    })
    .map_err(|_| invalid())?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Portable archives contain ID-keyed password copies, never native credential
/// references. Both adapters validate the whole archive before staging writes.
pub fn validate_portable_archive<'a>(
    schema: u32,
    profiles: &[crate::domain::VpnProfile],
    secrets: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<(), ControlError> {
    if schema != 1 || profiles.len() > MAX_PROFILES {
        return Err(invalid());
    }
    let mut ids = std::collections::HashSet::new();
    for profile in profiles {
        crate::validation::profile(profile)?;
        if profile.credential_ref.is_some() || !ids.insert(profile.id.as_str()) {
            return Err(invalid());
        }
    }
    let mut secret_ids = std::collections::HashSet::new();
    for (id, password) in secrets {
        if password.is_empty() || !ids.contains(id) || !secret_ids.insert(id) {
            return Err(invalid());
        }
        crate::validation::password(password)?;
    }
    if profiles
        .iter()
        .any(|p| p.auto_connect && !secret_ids.contains(p.id.as_str()))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Prepare the entire new catalog without writes. A single exhausted revision
/// aborts the restore before any adapter can stage a credential or metadata.
pub fn prepare_restored_catalog(
    profiles: &[crate::domain::VpnProfile],
    current: &std::collections::BTreeMap<String, crate::domain::VpnProfile>,
) -> Result<std::collections::BTreeMap<String, crate::domain::VpnProfile>, ControlError> {
    if profiles.len() > MAX_PROFILES {
        return Err(invalid());
    }
    let mut restored = std::collections::BTreeMap::new();
    for mut profile in profiles.iter().cloned() {
        crate::validation::profile(&profile)?;
        profile.trusted_cert = crate::validation::certificate_pin(&profile.trusted_cert)?;
        profile.revision = profile
            .revision
            .max(current.get(&profile.id).map_or(0, |p| p.revision))
            .checked_add(1)
            .ok_or_else(invalid)?;
        if restored.insert(profile.id.clone(), profile).is_some() {
            return Err(invalid());
        }
    }
    Ok(restored)
}
pub struct CredentialGc {
    pub delete: std::collections::BTreeSet<String>,
    pub deferred_for_backup: bool,
}
/// Recovery uses live references, rather than guessing whether an older intent
/// committed. A later save may supersede either side of an interrupted intent.
pub fn credential_gc(
    candidates: impl Iterator<Item = String>,
    active: &std::collections::HashSet<String>,
    backup: &std::collections::HashSet<String>,
) -> CredentialGc {
    let mut delete = std::collections::BTreeSet::new();
    let mut deferred = false;
    for candidate in candidates {
        if active.contains(&candidate) {
            continue;
        }
        if backup.contains(&candidate) {
            deferred = true;
            continue;
        }
        delete.insert(candidate);
    }
    CredentialGc {
        delete,
        deferred_for_backup: deferred,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn profile(id: &str, revision: u64) -> crate::domain::VpnProfile {
        serde_json::from_value(serde_json::json!({
            "id": id, "revision": revision, "name": "Synthetic profile", "host": "vpn.example.test",
        }))
        .unwrap()
    }
    #[test]
    fn portable_restore_never_adopts_internal_refs_or_orphaned_credentials() {
        let mut source = profile("one", 4);
        let secrets = || [("one", "synthetic-password")];
        assert!(validate_portable_archive(1, &[source.clone()], secrets()).is_ok());
        for version in [0, 2] {
            assert!(validate_portable_archive(version, &[source.clone()], secrets()).is_err());
        }
        assert!(
            validate_portable_archive(1, &[source.clone(), source.clone()], secrets()).is_err()
        );
        assert!(
            validate_portable_archive(1, &[source.clone()], [("foreign", "synthetic")]).is_err()
        );
        assert!(
            validate_portable_archive(1, &[source.clone()], [("one", "injected\npassword")])
                .is_err()
        );
        assert!(validate_portable_archive(1, &[source.clone()], [("one", "")]).is_err());
        source.credential_ref = Some("credential:00000000-0000-4000-8000-000000000001".into());
        assert!(validate_portable_archive(1, &[source.clone()], secrets()).is_err());
        source.credential_ref = None;
        source.auto_connect = true;
        assert!(validate_portable_archive(1, &[source], []).is_err());
    }
    #[test]
    fn restore_versions_and_pins_are_identical_for_both_adapters_and_overflow_aborts_every_record()
    {
        let current = std::collections::BTreeMap::from([("one".into(), profile("one", 9))]);
        let mut first = profile("one", 4);
        first.trusted_cert = "AB".repeat(32);
        let restored =
            prepare_restored_catalog(&[first.clone(), profile("two", 14)], &current).unwrap();
        assert_eq!(restored["one"].revision, 10);
        assert_eq!(restored["one"].trusted_cert, "ab".repeat(32));
        assert_eq!(restored["two"].revision, 15);
        assert!(prepare_restored_catalog(&[first, profile("two", u64::MAX)], &current).is_err());
        assert_eq!(current["one"].revision, 9);
    }
    #[test]
    fn legacy_and_versioned_metadata_preserve_records_but_future_versions_fail_closed() {
        let legacy = decode::<serde_json::Value>(
            br#"[{"id":"one","revision":7,"credentialRef":"synthetic-reference"}]"#,
        )
        .unwrap();
        assert!(legacy.legacy);
        let versioned = encode(legacy.profiles).unwrap();
        let decoded = decode::<serde_json::Value>(&versioned).unwrap();
        assert!(!decoded.legacy);
        assert_eq!(decoded.profiles[0]["revision"], 7);
        assert_eq!(decoded.profiles[0]["credentialRef"], "synthetic-reference");
        for value in [
            br#"{"schemaVersion":2,"profiles":[]}"#.as_slice(),
            br#"{"schemaVersion":1,"profiles":[],"unexpected":true}"#,
            br#"{"profiles":[]}"#,
        ] {
            assert!(decode::<serde_json::Value>(value).is_err());
        }
        // An old binary expecting an array cannot silently overwrite this file.
        assert!(serde_json::from_slice::<Vec<serde_json::Value>>(&versioned).is_err());
    }
    #[test]
    fn superseded_intents_preserve_current_and_backup_credentials_and_collect_both_orphans() {
        use std::collections::HashSet;
        let candidates = || {
            ["original", "intermediate", "current"]
                .into_iter()
                .map(str::to_owned)
        };
        let active = HashSet::from(["current".into()]);
        let backup = HashSet::from(["original".into()]);
        let gc = credential_gc(candidates(), &active, &backup);
        assert_eq!(gc.delete.into_iter().collect::<Vec<_>>(), ["intermediate"]);
        assert!(gc.deferred_for_backup);
        let gc = credential_gc(candidates(), &active, &HashSet::new());
        assert_eq!(
            gc.delete.into_iter().collect::<Vec<_>>(),
            ["intermediate", "original"]
        );
        assert!(!gc.deferred_for_backup);
        let gc = credential_gc(
            candidates(),
            &HashSet::from(["original".into()]),
            &HashSet::new(),
        );
        assert_eq!(
            gc.delete.into_iter().collect::<Vec<_>>(),
            ["current", "intermediate"]
        );
    }
}
