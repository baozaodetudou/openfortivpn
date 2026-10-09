//! A shareable diagnostic report built by an allowlist. Never serialize the
//! input snapshot, raw logs, messages, paths, credentials or network identity.
use serde_json::{json, Value};

pub fn report(snapshot: &Value, capabilities: &Value, generated_at: u64) -> Value {
    let profiles = array(snapshot, "profiles");
    let instances = array(snapshot, "instances");
    let logs = array(snapshot, "logs");
    let mut states = std::collections::BTreeMap::<&str, usize>::new();
    for instance in instances.iter().take(2000) {
        let state = enum_value(
            instance.get("status"),
            &[
                "starting",
                "connecting",
                "connected",
                "disconnecting",
                "disconnected",
                "failed",
            ],
        );
        *states.entry(state).or_default() += 1;
    }
    let engine = &snapshot["engine"];
    let privilege = &snapshot["privilege"];
    json!({
        "schemaVersion": 1,
        "generatedAt": generated_at,
        "privacy": "Operational metadata only; profile identity, credentials, paths, messages and raw log text are excluded.",
        "engine": {
            "platform": enum_value(engine.get("platform"), &["linux", "macos", "windows", "Linux", "macOS", "Windows"]),
            "available": boolean(engine, "available"),
            "eventProtocol": engine["eventProtocol"].as_u64().filter(|v| *v <= 2),
            "requiresElevation": boolean(engine, "requiresElevation")
        },
        "privilege": {"required":boolean(privilege,"required"),"ready":boolean(privilege,"ready")},
        "capabilities": {
            "coordinatedNetwork":boolean(capabilities,"coordinatedNetwork"),
            "sessionPasswords":boolean(capabilities,"sessionPasswords"),
            "concurrentNetworkConnections":capabilities["concurrentNetworkConnections"].as_u64().filter(|v| *v <= 1024),
            "apiVersions":array(capabilities,"apiVersions").iter().filter_map(Value::as_u64).filter(|v| matches!(v,1|2)).collect::<Vec<_>>()
        },
        "profiles": {
            "count": profiles.len(),
            "storedCredentials": profiles.iter().filter(|p| boolean(p,"passwordStored")).count(),
            "autoConnect": profiles.iter().filter(|p| boolean(&p["profile"],"autoConnect")).count(),
            "autoReconnect": profiles.iter().filter(|p| boolean(&p["profile"],"autoReconnect")).count()
        },
        "instances": {"count":instances.len(),"states":states},
        "recovery": {"unfinishedAttempts":array(snapshot,"runJournal").len()},
        "logs": {
            "sampleCount":logs.len(),
            "firstId":logs.first().and_then(|v| v["id"].as_u64()),
            "lastId":logs.last().and_then(|v| v["id"].as_u64()),
            "sampleTextBytes":logs.iter().filter_map(|v| v["line"].as_str()).map(str::len).sum::<usize>()
        }
    })
}

fn array<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value[field].as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn boolean(value: &Value, field: &str) -> bool {
    value[field].as_bool().unwrap_or(false)
}
fn enum_value<'a>(value: Option<&Value>, allowed: &[&'a str]) -> &'a str {
    value
        .and_then(Value::as_str)
        .and_then(|v| allowed.iter().copied().find(|s| *s == v))
        .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_fields_and_free_text_cannot_leak_into_export() {
        let secret = "synthetic-password-otp-cookie-token-private-key";
        let snapshot = json!({
            "profiles":[{"profile":{"id":secret,"name":secret,"username":secret,"host":secret,"credentialRef":secret,"autoConnect":true},"passwordStored":true,"password":secret}],
            "instances":[{"status":"connected","message":secret,"id":secret},{"status":secret}],
            "logs":[{"id":1,"stream":secret,"line":secret}],
            "engine":{"path":secret,"version":secret,"platform":secret,"available":true},
            "runJournal":[{"engine":secret}],"futureSecret":secret
        });
        let report = report(
            &snapshot,
            &json!({"authentication":[secret],"apiVersions":[1,2,3]}),
            123,
        );
        assert!(!report.to_string().contains(secret));
        assert_eq!(report["profiles"]["count"], 1);
        assert_eq!(report["instances"]["states"]["connected"], 1);
        assert_eq!(report["instances"]["states"]["unknown"], 1);
        assert_eq!(report["recovery"]["unfinishedAttempts"], 1);
        assert_eq!(report["capabilities"]["apiVersions"], json!([1, 2]));
    }
}
