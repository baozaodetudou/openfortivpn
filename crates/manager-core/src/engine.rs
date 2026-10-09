//! Bounded, noninteractive metadata probing. No HTTP snapshot runs a probe.
use crate::process_output::CancellablePipe;
use serde::Deserialize;
use std::{
    io::{self, Read},
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct EngineProbe {
    pub version: String,
    pub event_protocol: Option<u8>,
    pub manager_launch_gate: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityReply {
    version: String,
    protocol_version: u8,
    structured_errors: bool,
    ready_event: String,
    #[serde(default)]
    manager_launch_gate: bool,
}

fn capture(path: &Path, argument: &str, budget: Duration) -> io::Result<Vec<u8>> {
    let mut command = Command::new(path);
    command
        .arg(argument)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    let flag = Arc::new(AtomicBool::new(false));
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("probe has no stdout"))?;
    let cancelled = flag.clone();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        CancellablePipe::new(stdout, cancelled)
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + budget;
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) => {
                break Err(io::Error::other(
                    "engine does not support this metadata command",
                ))
            }
            Err(error) => break Err(error),
            Ok(None) if Instant::now() >= deadline => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "engine metadata probe timed out",
                ))
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    // A descendant may have inherited stdout even after the engine exited.
    while !reader.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let complete = reader.is_finished();
    flag.store(true, Ordering::Release);
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("probe output worker failed"))??;
    result?;
    if !complete || bytes.len() > 64 * 1024 {
        return Err(io::Error::other(
            "engine metadata output incomplete or oversized",
        ));
    }
    Ok(bytes)
}

pub fn probe(path: &Path) -> io::Result<EngineProbe> {
    if let Ok(output) = capture(path, "--capabilities-json", Duration::from_secs(1)) {
        let capability: CapabilityReply = serde_json::from_slice(&output)
            .map_err(|_| io::Error::other("invalid engine capabilities"))?;
        if !(1..=2).contains(&capability.protocol_version)
            || !capability.structured_errors
            || capability.ready_event != "tunnel_up"
            || capability.version.is_empty()
            || capability.version.len() > 128
        {
            return Err(io::Error::other("unsupported engine event contract"));
        }
        return Ok(EngineProbe {
            version: capability.version,
            event_protocol: Some(capability.protocol_version),
            manager_launch_gate: capability.manager_launch_gate,
        });
    }
    let output = capture(path, "--version", Duration::from_secs(1))?;
    let version = String::from_utf8(output)
        .map_err(|_| io::Error::other("invalid engine version encoding"))?;
    if version.trim().is_empty() || version.len() > 128 {
        return Err(io::Error::other("invalid legacy engine version"));
    }
    Ok(EngineProbe {
        version: version.trim().into(),
        event_protocol: None,
        manager_launch_gate: false,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn script(contents: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vpn-probe-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn legacy_version_does_not_claim_event_protocol_support() {
        let path = script("#!/bin/sh\n[ \"$1\" = --version ] || exit 1\necho legacy-version\n");
        let result = probe(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(result.version, "legacy-version");
        assert_eq!(result.event_protocol, None);
        assert!(!result.manager_launch_gate);
    }
    #[test]
    fn launch_barrier_is_explicit_and_absent_capabilities_keep_legacy_arguments() {
        for (extra, expected) in [("", false), (",\"managerLaunchGate\":true", true)] {
            let path = script(&format!("#!/bin/sh\necho '{{\"version\":\"1\",\"protocolVersion\":2,\"structuredErrors\":true,\"readyEvent\":\"tunnel_up\"{extra}}}'\n"));
            assert_eq!(probe(&path).unwrap().manager_launch_gate, expected);
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn unknown_successful_capability_protocol_never_downgrades_silently() {
        let path = script("#!/bin/sh\necho '{\"version\":\"1\",\"protocolVersion\":99,\"structuredErrors\":true,\"readyEvent\":\"tunnel_up\"}'\n");
        assert!(probe(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn nonresponsive_probe_is_killed_and_reaped() {
        let path = script("#!/bin/sh\nwhile :; do :; done\n");
        let started = Instant::now();
        assert!(capture(&path, "--version", Duration::from_millis(100)).is_err());
        std::fs::remove_file(path).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
