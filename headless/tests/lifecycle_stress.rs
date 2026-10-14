//! Real-time fake-engine stress. Never opens a VPN or changes routes/DNS.
use openfortivpn_manager_headless::{
    manager::VpnManager,
    model::{InstanceStatus, VpnProfile},
    storage::Storage,
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::{Duration, Instant},
};
fn resident_high_water() -> u64 {
    let mut usage: nix::libc::rusage = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { nix::libc::getrusage(nix::libc::RUSAGE_SELF, &mut usage) },
        0
    );
    #[cfg(target_os = "linux")]
    return usage.ru_maxrss as u64 * 1024;
    #[cfg(not(target_os = "linux"))]
    return usage.ru_maxrss as u64;
}
fn resident_current() -> u64 {
    #[cfg(target_os = "macos")]
    {
        #[allow(deprecated)]
        let task = unsafe { nix::libc::mach_task_self() };
        let mut info: nix::libc::mach_task_basic_info = unsafe { std::mem::zeroed() };
        let mut count = nix::libc::MACH_TASK_BASIC_INFO_COUNT;
        assert_eq!(
            unsafe {
                nix::libc::task_info(
                    task,
                    nix::libc::MACH_TASK_BASIC_INFO,
                    (&mut info as *mut nix::libc::mach_task_basic_info).cast(),
                    &mut count,
                )
            },
            0
        );
        info.resident_size
    }
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string("/proc/self/statm").unwrap();
        let pages: u64 = stat.split_whitespace().nth(1).unwrap().parse().unwrap();
        pages * unsafe { nix::libc::sysconf(nix::libc::_SC_PAGESIZE) } as u64
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    resident_high_water()
}
fn physical_footprint() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut info: nix::libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                nix::libc::proc_pid_rusage(
                    std::process::id() as i32,
                    nix::libc::RUSAGE_INFO_V2,
                    (&mut info as *mut nix::libc::rusage_info_v2).cast(),
                )
            },
            0
        );
        info.ri_phys_footprint
    }
    #[cfg(not(target_os = "macos"))]
    resident_current()
}
#[cfg(target_os = "macos")]
fn allocator_usage() -> (usize, usize, u32) {
    let mut stats: nix::libc::malloc_statistics_t = unsafe { std::mem::zeroed() };
    // A null zone asks Darwin to sum all registered zones, including nano.
    unsafe { nix::libc::malloc_zone_statistics(std::ptr::null_mut(), &mut stats) };
    (stats.size_in_use, stats.size_allocated, stats.blocks_in_use)
}
#[cfg(not(target_os = "macos"))]
fn allocator_usage() -> (usize, usize, u32) {
    (0, 0, 0)
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-time stress; run with OFV_STRESS_SECONDS and optional OFV_STRESS_EVIDENCE"]
async fn real_time_lifecycle_and_log_stress() {
    let duration: u64 = std::env::var("OFV_STRESS_SECONDS")
        .unwrap_or_else(|_| "86400".into())
        .parse()
        .unwrap();
    assert!((1..=604800).contains(&duration));
    let snapshot_every: u64 = std::env::var("OFV_STRESS_SNAPSHOT_EVERY")
        .unwrap_or_else(|_| "1".into())
        .parse()
        .unwrap();
    assert!(snapshot_every > 0);
    let measure_only = std::env::var("OFV_STRESS_MEASURE_ONLY").as_deref() == Ok("1");
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::new(
        root.path().join("etc"),
        root.path().join("state"),
        root.path().join("run"),
    );
    let profile = VpnProfile {
        id: "stress".into(),
        name: "Synthetic stress".into(),
        host: "vpn.example".into(),
        port: 443,
        username: "synthetic".into(),
        realm: String::new(),
        trusted_cert: String::new(),
        credential_ref: None,
        revision: 0,
        set_routes: true,
        set_dns: true,
        pppd_use_peerdns: false,
        half_internet_routes: false,
        use_sudo: false,
        auto_connect: false,
        auto_reconnect: true,
    };
    storage
        .save_profile(profile, Some("synthetic-stress-password".into()), true)
        .unwrap();
    let engine = root.path().join("engine");
    let live = quote(root.path().join("live").to_str().unwrap());
    let overlap = quote(root.path().join("overlap").to_str().unwrap());
    let script = format!(
        r#"#!/bin/sh
case "$1" in
 --version) echo 'synthetic-stress-engine'; exit 0;;
 --capabilities-json) echo '{{"version":"synthetic","protocolVersion":2,"structuredErrors":true,"readyEvent":"tunnel_up"}}'; exit 0;;
esac
mkdir {live} || {{ touch {overlap}; exit 30; }}
trap 'rmdir {live}; echo '\''{{"protocolVersion":2,"seq":1,"event":"cleanup_result","success":true}}'\'' >&2; exit 0' TERM INT
echo '{{"protocolVersion":2,"seq":0,"event":"tunnel_up"}}' >&2
for i in 1 2 3 4 5 6 7 8; do printf '%04096d\n' 0 >&2; done
i=0
while [ "$i" -lt 100 ]; do sleep 0.05; i=$((i+1)); done
rmdir {live}
echo '{{"protocolVersion":2,"seq":1,"event":"cleanup_result","success":true}}' >&2
exit 41
"#
    );
    fs::write(&engine, script).unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
    let manager = Arc::new(VpnManager::with_retry_delays(
        storage,
        engine,
        vec![Duration::from_millis(10)],
    ));
    let started = Instant::now();
    let mut cycles = 0_u64;
    let mut baseline_rss = None;
    let mut last_evidence = Instant::now();
    let evidence = std::env::var_os("OFV_STRESS_EVIDENCE").map(std::path::PathBuf::from);
    let write_evidence = |cycles, completed| {
        if let Some(path) = &evidence {
            let bytes = serde_json::to_vec_pretty(&json!({"schemaVersion":1,"kind":"synthetic-lifecycle-log-stress","requestedSeconds":duration,"elapsedSeconds":started.elapsed().as_secs(),"cycles":cycles,"maxLiveAttempts":1,"residentHighWaterBytes":resident_high_water(),"physicalFootprintBytes":physical_footprint(),"completed":completed,"acceptanceEligible":!measure_only && snapshot_every == 1,"allocatorUsage":allocator_usage(),"hostNetworkModified":false})).unwrap();
            openfortivpn_manager_core::atomic_file::write_private(path, &bytes).unwrap();
        }
    };
    while started.elapsed() < Duration::from_secs(duration) {
        // Race two admitted connects: both must resolve to one owned attempt.
        let (a, b) = tokio::join!(manager.connect("stress"), manager.connect("stress"));
        assert_eq!(a.unwrap().id, b.unwrap().id);
        let deadline = Instant::now() + Duration::from_secs(3);
        while manager.instances().await[0].status != InstanceStatus::Connected {
            assert!(
                Instant::now() < deadline,
                "fake engine failed to become ready"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        manager.disconnect("stress").await.unwrap();
        // Give the retry timer more than its delay: manual stop must cancel it.
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(!root.path().join("live").exists());
        assert!(!root.path().join("overlap").exists());
        assert!(manager.recovery_records().unwrap().is_empty());
        assert_eq!(manager.instances().await[0].pid, 0);
        cycles += 1;
        if !cycles.is_multiple_of(snapshot_every) {
            continue;
        }
        let logs = manager.logs(None, 2000).await;
        assert!(logs.len() <= openfortivpn_manager_core::log_buffer::MAX_LOGS);
        assert!(
            logs.iter().map(|l| l.line.len()).sum::<usize>()
                <= openfortivpn_manager_core::protocol::MAX_LOG_BYTES
        );
        let response = openfortivpn_manager_core::json_buffer::log_buffers()
            .encode(
                &logs,
                openfortivpn_manager_core::log_buffer::json_capacity(&logs),
            )
            .unwrap();
        assert!(!response
            .as_ref()
            .windows(b"synthetic-stress-password".len())
            .any(|window| window == b"synthetic-stress-password"));
        drop(response);
        let text_bytes = logs.iter().map(|l| l.line.len()).sum::<usize>();
        if baseline_rss.is_none()
            && (logs.len() == openfortivpn_manager_core::log_buffer::MAX_LOGS
                || text_bytes > openfortivpn_manager_core::protocol::MAX_LOG_BYTES - 65536)
        {
            baseline_rss = Some((cycles, resident_high_water()));
        }
        if cycles.is_multiple_of(50) {
            eprintln!("cycle={cycles} logs={} text_bytes={text_bytes} resident={} physical_footprint={} high_water={} allocator={:?} baseline={baseline_rss:?}", logs.len(), resident_current(), physical_footprint(), resident_high_water(), allocator_usage());
        }
        if let Some((warmup, baseline)) = baseline_rss.filter(|(warmup, _)| cycles >= warmup + 100)
        {
            if resident_high_water() > baseline + 64 * 1024 * 1024 {
                write_evidence(cycles, false);
            }
            assert!(
                measure_only || resident_high_water() <= baseline + 64 * 1024 * 1024,
                "resident growth exceeded the stress budget after log-buffer saturation at cycle {warmup}"
            );
        }
        if last_evidence.elapsed() >= Duration::from_secs(60) {
            write_evidence(cycles, false);
            last_evidence = Instant::now();
        }
    }
    manager.shutdown().await;
    write_evidence(cycles, true);
    eprintln!(
        "stress completed: {cycles} cycles in {} seconds",
        started.elapsed().as_secs()
    );
}
