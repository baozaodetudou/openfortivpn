use anyhow::{anyhow, bail, Context, Result};
use nix::sys::signal::{killpg, Signal};
#[cfg(not(target_os = "linux"))]
use nix::unistd::getpgid;
use nix::unistd::Pid;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::model::{
    EngineInfo, InstanceStatus, InstanceView, LogEvent, PrivilegeStatus, ProfileView, Snapshot,
};
use crate::storage::Storage;

const MAX_LOGS: usize = 2_000;
const DEFAULT_RETRY_DELAYS: &[u64] = &[3, 6, 12, 24, 30];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessSnapshot {
    process_group_id: i32,
    start_time_ticks: Option<u64>,
    executable: Option<FileIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnedEngineProcess {
    pid: i32,
    process_group_id: i32,
    start_time_ticks: Option<u64>,
    executable: Option<FileIdentity>,
}

impl OwnedEngineProcess {
    fn matches(self, snapshot: ProcessSnapshot) -> bool {
        self.process_group_id == snapshot.process_group_id
            && self.start_time_ticks == snapshot.start_time_ticks
            && self.executable == snapshot.executable
    }
}

#[derive(Default)]
struct ProfileControl {
    generation: u64,
    desired: bool,
    reconnect_blocked: bool,
    process: Option<OwnedEngineProcess>,
}

#[derive(Default)]
struct Runtime {
    controls: HashMap<String, ProfileControl>,
    instances: BTreeMap<String, InstanceView>,
    logs: VecDeque<LogEvent>,
}

pub struct VpnManager {
    storage: Storage,
    engine: PathBuf,
    runtime: Mutex<Runtime>,
    retry_delays: Vec<Duration>,
}

impl VpnManager {
    pub fn new(storage: Storage, engine: PathBuf) -> Self {
        Self::with_retry_delays(
            storage,
            engine,
            DEFAULT_RETRY_DELAYS
                .iter()
                .map(|seconds| Duration::from_secs(*seconds))
                .collect(),
        )
    }

    pub fn with_retry_delays(
        storage: Storage,
        engine: PathBuf,
        retry_delays: Vec<Duration>,
    ) -> Self {
        Self {
            storage,
            engine,
            runtime: Mutex::new(Runtime::default()),
            retry_delays,
        }
    }

    pub async fn profile_views(&self) -> Result<Vec<ProfileView>> {
        self.storage.list_profile_views()
    }

    pub async fn instances(&self) -> Vec<InstanceView> {
        self.runtime
            .lock()
            .await
            .instances
            .values()
            .cloned()
            .collect()
    }

    pub async fn logs(&self, instance_id: Option<&str>, limit: usize) -> Vec<LogEvent> {
        let runtime = self.runtime.lock().await;
        let mut logs: Vec<_> = runtime
            .logs
            .iter()
            .filter(|event| instance_id.is_none_or(|id| event.instance_id == id))
            .cloned()
            .collect();
        let keep = limit.clamp(1, MAX_LOGS);
        if logs.len() > keep {
            logs.drain(0..logs.len() - keep);
        }
        logs
    }

    pub async fn snapshot(&self) -> Result<Snapshot> {
        Ok(Snapshot {
            profiles: self.profile_views().await?,
            instances: self.instances().await,
            logs: self.logs(None, 400).await,
            engine: self.engine_info(),
            privilege: PrivilegeStatus {
                required: true,
                ready: nix::unistd::Uid::effective().is_root(),
                platform: std::env::consts::OS.to_string(),
            },
        })
    }

    pub fn engine_info(&self) -> EngineInfo {
        EngineInfo {
            platform: std::env::consts::OS.to_string(),
            path: self.engine.to_string_lossy().into_owned(),
            available: self.engine.is_file(),
            version: crate::VERSION.to_string(),
            requires_elevation: true,
        }
    }

    pub async fn save_profile(&self, input: crate::model::SaveProfileInput) -> Result<ProfileView> {
        if self.is_active(&input.profile.id).await {
            bail!("disconnect the profile before editing it");
        }
        self.storage
            .save_profile(input.profile, input.password, input.remember_password)
    }

    pub async fn delete_profile(&self, profile_id: &str) -> Result<bool> {
        if self.is_active(profile_id).await {
            bail!("disconnect the profile before deleting it");
        }
        self.storage.delete_profile(profile_id)
    }

    pub async fn connect(self: &Arc<Self>, profile_id: &str) -> Result<InstanceView> {
        if !self.engine.is_file() {
            bail!("openfortivpn engine not found: {}", self.engine.display());
        }
        let (profile, password) = self.storage.profile_and_password(profile_id)?;
        drop(Zeroizing::new(password));

        let mut runtime = self.runtime.lock().await;
        let control = runtime.controls.entry(profile_id.to_string()).or_default();
        if control.desired {
            return runtime
                .instances
                .get(profile_id)
                .cloned()
                .ok_or_else(|| anyhow!("profile is already starting"));
        }
        control.generation = control.generation.saturating_add(1);
        control.desired = true;
        control.reconnect_blocked = false;
        control.process = None;
        let generation = control.generation;
        let instance = InstanceView {
            id: Uuid::new_v4().to_string(),
            profile_generation: generation,
            profile_id: profile.id.clone(),
            profile_name: profile.name,
            adapter_name: String::new(),
            status: InstanceStatus::Starting,
            message: "waiting for openfortivpn".to_string(),
            pid: 0,
            started_at: now_epoch(),
            ended_at: None,
            exit_code: None,
            revision: 1,
        };
        runtime
            .instances
            .insert(profile_id.to_string(), instance.clone());
        drop(runtime);

        let manager = self.clone();
        let profile_id = profile_id.to_string();
        let instance_id = instance.id.clone();
        tokio::spawn(async move {
            manager.supervise(profile_id, generation, instance_id).await;
        });
        Ok(instance)
    }

    pub async fn disconnect(&self, profile_id: &str) -> Result<()> {
        let process = {
            let mut runtime = self.runtime.lock().await;
            let control = runtime.controls.entry(profile_id.to_string()).or_default();
            control.desired = false;
            control.generation = control.generation.saturating_add(1);
            let process = control.process.take();
            if let Some(instance) = runtime.instances.get_mut(profile_id) {
                instance.status = InstanceStatus::Disconnecting;
                instance.message = "disconnect requested".to_string();
                instance.revision = instance.revision.saturating_add(1);
            }
            process
        };
        if let Some(process) = process {
            stop_owned_process(process, Duration::from_secs(5)).await?;
        } else {
            self.mark_disconnected(profile_id, None, "disconnected")
                .await;
        }
        Ok(())
    }

    pub async fn reconnect(self: &Arc<Self>, profile_id: &str) -> Result<InstanceView> {
        self.disconnect(profile_id).await?;
        self.connect(profile_id).await
    }

    pub async fn auto_connect(self: &Arc<Self>) {
        if let Ok(profiles) = self.storage.load_profiles() {
            for profile in profiles
                .into_values()
                .filter(|profile| profile.auto_connect)
            {
                if let Err(error) = self.connect(&profile.id).await {
                    self.append_log(
                        "system",
                        "manager",
                        format!("auto-connect {} failed: {error}", profile.id),
                    )
                    .await;
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        let processes = {
            let mut runtime = self.runtime.lock().await;
            let processes: Vec<OwnedEngineProcess> = runtime
                .controls
                .values()
                .filter_map(|control| control.process)
                .collect();
            for control in runtime.controls.values_mut() {
                control.desired = false;
                control.generation = control.generation.saturating_add(1);
                control.process = None;
            }
            processes
        };
        for process in processes {
            let _ = stop_owned_process(process, Duration::from_secs(5)).await;
        }
    }

    async fn is_active(&self, profile_id: &str) -> bool {
        self.runtime
            .lock()
            .await
            .controls
            .get(profile_id)
            .is_some_and(|control| control.desired)
    }

    async fn supervise(self: Arc<Self>, profile_id: String, generation: u64, instance_id: String) {
        let mut reconnect_attempt = 0_usize;
        loop {
            if !self.is_current(&profile_id, generation).await {
                self.mark_disconnected(&profile_id, Some(&instance_id), "disconnected")
                    .await;
                return;
            }
            if reconnect_attempt > 0 {
                let delay =
                    self.retry_delays[(reconnect_attempt - 1).min(self.retry_delays.len() - 1)];
                self.update_instance(
                    &profile_id,
                    &instance_id,
                    InstanceStatus::Starting,
                    format!(
                        "automatic reconnect attempt {reconnect_attempt} in {}s",
                        delay.as_secs_f32()
                    ),
                    None,
                )
                .await;
                tokio::time::sleep(delay).await;
                if !self.is_current(&profile_id, generation).await {
                    self.mark_disconnected(&profile_id, Some(&instance_id), "disconnected")
                        .await;
                    return;
                }
            }

            let result = self.run_once(&profile_id, generation, &instance_id).await;
            let auto_reconnect = self
                .storage
                .load_profiles()
                .ok()
                .and_then(|profiles| {
                    profiles
                        .get(&profile_id)
                        .map(|profile| profile.auto_reconnect)
                })
                .unwrap_or(false);
            let reconnect_blocked = self
                .runtime
                .lock()
                .await
                .controls
                .get(&profile_id)
                .is_some_and(|control| control.reconnect_blocked);
            if !self.is_current(&profile_id, generation).await {
                self.mark_disconnected(&profile_id, Some(&instance_id), "disconnected")
                    .await;
                return;
            }
            if !auto_reconnect || reconnect_blocked || self.retry_delays.is_empty() {
                let message = result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "VPN process exited unexpectedly".to_string());
                self.finish_failed(&profile_id, &instance_id, message).await;
                return;
            }
            reconnect_attempt = reconnect_attempt.saturating_add(1);
        }
    }

    async fn run_once(
        self: &Arc<Self>,
        profile_id: &str,
        generation: u64,
        instance_id: &str,
    ) -> Result<()> {
        let (profile, password) = self.storage.profile_and_password(profile_id)?;
        let password = Zeroizing::new(password);
        let config_path = self
            .storage
            .write_runtime_config(&profile, &password, instance_id)?;
        let _config_guard = RuntimeConfigGuard(config_path.clone());
        let mut command = Command::new(&self.engine);
        command
            .arg("--json-events")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.as_std_mut().process_group(0);
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to start {}", self.engine.display()))?;
        let pid = child.id().ok_or_else(|| anyhow!("engine has no PID"))?;
        let process = match capture_engine_process(pid as i32, &self.engine) {
            Ok(process) => process,
            Err(error) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
        };
        {
            let mut runtime = self.runtime.lock().await;
            let control = runtime
                .controls
                .get_mut(profile_id)
                .ok_or_else(|| anyhow!("missing profile control"))?;
            if control.generation != generation || !control.desired {
                let _ = signal_owned_process(process, Signal::SIGTERM);
                bail!("connection was cancelled");
            }
            control.process = Some(process);
            if let Some(instance) = runtime.instances.get_mut(profile_id) {
                if instance.id == instance_id {
                    instance.pid = pid;
                    instance.status = InstanceStatus::Connecting;
                    instance.message = "openfortivpn started".to_string();
                    instance.revision = instance.revision.saturating_add(1);
                }
            }
        }

        let stdout_task = child.stdout.take().map(|stream| {
            let manager = self.clone();
            let id = instance_id.to_string();
            tokio::spawn(async move { manager.read_stream(id, "stdout", stream).await })
        });
        let stderr_task = child.stderr.take().map(|stream| {
            let manager = self.clone();
            let id = instance_id.to_string();
            tokio::spawn(async move { manager.read_stream(id, "stderr", stream).await })
        });
        let status = child
            .wait()
            .await
            .context("failed waiting for openfortivpn")?;
        if let Some(task) = stdout_task {
            let _ = task.await;
        }
        if let Some(task) = stderr_task {
            let _ = task.await;
        }
        {
            let mut runtime = self.runtime.lock().await;
            if let Some(control) = runtime.controls.get_mut(profile_id) {
                if control.generation == generation {
                    control.process = None;
                }
            }
            if let Some(instance) = runtime.instances.get_mut(profile_id) {
                if instance.id == instance_id {
                    instance.exit_code = status.code();
                    instance.pid = 0;
                    instance.revision = instance.revision.saturating_add(1);
                }
            }
        }
        bail!(
            "openfortivpn exited with {}",
            status
                .code()
                .map_or_else(|| "signal".to_string(), |code| code.to_string())
        )
    }

    async fn read_stream<R>(&self, instance_id: String, stream_name: &'static str, stream: R)
    where
        R: AsyncRead + Unpin,
    {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            self.append_log(&instance_id, stream_name, line.clone())
                .await;
            if line.contains("Could not authenticate to gateway.") {
                self.block_reconnect_for_instance(&instance_id).await;
            }
            if let Ok(event) = serde_json::from_str::<Value>(&line) {
                self.apply_engine_event(&instance_id, &event).await;
            }
        }
    }

    async fn append_log(&self, instance_id: &str, stream: &str, line: String) {
        let mut runtime = self.runtime.lock().await;
        runtime.logs.push_back(LogEvent {
            instance_id: instance_id.to_string(),
            stream: stream.to_string(),
            line,
            timestamp: now_epoch(),
        });
        while runtime.logs.len() > MAX_LOGS {
            runtime.logs.pop_front();
        }
    }

    async fn apply_engine_event(&self, instance_id: &str, event: &Value) {
        let event_type = event
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let state_name = event
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if event_type == "cert_error" {
            self.block_reconnect_for_instance(instance_id).await;
        }
        let (status, message) = match (event_type, state_name) {
            ("tunnel_up", _) | ("state_change", "connected" | "tunneling") => (
                InstanceStatus::Connected,
                "VPN tunnel connected".to_string(),
            ),
            ("state_change", "disconnecting") | ("tunnel_down", _) => (
                InstanceStatus::Disconnecting,
                "VPN tunnel is closing".to_string(),
            ),
            ("cert_error", _) => (
                InstanceStatus::Failed,
                format!(
                    "untrusted certificate: {}",
                    event
                        .get("digest")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                ),
            ),
            ("error", _) => (
                InstanceStatus::Failed,
                event
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("VPN error")
                    .to_string(),
            ),
            ("state_change", state) if !state.is_empty() => {
                (InstanceStatus::Connecting, state.replace('_', " "))
            }
            _ => return,
        };
        let mut runtime = self.runtime.lock().await;
        for instance in runtime.instances.values_mut() {
            if instance.id == instance_id {
                instance.status = status;
                instance.message = message;
                instance.revision = instance.revision.saturating_add(1);
                break;
            }
        }
    }

    async fn block_reconnect_for_instance(&self, instance_id: &str) {
        let mut runtime = self.runtime.lock().await;
        let profile_id = runtime.instances.iter().find_map(|(profile_id, instance)| {
            (instance.id == instance_id).then_some(profile_id.clone())
        });
        if let Some(profile_id) = profile_id {
            if let Some(control) = runtime.controls.get_mut(&profile_id) {
                control.reconnect_blocked = true;
            }
        }
    }

    async fn is_current(&self, profile_id: &str, generation: u64) -> bool {
        self.runtime
            .lock()
            .await
            .controls
            .get(profile_id)
            .is_some_and(|control| control.desired && control.generation == generation)
    }

    async fn update_instance(
        &self,
        profile_id: &str,
        instance_id: &str,
        status: InstanceStatus,
        message: String,
        exit_code: Option<i32>,
    ) {
        let mut runtime = self.runtime.lock().await;
        if let Some(instance) = runtime.instances.get_mut(profile_id) {
            if instance.id == instance_id {
                instance.status = status;
                instance.message = message;
                instance.exit_code = exit_code;
                instance.revision = instance.revision.saturating_add(1);
            }
        }
    }

    async fn finish_failed(&self, profile_id: &str, instance_id: &str, message: String) {
        let mut runtime = self.runtime.lock().await;
        if let Some(control) = runtime.controls.get_mut(profile_id) {
            control.desired = false;
            control.process = None;
        }
        if let Some(instance) = runtime.instances.get_mut(profile_id) {
            if instance.id == instance_id {
                instance.status = InstanceStatus::Failed;
                instance.message = message;
                instance.pid = 0;
                instance.ended_at = Some(now_epoch());
                instance.revision = instance.revision.saturating_add(1);
            }
        }
    }

    async fn mark_disconnected(&self, profile_id: &str, instance_id: Option<&str>, message: &str) {
        let mut runtime = self.runtime.lock().await;
        if let Some(instance) = runtime.instances.get_mut(profile_id) {
            if instance_id.is_none_or(|id| instance.id == id) {
                instance.status = InstanceStatus::Disconnected;
                instance.message = message.to_string();
                instance.pid = 0;
                instance.ended_at = Some(now_epoch());
                instance.revision = instance.revision.saturating_add(1);
            }
        }
    }
}

struct RuntimeConfigGuard(PathBuf);

impl Drop for RuntimeConfigGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn file_identity(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect executable {}", path.display()))?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn expected_executable_identities(engine: &Path) -> Result<Vec<FileIdentity>> {
    let mut identities = vec![file_identity(engine)?];
    let mut file = fs::File::open(engine)?;
    let mut prefix = [0_u8; 256];
    let length = file.read(&mut prefix)?;
    if let Some(shebang) = prefix[..length].strip_prefix(b"#!") {
        if let Some(interpreter) = String::from_utf8_lossy(shebang)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().next())
        {
            let interpreter = Path::new(interpreter);
            if interpreter.is_absolute() {
                if let Ok(identity) = file_identity(interpreter) {
                    identities.push(identity);
                }
            }
        }
    }
    Ok(identities)
}

fn capture_engine_process(pid: i32, engine: &Path) -> Result<OwnedEngineProcess> {
    let snapshot = inspect_process(pid)?
        .ok_or_else(|| anyhow!("openfortivpn exited before its process identity was captured"))?;
    if snapshot.process_group_id != pid {
        bail!(
            "openfortivpn process group mismatch: expected {pid}, got {}",
            snapshot.process_group_id
        );
    }
    #[cfg(target_os = "linux")]
    {
        let expected = expected_executable_identities(engine)?;
        if !snapshot
            .executable
            .is_some_and(|identity| expected.contains(&identity))
        {
            bail!("spawned process does not belong to the configured openfortivpn engine");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = engine;
    Ok(OwnedEngineProcess {
        pid,
        process_group_id: snapshot.process_group_id,
        start_time_ticks: snapshot.start_time_ticks,
        executable: snapshot.executable,
    })
}

#[cfg(target_os = "linux")]
fn inspect_process(pid: i32) -> Result<Option<ProcessSnapshot>> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat = match fs::read_to_string(&stat_path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("failed to read {stat_path}")),
    };
    let (process_group_id, start_time_ticks) = parse_linux_process_stat(&stat)?;
    let executable_path = format!("/proc/{pid}/exe");
    let executable = match fs::metadata(&executable_path) {
        Ok(metadata) => FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {executable_path}"));
        }
    };
    Ok(Some(ProcessSnapshot {
        process_group_id,
        start_time_ticks: Some(start_time_ticks),
        executable: Some(executable),
    }))
}

#[cfg(target_os = "linux")]
fn parse_linux_process_stat(stat: &str) -> Result<(i32, u64)> {
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| anyhow!("invalid /proc process stat"))?;
    let fields: Vec<&str> = stat[command_end + 1..].split_whitespace().collect();
    let process_group_id = fields
        .get(2)
        .ok_or_else(|| anyhow!("missing process group in /proc process stat"))?
        .parse()
        .context("invalid process group in /proc process stat")?;
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(|| anyhow!("missing start time in /proc process stat"))?
        .parse()
        .context("invalid start time in /proc process stat")?;
    Ok((process_group_id, start_time_ticks))
}

#[cfg(not(target_os = "linux"))]
fn inspect_process(pid: i32) -> Result<Option<ProcessSnapshot>> {
    match getpgid(Some(Pid::from_raw(pid))) {
        Ok(process_group_id) => Ok(Some(ProcessSnapshot {
            process_group_id: process_group_id.as_raw(),
            start_time_ticks: None,
            executable: None,
        })),
        Err(nix::errno::Errno::ESRCH) => Ok(None),
        Err(error) => Err(error).context("failed to inspect VPN process"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignalDisposition {
    Sent,
    ProcessGoneOrReplaced,
}

fn signal_owned_process_with<Inspect, SendSignal>(
    process: OwnedEngineProcess,
    signal: Signal,
    inspect: Inspect,
    send_signal: SendSignal,
) -> Result<SignalDisposition>
where
    Inspect: FnOnce(i32) -> Result<Option<ProcessSnapshot>>,
    SendSignal: FnOnce(i32, Signal) -> Result<()>,
{
    let Some(snapshot) = inspect(process.pid)? else {
        return Ok(SignalDisposition::ProcessGoneOrReplaced);
    };
    if !process.matches(snapshot) {
        return Ok(SignalDisposition::ProcessGoneOrReplaced);
    }
    send_signal(process.process_group_id, signal)?;
    Ok(SignalDisposition::Sent)
}

fn signal_owned_process(process: OwnedEngineProcess, signal: Signal) -> Result<SignalDisposition> {
    signal_owned_process_with(
        process,
        signal,
        inspect_process,
        |group, signal| match killpg(Pid::from_raw(group), signal) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
            Err(error) => Err(error).context("failed to signal owned VPN process group"),
        },
    )
}

async fn stop_owned_process(process: OwnedEngineProcess, timeout: Duration) -> Result<()> {
    if signal_owned_process(process, Signal::SIGTERM)? == SignalDisposition::ProcessGoneOrReplaced {
        return Ok(());
    }
    let started = std::time::Instant::now();
    loop {
        let Some(snapshot) = inspect_process(process.pid)? else {
            return Ok(());
        };
        if !process.matches(snapshot) {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            let _ = signal_owned_process(process, Signal::SIGKILL)?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::VpnProfile;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn profile(id: &str) -> VpnProfile {
        VpnProfile {
            id: id.into(),
            name: id.into(),
            host: "vpn.example.com".into(),
            port: 443,
            username: "alice".into(),
            realm: String::new(),
            trusted_cert: String::new(),
            set_routes: true,
            set_dns: true,
            pppd_use_peerdns: false,
            half_internet_routes: false,
            use_sudo: true,
            auto_connect: false,
            auto_reconnect: false,
        }
    }

    fn owned_process() -> OwnedEngineProcess {
        OwnedEngineProcess {
            pid: 123,
            process_group_id: 123,
            start_time_ticks: Some(456),
            executable: Some(FileIdentity {
                device: 7,
                inode: 8,
            }),
        }
    }

    #[test]
    fn term_is_not_sent_after_pid_or_pgid_reuse() {
        let sent = AtomicUsize::new(0);
        let disposition = signal_owned_process_with(
            owned_process(),
            Signal::SIGTERM,
            |_| {
                Ok(Some(ProcessSnapshot {
                    process_group_id: 123,
                    start_time_ticks: Some(999),
                    executable: Some(FileIdentity {
                        device: 7,
                        inode: 8,
                    }),
                }))
            },
            |_, _| {
                sent.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(disposition, SignalDisposition::ProcessGoneOrReplaced);
        assert_eq!(sent.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn kill_is_not_sent_after_engine_executable_changes() {
        let sent = AtomicUsize::new(0);
        let disposition = signal_owned_process_with(
            owned_process(),
            Signal::SIGKILL,
            |_| {
                Ok(Some(ProcessSnapshot {
                    process_group_id: 123,
                    start_time_ticks: Some(456),
                    executable: Some(FileIdentity {
                        device: 7,
                        inode: 999,
                    }),
                }))
            },
            |_, _| {
                sent.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(disposition, SignalDisposition::ProcessGoneOrReplaced);
        assert_eq!(sent.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn signal_is_sent_only_for_the_captured_engine_process() {
        let sent = AtomicUsize::new(0);
        let process = owned_process();
        let disposition = signal_owned_process_with(
            process,
            Signal::SIGTERM,
            |_| {
                Ok(Some(ProcessSnapshot {
                    process_group_id: process.process_group_id,
                    start_time_ticks: process.start_time_ticks,
                    executable: process.executable,
                }))
            },
            |group, signal| {
                assert_eq!(group, process.process_group_id);
                assert_eq!(signal, Signal::SIGTERM);
                sent.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(disposition, SignalDisposition::Sent);
        assert_eq!(sent.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_profiles_run_concurrently_but_duplicates_do_not() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        storage.ensure_layout().unwrap();
        for id in ["one", "two"] {
            storage
                .save_profile(profile(id), Some("secret".into()), true)
                .unwrap();
        }
        let engine = root.path().join("engine.sh");
        fs::write(
            &engine,
            "#!/bin/sh\necho '{\"event\":\"tunnel_up\"}' >&2\nsleep 5\n",
        )
        .unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
        let manager = Arc::new(VpnManager::with_retry_delays(storage, engine, vec![]));
        let first = manager.connect("one").await.unwrap();
        let duplicate = manager.connect("one").await.unwrap();
        manager.connect("two").await.unwrap();
        assert_eq!(first.id, duplicate.id);
        tokio::time::sleep(Duration::from_millis(150)).await;
        let instances = manager.instances().await;
        assert_eq!(instances.len(), 2);
        assert_eq!(
            instances.iter().filter(|instance| instance.pid > 0).count(),
            2
        );
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn unexpected_exit_retries_continuously_with_a_bounded_delay() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        storage.ensure_layout().unwrap();
        let mut retry_profile = profile("retry");
        retry_profile.auto_reconnect = true;
        storage
            .save_profile(retry_profile, Some("secret".into()), true)
            .unwrap();
        let counter = root.path().join("counter");
        let engine = root.path().join("engine.sh");
        fs::write(
            &engine,
            format!("#!/bin/sh\necho x >> '{}'\nexit 1\n", counter.display()),
        )
        .unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
        let manager = Arc::new(VpnManager::with_retry_delays(
            storage,
            engine,
            vec![Duration::from_millis(10), Duration::from_millis(10)],
        ));
        manager.connect("retry").await.unwrap();
        for _ in 0..100 {
            if fs::read_to_string(&counter)
                .unwrap_or_default()
                .lines()
                .count()
                >= 4
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let attempts = fs::read_to_string(counter)
            .unwrap_or_default()
            .lines()
            .count();
        assert!(attempts >= 4);
        let _ = manager.disconnect("retry").await;
    }

    #[tokio::test]
    async fn authentication_failure_blocks_automatic_retry() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        storage.ensure_layout().unwrap();
        let mut retry_profile = profile("auth");
        retry_profile.auto_reconnect = true;
        storage
            .save_profile(retry_profile, Some("wrong".into()), true)
            .unwrap();
        let counter = root.path().join("counter");
        let engine = root.path().join("engine.sh");
        fs::write(
            &engine,
            format!(
                "#!/bin/sh\necho x >> '{}'\necho 'Could not authenticate to gateway.' >&2\nexit 1\n",
                counter.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
        let manager = Arc::new(VpnManager::with_retry_delays(
            storage,
            engine,
            vec![Duration::from_millis(10)],
        ));
        manager.connect("auth").await.unwrap();
        for _ in 0..100 {
            if manager
                .instances()
                .await
                .first()
                .is_some_and(|instance| instance.status == InstanceStatus::Failed)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            fs::read_to_string(counter)
                .unwrap_or_default()
                .lines()
                .count(),
            1
        );
        assert_eq!(manager.instances().await[0].status, InstanceStatus::Failed);
    }
}
