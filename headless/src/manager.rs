use anyhow::{anyhow, bail, Context, Result};
use nix::sys::signal::{killpg, Signal};
#[cfg(not(target_os = "linux"))]
use nix::unistd::getpgid;
use nix::unistd::Pid;
use openfortivpn_manager_core::log_buffer::LogBuffer;
use openfortivpn_manager_core::protocol::{Line, LineDecoder};
use openfortivpn_manager_core::{ControlError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::model::{
    EngineInfo, InstanceStatus, InstanceView, LogEvent, PrivilegeStatus, ProfileView, Snapshot,
};
use crate::storage::Storage;

const DEFAULT_RETRY_DELAYS: &[u64] = &[3, 6, 12, 24, 30];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct OwnedEngineProcess {
    pid: i32,
    process_group_id: i32,
    start_time_ticks: Option<u64>,
    executable: Option<FileIdentity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRecord {
    pub schema_version: u32,
    pub attempt_id: String,
    pub profile_id: String,
    pub generation: u64,
    pub started_at: u64,
    pub engine: PathBuf,
    pub boot_id: Option<String>,
    process: Option<OwnedEngineProcess>,
}

fn boot_identity() -> Option<String> {
    #[cfg(target_os = "linux")]
    return fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|v| v.trim().into());
    #[cfg(not(target_os = "linux"))]
    None
}

/// Offline acknowledgement is deliberately separate from disconnect: an
/// interrupted legacy engine has no resource ledger proving network cleanup.
pub fn acknowledge_recovery(storage: &Storage, attempt: &str) -> Result<()> {
    acknowledge_recovery_at(
        storage,
        attempt,
        Path::new(openfortivpn_manager_core::network_authority::SYSTEM_DIRECTORY),
    )
}

fn acknowledge_recovery_at(storage: &Storage, attempt: &str, directory: &Path) -> Result<()> {
    let _service = storage.service_lock()?;
    let record = storage
        .run_records::<RecoveryRecord>()?
        .into_iter()
        .find(|record| record.attempt_id == attempt)
        .ok_or_else(|| anyhow!("recovery attempt not found"))?;
    if record.schema_version != 1 {
        bail!("unsupported recovery journal schema");
    }
    let same_boot = record.boot_id.is_none() || record.boot_id == boot_identity();
    if same_boot {
        if let Some(process) = record.process {
            if inspect_process(process.pid)?.is_some_and(|current| process.matches(current)) {
                bail!(
                    "owned engine is still alive; stop it and restore its network resources first"
                );
            }
        }
    }
    if directory.try_exists()? {
        if let Some(owner) = openfortivpn_manager_core::network_authority::inspect(directory)? {
            if owner.manager == "headless" && owner.attempt_id == attempt {
                openfortivpn_manager_core::network_authority::acknowledge(
                    directory,
                    attempt,
                    unsafe { nix::libc::geteuid() },
                    || {
                        if same_boot
                            && if owner.process_group == 0 {
                                !owner.pre_spawn_gated
                            } else {
                                (unsafe { nix::libc::kill(-(owner.process_group as i32), 0) }) == 0
                                    || std::io::Error::last_os_error().raw_os_error()
                                        != Some(nix::libc::ESRCH)
                            }
                        {
                            return Err(ControlError::new(ErrorCode::RecoveryRequired, "engine group cannot be proven absent; restore networking and finish process recovery first"));
                        }
                        Ok(true)
                    },
                )?;
            }
        }
    }
    // A global unlink may have become visible before its fsync failed. Even
    // without an active.json owner, native evidence must survive manual legacy
    // acknowledgement. Hold the native lock through local anchor deletion.
    let _native = if directory.try_exists()? {
        Some(openfortivpn_manager_core::network::LockedStore::idle_guard(
            directory,
        )?)
    } else {
        None
    };
    storage.remove_run_record(attempt)
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
    active: bool,
    lifecycle: openfortivpn_manager_core::lifecycle::EngineLifecycle,
    cancelled: Arc<Notify>,
    reconnect_blocked: bool,
    process: Option<OwnedEngineProcess>,
    channel: Option<Arc<Mutex<tokio::process::ChildStdin>>>,
    native_admission: Option<openfortivpn_manager_core::network_control::Admission>,
    native_selected: bool,
    native_applied: bool,
    native_acknowledged: bool,
    native_request: Option<String>,
    native_released: bool,
}

#[derive(Default)]
struct Runtime {
    controls: HashMap<String, ProfileControl>,
    instances: BTreeMap<String, InstanceView>,
    logs: LogBuffer,
    shutting_down: bool,
    challenges: openfortivpn_manager_core::control::Challenges,
    supervisors: Vec<tokio::task::JoinHandle<()>>,
}

pub struct VpnManager {
    storage: Storage,
    engine: PathBuf,
    runtime: Mutex<Runtime>,
    retry_delays: Vec<Duration>,
    commands: openfortivpn_manager_core::actor::ProfileActors,
    changed: Notify,
    engine_metadata: std::sync::Mutex<Option<openfortivpn_manager_core::engine::EngineProbe>>,
    experimental_control: bool,
    network_authority: Option<PathBuf>,
    native_network: Option<Arc<dyn crate::native_network::NativeNetwork>>,
    native_workers: Arc<crate::native_network::Workers>,
}

impl VpnManager {
    pub async fn restore_recovery(&self) -> Result<()> {
        let records = self.storage.run_records::<RecoveryRecord>()?;
        let mut runtime = self.runtime.lock().await;
        for record in records {
            if record.schema_version != 1 || uuid::Uuid::parse_str(&record.attempt_id).is_err() {
                bail!("unsupported or malformed run journal");
            }
            if runtime.controls.contains_key(&record.profile_id) {
                bail!(
                    "multiple unfinished attempts for profile {}",
                    record.profile_id
                );
            }
            runtime.controls.insert(
                record.profile_id.clone(),
                ProfileControl {
                    generation: record.generation,
                    active: true,
                    lifecycle: {
                        let mut lifecycle =
                            openfortivpn_manager_core::lifecycle::EngineLifecycle::default();
                        lifecycle.require_recovery();
                        lifecycle
                    },
                    reconnect_blocked: true,
                    ..Default::default()
                },
            );
            runtime.instances.insert(record.profile_id.clone(), InstanceView {
                id: record.attempt_id,
                profile_generation: record.generation,
                attempt_sequence: 0,
                profile_id: record.profile_id.clone(),
                profile_name: record.profile_id,
                adapter_name: String::new(),
                status: InstanceStatus::Failed,
                message: "recovery required: previous manager exited before process and network cleanup were confirmed".into(),
                // A stored PID is never represented as a newly owned child.
                pid: 0,
                started_at: record.started_at,
                ended_at: None,
                exit_code: None,
                revision: 1,
            });
        }
        Ok(())
    }

    pub fn recovery_records(&self) -> Result<Vec<RecoveryRecord>> {
        self.storage.run_records()
    }

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
            commands: Default::default(),
            changed: Notify::new(),
            engine_metadata: std::sync::Mutex::new(None),
            experimental_control: false,
            network_authority: None,
            native_network: None,
            native_workers: Default::default(),
        }
    }
    /// Production entry points use the root-owned system authority; tests inject
    /// a private temporary directory and never change the developer network.
    pub fn with_network_authority(mut self, directory: PathBuf) -> Self {
        self.network_authority = Some(directory);
        self
    }
    pub fn with_experimental_control(mut self, enabled: bool) -> Self {
        self.experimental_control = enabled;
        self
    }
    pub fn with_system_native_network(mut self) -> Result<Self> {
        if !self.experimental_control {
            bail!("native network mode requires experimental private control");
        }
        #[cfg(target_os = "linux")]
        {
            let directory = openfortivpn_manager_core::network_authority::system_directory()?;
            self.network_authority = Some(directory.clone());
            self.native_network = Some(Arc::new(
                openfortivpn_manager_core::network_linux_worker::LinuxTransactions::new(directory),
            ));
            Ok(self)
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Keep the method available so unsupported CLI use fails explicitly.
            let _ = &mut self;
            bail!("native network mode currently requires Linux");
        }
    }

    pub async fn authentication_challenges(
        &self,
    ) -> Vec<openfortivpn_manager_core::control::Challenge> {
        let mut runtime = self.runtime.lock().await;
        let challenges = runtime.challenges.list(now_epoch().saturating_mul(1000));
        challenges
            .into_iter()
            .filter(|challenge| {
                runtime
                    .controls
                    .get(&challenge.profile_id)
                    .is_some_and(|control| control.desired && control.active)
                    && runtime
                        .instances
                        .get(&challenge.profile_id)
                        .is_some_and(|instance| instance.id == challenge.attempt_id)
            })
            .collect()
    }
    pub async fn respond_to_authentication(
        &self,
        input: openfortivpn_manager_core::control::AuthResponse,
    ) -> Result<()> {
        let (frame, channel) = {
            let mut runtime = self.runtime.lock().await;
            let instance = runtime.instances.get(&input.profile_id).ok_or_else(|| {
                ControlError::new(
                    ErrorCode::InvalidInput,
                    "authentication attempt is no longer active",
                )
            })?;
            if instance.id != input.attempt_id {
                return Err(ControlError::new(
                    ErrorCode::InvalidInput,
                    "authentication attempt changed",
                )
                .into());
            }
            let control = runtime.controls.get(&input.profile_id).ok_or_else(|| {
                ControlError::new(
                    ErrorCode::InvalidInput,
                    "authentication attempt is no longer active",
                )
            })?;
            if !control.desired || !control.active {
                return Err(ControlError::new(
                    ErrorCode::InvalidInput,
                    "authentication attempt is stopping",
                )
                .into());
            }
            let generation = control.generation;
            let channel = control.channel.clone().ok_or_else(|| {
                ControlError::new(
                    ErrorCode::InvalidInput,
                    "engine has no private control channel",
                )
            })?;
            let frame = runtime.challenges.respond(
                &input.profile_id,
                &input.attempt_id,
                generation,
                &input.request_id,
                now_epoch().saturating_mul(1000),
                &input.response,
            )?;
            (frame, channel)
        };
        use tokio::io::AsyncWriteExt;
        let sent = tokio::time::timeout(Duration::from_secs(5), async {
            channel.lock().await.write_all(frame.as_bytes()).await
        })
        .await;
        if !matches!(sent, Ok(Ok(()))) {
            let process = {
                let mut runtime = self.runtime.lock().await;
                if runtime
                    .instances
                    .get(&input.profile_id)
                    .is_none_or(|instance| instance.id != input.attempt_id)
                {
                    return Err(ControlError::new(
                        ErrorCode::InvalidInput,
                        "authentication attempt changed while delivering response",
                    )
                    .into());
                }
                runtime
                    .controls
                    .get_mut(&input.profile_id)
                    .and_then(|control| {
                        control.desired = false;
                        control.reconnect_blocked = true;
                        control.process
                    })
            };
            if let Some(process) = process {
                let _ = signal_owned_process(process, Signal::SIGTERM);
            }
            return Err(ControlError::new(
                ErrorCode::RecoveryRequired,
                "engine authentication response could not be delivered; attempt is stopping",
            )
            .into());
        }
        Ok(())
    }

    pub async fn profile_views(&self) -> Result<Vec<ProfileView>> {
        self.storage.list_profile_views()
    }

    pub async fn instances(&self) -> Vec<InstanceView> {
        let mut runtime = self.runtime.lock().await;
        let keep = openfortivpn_manager_core::retention::terminal_ids_to_keep(
            runtime.instances.iter().filter_map(|(id, instance)| {
                let control = runtime.controls.get(id);
                let reserved = control.is_some_and(|control| {
                    control.active
                        || control.desired
                        || control.process.is_some()
                        || control.lifecycle.cleanup_failed()
                });
                (!reserved)
                    .then_some(instance.ended_at)
                    .flatten()
                    .map(|ended| (id.clone(), ended))
            }),
            now_epoch(),
        );
        let evict: Vec<_> = runtime
            .instances
            .iter()
            .filter_map(|(id, instance)| {
                let reserved = runtime.controls.get(id).is_some_and(|control| {
                    control.active
                        || control.desired
                        || control.process.is_some()
                        || control.lifecycle.cleanup_failed()
                });
                (!reserved && instance.ended_at.is_some() && !keep.contains(id))
                    .then_some(id.clone())
            })
            .collect();
        for id in evict {
            runtime.instances.remove(&id);
            runtime.controls.remove(&id);
        }
        runtime.instances.values().cloned().collect()
    }

    pub async fn logs(
        &self,
        instance_id: Option<&str>,
        limit: usize,
    ) -> openfortivpn_manager_core::domain::LogSnapshot {
        let runtime = self.runtime.lock().await;
        runtime.logs.recent(instance_id, limit)
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
        let metadata = self
            .engine_metadata
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        EngineInfo {
            platform: std::env::consts::OS.to_string(),
            path: self.engine.to_string_lossy().into_owned(),
            available: self.engine.is_file(),
            version: metadata
                .as_ref()
                .map_or_else(|| "unknown (not probed)".into(), |m| m.version.clone()),
            event_protocol: metadata.as_ref().and_then(|m| m.event_protocol),
            manager_launch_gate: metadata.as_ref().is_some_and(|m| m.manager_launch_gate),
            requires_elevation: true,
        }
    }

    pub async fn probe_engine(&self) -> Result<()> {
        let engine = self.engine.clone();
        let metadata =
            tokio::task::spawn_blocking(move || openfortivpn_manager_core::engine::probe(&engine))
                .await??;
        *self
            .engine_metadata
            .lock()
            .map_err(|_| anyhow!("engine metadata lock poisoned"))? = Some(metadata);
        Ok(())
    }

    pub async fn save_profile(
        self: &Arc<Self>,
        input: crate::model::SaveProfileInput,
    ) -> Result<ProfileView> {
        let profile = input.profile.id.clone();
        let manager = self.clone();
        self.commands
            .dispatch(
                &profile,
                async move { manager.save_profile_inner(input).await },
            )
            .await?
    }

    async fn save_profile_inner(
        &self,
        mut input: crate::model::SaveProfileInput,
    ) -> Result<ProfileView> {
        if self.is_active(&input.profile.id).await {
            return Err(ControlError::new(
                ErrorCode::ProfileBusy,
                "disconnect the profile before editing it",
            )
            .into());
        }
        self.storage.save_profile_expected(
            input.profile.clone(),
            input.password.take(),
            input.remember_password,
            input.expected_revision,
        )
    }

    pub async fn delete_profile(self: &Arc<Self>, profile_id: &str) -> Result<bool> {
        self.delete_profile_expected(profile_id, None, true).await
    }

    pub async fn delete_profile_expected(
        self: &Arc<Self>,
        profile_id: &str,
        expected_revision: Option<u64>,
        stop_first: bool,
    ) -> Result<bool> {
        let manager = self.clone();
        let profile = profile_id.to_string();
        self.commands
            .dispatch(profile_id, async move {
                manager
                    .delete_profile_inner(&profile, expected_revision, stop_first)
                    .await
            })
            .await?
    }

    async fn delete_profile_inner(
        &self,
        profile_id: &str,
        expected_revision: Option<u64>,
        stop_first: bool,
    ) -> Result<bool> {
        let profiles = self.storage.load_profiles()?;
        let Some(profile) = profiles.get(profile_id) else {
            return Ok(false);
        };
        openfortivpn_manager_core::profile_service::check_delete(
            profile,
            expected_revision,
            self.is_active(profile_id).await,
            stop_first,
        )?;
        self.disconnect_inner(profile_id).await?;
        let removed = self
            .storage
            .delete_profile_expected(profile_id, expected_revision)?;
        if removed {
            let mut runtime = self.runtime.lock().await;
            runtime.controls.remove(profile_id);
            runtime.instances.remove(profile_id);
        }
        Ok(removed)
    }

    pub async fn connect(self: &Arc<Self>, profile_id: &str) -> Result<InstanceView> {
        self.connect_with_origin(
            profile_id,
            openfortivpn_manager_core::connection_service::StartOrigin::User,
        )
        .await
    }

    async fn connect_with_origin(
        self: &Arc<Self>,
        profile_id: &str,
        origin: openfortivpn_manager_core::connection_service::StartOrigin,
    ) -> Result<InstanceView> {
        let manager = self.clone();
        let profile = profile_id.to_string();
        self.commands
            .dispatch(profile_id, async move {
                manager.connect_inner_with_origin(&profile, origin).await
            })
            .await?
    }

    async fn connect_inner(self: &Arc<Self>, profile_id: &str) -> Result<InstanceView> {
        self.connect_inner_with_origin(
            profile_id,
            openfortivpn_manager_core::connection_service::StartOrigin::User,
        )
        .await
    }

    async fn connect_inner_with_origin(
        self: &Arc<Self>,
        profile_id: &str,
        origin: openfortivpn_manager_core::connection_service::StartOrigin,
    ) -> Result<InstanceView> {
        if !self.engine.is_file() {
            bail!("openfortivpn engine not found: {}", self.engine.display());
        }
        let (profile, password) = self.storage.profile_and_password(profile_id)?;
        drop(Zeroizing::new(password));

        let mut runtime = self.runtime.lock().await;
        {
            use openfortivpn_manager_core::connection_service::{
                self, ConnectDecision, ConnectFacts, ConnectionOwner, OwnershipState,
            };
            let owners = runtime
                .controls
                .iter()
                .filter_map(|(id, control)| {
                    let view = runtime.instances.get(id);
                    let state = if control.lifecycle.cleanup_failed() {
                        OwnershipState::RecoveryRequired
                    } else if !(control.active || control.process.is_some() || control.desired) {
                        return None;
                    } else if !control.desired
                        || view.is_some_and(|view| view.status == InstanceStatus::Disconnecting)
                    {
                        OwnershipState::Stopping
                    } else if view.is_some() {
                        OwnershipState::Healthy
                    } else {
                        OwnershipState::StartingReservation
                    };
                    Some(ConnectionOwner {
                        profile_id: id,
                        instance_id: view.map(|view| view.id.as_str()),
                        state,
                    })
                })
                .collect::<Vec<_>>();
            let facts = ConnectFacts {
                profile_id,
                // Storage has already validated and loaded this profile and
                // credential under its transaction lock before runtime admission.
                profile_exists: true,
                shutting_down: runtime.shutting_down,
                repository_recovery_required: false,
                repository_restoring: false,
                profile_mutating: false,
                orphaned_recovery: false,
                owners: &owners,
            };
            if let ConnectDecision::Reuse(id) = connection_service::admit(&facts, origin)? {
                return runtime
                    .instances
                    .get(profile_id)
                    .filter(|view| view.id == id)
                    .cloned()
                    .ok_or_else(|| {
                        ControlError::new(
                            ErrorCode::RecoveryRequired,
                            "published connection ownership is inconsistent",
                        )
                        .into()
                    });
            }
        }
        // Admission and reservation use this same runtime lock. A concurrent
        // profile command cannot observe an unreserved admitted start.
        let control = runtime.controls.entry(profile_id.to_string()).or_default();
        control.generation = control.generation.saturating_add(1);
        control.desired = true;
        control.active = true;
        control.lifecycle = Default::default();
        control.reconnect_blocked = false;
        control.process = None;
        let generation = control.generation;
        let instance = InstanceView {
            id: Uuid::new_v4().to_string(),
            profile_generation: generation,
            attempt_sequence: 1,
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
        let manager = self.clone();
        let profile_id = profile_id.to_string();
        let instance_id = instance.id.clone();
        let supervisor = tokio::spawn(async move {
            manager.supervise(profile_id, generation, instance_id).await;
        });
        // Register under the same lock as admission. Shutdown cannot miss an
        // admitted child whose task has not yet been added to its join set.
        runtime.supervisors.retain(|task| !task.is_finished());
        runtime.supervisors.push(supervisor);
        drop(runtime);
        Ok(instance)
    }

    pub async fn disconnect(self: &Arc<Self>, profile_id: &str) -> Result<()> {
        let manager = self.clone();
        let profile = profile_id.to_string();
        self.commands
            .dispatch(profile_id, async move {
                manager.disconnect_inner(&profile).await
            })
            .await?
    }

    async fn disconnect_inner(&self, profile_id: &str) -> Result<()> {
        let process = {
            let mut runtime = self.runtime.lock().await;
            let Some(control) = runtime.controls.get_mut(profile_id) else {
                return Ok(());
            };
            control.desired = false;
            control.cancelled.notify_waiters();
            // Generation and process ownership belong to the supervisor until
            // Child::wait and stream draining have completed.
            let process = control.process;
            if let Some(instance) = runtime.instances.get_mut(profile_id) {
                if instance.ended_at.is_none() {
                    instance.status = InstanceStatus::Disconnecting;
                    instance.message = "waiting for process exit and cleanup".into();
                    instance.revision = instance.revision.saturating_add(1);
                }
            }
            process
        };
        self.changed.notify_waiters();
        if let Some(process) = process {
            stop_owned_process(process, Duration::from_secs(5)).await?;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        while self.is_active(profile_id).await {
            if tokio::time::Instant::now() >= deadline {
                return Err(ControlError::new(
                    ErrorCode::RecoveryRequired,
                    "process cleanup has not been confirmed",
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    pub async fn reconnect(self: &Arc<Self>, profile_id: &str) -> Result<InstanceView> {
        let manager = self.clone();
        let profile = profile_id.to_string();
        self.commands
            .dispatch(profile_id, async move {
                manager.disconnect_inner(&profile).await?;
                manager.connect_inner(&profile).await
            })
            .await?
    }

    pub async fn auto_connect(self: &Arc<Self>) {
        if let Ok(profiles) = self.storage.load_profiles() {
            for profile in profiles
                .into_values()
                .filter(|profile| profile.auto_connect)
            {
                if let Err(error) = self
                    .connect_with_origin(
                        &profile.id,
                        openfortivpn_manager_core::connection_service::StartOrigin::Startup,
                    )
                    .await
                {
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

    pub async fn shutdown(self: &Arc<Self>) {
        let profile_ids = {
            let mut runtime = self.runtime.lock().await;
            runtime.shutting_down = true;
            for control in runtime.controls.values_mut() {
                control.desired = false;
                control.cancelled.notify_waiters();
            }
            runtime.controls.keys().cloned().collect::<Vec<_>>()
        };
        self.changed.notify_waiters();
        // A single deadline applies to the whole shutdown, not N sequential timeouts.
        let shutdown = async {
            let mut stops = tokio::task::JoinSet::new();
            for profile_id in profile_ids {
                let manager = self.clone();
                stops.spawn(async move { manager.disconnect(&profile_id).await });
            }
            while let Some(result) = stops.join_next().await {
                if let Err(error) = result
                    .map_err(anyhow::Error::from)
                    .and_then(|result| result)
                {
                    self.append_log(
                        "system",
                        "manager",
                        format!("shutdown recovery required: {error}"),
                    )
                    .await;
                }
            }
        };
        if tokio::time::timeout(Duration::from_secs(30), shutdown)
            .await
            .is_err()
        {
            self.append_log(
                "system",
                "manager",
                "shutdown deadline exceeded; recovery required".into(),
            )
            .await;
        }
        let supervisors = std::mem::take(&mut self.runtime.lock().await.supervisors);
        for supervisor in supervisors {
            let _ = supervisor.await;
        }
        // serve retains its cross-process service lock until this returns.
        // A timeout reports uncertainty; it cannot release a worker's owner.
        self.native_workers.wait().await;
    }

    async fn is_active(&self, profile_id: &str) -> bool {
        self.runtime
            .lock()
            .await
            .controls
            .get(profile_id)
            .is_some_and(|control| control.desired || control.active || control.process.is_some())
    }

    async fn supervise(
        self: Arc<Self>,
        profile_id: String,
        generation: u64,
        mut instance_id: String,
    ) {
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
                let cancellation = self
                    .runtime
                    .lock()
                    .await
                    .controls
                    .get(&profile_id)
                    .map(|c| c.cancelled.clone())
                    .unwrap_or_default();
                let cancelled = cancellation.notified();
                tokio::pin!(cancelled);
                cancelled.as_mut().enable();
                if self.is_current(&profile_id, generation).await {
                    tokio::select! { _ = tokio::time::sleep(delay) => {}, _ = &mut cancelled => {} }
                }
                if !self.is_current(&profile_id, generation).await {
                    self.mark_disconnected(&profile_id, Some(&instance_id), "disconnected")
                        .await;
                    return;
                }
                // A retry is a new child attempt under the same user intent.
                // Never reuse its journal/cursor identity for the next process.
                let mut runtime = self.runtime.lock().await;
                if let Some(instance) = runtime.instances.get_mut(&profile_id) {
                    if instance.id != instance_id {
                        return;
                    }
                    instance_id = Uuid::new_v4().to_string();
                    instance.id = instance_id.clone();
                    instance.attempt_sequence = instance.attempt_sequence.saturating_add(1);
                    instance.started_at = now_epoch();
                    instance.ended_at = None;
                    instance.pid = 0;
                    instance.exit_code = None;
                    instance.revision = instance.revision.saturating_add(1);
                } else {
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
        let gated_launch = self.engine_info().manager_launch_gate;
        let password = Zeroizing::new(password);
        let config_path = self
            .storage
            .write_runtime_config(&profile, &password, instance_id)?;
        let _config_guard = RuntimeConfigGuard(config_path.clone());
        let mut record = RecoveryRecord {
            schema_version: 1,
            attempt_id: instance_id.into(),
            profile_id: profile_id.into(),
            generation,
            started_at: now_epoch(),
            engine: self.engine.clone(),
            boot_id: boot_identity(),
            process: None,
        };
        self.storage.write_run_record(instance_id, &record)?;
        let lease_result = (|| -> Result<_> {
            let network_lease = if let Some(directory) = &self.network_authority {
                if directory
                    == std::path::Path::new(
                        openfortivpn_manager_core::network_authority::SYSTEM_DIRECTORY,
                    )
                {
                    openfortivpn_manager_core::network_authority::system_directory()?;
                }
                Some(
                    openfortivpn_manager_core::network_authority::ExclusiveLease::acquire(
                        directory,
                        openfortivpn_manager_core::network_authority::Owner {
                            attempt_id: instance_id.into(),
                            manager: "headless".into(),
                            uid: unsafe { nix::libc::geteuid() },
                            process_group: 0,
                            pre_spawn_gated: gated_launch,
                        },
                    )?,
                )
            } else {
                None
            };
            Ok(network_lease)
        })();
        let mut network_lease = match lease_result {
            Ok(lease) => lease,
            Err(error) => {
                let uncertain = self.network_authority.as_ref().is_some_and(|directory| {
                    match openfortivpn_manager_core::network_authority::inspect(directory) {
                        Ok(Some(owner)) => owner.attempt_id == instance_id,
                        Ok(None) => false,
                        Err(_) => true,
                    }
                });
                if uncertain {
                    self.retain_recovery(profile_id, generation).await;
                } else {
                    self.storage.remove_run_record(instance_id)?;
                }
                return Err(error);
            }
        };
        let mut command = Command::new(&self.engine);
        command
            .arg("--json-events")
            .arg("-c")
            .arg(&config_path)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if self.experimental_control {
            command
                .arg("--manager-control")
                .arg(instance_id)
                .stdin(Stdio::piped());
        }
        command.as_std_mut().process_group(0);
        let launch_gate = match if gated_launch {
            openfortivpn_manager_core::supervisor::LaunchGate::prepare(command.as_std_mut())
                .map(Some)
        } else {
            Ok(None)
        } {
            Ok(gate) => gate,
            Err(error) => {
                self.finish_unstarted_attempt(
                    profile_id,
                    generation,
                    instance_id,
                    network_lease.take(),
                )
                .await?;
                return Err(error.into());
            }
        };
        let mut child = match command.spawn() {
            Ok(child) => openfortivpn_manager_core::supervisor::AsyncOwnedProcess::new(child),
            Err(error) => {
                self.finish_unstarted_attempt(
                    profile_id,
                    generation,
                    instance_id,
                    network_lease.take(),
                )
                .await?;
                return Err(error)
                    .with_context(|| format!("failed to start {}", self.engine.display()));
            }
        };
        let pid = child.id().ok_or_else(|| anyhow!("engine has no PID"))?;
        drop(command);
        let channel = child.stdin.take().map(|stdin| Arc::new(Mutex::new(stdin)));
        let process = match capture_engine_process(pid as i32, &self.engine) {
            Ok(process) => process,
            Err(error) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                self.retain_recovery(profile_id, generation).await;
                return Err(error);
            }
        };
        record.process = Some(process);
        let persisted = self
            .storage
            .write_run_record(instance_id, &record)
            .and_then(|_| {
                if let Some(lease) = network_lease.as_mut() {
                    lease.bind_process_group(pid)?;
                }
                Ok(())
            })
            .and_then(|_| {
                launch_gate
                    .map_or(Ok(()), |gate| gate.release())
                    .map_err(Into::into)
            });
        if let Err(error) = persisted {
            let _ = signal_owned_process(process, Signal::SIGKILL);
            let _ = child.wait().await;
            self.retain_recovery(profile_id, generation).await;
            return Err(error);
        }
        let cancelled = {
            let mut runtime = self.runtime.lock().await;
            let control = runtime
                .controls
                .get_mut(profile_id)
                .ok_or_else(|| anyhow!("missing profile control"))?;
            let cancelled = control.generation != generation || !control.desired;
            control.process = Some(process);
            control.channel = channel;
            control.lifecycle = openfortivpn_manager_core::lifecycle::EngineLifecycle::for_attempt(
                instance_id,
                self.experimental_control,
            );
            control.native_admission = None;
            control.native_selected = false;
            control.native_applied = false;
            control.native_acknowledged = false;
            control.native_request = None;
            control.native_released = false;
            if let Some(instance) = runtime.instances.get_mut(profile_id) {
                if instance.id == instance_id {
                    instance.pid = pid;
                    instance.status = if cancelled {
                        InstanceStatus::Disconnecting
                    } else {
                        InstanceStatus::Connecting
                    };
                    instance.message = "openfortivpn started".to_string();
                    instance.revision = instance.revision.saturating_add(1);
                }
            }
            cancelled
        };
        if cancelled {
            let _ = signal_owned_process(process, Signal::SIGTERM);
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
        let output_incomplete = !openfortivpn_manager_core::supervisor::drain_tasks(
            [stdout_task, stderr_task].into_iter().flatten(),
            Duration::from_secs(2),
        )
        .await;
        // Aborting a stream reader cannot cancel a running blocking syscall.
        // Retain the process/network reservation until every worker has joined.
        self.native_workers.wait().await;
        if output_incomplete {
            self.append_log(
                instance_id,
                "manager",
                "engine output drain incomplete".into(),
            )
            .await;
        }

        {
            let mut runtime = self.runtime.lock().await;
            if let Some(control) = runtime.controls.get_mut(profile_id) {
                if control.generation == generation {
                    control.process = None;
                    control.channel = None;
                    if !control.lifecycle.reaped(
                        !output_incomplete,
                        status.signal() == Some(nix::libc::SIGKILL),
                    ) {
                        control.reconnect_blocked = true;
                    }
                    if !openfortivpn_manager_core::lifecycle::exit_retryable(status.code()) {
                        control.reconnect_blocked = true;
                    }
                }
            }
            runtime.challenges.cancel_attempt(profile_id, instance_id);
            if let Some(instance) = runtime.instances.get_mut(profile_id) {
                if instance.id == instance_id {
                    instance.exit_code = status.code();
                    instance.pid = 0;
                    instance.revision = instance.revision.saturating_add(1);
                }
            }
        }
        let cleanup_confirmed = self
            .runtime
            .lock()
            .await
            .controls
            .get(profile_id)
            .is_some_and(|control| {
                control.generation == generation
                    && !control.lifecycle.cleanup_failed()
                    && (!control.native_selected
                        || control.native_released
                        || !control
                            .native_admission
                            .as_ref()
                            .is_some_and(|admission| admission.started()))
            });
        if cleanup_confirmed {
            if let Some(lease) = network_lease.take() {
                if let Err(error) = lease.finish(true, true) {
                    self.retain_recovery(profile_id, generation).await;
                    return Err(error.into());
                }
            }
            if let Err(error) = self.storage.remove_run_record(instance_id) {
                self.retain_recovery(profile_id, generation).await;
                return Err(error);
            }
        }
        bail!(
            "openfortivpn exited with {}",
            status
                .code()
                .map_or_else(|| "signal".to_string(), |code| code.to_string())
        )
    }

    async fn retain_recovery(&self, profile_id: &str, generation: u64) {
        if let Some(control) = self.runtime.lock().await.controls.get_mut(profile_id) {
            if control.generation == generation {
                control.lifecycle.require_recovery();
                control.reconnect_blocked = true;
            }
        }
    }
    async fn finish_unstarted_attempt(
        &self,
        profile_id: &str,
        generation: u64,
        attempt: &str,
        lease: Option<openfortivpn_manager_core::network_authority::ExclusiveLease>,
    ) -> Result<()> {
        let outcome = lease
            .map_or(Ok(()), |lease| lease.finish(true, true).map_err(Into::into))
            .and_then(|_| self.storage.remove_run_record(attempt));
        if outcome.is_err() {
            self.retain_recovery(profile_id, generation).await;
        }
        outcome
    }

    async fn read_stream<R>(
        &self,
        instance_id: String,
        stream_name: &'static str,
        mut stream: R,
    ) -> bool
    where
        R: AsyncRead + Unpin,
    {
        let mut decoder = LineDecoder::default();
        let mut buffer = [0u8; 4096];
        let mut complete = true;
        loop {
            let length = match stream.read(&mut buffer).await {
                Ok(length) => length,
                Err(_) => return false,
            };
            let records = if length == 0 {
                decoder.eof().into_iter().collect()
            } else {
                decoder.feed(&buffer[..length])
            };
            for record in records {
                let line = match record {
                    Line::Text(line) => line,
                    Line::Oversized => {
                        complete = false;
                        self.append_log(
                            &instance_id,
                            "manager",
                            "oversized engine record discarded".into(),
                        )
                        .await;
                        self.block_reconnect_for_instance(&instance_id).await;
                        continue;
                    }
                    Line::InvalidUtf8 => {
                        complete = false;
                        self.append_log(
                            &instance_id,
                            "manager",
                            "invalid UTF-8 engine record discarded".into(),
                        )
                        .await;
                        continue;
                    }
                };
                self.append_log(
                    &instance_id,
                    stream_name,
                    openfortivpn_manager_core::protocol::redact(&line),
                )
                .await;
                if let Ok(event) = serde_json::from_str::<Value>(&line) {
                    self.apply_engine_event(&instance_id, &event).await;
                }
            }
            if length == 0 {
                return complete;
            }
        }
    }

    async fn append_log(&self, instance_id: &str, stream: &str, line: String) {
        let mut runtime = self.runtime.lock().await;
        runtime.logs.push(LogEvent {
            id: openfortivpn_manager_core::protocol::next_log_id(),
            instance_id: instance_id.to_string(),
            stream: stream.to_string(),
            line,
            timestamp: now_epoch(),
        });
    }

    async fn apply_engine_event(&self, instance_id: &str, event: &Value) {
        let mut rejected = false;
        let mut rejected_process = None;
        {
            let mut runtime = self.runtime.lock().await;
            let profile_id = runtime
                .instances
                .iter()
                .find_map(|(id, instance)| (instance.id == instance_id).then_some(id.clone()));
            if let Some(control) = profile_id.and_then(|id| runtime.controls.get_mut(&id)) {
                match control.lifecycle.observe(event) {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(_) => {
                        control.reconnect_blocked = true;
                        control.desired = false;
                        rejected = true;
                        rejected_process = control.process;
                    }
                }
                control.reconnect_blocked |= control.lifecycle.retry_blocked();
            }
        }
        if rejected {
            if let Some(process) = rejected_process {
                let _ = signal_owned_process(process, Signal::SIGTERM);
            }
            self.append_log(
                instance_id,
                "manager",
                "engine event contract failed; owned attempt stopped and recovery retained".into(),
            )
            .await;
            return;
        }
        if self.experimental_control
            && matches!(
                event["event"].as_str(),
                Some(
                    "auth_challenge"
                        | "auth_challenge_closed"
                        | "network_plan"
                        | "network_begin"
                        | "network_resource"
                        | "network_commit"
                        | "network_release"
                        | "network_applied"
                )
            )
        {
            if self.handle_control_event(instance_id, event).await.is_err() {
                let process = {
                    let mut runtime = self.runtime.lock().await;
                    let profile = runtime.instances.iter().find_map(|(id, instance)| {
                        (instance.id == instance_id).then_some(id.clone())
                    });
                    profile
                        .and_then(|profile| runtime.controls.get_mut(&profile))
                        .and_then(|control| {
                            control.lifecycle.require_recovery();
                            control.reconnect_blocked = true;
                            control.desired = false;
                            control.process
                        })
                };
                if let Some(process) = process {
                    let _ = signal_owned_process(process, Signal::SIGTERM);
                }
                self.append_log(
                    instance_id,
                    "manager",
                    "private engine control failed; recovery may be required".into(),
                )
                .await;
            }
            return;
        }
        let event_type = event
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if event_type == "tunnel_up" {
            let native_ready = {
                let runtime = self.runtime.lock().await;
                runtime
                    .instances
                    .iter()
                    .find_map(|(profile, instance)| {
                        (instance.id == instance_id).then(|| runtime.controls.get(profile))
                    })
                    .flatten()
                    .is_some_and(|control| {
                        self.native_network.is_none()
                            || (control.native_selected
                                && control.native_applied
                                && control.native_acknowledged
                                && !control.native_released)
                    })
            };
            if !native_ready {
                self.fail_private_control(instance_id).await;
                return;
            }
        }
        let state_name = event
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if event_type == "cleanup_result" {
            let native_unreleased = {
                let runtime = self.runtime.lock().await;
                runtime
                    .instances
                    .iter()
                    .find_map(|(profile, instance)| {
                        (instance.id == instance_id).then(|| runtime.controls.get(profile))
                    })
                    .flatten()
                    .is_some_and(|control| {
                        control.native_selected
                            && !control.native_released
                            && control
                                .native_admission
                                .as_ref()
                                .is_some_and(|admission| admission.started())
                    })
            };
            if native_unreleased {
                self.fail_private_control(instance_id).await;
            }
            return;
        }
        if event_type == "cert_error"
            || (event_type == "error"
                && (event.get("retryable").and_then(Value::as_bool) == Some(false)
                    || event.get("category").and_then(Value::as_str) == Some("auth")))
        {
            self.block_reconnect_for_instance(instance_id).await;
        }
        let (status, message) = match (event_type, state_name) {
            ("tunnel_up", _) => (
                InstanceStatus::Connected,
                "VPN tunnel connected".to_string(),
            ),
            ("state_change", "disconnecting") | ("tunnel_down", _) => (
                InstanceStatus::Disconnecting,
                "VPN tunnel is closing".to_string(),
            ),
            ("cert_error", _) => (
                InstanceStatus::Connecting,
                format!(
                    "untrusted certificate: {}",
                    event
                        .get("digest")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                ),
            ),
            ("error", _) => (
                InstanceStatus::Connecting,
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
            if instance.id == instance_id
                && instance.status != InstanceStatus::Disconnecting
                && instance.ended_at.is_none()
            {
                instance.status = status;
                instance.message = message;
                instance.revision = instance.revision.saturating_add(1);
                break;
            }
        }
    }

    async fn handle_control_event(&self, instance_id: &str, event: &Value) -> Result<()> {
        if matches!(
            event["event"].as_str(),
            Some(
                "network_begin"
                    | "network_resource"
                    | "network_commit"
                    | "network_release"
                    | "network_applied"
            )
        ) {
            return self.handle_native_event(instance_id, event).await;
        }
        let (channel, frame) = {
            let mut runtime = self.runtime.lock().await;
            let profile = runtime
                .instances
                .iter()
                .find_map(|(profile, instance)| {
                    (instance.id == instance_id).then_some(profile.clone())
                })
                .ok_or_else(|| anyhow!("obsolete control event"))?;
            if event["attemptId"].as_str() != Some(instance_id) {
                return Err(anyhow!("engine attempt mismatch"));
            }
            let control = runtime
                .controls
                .get(&profile)
                .ok_or_else(|| anyhow!("missing control"))?;
            let generation = control.generation;
            let desired = control.desired;
            let channel = control
                .channel
                .clone()
                .ok_or_else(|| anyhow!("missing private pipe"))?;
            let request = event["requestId"]
                .as_str()
                .ok_or_else(|| anyhow!("missing request identity"))?;
            match event["event"].as_str() {
                Some("auth_challenge_closed") => {
                    runtime.challenges.close(&profile, instance_id, request);
                    return Ok(());
                }
                Some("auth_challenge") => {
                    if !desired || event["kind"].as_str() != Some("otp") {
                        return Err(anyhow!("unexpected authentication challenge"));
                    }
                    let timeout = event["timeoutMs"]
                        .as_u64()
                        .ok_or_else(|| anyhow!("missing challenge deadline"))?;
                    let max_response = event["maxResponseBytes"]
                        .as_u64()
                        .filter(|value| *value <= 1024)
                        .ok_or_else(|| anyhow!("invalid response limit"))?
                        as usize;
                    let now = now_epoch().saturating_mul(1000);
                    runtime.challenges.register(
                        openfortivpn_manager_core::control::Challenge {
                            profile_id: profile.clone(),
                            attempt_id: instance_id.into(),
                            request_id: request.into(),
                            prompt: event["prompt"]
                                .as_str()
                                .ok_or_else(|| anyhow!("invalid prompt"))?
                                .into(),
                            expires_at_ms: now.saturating_add(timeout),
                            max_response_bytes: max_response,
                        },
                        generation,
                        now,
                    )?;
                    if let Some(instance) = runtime.instances.get_mut(&profile) {
                        instance.message = "Authentication input required".into();
                        instance.revision = instance.revision.saturating_add(1);
                    }
                    return Ok(());
                }
                Some("network_plan") => {
                    let exclusive = event["exclusiveRequired"].as_bool() == Some(true);
                    let no_other_owner = runtime.controls.iter().all(|(id, control)| {
                        id == &profile
                            || (!control.active
                                && !control.desired
                                && control.process.is_none()
                                && !control.lifecycle.cleanup_failed())
                    });
                    let decision = if desired && exclusive && no_other_owner {
                        if self.native_network.is_some() {
                            if event["resourceProtocol"].as_u64() != Some(1) {
                                return Err(anyhow!("engine does not support the requested native resource protocol"));
                            }
                            let control = runtime.controls.get_mut(&profile).unwrap();
                            if control.native_selected {
                                return Err(anyhow!("duplicate native lease request"));
                            }
                            control.native_selected = true;
                            control.native_admission =
                                Some(openfortivpn_manager_core::network_control::Admission::new(
                                    instance_id.into(),
                                    profile.clone(),
                                    generation,
                                ));
                            "grant_native"
                        } else {
                            "grant"
                        }
                    } else {
                        "deny"
                    };
                    (
                        channel,
                        openfortivpn_manager_core::control::frame(
                            instance_id,
                            request,
                            openfortivpn_manager_core::control::Command::LeaseDecision,
                            decision,
                        )?,
                    )
                }
                _ => return Err(anyhow!("unsupported control event")),
            }
        };
        use tokio::io::AsyncWriteExt;
        tokio::time::timeout(Duration::from_secs(5), async {
            channel.lock().await.write_all(frame.as_bytes()).await
        })
        .await
        .context("engine lease response timed out")??;
        Ok(())
    }

    async fn fail_private_control(&self, instance_id: &str) {
        let process = {
            let mut runtime = self.runtime.lock().await;
            let profile = runtime
                .instances
                .iter()
                .find_map(|(id, instance)| (instance.id == instance_id).then_some(id.clone()));
            profile
                .and_then(|id| runtime.controls.get_mut(&id))
                .and_then(|control| {
                    control.lifecycle.require_recovery();
                    control.reconnect_blocked = true;
                    control.desired = false;
                    control.process
                })
        };
        if let Some(process) = process {
            let _ = signal_owned_process(process, Signal::SIGTERM);
        }
    }

    async fn handle_native_event(&self, instance_id: &str, event: &Value) -> Result<()> {
        let driver = self
            .native_network
            .clone()
            .ok_or_else(|| anyhow!("native mode was not selected"))?;
        let name = event["event"]
            .as_str()
            .ok_or_else(|| anyhow!("missing native event"))?;
        let result_frame = if matches!(name, "network_commit" | "network_release") {
            Some(openfortivpn_manager_core::control::frame(
                instance_id,
                event["requestId"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing native request"))?,
                openfortivpn_manager_core::control::Command::NetworkResult,
                if name == "network_release" {
                    "released"
                } else {
                    "applied"
                },
            )?)
        } else {
            None
        };
        let epoch = if name == "network_commit" {
            let driver = driver.clone();
            self.native_workers.run(move || driver.epoch()).await??
        } else {
            0
        };
        let (profile, generation, channel, plan) = {
            let mut runtime = self.runtime.lock().await;
            let profile = runtime
                .instances
                .iter()
                .find_map(|(id, instance)| (instance.id == instance_id).then_some(id.clone()))
                .ok_or_else(|| anyhow!("obsolete native event"))?;
            let control = runtime
                .controls
                .get_mut(&profile)
                .ok_or_else(|| anyhow!("missing native attempt"))?;
            if !control.native_selected
                || control.native_released
                || event["attemptId"].as_str() != Some(instance_id)
            {
                bail!("native event is not bound to a selected attempt");
            }
            let channel = control
                .channel
                .clone()
                .ok_or_else(|| anyhow!("missing native response pipe"))?;
            let plan = match name {
                "network_applied" => {
                    if !control.native_applied
                        || control.native_acknowledged
                        || control.native_released
                        || event["success"].as_bool() != Some(true)
                        || event["requestId"].as_str() != control.native_request.as_deref()
                    {
                        bail!("engine application acknowledgement differs from manager commit");
                    }
                    control.native_acknowledged = true;
                    return Ok(());
                }
                "network_release" => {
                    if !control
                        .native_admission
                        .as_ref()
                        .is_some_and(|admission| admission.started())
                    {
                        bail!("duplicate or premature native release");
                    }
                    None
                }
                _ => {
                    if !control.desired {
                        bail!("cancelled attempt cannot apply native resources");
                    }
                    let plan = control
                        .native_admission
                        .as_mut()
                        .ok_or_else(|| anyhow!("missing native admission"))?
                        .observe(event, epoch)?;
                    if plan.is_none() {
                        return Ok(());
                    }
                    control.native_request = event["requestId"].as_str().map(str::to_string);
                    plan
                }
            };
            (profile, control.generation, channel, plan)
        };
        let releasing = name == "network_release";
        let attempt = instance_id.to_string();
        // Await the worker through cleanup. A timeout/stop request cannot drop
        // its ownership or permit a second transaction while it still mutates.
        self.native_workers
            .run(move || {
                if let Some((plan, binding)) = plan {
                    driver.apply(plan, binding)
                } else {
                    driver.release(&attempt)
                }
            })
            .await??;
        {
            let mut runtime = self.runtime.lock().await;
            if runtime
                .instances
                .get(&profile)
                .is_none_or(|instance| instance.id != instance_id)
            {
                bail!("native worker belongs to an obsolete attempt");
            }
            let control = runtime
                .controls
                .get_mut(&profile)
                .ok_or_else(|| anyhow!("native attempt disappeared"))?;
            if control.generation != generation {
                bail!("native generation changed during transaction");
            }
            if releasing {
                control.native_released = true;
                control.native_applied = false;
                control.native_acknowledged = false;
            } else {
                control.native_applied = true;
            }
        }
        let frame = result_frame.ok_or_else(|| anyhow!("missing native result frame"))?;
        use tokio::io::AsyncWriteExt;
        tokio::time::timeout(Duration::from_secs(5), async {
            channel.lock().await.write_all(frame.as_bytes()).await
        })
        .await
        .context("native result delivery timed out")??;
        Ok(())
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
        if runtime
            .instances
            .get(profile_id)
            .is_none_or(|i| i.id != instance_id)
        {
            return;
        }
        let reaped = if let Some(control) = runtime.controls.get_mut(profile_id) {
            control.desired = false;
            control.active = control.process.is_some() || control.lifecycle.cleanup_failed();
            !control.active
        } else {
            true
        };
        if let Some(instance) = runtime.instances.get_mut(profile_id) {
            instance.status = InstanceStatus::Failed;
            instance.message = if reaped {
                message
            } else {
                format!("recovery required: {message}")
            };
            if reaped {
                instance.pid = 0;
                instance.ended_at = Some(now_epoch());
            }
            instance.revision = instance.revision.saturating_add(1);
        }
        self.changed.notify_waiters();
    }

    async fn mark_disconnected(&self, profile_id: &str, instance_id: Option<&str>, message: &str) {
        let mut runtime = self.runtime.lock().await;
        if runtime
            .instances
            .get(profile_id)
            .is_none_or(|i| instance_id.is_some_and(|id| i.id != id))
        {
            return;
        }
        if let Some(control) = runtime.controls.get_mut(profile_id) {
            if control.process.is_some() {
                return;
            }
            if control.lifecycle.cleanup_failed() {
                if let Some(instance) = runtime.instances.get_mut(profile_id) {
                    instance.status = InstanceStatus::Failed;
                    instance.message = "network cleanup failed; recovery required".into();
                    instance.revision = instance.revision.saturating_add(1);
                }
                return;
            }
            control.active = false;
            control.desired = false;
        }
        if let Some(instance) = runtime.instances.get_mut(profile_id) {
            instance.status = InstanceStatus::Disconnected;
            instance.message = message.to_string();
            instance.pid = 0;
            instance.ended_at = Some(now_epoch());
            instance.revision = instance.revision.saturating_add(1);
        }
        self.changed.notify_waiters();
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
    let mut killed = false;
    loop {
        let Some(snapshot) = inspect_process(process.pid)? else {
            return Ok(());
        };
        if !process.matches(snapshot) {
            return Ok(());
        }
        if !killed && started.elapsed() >= timeout {
            let _ = signal_owned_process(process, Signal::SIGKILL)?;
            killed = true;
        }
        if started.elapsed() >= timeout + Duration::from_secs(3) {
            return Err(ControlError::new(
                ErrorCode::RecoveryRequired,
                "process remained alive after SIGKILL",
            )
            .into());
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

    struct FakeNativeNetwork {
        applied: AtomicUsize,
        released: AtomicUsize,
        active: std::sync::Mutex<Option<String>>,
    }
    impl crate::native_network::NativeNetwork for FakeNativeNetwork {
        fn epoch(&self) -> std::result::Result<u64, ControlError> {
            Ok(7)
        }
        fn apply(
            &self,
            plan: openfortivpn_manager_core::network::Plan,
            binding: openfortivpn_manager_core::network_control::InterfaceBinding,
        ) -> std::result::Result<(), ControlError> {
            assert!(tokio::runtime::Handle::try_current().is_err());
            assert_eq!(plan.profile_id, "one");
            assert_eq!(plan.network_epoch, 7);
            assert_eq!(binding.interface, "ppp-test");
            assert_eq!(plan.resources.len(), 1);
            *self.active.lock().unwrap() = Some(plan.attempt_id);
            self.applied.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn release(&self, attempt: &str) -> std::result::Result<(), ControlError> {
            assert_eq!(self.active.lock().unwrap().as_deref(), Some(attempt));
            self.active.lock().unwrap().take();
            self.released.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn native_handshake_commits_before_ready_and_releases_before_global_owner() {
        for missing_release in [false, true] {
            let (root, fixture) = fixture_manager().await;
            let engine = root.path().join("native-engine");
            let script = r#"#!/bin/sh
attempt=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--manager-control" ]; then shift; attempt="$1"; fi
  shift
done
nonce=0123456789abcdef0123456789abcdef
emit() { echo "{\"protocolVersion\":2,\"attemptId\":\"$attempt\",\"requestId\":\"$nonce\",$1}" >&2; }
cleanup() {
 emit '"seq":7,"event":"network_release"'
 IFS= read -r answer
 [ "$answer" = "OFV2 $attempt $nonce network_result cmVsZWFzZWQ=" ] || exit 40
 emit '"seq":8,"event":"cleanup_result","success":true'
 exit 0
}
trap cleanup TERM
emit '"seq":0,"event":"network_plan","exclusiveRequired":true,"resourceProtocol":1'
IFS= read -r answer
[ "$answer" = "OFV2 $attempt $nonce lease_decision Z3JhbnRfbmF0aXZl" ] || exit 40
emit '"seq":1,"event":"network_begin","resourceCount":1,"binding":{"interface":"ppp-test","index":17,"localAddress":"10.1.1.2","transportAddress":"192.0.2.9"}'
emit '"seq":2,"event":"network_resource","ordinal":0,"resource":{"kind":"route","spec":{"destination":"10.0.0.0/8","interface":"ppp-test","gateway":null,"metric":0,"gatewayException":false}}'
emit '"seq":3,"event":"network_commit"'
IFS= read -r answer
[ "$answer" = "OFV2 $attempt $nonce network_result YXBwbGllZA==" ] || exit 40
emit '"seq":4,"event":"network_applied","success":true'
emit '"seq":5,"event":"tunnel_up"'
while :; do sleep 0.05; done
"#;
            let script = if missing_release {
                script.replace(
                    "while :; do sleep 0.05; done",
                    "emit '\"seq\":6,\"event\":\"cleanup_result\",\"success\":true'\nexit 0",
                )
            } else {
                script.to_string()
            };
            fs::write(&engine, script).unwrap();
            fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
            let authority = root.path().join("native-authority");
            fs::create_dir(&authority).unwrap();
            fs::set_permissions(&authority, fs::Permissions::from_mode(0o700)).unwrap();
            let driver = Arc::new(FakeNativeNetwork {
                applied: AtomicUsize::new(0),
                released: AtomicUsize::new(0),
                active: Default::default(),
            });
            let mut manager =
                VpnManager::with_retry_delays(fixture.storage.clone(), engine, vec![])
                    .with_experimental_control(true)
                    .with_network_authority(authority.clone());
            manager.native_network = Some(driver.clone());
            let manager = Arc::new(manager);
            manager.connect("one").await.unwrap();
            if missing_release {
                for _ in 0..100 {
                    if driver.applied.load(Ordering::SeqCst) == 1
                        && manager.instances().await[0].pid == 0
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert_eq!(driver.applied.load(Ordering::SeqCst), 1);
                assert_eq!(driver.released.load(Ordering::SeqCst), 0);
                assert!(manager.runtime.lock().await.controls["one"]
                    .lifecycle
                    .cleanup_failed());
                assert!(!manager.recovery_records().unwrap().is_empty());
                assert!(
                    openfortivpn_manager_core::network_authority::inspect(&authority)
                        .unwrap()
                        .is_some()
                );
                continue;
            }
            for _ in 0..100 {
                if manager.instances().await[0].status == InstanceStatus::Connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(
                manager.instances().await[0].status,
                InstanceStatus::Connected
            );
            assert_eq!(driver.applied.load(Ordering::SeqCst), 1);
            assert!(
                openfortivpn_manager_core::network_authority::inspect(&authority)
                    .unwrap()
                    .is_some()
            );
            manager.disconnect("one").await.unwrap();
            assert_eq!(driver.released.load(Ordering::SeqCst), 1);
            assert!(driver.active.lock().unwrap().is_none());
            assert!(
                openfortivpn_manager_core::network_authority::inspect(&authority)
                    .unwrap()
                    .is_none()
            );
            assert!(manager.recovery_records().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn private_otp_and_pre_adapter_lease_flow_without_persisting_responses() {
        let (root, manager) = fixture_manager().await;
        let engine = root.path().join("controlled-engine");
        fs::write(&engine,r#"#!/bin/sh
attempt=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--manager-control" ]; then shift; attempt="$1"; fi
  shift
done
nonce=0123456789abcdef0123456789abcdef
trap 'echo "{\"protocolVersion\":2,\"attemptId\":\"'$attempt'\",\"seq\":9,\"event\":\"cleanup_result\",\"success\":true}" >&2; exit 0' TERM
echo "{\"protocolVersion\":2,\"attemptId\":\"$attempt\",\"seq\":0,\"event\":\"auth_challenge\",\"kind\":\"otp\",\"requestId\":\"$nonce\",\"prompt\":\"Synthetic token challenge\",\"timeoutMs\":120000,\"maxResponseBytes\":64}" >&2
IFS= read -r answer
[ "$answer" = "OFV2 $attempt $nonce auth_response c3ludGhldGljLW90cA==" ] || exit 20
unset answer
echo "{\"protocolVersion\":2,\"attemptId\":\"$attempt\",\"seq\":1,\"event\":\"auth_challenge_closed\",\"requestId\":\"$nonce\",\"accepted\":true}" >&2
echo "{\"protocolVersion\":2,\"attemptId\":\"$attempt\",\"seq\":2,\"event\":\"network_plan\",\"requestId\":\"$nonce\",\"exclusiveRequired\":true,\"timeoutMs\":30000}" >&2
IFS= read -r answer
[ "$answer" = "OFV2 $attempt $nonce lease_decision Z3JhbnQ=" ] || exit 40
unset answer
echo "{\"protocolVersion\":2,\"attemptId\":\"$attempt\",\"seq\":3,\"event\":\"tunnel_up\"}" >&2
while :; do sleep 0.05; done
"#).unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
        let manager = Arc::new(
            VpnManager::with_retry_delays(manager.storage.clone(), engine, vec![])
                .with_experimental_control(true),
        );
        manager.connect("one").await.unwrap();
        let mut challenge = None;
        for _ in 0..100 {
            challenge = manager.authentication_challenges().await.pop();
            if challenge.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let challenge = challenge.expect("engine challenge was not exposed");
        let input = |attempt: String| openfortivpn_manager_core::control::AuthResponse {
            profile_id: "one".into(),
            attempt_id: attempt,
            request_id: challenge.request_id.clone(),
            response: "synthetic-otp".into(),
        };
        assert!(manager
            .respond_to_authentication(input(Uuid::new_v4().to_string()))
            .await
            .is_err());
        manager
            .respond_to_authentication(input(challenge.attempt_id.clone()))
            .await
            .unwrap();
        assert!(manager
            .respond_to_authentication(input(challenge.attempt_id))
            .await
            .is_err());
        for _ in 0..100 {
            if manager.instances().await[0].status == InstanceStatus::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            manager.instances().await[0].status,
            InstanceStatus::Connected
        );
        assert!(manager.authentication_challenges().await.is_empty());
        assert!(!serde_json::to_string(&manager.snapshot().await.unwrap())
            .unwrap()
            .contains("synthetic-otp"));
        assert_eq!(
            manager.storage.profile_and_password("one").unwrap().1,
            "synthetic-secret"
        );
        manager.disconnect("one").await.unwrap();
        assert!(manager.recovery_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pipe_errors_and_malformed_output_never_confirm_complete_cleanup() {
        use tokio::io::AsyncWriteExt;
        let (_root, manager) = fixture_manager().await;
        for bytes in [b"\xff\n".as_slice(), &vec![b'a'; 65537]] {
            let (read, mut write) = tokio::io::duplex(131072);
            write.write_all(bytes).await.unwrap();
            drop(write);
            assert!(
                !manager
                    .read_stream("synthetic".into(), "stderr", read)
                    .await
            );
        }
        struct Broken;
        impl AsyncRead for Broken {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("injected pipe error")))
            }
        }
        assert!(
            !manager
                .read_stream("synthetic".into(), "stderr", Broken)
                .await
        );
        assert!(
            manager
                .read_stream("synthetic".into(), "stderr", tokio::io::empty())
                .await
        );
    }

    fn profile(id: &str) -> VpnProfile {
        VpnProfile {
            id: id.into(),
            revision: 0,
            name: id.into(),
            host: "vpn.example.com".into(),
            port: 443,
            username: "alice".into(),
            realm: String::new(),
            trusted_cert: String::new(),
            credential_ref: None,
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

    async fn fixture_manager() -> (tempfile::TempDir, Arc<VpnManager>) {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        for id in ["one", "two"] {
            storage
                .save_profile(profile(id), Some("synthetic-secret".into()), true)
                .unwrap();
        }
        let engine = root.path().join("engine");
        fs::write(&engine, "#!/bin/sh\ntrap 'sleep 0.2; echo '\"'\"'{\"protocolVersion\":2,\"seq\":1,\"event\":\"cleanup_result\",\"success\":true}'\"'\"' >&2; exit 0' TERM\necho '{\"protocolVersion\":2,\"seq\":0,\"event\":\"tunnel_up\"}' >&2\nwhile :; do sleep 0.05; done\n").unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
        let manager = Arc::new(VpnManager::with_retry_delays(storage, engine, vec![]));
        (root, manager)
    }

    fn unfinished_record(manager: &VpnManager, profile_id: &str) -> RecoveryRecord {
        RecoveryRecord {
            schema_version: 1,
            attempt_id: Uuid::new_v4().to_string(),
            profile_id: profile_id.into(),
            generation: 7,
            started_at: now_epoch(),
            engine: manager.engine.clone(),
            boot_id: boot_identity(),
            process: None,
        }
    }

    #[tokio::test]
    async fn offline_acknowledgement_retains_local_anchor_when_global_owner_is_missing_but_native_evidence_remains(
    ) {
        let (root, manager) = fixture_manager().await;
        let directory = root.path().join("native-authority");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let record = unfinished_record(&manager, "one");
        manager
            .storage
            .write_run_record(&record.attempt_id, &record)
            .unwrap();
        let binding = directory.join(format!("binding-{}.json", record.attempt_id));
        openfortivpn_manager_core::atomic_file::write_private(&binding, b"interrupted binding")
            .unwrap();
        assert!(acknowledge_recovery_at(&manager.storage, &record.attempt_id, &directory).is_err());
        assert_eq!(manager.recovery_records().unwrap().len(), 1);
        assert!(binding.exists());
        fs::remove_file(binding).unwrap();
        acknowledge_recovery_at(&manager.storage, &record.attempt_id, &directory).unwrap();
        assert!(manager.recovery_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_exec_releases_the_unstarted_reservation_and_allows_a_later_real_attempt() {
        let (root, fixture) = fixture_manager().await;
        let authority = root.path().join("network-authority");
        fs::create_dir(&authority).unwrap();
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o700)).unwrap();
        let missing = root.path().join("initially-unavailable-engine");
        fs::write(&missing, b"synthetic non-executable payload").unwrap();
        fs::set_permissions(&missing, fs::Permissions::from_mode(0o600)).unwrap();
        let manager = Arc::new(
            VpnManager::with_retry_delays(fixture.storage.clone(), missing.clone(), vec![])
                .with_network_authority(authority.clone()),
        );
        manager.connect("one").await.unwrap();
        for _ in 0..200 {
            if manager.instances().await[0].status == InstanceStatus::Failed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(manager.instances().await[0].status, InstanceStatus::Failed);
        assert_eq!(manager.instances().await[0].pid, 0);
        assert!(manager.recovery_records().unwrap().is_empty());
        assert!(
            openfortivpn_manager_core::network_authority::inspect(&authority)
                .unwrap()
                .is_none()
        );
        let legacy = fs::read_to_string(&fixture.engine).unwrap().replacen(
            "#!/bin/sh\n",
            "#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in --manager-launch-fd=*) exit 30 ;; esac; done\n",
            1,
        );
        fs::write(&fixture.engine, legacy).unwrap();
        fs::rename(&fixture.engine, missing).unwrap();
        manager.connect("two").await.unwrap();
        for _ in 0..200 {
            if manager
                .instances()
                .await
                .iter()
                .any(|i| i.profile_id == "two" && i.status == InstanceStatus::Connected)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(manager
            .instances()
            .await
            .iter()
            .any(|i| i.profile_id == "two" && i.status == InstanceStatus::Connected));
        assert!(
            !openfortivpn_manager_core::network_authority::inspect(&authority)
                .unwrap()
                .unwrap()
                .pre_spawn_gated
        );
        manager.shutdown().await;
        assert!(manager.recovery_records().unwrap().is_empty());
        assert!(
            openfortivpn_manager_core::network_authority::inspect(&authority)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn failed_global_release_never_deletes_the_local_recovery_anchor() {
        use openfortivpn_manager_core::network_authority::{ExclusiveLease, Owner};
        let (root, manager) = fixture_manager().await;
        let authority = root.path().join("network-authority");
        fs::create_dir(&authority).unwrap();
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o700)).unwrap();
        let record = unfinished_record(&manager, "one");
        manager
            .storage
            .write_run_record(&record.attempt_id, &record)
            .unwrap();
        let lease = ExclusiveLease::acquire(
            &authority,
            Owner {
                attempt_id: record.attempt_id.clone(),
                manager: "headless".into(),
                uid: unsafe { nix::libc::geteuid() },
                process_group: 0,
                pre_spawn_gated: true,
            },
        )
        .unwrap();
        // A durable ownership mismatch/uncertain global record is a real I/O
        // recovery failure; the local attempt must remain operator-addressable.
        openfortivpn_manager_core::atomic_file::write_private(
            &authority.join("active.json"),
            b"corrupt",
        )
        .unwrap();
        assert!(manager
            .finish_unstarted_attempt("one", 7, &record.attempt_id, Some(lease))
            .await
            .is_err());
        assert_eq!(
            manager.recovery_records().unwrap()[0].attempt_id,
            record.attempt_id
        );
    }

    #[tokio::test]
    async fn independent_managers_share_one_system_network_authority() {
        let (first_root, first) = fixture_manager().await;
        let (_second_root, second) = fixture_manager().await;
        let authority = first_root.path().join("network-authority");
        fs::create_dir(&authority).unwrap();
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o700)).unwrap();
        let first = Arc::new(
            VpnManager::with_retry_delays(first.storage.clone(), first.engine.clone(), vec![])
                .with_network_authority(authority.clone()),
        );
        let second = Arc::new(
            VpnManager::with_retry_delays(second.storage.clone(), second.engine.clone(), vec![])
                .with_network_authority(authority.clone()),
        );
        first.connect("one").await.unwrap();
        for _ in 0..200 {
            if first.instances().await[0].status == InstanceStatus::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(first.instances().await[0].status, InstanceStatus::Connected);
        second.connect("two").await.unwrap();
        for _ in 0..200 {
            if second.instances().await[0].status == InstanceStatus::Failed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let rejected = &second.instances().await[0];
        assert_eq!(rejected.status, InstanceStatus::Failed);
        assert_eq!(rejected.pid, 0);
        assert!(rejected.message.contains("system network"));
        assert!(second.recovery_records().unwrap().is_empty());
        first.shutdown().await;
        assert!(
            openfortivpn_manager_core::network_authority::inspect(&authority)
                .unwrap()
                .is_none()
        );
        second.connect("two").await.unwrap();
        for _ in 0..200 {
            if second.instances().await[0].status == InstanceStatus::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            second.instances().await[0].status,
            InstanceStatus::Connected
        );
        second.shutdown().await;
        assert!(
            openfortivpn_manager_core::network_authority::inspect(&authority)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn crash_before_identity_capture_blocks_auto_connect_and_other_profiles() {
        let (_root, manager) = fixture_manager().await;
        let record = unfinished_record(&manager, "one");
        manager
            .storage
            .write_run_record(&record.attempt_id, &record)
            .unwrap();
        manager.restore_recovery().await.unwrap();
        assert!(manager.connect("one").await.is_err());
        let error = manager.connect("two").await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<ControlError>().unwrap().code,
            ErrorCode::RecoveryRequired
        );
        assert_eq!(manager.instances().await[0].status, InstanceStatus::Failed);
        assert!(manager.instances().await[0]
            .message
            .contains("recovery required"));
        acknowledge_recovery(&manager.storage, &record.attempt_id).unwrap();
        assert!(manager.recovery_records().unwrap().is_empty());
        // A new service reloads the acknowledgement; the old one never silently
        // discards its in-memory reservation while serving requests.
        let restarted = Arc::new(VpnManager::with_retry_delays(
            manager.storage.clone(),
            manager.engine.clone(),
            vec![],
        ));
        restarted.restore_recovery().await.unwrap();
        restarted.connect("two").await.unwrap();
        restarted.shutdown().await;
        assert!(restarted.recovery_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn recovery_acknowledgement_rejects_a_live_owned_process() {
        let (_root, manager) = fixture_manager().await;
        manager.connect("one").await.unwrap();
        for _ in 0..100 {
            if manager.instances().await[0].status == InstanceStatus::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let record = manager.recovery_records().unwrap().remove(0);
        assert!(record.process.is_some());
        assert!(acknowledge_recovery(&manager.storage, &record.attempt_id).is_err());
        assert!(!manager.recovery_records().unwrap().is_empty());
        manager.shutdown().await;
        assert!(manager.recovery_records().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delayed_stop_retains_ownership_until_reaped() {
        let (_root, manager) = fixture_manager().await;
        manager.connect("one").await.unwrap();
        for _ in 0..100 {
            if manager.instances().await[0].status == InstanceStatus::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            manager.instances().await[0].status,
            InstanceStatus::Connected
        );
        let stopping = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.disconnect("one").await })
        };
        for _ in 0..100 {
            if manager.instances().await[0].status == InstanceStatus::Disconnecting {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            manager
                .connect("two")
                .await
                .unwrap_err()
                .downcast_ref::<ControlError>()
                .unwrap()
                .code,
            ErrorCode::NetworkConflict
        );
        stopping.await.unwrap().unwrap();
        let instance = &manager.instances().await[0];
        assert_eq!(instance.pid, 0);
        assert_eq!(instance.status, InstanceStatus::Disconnected);
        manager.connect("two").await.unwrap();
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn stale_failure_cannot_clear_a_new_attempt() {
        let (_root, manager) = fixture_manager().await;
        let current = manager.connect("one").await.unwrap();
        manager
            .finish_failed("one", "previous-attempt", "stale failure".into())
            .await;
        let runtime = manager.runtime.lock().await;
        assert!(runtime.controls["one"].desired);
        assert_eq!(runtime.instances["one"].id, current.id);
        drop(runtime);
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn failed_network_cleanup_blocks_new_connections_after_process_exit() {
        let (_root, manager) = fixture_manager().await;
        let current = manager.connect("one").await.unwrap();
        manager
            .apply_engine_event(
                &current.id,
                &serde_json::json!({"event":"cleanup_result","success":false}),
            )
            .await;
        // The process may be reaped, but this is not proof of network recovery.
        manager
            .mark_disconnected("one", Some(&current.id), "stopped")
            .await;
        assert!(manager.is_active("one").await);
        assert!(manager.connect("two").await.is_err());
        // Fixture did not change any network resources; clear the injected failure
        // before stopping its real child, so this test cannot leak a process.
        manager
            .apply_engine_event(
                &current.id,
                &serde_json::json!({"event":"cleanup_result","success":true}),
            )
            .await;
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn stopping_reservation_rejects_edit_and_connect() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        storage.ensure_layout().unwrap();
        storage
            .save_profile(profile("office"), Some("secret".into()), true)
            .unwrap();
        let engine = root.path().join("engine");
        fs::write(&engine, "#!/bin/sh\nexit 0\n").unwrap();
        let manager = Arc::new(VpnManager::new(storage, engine));
        manager.runtime.lock().await.controls.insert(
            "office".into(),
            ProfileControl {
                process: Some(owned_process()),
                ..ProfileControl::default()
            },
        );
        assert!(manager
            .save_profile(crate::model::SaveProfileInput {
                profile: profile("office"),
                password: None,
                remember_password: true,
                expected_revision: None,
            })
            .await
            .is_err());
        assert!(manager.connect("office").await.is_err());
    }

    fn published_admission_view() -> InstanceView {
        InstanceView {
            id: "published-attempt".into(),
            profile_generation: 9,
            attempt_sequence: 1,
            profile_id: "one".into(),
            profile_name: "one".into(),
            adapter_name: String::new(),
            status: InstanceStatus::Starting,
            message: String::new(),
            pid: 0,
            started_at: 0,
            ended_at: None,
            exit_code: None,
            revision: 1,
        }
    }

    #[tokio::test]
    async fn headless_connect_admission_reuses_published_intent_without_new_generation_or_worker() {
        let (_root, manager) = fixture_manager().await;
        {
            let mut runtime = manager.runtime.lock().await;
            runtime.controls.insert(
                "one".into(),
                ProfileControl {
                    generation: 9,
                    desired: true,
                    active: true,
                    ..Default::default()
                },
            );
            runtime
                .instances
                .insert("one".into(), published_admission_view());
        }
        assert_eq!(
            manager.connect_inner("one").await.unwrap().id,
            "published-attempt"
        );
        let runtime = manager.runtime.lock().await;
        assert_eq!(runtime.controls["one"].generation, 9);
        assert!(runtime.supervisors.is_empty());
    }

    #[tokio::test]
    async fn headless_startup_admission_cannot_reuse_published_user_intent() {
        let (_root, manager) = fixture_manager().await;
        {
            let mut runtime = manager.runtime.lock().await;
            runtime.controls.insert(
                "one".into(),
                ProfileControl {
                    generation: 9,
                    desired: true,
                    active: true,
                    ..Default::default()
                },
            );
            runtime
                .instances
                .insert("one".into(), published_admission_view());
        }
        let error = manager
            .connect_with_origin(
                "one",
                openfortivpn_manager_core::connection_service::StartOrigin::Startup,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<ControlError>().unwrap().code,
            ErrorCode::ProfileBusy
        );
        let runtime = manager.runtime.lock().await;
        assert_eq!(runtime.controls["one"].generation, 9);
        assert_eq!(runtime.instances["one"].id, "published-attempt");
        assert!(runtime.supervisors.is_empty());
    }

    #[tokio::test]
    async fn headless_connect_admission_blocks_stopping_recovery_and_unpublished_reservations() {
        for gate in [
            "stop-intent",
            "disconnecting",
            "recovery",
            "pending",
            "other",
            "shutdown",
        ] {
            let (_root, manager) = fixture_manager().await;
            // This test injects ownership facts, and never needs to launch a
            // child, even if an admission regression unexpectedly reserves.
            fs::set_permissions(&manager.engine, fs::Permissions::from_mode(0o600)).unwrap();
            let expected = {
                let mut runtime = manager.runtime.lock().await;
                let mut view = published_admission_view();
                let mut control = ProfileControl {
                    generation: 9,
                    desired: true,
                    active: true,
                    ..Default::default()
                };
                let expected = match gate {
                    "stop-intent" => {
                        control.desired = false;
                        ErrorCode::ProfileBusy
                    }
                    "disconnecting" => {
                        view.status = InstanceStatus::Disconnecting;
                        ErrorCode::ProfileBusy
                    }
                    "recovery" => {
                        control.active = false;
                        control.desired = false;
                        control.lifecycle.require_recovery();
                        ErrorCode::RecoveryRequired
                    }
                    "pending" => ErrorCode::ProfileBusy,
                    "other" => ErrorCode::NetworkConflict,
                    _ => {
                        runtime.shutting_down = true;
                        ErrorCode::ShuttingDown
                    }
                };
                if gate == "other" {
                    runtime.controls.insert("two".into(), control);
                } else {
                    runtime.controls.insert("one".into(), control);
                    if gate != "pending" {
                        runtime.instances.insert("one".into(), view);
                    }
                }
                expected
            };
            assert_eq!(
                manager
                    .connect_inner("one")
                    .await
                    .unwrap_err()
                    .downcast_ref::<ControlError>()
                    .unwrap()
                    .code,
                expected
            );
            let runtime = manager.runtime.lock().await;
            assert!(runtime.supervisors.is_empty());
            assert_eq!(runtime.controls.values().next().unwrap().generation, 9);
        }
    }

    #[tokio::test]
    async fn premature_connected_state_is_not_ready() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        let manager = VpnManager::new(storage, root.path().join("engine"));
        manager.runtime.lock().await.instances.insert(
            "office".into(),
            InstanceView {
                id: "attempt".into(),
                profile_generation: 1,
                attempt_sequence: 1,
                profile_id: "office".into(),
                profile_name: "office".into(),
                adapter_name: String::new(),
                status: InstanceStatus::Connecting,
                message: String::new(),
                pid: 1,
                started_at: 0,
                ended_at: None,
                exit_code: None,
                revision: 1,
            },
        );
        manager
            .apply_engine_event(
                "attempt",
                &serde_json::json!({"event":"state_change","state":"connected"}),
            )
            .await;
        assert_eq!(
            manager.instances().await[0].status,
            InstanceStatus::Connecting
        );
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
    async fn legacy_network_ownership_blocks_conflicting_profiles() {
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
        let conflict = manager.connect("two").await.unwrap_err();
        assert_eq!(
            conflict.downcast_ref::<ControlError>().unwrap().code,
            ErrorCode::NetworkConflict
        );
        assert_eq!(first.id, duplicate.id);
        tokio::time::sleep(Duration::from_millis(150)).await;
        let instances = manager.instances().await;
        assert_eq!(instances.len(), 1);
        assert_eq!(
            instances.iter().filter(|instance| instance.pid > 0).count(),
            1
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
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$3\" >> '{}'\nexit 1\n",
                counter.display()
            ),
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
        let recorded = fs::read_to_string(counter).unwrap_or_default();
        let attempts: Vec<_> = recorded.lines().collect();
        assert!(attempts.len() >= 4);
        assert_eq!(
            attempts
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            attempts.len()
        );
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
                "#!/bin/sh\necho x >> '{}'\necho '{{\"event\":\"error\",\"code\":20,\"category\":\"auth\",\"retryable\":false,\"message\":\"synthetic denial\"}}' >&2\nexit 1\n",
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
