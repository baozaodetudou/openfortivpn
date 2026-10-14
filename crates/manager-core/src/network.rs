//! Network leases and recoverable transactions. Backends must report exact
//! resource identity; cleanup never restores a stale global network snapshot.
use crate::{ControlError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    path::PathBuf,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub destination: String,
    pub gateway: Option<Ipv4Addr>,
    pub interface: String,
    pub metric: u32,
    pub gateway_exception: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Dns {
    pub interface: String,
    pub servers: Vec<Ipv4Addr>,
    /// Empty domains means global DNS. Domain suffixes have independent leases.
    pub domains: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", content = "spec", rename_all = "camelCase")]
pub enum Resource {
    Route(Route),
    Dns(Dns),
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub attempt_id: String,
    pub profile_id: String,
    pub generation: u64,
    pub network_epoch: u64,
    pub resources: Vec<Resource>,
}
#[derive(Clone, Copy)]
pub struct BackendCapabilities {
    pub split_dns: bool,
}

fn error(code: ErrorCode, message: &str) -> ControlError {
    ControlError::new(code, message)
}
fn recovery() -> ControlError {
    error(
        ErrorCode::RecoveryRequired,
        "network transaction requires recovery",
    )
}
fn prefix(cidr: &str) -> Result<(u32, u8), ControlError> {
    let (ip, bits) = cidr.split_once('/').ok_or_else(|| {
        error(
            ErrorCode::InvalidInput,
            "route must use canonical IPv4 CIDR",
        )
    })?;
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|_| error(ErrorCode::InvalidInput, "invalid route address"))?;
    let bits: u8 = bits
        .parse()
        .map_err(|_| error(ErrorCode::InvalidInput, "invalid route prefix"))?;
    if bits > 32 {
        return Err(error(ErrorCode::InvalidInput, "invalid route prefix"));
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    let address = u32::from(ip);
    if address & mask != address || cidr != format!("{ip}/{bits}") {
        return Err(error(
            ErrorCode::InvalidInput,
            "route must use canonical IPv4 CIDR",
        ));
    }
    Ok((address, bits))
}
fn overlaps(left: &str, right: &str) -> bool {
    let (a, bits_a) = prefix(left).expect("validated lease");
    let (b, bits_b) = prefix(right).expect("validated lease");
    let bits = bits_a.min(bits_b);
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    a & mask == b & mask
}
fn domain_overlaps(a: &str, b: &str) -> bool {
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}
fn shareable(a: &Resource, b: &Resource) -> bool {
    matches!((a,b), (Resource::Route(a),Resource::Route(b)) if a.gateway_exception && b.gateway_exception && a == b)
}
fn conflicts(a: &Resource, b: &Resource) -> bool {
    match (a, b) {
        (Resource::Route(a), Resource::Route(b)) => {
            if a.gateway_exception != b.gateway_exception {
                return a.destination == b.destination;
            }
            overlaps(&a.destination, &b.destination)
        }
        (Resource::Dns(a), Resource::Dns(b)) => {
            a.domains.is_empty()
                || b.domains.is_empty()
                || a.domains
                    .iter()
                    .any(|a| b.domains.iter().any(|b| domain_overlaps(a, b)))
        }
        _ => false,
    }
}

impl Plan {
    pub fn validate(&self, capabilities: BackendCapabilities) -> Result<(), ControlError> {
        for id in [&self.attempt_id, &self.profile_id] {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            {
                return Err(error(ErrorCode::InvalidInput, "invalid lease identity"));
            }
        }
        if self.resources.len() > 128 {
            return Err(error(
                ErrorCode::InvalidInput,
                "network plan exceeds resource limit",
            ));
        }
        let mut unique = BTreeSet::new();
        for resource in &self.resources {
            if !unique.insert(resource) {
                return Err(error(ErrorCode::InvalidInput, "duplicate network resource"));
            }
            let interface = match resource {
                Resource::Route(route) => {
                    prefix(&route.destination)?;
                    &route.interface
                }
                Resource::Dns(dns) => {
                    if dns.servers.is_empty() || dns.servers.len() > 4 || dns.domains.len() > 32 {
                        return Err(error(ErrorCode::InvalidInput, "invalid DNS plan"));
                    }
                    if !capabilities.split_dns && !dns.domains.is_empty() {
                        return Err(error(
                            ErrorCode::InvalidInput,
                            "backend does not support split DNS",
                        ));
                    }
                    for domain in &dns.domains {
                        if domain.is_empty()
                            || domain.len() > 253
                            || domain != &domain.to_ascii_lowercase()
                            || domain.split('.').any(|label| {
                                label.is_empty()
                                    || label.len() > 63
                                    || label.starts_with('-')
                                    || label.ends_with('-')
                                    || !label
                                        .bytes()
                                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                            })
                        {
                            return Err(error(
                                ErrorCode::InvalidInput,
                                "invalid DNS domain suffix",
                            ));
                        }
                    }
                    &dns.interface
                }
            };
            if interface.is_empty()
                || interface.len() > 128
                || interface.chars().any(char::is_control)
            {
                return Err(error(
                    ErrorCode::InvalidInput,
                    "invalid network interface identity",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Prepared,
    Applying,
    Active,
    Releasing,
    RecoveryRequired,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    plan: Plan,
    phase: Phase,
    /// Remains durable through repeated cleanup attempts after an interrupted
    /// apply, including a crash while the phase is already Releasing.
    uncertain: bool,
    entries: Vec<Entry>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    resource: Resource,
    /// None means this transaction has not completed apply. Presence plus
    /// borrowed distinguishes an existing resource from one that we created.
    fingerprint: Option<String>,
    borrowed: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    schema_version: u32,
    network_epoch: u64,
    records: BTreeMap<String, Record>,
}
impl Snapshot {
    pub fn network_epoch(&self) -> u64 {
        self.network_epoch
    }
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            schema_version: 1,
            network_epoch: 0,
            records: BTreeMap::new(),
        }
    }
}

pub trait Journal {
    fn save(&mut self, snapshot: &Snapshot) -> Result<(), ControlError>;
}
pub struct FileJournal(pub PathBuf);
impl Journal for FileJournal {
    fn save(&mut self, snapshot: &Snapshot) -> Result<(), ControlError> {
        let bytes = serde_json::to_vec_pretty(snapshot).map_err(|_| recovery())?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(recovery());
        }
        crate::atomic_file::write_private(&self.0, &bytes).map_err(|_| recovery())
    }
}
impl FileJournal {
    pub fn load(&self) -> Result<Snapshot, ControlError> {
        let bytes = crate::private_file::read(&self.0, 16 * 1024 * 1024).map_err(|_| recovery())?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| recovery())?;
        if snapshot.schema_version != 1 || snapshot.records.len() > 512 {
            return Err(recovery());
        }
        for (id, record) in &snapshot.records {
            record
                .plan
                .validate(BackendCapabilities { split_dns: true })?;
            if id != &record.plan.attempt_id
                || record.entries.len() != record.plan.resources.len()
                || record
                    .entries
                    .iter()
                    .zip(&record.plan.resources)
                    .any(|(entry, resource)| {
                        &entry.resource != resource
                            || entry
                                .fingerprint
                                .as_ref()
                                .is_some_and(|id| id.is_empty() || id.len() > 512)
                    })
            {
                return Err(recovery());
            }
        }
        Ok(snapshot)
    }
}

/// One privileged authority must use the same private directory for every
/// desktop/headless client. Each operation reloads under a stable OS file lock;
/// a cached Coordinator alone cannot arbitrate across manager processes.
pub struct LockedStore {
    _lock: std::fs::File,
    coordinator: Coordinator,
    journal: FileJournal,
}
impl LockedStore {
    pub fn open(directory: &std::path::Path) -> Result<Self, ControlError> {
        Self::open_locked(directory, false)
    }
    fn open_locked(directory: &std::path::Path, nonblocking: bool) -> Result<Self, ControlError> {
        crate::private_file::verify_directory(directory).map_err(|_| recovery())?;
        let path = directory.join(".network.lock");
        let lock = if nonblocking {
            crate::private_file::try_lock(&path, false)
        } else {
            crate::private_file::lock(&path)
        }
        .map_err(|_| recovery())?;
        let journal = FileJournal(directory.join("network.json"));
        let snapshot = match std::fs::symlink_metadata(&journal.0) {
            Ok(_) => journal.load()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Snapshot::default(),
            Err(_) => return Err(recovery()),
        };
        Ok(Self {
            _lock: lock,
            coordinator: Coordinator::from_snapshot(snapshot),
            journal,
        })
    }

    /// Retain this guard until machine-level release or maintenance finishes.
    /// A stopped process or operator acknowledgement cannot erase native
    /// reservations, including a binding saved before the transaction journal.
    /// Callers acquire the machine authority lock first, then this lock.
    pub fn idle_guard(directory: &std::path::Path) -> Result<Self, ControlError> {
        let store = Self::open_locked(directory, true)?;
        if !store.coordinator.snapshot.records.is_empty() {
            return Err(recovery());
        }
        for (count, entry) in std::fs::read_dir(directory)
            .map_err(|_| recovery())?
            .enumerate()
        {
            if count >= 4096 {
                return Err(recovery());
            }
            let entry = entry.map_err(|_| recovery())?;
            if entry.file_name().to_string_lossy().starts_with("binding-") {
                return Err(recovery());
            }
        }
        Ok(store)
    }
    pub fn coordinator(&self) -> &Coordinator {
        &self.coordinator
    }
    pub fn prepare(
        &mut self,
        plan: Plan,
        capabilities: BackendCapabilities,
        backend: &mut impl Backend,
    ) -> Result<(), ControlError> {
        self.coordinator
            .prepare(plan, capabilities, backend, &mut self.journal)
    }
    pub fn apply(&mut self, attempt: &str, backend: &mut impl Backend) -> Result<(), ControlError> {
        self.coordinator
            .apply_or_rollback(attempt, backend, &mut self.journal)
    }
    pub fn release(
        &mut self,
        attempt: &str,
        backend: &mut impl Backend,
    ) -> Result<(), ControlError> {
        self.coordinator
            .release(attempt, backend, &mut self.journal)
    }
    pub fn network_changed(&mut self) -> Result<u64, ControlError> {
        self.coordinator.network_changed(&mut self.journal)
    }
}

/// Each backend must return a stable identity containing all routing/DNS
/// attributes that could distinguish an external modification.
pub trait Backend {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError>;
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError>;
    fn remove(
        &mut self,
        resource: &Resource,
        expected_fingerprint: &str,
    ) -> Result<(), ControlError>;
}
/// Compose platform route and DNS providers without letting either provider
/// interpret or mutate the other's resource type.
pub struct PlatformBackend<R, D> {
    pub routes: R,
    pub dns: D,
}
impl<R: Backend, D: Backend> Backend for PlatformBackend<R, D> {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        match resource {
            Resource::Route(_) => self.routes.inspect(resource),
            Resource::Dns(_) => self.dns.inspect(resource),
        }
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        match resource {
            Resource::Route(_) => self.routes.apply(resource),
            Resource::Dns(_) => self.dns.apply(resource),
        }
    }
    fn remove(&mut self, resource: &Resource, fingerprint: &str) -> Result<(), ControlError> {
        match resource {
            Resource::Route(_) => self.routes.remove(resource, fingerprint),
            Resource::Dns(_) => self.dns.remove(resource, fingerprint),
        }
    }
}
#[derive(Default)]
pub struct Coordinator {
    snapshot: Snapshot,
}
impl Coordinator {
    pub fn plan(&self, attempt: &str) -> Option<&Plan> {
        self.snapshot
            .records
            .get(attempt)
            .map(|record| &record.plan)
    }
    pub fn from_snapshot(mut snapshot: Snapshot) -> Self {
        // An interrupted apply cannot prove that a currently matching resource
        // was created by us. Keep the reservation until explicit recovery.
        for record in snapshot.records.values_mut() {
            if record.phase == Phase::Applying {
                record.phase = Phase::RecoveryRequired;
                record.uncertain = true;
            }
        }
        Self { snapshot }
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn phase(&self, attempt: &str) -> Option<&Phase> {
        self.snapshot
            .records
            .get(attempt)
            .map(|record| &record.phase)
    }
    /// A wake/network-change notification invalidates existing plans. It does
    /// not restore routes or DNS from the previous network.
    pub fn network_changed(&mut self, journal: &mut impl Journal) -> Result<u64, ControlError> {
        self.snapshot.network_epoch = self.snapshot.network_epoch.saturating_add(1);
        for record in self.snapshot.records.values_mut() {
            record.phase = Phase::RecoveryRequired;
            record.uncertain = true;
        }
        journal.save(&self.snapshot)?;
        Ok(self.snapshot.network_epoch)
    }
    pub fn preview(
        &self,
        plan: &Plan,
        capabilities: BackendCapabilities,
    ) -> Result<(), ControlError> {
        plan.validate(capabilities)?;
        if plan.network_epoch != self.snapshot.network_epoch {
            return Err(error(
                ErrorCode::NetworkConflict,
                "network changed; obtain a new plan",
            ));
        }
        for record in self.snapshot.records.values() {
            if record.plan.attempt_id == plan.attempt_id {
                if matches!(
                    record.phase,
                    Phase::RecoveryRequired | Phase::Releasing | Phase::Applying
                ) {
                    return Err(recovery());
                }
                if &record.plan != plan {
                    return Err(error(
                        ErrorCode::NetworkConflict,
                        "attempt already owns a different network plan",
                    ));
                }
                continue;
            }
            if record.plan.profile_id == plan.profile_id
                || plan.resources.iter().any(|a| {
                    record
                        .plan
                        .resources
                        .iter()
                        .any(|b| !shareable(a, b) && conflicts(a, b))
                })
            {
                return Err(error(
                    ErrorCode::NetworkConflict,
                    "network resources are reserved by another attempt",
                ));
            }
        }
        Ok(())
    }
    pub fn prepare(
        &mut self,
        plan: Plan,
        capabilities: BackendCapabilities,
        backend: &mut impl Backend,
        journal: &mut impl Journal,
    ) -> Result<(), ControlError> {
        self.preview(&plan, capabilities)?;
        if self.snapshot.records.contains_key(&plan.attempt_id) {
            return Ok(());
        }
        if self.snapshot.records.len() == 512 {
            return Err(error(
                ErrorCode::NetworkConflict,
                "network lease capacity reached",
            ));
        }
        let mut entries = Vec::new();
        for resource in &plan.resources {
            let existing = backend.inspect(resource)?;
            if existing
                .as_ref()
                .is_some_and(|id| id.is_empty() || id.len() > 512)
            {
                return Err(recovery());
            }
            let created_by_existing_owner = self.snapshot.records.values().any(|record| {
                record.entries.iter().any(|entry| {
                    !entry.borrowed
                        && entry.fingerprint.is_some()
                        && entry.fingerprint == existing
                        && shareable(resource, &entry.resource)
                })
            });
            entries.push(Entry {
                resource: resource.clone(),
                borrowed: existing.is_some() && !created_by_existing_owner,
                fingerprint: existing,
            });
        }
        let id = plan.attempt_id.clone();
        self.snapshot.records.insert(
            id.clone(),
            Record {
                plan,
                phase: Phase::Prepared,
                uncertain: false,
                entries,
            },
        );
        if let Err(error) = journal.save(&self.snapshot) {
            self.snapshot.records.remove(&id);
            return Err(error);
        }
        Ok(())
    }
    pub fn apply(
        &mut self,
        attempt: &str,
        backend: &mut impl Backend,
        journal: &mut impl Journal,
    ) -> Result<(), ControlError> {
        let phase = self.phase(attempt).ok_or_else(recovery)?;
        if phase == &Phase::Active {
            return Ok(());
        }
        if phase != &Phase::Prepared {
            return Err(recovery());
        }
        self.snapshot.records.get_mut(attempt).unwrap().phase = Phase::Applying;
        self.snapshot.records.get_mut(attempt).unwrap().uncertain = true;
        journal.save(&self.snapshot)?;
        for index in 0..self.snapshot.records[attempt].entries.len() {
            let entry = self.snapshot.records[attempt].entries[index].clone();
            if entry.borrowed {
                if backend.inspect(&entry.resource)? != entry.fingerprint {
                    return self.failed(attempt, journal);
                }
                continue;
            }
            // A prepared shared exception may have been applied by another
            // owner since prepare. Only share an already recorded creation.
            let shared = self
                .snapshot
                .records
                .iter()
                .filter(|(id, record)| id.as_str() != attempt && record.phase == Phase::Active)
                .flat_map(|(_, record)| &record.entries)
                .find(|other| shareable(&entry.resource, &other.resource) && !other.borrowed)
                .cloned();
            let fingerprint = if let Some(shared) = shared {
                if backend.inspect(&entry.resource)? != shared.fingerprint {
                    return self.failed(attempt, journal);
                }
                shared.fingerprint.unwrap()
            } else {
                if backend.inspect(&entry.resource)?.is_some() {
                    return self.failed(attempt, journal);
                }
                match backend.apply(&entry.resource) {
                    Ok(id) if !id.is_empty() && id.len() <= 512 => id,
                    _ => return self.failed(attempt, journal),
                }
            };
            self.snapshot.records.get_mut(attempt).unwrap().entries[index].fingerprint =
                Some(fingerprint);
            journal.save(&self.snapshot)?;
        }
        self.snapshot.records.get_mut(attempt).unwrap().phase = Phase::Active;
        self.snapshot.records.get_mut(attempt).unwrap().uncertain = false;
        if let Err(error) = journal.save(&self.snapshot) {
            let record = self.snapshot.records.get_mut(attempt).unwrap();
            record.phase = Phase::RecoveryRequired;
            record.uncertain = true;
            return Err(error);
        }
        Ok(())
    }
    /// An unsuccessful apply always attempts bounded ownership-safe rollback.
    /// The original failure is returned even when rollback completes; callers
    /// must not mark a tunnel ready after a failed network transaction.
    pub fn apply_or_rollback(
        &mut self,
        attempt: &str,
        backend: &mut impl Backend,
        journal: &mut impl Journal,
    ) -> Result<(), ControlError> {
        if let Err(error) = self.apply(attempt, backend, journal) {
            if self.release(attempt, backend, journal).is_err() {
                return Err(recovery());
            }
            return Err(error);
        }
        Ok(())
    }
    fn failed(&mut self, attempt: &str, journal: &mut impl Journal) -> Result<(), ControlError> {
        self.snapshot.records.get_mut(attempt).unwrap().phase = Phase::RecoveryRequired;
        journal.save(&self.snapshot)?;
        Err(recovery())
    }
    /// Safe rollback and normal cleanup use the same operation. Unknown
    /// partially applied resources retain their lease for operator recovery.
    pub fn release(
        &mut self,
        attempt: &str,
        backend: &mut impl Backend,
        journal: &mut impl Journal,
    ) -> Result<(), ControlError> {
        let Some(record) = self.snapshot.records.get(attempt).cloned() else {
            return Ok(());
        };
        let uncertain =
            record.uncertain || matches!(record.phase, Phase::Applying | Phase::RecoveryRequired);
        self.snapshot.records.get_mut(attempt).unwrap().phase = Phase::Releasing;
        self.snapshot.records.get_mut(attempt).unwrap().uncertain = uncertain;
        journal.save(&self.snapshot)?;
        let mut failed = false;
        for (index, entry) in record.entries.iter().enumerate().rev() {
            if entry.borrowed {
                continue;
            }
            let Some(fingerprint) = &entry.fingerprint else {
                if uncertain && !matches!(backend.inspect(&entry.resource), Ok(None)) {
                    failed = true;
                }
                continue;
            };
            let shared = self.snapshot.records.iter().any(|(id, record)| {
                id != attempt
                    && record.entries.iter().any(|other| {
                        shareable(&entry.resource, &other.resource)
                            && other.fingerprint.as_ref() == Some(fingerprint)
                    })
            });
            if shared {
                continue;
            }
            match backend.inspect(&entry.resource) {
                Ok(None) => {}
                Ok(Some(current)) if &current == fingerprint => {
                    if backend.remove(&entry.resource, fingerprint).is_err() {
                        failed = true;
                        continue;
                    }
                }
                _ => {
                    failed = true;
                    continue;
                }
            }
            self.snapshot.records.get_mut(attempt).unwrap().entries[index].fingerprint = None;
            journal.save(&self.snapshot)?;
        }
        if failed {
            return self.failed(attempt, journal);
        }
        // A failed save keeps the in-memory reservation too, preventing a new
        // attempt from starting with stale durable ownership.
        let removed = self.snapshot.records.remove(attempt).unwrap();
        if let Err(error) = journal.save(&self.snapshot) {
            self.snapshot.records.insert(attempt.into(), removed);
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Fake {
        resources: BTreeMap<Resource, String>,
        writes: usize,
        fail_apply: bool,
    }
    impl Backend for Fake {
        fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
            Ok(self.resources.get(resource).cloned())
        }
        fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
            if self.fail_apply {
                return Err(recovery());
            }
            self.writes += 1;
            let fingerprint = format!("created-{}", self.writes);
            self.resources.insert(resource.clone(), fingerprint.clone());
            Ok(fingerprint)
        }
        fn remove(&mut self, resource: &Resource, fingerprint: &str) -> Result<(), ControlError> {
            assert_eq!(
                self.resources.get(resource).map(String::as_str),
                Some(fingerprint)
            );
            self.writes += 1;
            self.resources.remove(resource);
            Ok(())
        }
    }
    #[derive(Default)]
    struct Memory {
        saved: Snapshot,
        fail: bool,
    }
    impl Journal for Memory {
        fn save(&mut self, snapshot: &Snapshot) -> Result<(), ControlError> {
            if self.fail {
                return Err(recovery());
            }
            self.saved = snapshot.clone();
            Ok(())
        }
    }
    fn route(cidr: &str, gateway: bool) -> Resource {
        Resource::Route(Route {
            destination: cidr.into(),
            gateway: Some("192.0.2.1".parse().unwrap()),
            interface: "test0".into(),
            metric: 10,
            gateway_exception: gateway,
        })
    }
    fn plan(id: &str, resources: Vec<Resource>) -> Plan {
        Plan {
            attempt_id: id.into(),
            profile_id: id.into(),
            generation: 1,
            network_epoch: 0,
            resources,
        }
    }
    const CAPS: BackendCapabilities = BackendCapabilities { split_dns: true };
    struct FailOnce {
        calls: usize,
        fail_at: usize,
        saved: Snapshot,
    }
    impl Journal for FailOnce {
        fn save(&mut self, snapshot: &Snapshot) -> Result<(), ControlError> {
            self.calls += 1;
            if self.calls == self.fail_at {
                return Err(recovery());
            }
            self.saved = snapshot.clone();
            Ok(())
        }
    }
    #[test]
    fn failed_commit_cannot_be_retried_as_a_successful_active_transaction() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = FailOnce {
            calls: 0,
            fail_at: 4,
            saved: Snapshot::default(),
        };
        coordinator
            .prepare(
                plan("a", vec![route("10.0.0.0/8", false)]),
                CAPS,
                &mut backend,
                &mut journal,
            )
            .unwrap();
        assert!(coordinator.apply("a", &mut backend, &mut journal).is_err());
        assert_eq!(coordinator.phase("a"), Some(&Phase::RecoveryRequired));
        assert!(coordinator.apply("a", &mut backend, &mut journal).is_err());
        coordinator
            .release("a", &mut backend, &mut journal)
            .unwrap();
        assert!(backend.resources.is_empty());
        assert!(coordinator.phase("a").is_none());
    }
    #[test]
    fn apply_fault_matrix_rolls_back_known_creations_at_every_persistence_boundary() {
        for fail_at in 1..=5 {
            let mut coordinator = Coordinator::default();
            let mut backend = Fake::default();
            let mut journal = FailOnce {
                calls: 0,
                fail_at,
                saved: Snapshot::default(),
            };
            if coordinator
                .prepare(
                    plan(
                        "a",
                        vec![route("10.0.0.0/8", false), route("172.16.0.0/16", false)],
                    ),
                    CAPS,
                    &mut backend,
                    &mut journal,
                )
                .is_ok()
            {
                assert!(coordinator
                    .apply_or_rollback("a", &mut backend, &mut journal)
                    .is_err());
            }
            assert!(backend.resources.is_empty(), "failure boundary {fail_at}");
            assert!(coordinator.phase("a").is_none());
            // A second recovery after reloading the persisted snapshot is safe.
            let mut recovered = Coordinator::from_snapshot(journal.saved.clone());
            recovered.release("a", &mut backend, &mut journal).unwrap();
            assert!(backend.resources.is_empty());
        }
    }
    #[test]
    fn uncertain_resource_retains_lease_but_does_not_prevent_known_resource_rollback() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = Memory::default();
        let known = route("10.0.0.0/8", false);
        let uncertain = route("172.16.0.0/16", false);
        coordinator
            .prepare(
                plan("a", vec![known.clone(), uncertain.clone()]),
                CAPS,
                &mut backend,
                &mut journal,
            )
            .unwrap();
        coordinator.apply("a", &mut backend, &mut journal).unwrap();
        let record = coordinator.snapshot.records.get_mut("a").unwrap();
        record.uncertain = true;
        record.entries[1].fingerprint = None;
        backend
            .resources
            .insert(uncertain.clone(), "external-or-partial".into());
        assert!(coordinator
            .release("a", &mut backend, &mut journal)
            .is_err());
        assert!(!backend.resources.contains_key(&known));
        assert_eq!(backend.resources[&uncertain], "external-or-partial");
        assert_eq!(coordinator.phase("a"), Some(&Phase::RecoveryRequired));
        assert!(coordinator
            .release("a", &mut backend, &mut journal)
            .is_err());
    }
    #[test]
    fn independently_opened_stores_preserve_one_hundred_concurrent_reservations() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut workers = Vec::new();
        for worker in 0..4 {
            let path = directory.path().to_owned();
            workers.push(std::thread::spawn(move || {
                let mut backend = Fake::default();
                for item in 0..25 {
                    let mut store = LockedStore::open(&path).unwrap();
                    let index = worker * 25 + item;
                    store
                        .prepare(
                            plan(
                                &format!("p{index}"),
                                vec![route(&format!("10.{index}.0.0/16"), false)],
                            ),
                            CAPS,
                            &mut backend,
                        )
                        .unwrap();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let store = LockedStore::open(directory.path()).unwrap();
        assert_eq!(store.coordinator().snapshot().records.len(), 100);
        assert!(store
            .coordinator()
            .preview(&plan("overlap", vec![route("10.0.0.0/8", false)]), CAPS)
            .is_err());
    }
    #[test]
    fn overlap_global_dns_and_domain_suffixes_conflict_before_any_mutation() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = Memory::default();
        coordinator
            .prepare(
                plan("a", vec![route("10.0.0.0/8", false)]),
                CAPS,
                &mut backend,
                &mut journal,
            )
            .unwrap();
        assert!(coordinator
            .preview(&plan("b", vec![route("10.1.0.0/16", false)]), CAPS)
            .is_err());
        assert!(coordinator
            .preview(&plan("b", vec![route("0.0.0.0/0", false)]), CAPS)
            .is_err());
        assert!(coordinator
            .preview(&plan("b", vec![route("172.16.0.0/16", false)]), CAPS)
            .is_ok());
        let dns = |domains: Vec<&str>| {
            Resource::Dns(Dns {
                interface: "test0".into(),
                servers: vec!["192.0.2.53".parse().unwrap()],
                domains: domains.into_iter().map(str::to_string).collect(),
            })
        };
        coordinator
            .prepare(
                plan("dns", vec![dns(vec!["corp.example"])]),
                CAPS,
                &mut backend,
                &mut journal,
            )
            .unwrap();
        assert!(coordinator
            .preview(&plan("nested", vec![dns(vec!["dev.corp.example"])]), CAPS)
            .is_err());
        assert!(coordinator
            .preview(&plan("global", vec![dns(vec![])]), CAPS)
            .is_err());
        assert!(coordinator
            .preview(&plan("separate", vec![dns(vec!["other.example"])]), CAPS)
            .is_ok());
        assert_eq!(backend.writes, 0);
    }
    #[test]
    fn preexisting_resources_survive_and_external_changes_block_cleanup() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = Memory::default();
        let borrowed = route("192.0.2.9/32", true);
        backend
            .resources
            .insert(borrowed.clone(), "external-original".into());
        coordinator
            .prepare(
                plan("a", vec![borrowed.clone(), route("10.0.0.0/8", false)]),
                CAPS,
                &mut backend,
                &mut journal,
            )
            .unwrap();
        coordinator.apply("a", &mut backend, &mut journal).unwrap();
        backend
            .resources
            .insert(route("10.0.0.0/8", false), "externally-replaced".into());
        assert!(coordinator
            .release("a", &mut backend, &mut journal)
            .is_err());
        assert_eq!(coordinator.phase("a"), Some(&Phase::RecoveryRequired));
        assert_eq!(backend.resources[&borrowed], "external-original");
        assert!(coordinator
            .preview(&plan("b", vec![route("10.1.0.0/16", false)]), CAPS)
            .is_err());
    }
    #[test]
    fn shared_gateway_exception_is_removed_only_after_last_created_owner() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = Memory::default();
        let shared = route("192.0.2.9/32", true);
        for id in ["a", "b"] {
            coordinator
                .prepare(
                    plan(id, vec![shared.clone()]),
                    CAPS,
                    &mut backend,
                    &mut journal,
                )
                .unwrap();
        }
        for id in ["a", "b"] {
            coordinator.apply(id, &mut backend, &mut journal).unwrap();
        }
        assert_eq!(backend.writes, 1);
        coordinator
            .release("a", &mut backend, &mut journal)
            .unwrap();
        assert!(backend.resources.contains_key(&shared));
        coordinator
            .release("b", &mut backend, &mut journal)
            .unwrap();
        assert!(!backend.resources.contains_key(&shared));
        assert_eq!(backend.writes, 2);
    }
    #[test]
    fn sharing_an_already_active_gateway_retains_creation_ownership() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = Memory::default();
        let resource = route("192.0.2.9/32", true);
        for id in ["a", "b"] {
            coordinator
                .prepare(
                    plan(id, vec![resource.clone()]),
                    CAPS,
                    &mut backend,
                    &mut journal,
                )
                .unwrap();
            coordinator.apply(id, &mut backend, &mut journal).unwrap();
        }
        coordinator
            .release("a", &mut backend, &mut journal)
            .unwrap();
        assert!(backend.resources.contains_key(&resource));
        coordinator
            .release("b", &mut backend, &mut journal)
            .unwrap();
        assert!(backend.resources.is_empty());
    }
    #[test]
    fn a_second_crash_during_recovery_never_erases_uncertain_ownership() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = Memory::default();
        let resource = route("10.0.0.0/8", false);
        coordinator
            .prepare(
                plan("a", vec![resource.clone()]),
                CAPS,
                &mut backend,
                &mut journal,
            )
            .unwrap();
        coordinator.snapshot.records.get_mut("a").unwrap().phase = Phase::Applying;
        let mut coordinator = Coordinator::from_snapshot(coordinator.snapshot.clone());
        backend
            .resources
            .insert(resource.clone(), "external-or-owned-after-crash".into());
        assert!(coordinator
            .release("a", &mut backend, &mut journal)
            .is_err());
        // Simulate failure after persisting the beginning of cleanup.
        journal.saved.records.get_mut("a").unwrap().phase = Phase::Releasing;
        let mut coordinator = Coordinator::from_snapshot(journal.saved);
        let mut journal = Memory::default();
        assert!(coordinator
            .release("a", &mut backend, &mut journal)
            .is_err());
        assert!(backend.resources.contains_key(&resource));
        assert_eq!(backend.writes, 0);
    }
    #[test]
    fn changed_networks_invalidate_lease_replays_without_mutating_resources() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = Memory::default();
        let old = plan("a", vec![route("10.0.0.0/8", false)]);
        coordinator
            .prepare(old.clone(), CAPS, &mut backend, &mut journal)
            .unwrap();
        coordinator.apply("a", &mut backend, &mut journal).unwrap();
        assert_eq!(coordinator.network_changed(&mut journal).unwrap(), 1);
        assert!(coordinator.preview(&old, CAPS).is_err());
        assert_eq!(backend.writes, 1);
        assert_eq!(coordinator.phase("a"), Some(&Phase::RecoveryRequired));
        let mut new = plan("b", vec![route("172.16.0.0/16", false)]);
        new.network_epoch = 1;
        assert!(coordinator.preview(&new, CAPS).is_ok());
    }
    #[test]
    fn journal_failure_prevents_mutation_and_interrupted_apply_never_deletes_unowned_resources() {
        let mut coordinator = Coordinator::default();
        let mut backend = Fake::default();
        let mut journal = Memory::default();
        let resource = route("10.0.0.0/8", false);
        coordinator
            .prepare(
                plan("a", vec![resource.clone()]),
                CAPS,
                &mut backend,
                &mut journal,
            )
            .unwrap();
        journal.fail = true;
        assert!(coordinator.apply("a", &mut backend, &mut journal).is_err());
        assert_eq!(backend.writes, 0);
        journal.fail = false;
        coordinator.snapshot.records.get_mut("a").unwrap().phase = Phase::Applying;
        journal.save(coordinator.snapshot()).unwrap();
        backend
            .resources
            .insert(resource.clone(), "unknown-after-crash".into());
        let mut recovered = Coordinator::from_snapshot(journal.saved.clone());
        assert!(recovered.release("a", &mut backend, &mut journal).is_err());
        assert_eq!(backend.resources[&resource], "unknown-after-crash");
        assert_eq!(backend.writes, 0);
    }
}
