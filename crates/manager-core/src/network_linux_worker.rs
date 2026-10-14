//! Blocking Linux network transactions bound to one launcher-owned PPP link.
//! A durable binding is retained whenever network ownership cannot be disproved.
use crate::{
    network::{
        Backend, BackendCapabilities, Coordinator, FileJournal, LockedStore, Phase, Plan, Resource,
    },
    network_control::InterfaceBinding,
    ControlError, ErrorCode,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

fn recovery() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "Linux network binding requires recovery",
    )
}
fn invalid() -> ControlError {
    ControlError::new(
        ErrorCode::InvalidInput,
        "invalid bound Linux split network plan",
    )
}
fn valid_attempt(attempt: &str) -> bool {
    !attempt.is_empty()
        && attempt.len() <= 128
        && attempt
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    interface: String,
    index: u32,
    local_address: Ipv4Addr,
    transport_address: Ipv4Addr,
}
impl From<InterfaceBinding> for Binding {
    fn from(binding: InterfaceBinding) -> Self {
        Self {
            interface: binding.interface,
            index: binding.index,
            local_address: binding.local_address,
            transport_address: binding.transport_address,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindingRecord {
    schema_version: u32,
    plan: Plan,
    binding: Binding,
}
fn contains(cidr: &str, address: Ipv4Addr) -> bool {
    let Some((network, bits)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(bits)) = (network.parse::<Ipv4Addr>(), bits.parse::<u8>()) else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(address) & mask == u32::from(network)
}
fn usable_address(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_loopback()
}
fn validate_plan(plan: &Plan, binding: &Binding) -> Result<(), ControlError> {
    plan.validate(BackendCapabilities { split_dns: true })?;
    if binding.interface.is_empty()
        || binding.interface.len() >= libc::IFNAMSIZ
        || !binding
            .interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        || binding.index == 0
        || binding.index > i32::MAX as u32
        || !usable_address(binding.local_address)
        || !usable_address(binding.transport_address)
    {
        return Err(invalid());
    }
    let mut dns_count = 0;
    for resource in &plan.resources {
        match resource {
            Resource::Route(route) => {
                if route.interface != binding.interface
                    || route.gateway.is_some()
                    || route.metric != 0
                    || route.gateway_exception
                    || route.destination.ends_with("/0")
                    || contains(&route.destination, binding.transport_address)
                {
                    return Err(invalid());
                }
            }
            Resource::Dns(dns) => {
                dns_count += 1;
                // resolved has one link-level DNS state; multiple independently
                // leased resources on the same link cannot be safely composed.
                if dns_count > 1
                    || dns.interface != binding.interface
                    || dns.domains.is_empty()
                    || dns.domains.iter().collect::<BTreeSet<_>>().len() != dns.domains.len()
                    || dns.servers.iter().collect::<BTreeSet<_>>().len() != dns.servers.len()
                    || dns.servers.iter().any(|server| {
                        !usable_address(*server)
                            || !plan.resources.iter().any(|resource| {
                                matches!(resource,
                            Resource::Route(route) if route.interface == binding.interface
                                && contains(&route.destination, *server))
                            })
                    })
                {
                    return Err(invalid());
                }
            }
        }
    }
    Ok(())
}

trait BindingVerifier {
    fn verify(&mut self, binding: &Binding) -> Result<(), ControlError>;
}
struct BoundBackend<'a, B, V> {
    backend: B,
    verifier: &'a mut V,
    record: &'a BindingRecord,
}
impl<B: Backend, V: BindingVerifier> BoundBackend<'_, B, V> {
    fn check(&mut self, resource: &Resource) -> Result<(), ControlError> {
        if !self.record.plan.resources.contains(resource) {
            return Err(invalid());
        }
        self.verifier.verify(&self.record.binding)
    }
}
impl<B: Backend, V: BindingVerifier> Backend for BoundBackend<'_, B, V> {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        self.check(resource)?;
        self.backend.inspect(resource)
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        self.check(resource)?;
        self.backend.apply(resource)
    }
    fn remove(&mut self, resource: &Resource, fingerprint: &str) -> Result<(), ControlError> {
        self.check(resource)?;
        self.backend.remove(resource, fingerprint)
    }
}
trait Transactions {
    fn phase(&self, attempt: &str) -> Option<Phase>;
    fn plan(&self, attempt: &str) -> Option<&Plan>;
    fn preview(&self, plan: &Plan) -> Result<(), ControlError>;
    fn prepare(&mut self, plan: Plan, backend: &mut impl Backend) -> Result<(), ControlError>;
    fn apply(&mut self, attempt: &str, backend: &mut impl Backend) -> Result<(), ControlError>;
    fn release(&mut self, attempt: &str, backend: &mut impl Backend) -> Result<(), ControlError>;
    fn durable_absent(&self, attempt: &str) -> Result<bool, ControlError>;
}
struct DurableTransactions<'a> {
    store: LockedStore,
    directory: &'a Path,
}
impl Transactions for DurableTransactions<'_> {
    fn phase(&self, attempt: &str) -> Option<Phase> {
        self.store.coordinator().phase(attempt).cloned()
    }
    fn plan(&self, attempt: &str) -> Option<&Plan> {
        self.store.coordinator().plan(attempt)
    }
    fn preview(&self, plan: &Plan) -> Result<(), ControlError> {
        self.store
            .coordinator()
            .preview(plan, BackendCapabilities { split_dns: true })
    }
    fn prepare(&mut self, plan: Plan, backend: &mut impl Backend) -> Result<(), ControlError> {
        self.store
            .prepare(plan, BackendCapabilities { split_dns: true }, backend)
    }
    fn apply(&mut self, attempt: &str, backend: &mut impl Backend) -> Result<(), ControlError> {
        self.store.apply(attempt, backend)
    }
    fn release(&mut self, attempt: &str, backend: &mut impl Backend) -> Result<(), ControlError> {
        self.store.release(attempt, backend)
    }
    fn durable_absent(&self, attempt: &str) -> Result<bool, ControlError> {
        // A failed save may have renamed its data before directory fsync failed.
        // The cached Coordinator is insufficient proof for unlinking a binding.
        let journal = FileJournal(self.directory.join("network.json"));
        match std::fs::symlink_metadata(&journal.0) {
            Ok(_) => Ok(Coordinator::from_snapshot(journal.load()?)
                .phase(attempt)
                .is_none()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(_) => Err(recovery()),
        }
    }
}
trait BindingRecords {
    fn read(&mut self, attempt: &str) -> Result<Option<BindingRecord>, ControlError>;
    fn save(&mut self, record: &BindingRecord) -> Result<(), ControlError>;
    fn remove(&mut self, record: &BindingRecord) -> Result<(), ControlError>;
}
struct Files<'a>(&'a Path);
impl Files<'_> {
    fn path(&self, attempt: &str) -> Result<PathBuf, ControlError> {
        if !valid_attempt(attempt) {
            return Err(invalid());
        }
        Ok(self.0.join(format!("binding-{attempt}.json")))
    }
}
impl BindingRecords for Files<'_> {
    fn read(&mut self, attempt: &str) -> Result<Option<BindingRecord>, ControlError> {
        let path = self.path(attempt)?;
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(recovery()),
            Ok(_) => {}
        }
        let bytes = crate::private_file::read(&path, 256 * 1024).map_err(|_| recovery())?;
        let record: BindingRecord = serde_json::from_slice(&bytes).map_err(|_| recovery())?;
        if record.schema_version != 1
            || record.plan.attempt_id != attempt
            || validate_plan(&record.plan, &record.binding).is_err()
        {
            return Err(recovery());
        }
        Ok(Some(record))
    }
    fn save(&mut self, record: &BindingRecord) -> Result<(), ControlError> {
        let bytes = serde_json::to_vec(record).map_err(|_| recovery())?;
        if bytes.len() > 256 * 1024 {
            return Err(recovery());
        }
        crate::atomic_file::write_private(&self.path(&record.plan.attempt_id)?, &bytes)
            .map_err(|_| recovery())
    }
    fn remove(&mut self, record: &BindingRecord) -> Result<(), ControlError> {
        let path = self.path(&record.plan.attempt_id)?;
        // Refuse to unlink an unexpected replacement, including private-file
        // ownership/mode/link-count changes detected by read().
        if self.read(&record.plan.attempt_id)?.as_ref() != Some(record) {
            return Err(recovery());
        }
        std::fs::remove_file(&path).map_err(|_| recovery())?;
        if std::fs::File::open(self.0)
            .and_then(|file| file.sync_all())
            .is_err()
        {
            // Retain a best-effort recovery anchor on an uncertain unlink.
            let _ = self.save(record);
            return Err(recovery());
        }
        Ok(())
    }
}
fn finish_if_absent(
    store: &impl Transactions,
    files: &mut impl BindingRecords,
    record: &BindingRecord,
) -> Result<bool, ControlError> {
    if store.durable_absent(&record.plan.attempt_id)? {
        files.remove(record)?;
        return Ok(true);
    }
    Ok(false)
}
fn apply_with<B: Backend, V: BindingVerifier>(
    mut plan: Plan,
    binding: Binding,
    store: &mut impl Transactions,
    files: &mut impl BindingRecords,
    verifier: &mut V,
    factory: impl FnOnce(&BindingRecord) -> Result<B, ControlError>,
) -> Result<(), ControlError> {
    validate_plan(&plan, &binding)?;
    // DNS traffic must have its VPN routes before link DNS is installed.
    plan.resources
        .sort_by_key(|resource| matches!(resource, Resource::Dns(_)));
    store.preview(&plan)?;
    let record = BindingRecord {
        schema_version: 1,
        plan,
        binding,
    };
    let existing = files.read(&record.plan.attempt_id)?;
    if existing
        .as_ref()
        .is_some_and(|existing| existing != &record)
    {
        return Err(recovery());
    }
    verifier.verify(&record.binding)?;
    if existing.is_none() {
        files.save(&record)?;
    }
    let result = match factory(&record) {
        Ok(backend) => {
            let mut backend = BoundBackend {
                backend,
                verifier,
                record: &record,
            };
            store
                .prepare(record.plan.clone(), &mut backend)
                .and_then(|()| store.apply(&record.plan.attempt_id, &mut backend))
        }
        Err(error) => Err(error),
    };
    finish_if_absent(store, files, &record)?;
    result
}
fn release_with<B: Backend, V: BindingVerifier>(
    attempt: &str,
    store: &mut impl Transactions,
    files: &mut impl BindingRecords,
    verifier: &mut V,
    factory: impl FnOnce(&BindingRecord) -> Result<B, ControlError>,
) -> Result<(), ControlError> {
    if !valid_attempt(attempt) {
        return Err(invalid());
    }
    let Some(record) = files.read(attempt)? else {
        return if store.phase(attempt).is_none() && store.durable_absent(attempt)? {
            Ok(())
        } else {
            Err(recovery())
        };
    };
    if store.plan(attempt).is_some_and(|plan| plan != &record.plan) {
        return Err(recovery());
    }
    // An absent/reused link is not proof that owned network state disappeared.
    verifier.verify(&record.binding)?;
    if store.phase(attempt).is_none() {
        return if finish_if_absent(store, files, &record)? {
            Ok(())
        } else {
            Err(recovery())
        };
    }
    let backend = factory(&record)?;
    let mut backend = BoundBackend {
        backend,
        verifier,
        record: &record,
    };
    let result = store.release(attempt, &mut backend);
    let absent = finish_if_absent(store, files, &record)?;
    if result.is_ok() && !absent {
        Err(recovery())
    } else {
        result
    }
}

/// Never caches a coordinator or a platform handle between transactions.
pub struct LinuxTransactions {
    directory: PathBuf,
}
impl LinuxTransactions {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }
    pub fn epoch(&self) -> Result<u64, ControlError> {
        ensure_worker(&self.directory)?;
        Ok(LockedStore::open(&self.directory)?
            .coordinator()
            .snapshot()
            .network_epoch())
    }
    #[cfg(all(target_os = "linux", feature = "linux-network"))]
    pub fn apply(&self, plan: Plan, binding: InterfaceBinding) -> Result<(), ControlError> {
        ensure_worker(&self.directory)?;
        let mut store = DurableTransactions {
            store: LockedStore::open(&self.directory)?,
            directory: &self.directory,
        };
        apply_with(
            plan,
            binding.into(),
            &mut store,
            &mut Files(&self.directory),
            &mut NativeBinding,
            native_backend,
        )
    }
    #[cfg(all(target_os = "linux", feature = "linux-network"))]
    pub fn release(&self, attempt: &str) -> Result<(), ControlError> {
        ensure_worker(&self.directory)?;
        let mut store = DurableTransactions {
            store: LockedStore::open(&self.directory)?,
            directory: &self.directory,
        };
        release_with(
            attempt,
            &mut store,
            &mut Files(&self.directory),
            &mut NativeBinding,
            native_backend,
        )
    }
}
fn ensure_worker(directory: &Path) -> Result<(), ControlError> {
    if tokio::runtime::Handle::try_current().is_ok() || unsafe { libc::geteuid() } != 0 {
        return Err(ControlError::new(
            ErrorCode::InvalidInput,
            "native Linux network transactions require a plain root worker thread",
        ));
    }
    if !directory.is_absolute() {
        return Err(invalid());
    }
    crate::private_file::verify_directory(directory).map_err(|_| recovery())
}

#[cfg(all(target_os = "linux", feature = "linux-network"))]
struct NativeBinding;
#[cfg(all(target_os = "linux", feature = "linux-network"))]
impl BindingVerifier for NativeBinding {
    fn verify(&mut self, binding: &Binding) -> Result<(), ControlError> {
        use std::ffi::{CStr, CString};
        let name = CString::new(binding.interface.as_bytes()).map_err(|_| invalid())?;
        if unsafe { libc::if_nametoindex(name.as_ptr()) } != binding.index {
            return Err(recovery());
        }
        let mut addresses = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
            return Err(recovery());
        }
        struct Addresses(*mut libc::ifaddrs);
        impl Drop for Addresses {
            fn drop(&mut self) {
                unsafe {
                    libc::freeifaddrs(self.0);
                }
            }
        }
        let _guard = Addresses(addresses);
        let mut cursor = addresses;
        let mut found = false;
        let mut count = 0;
        while !cursor.is_null() {
            count += 1;
            if count > 4096 {
                return Err(recovery());
            }
            let address = unsafe { &*cursor };
            if !address.ifa_name.is_null()
                && !address.ifa_addr.is_null()
                && unsafe { CStr::from_ptr(address.ifa_name) }.to_bytes()
                    == binding.interface.as_bytes()
                && address.ifa_flags & (libc::IFF_POINTOPOINT | libc::IFF_UP) as u32
                    == (libc::IFF_POINTOPOINT | libc::IFF_UP) as u32
                && unsafe { (*address.ifa_addr).sa_family } as i32 == libc::AF_INET
            {
                let ipv4 = unsafe { &*address.ifa_addr.cast::<libc::sockaddr_in>() };
                if Ipv4Addr::from(ipv4.sin_addr.s_addr.to_ne_bytes()) == binding.local_address {
                    found = true;
                }
            }
            cursor = address.ifa_next;
        }
        if !found || unsafe { libc::if_nametoindex(name.as_ptr()) } != binding.index {
            return Err(recovery());
        }
        Ok(())
    }
}
#[cfg(all(target_os = "linux", feature = "linux-network"))]
struct OptionalDns(Option<crate::network_resolved::ResolvedDns>);
#[cfg(all(target_os = "linux", feature = "linux-network"))]
impl Backend for OptionalDns {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        self.0.as_mut().ok_or_else(invalid)?.inspect(resource)
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        self.0.as_mut().ok_or_else(invalid)?.apply(resource)
    }
    fn remove(&mut self, resource: &Resource, fingerprint: &str) -> Result<(), ControlError> {
        self.0
            .as_mut()
            .ok_or_else(invalid)?
            .remove(resource, fingerprint)
    }
}
#[cfg(all(target_os = "linux", feature = "linux-network"))]
fn native_backend(
    record: &BindingRecord,
) -> Result<
    crate::network::PlatformBackend<crate::network_linux::LinuxRoutes, OptionalDns>,
    ControlError,
> {
    let dns = if record
        .plan
        .resources
        .iter()
        .any(|resource| matches!(resource, Resource::Dns(_)))
    {
        Some(crate::network_resolved::ResolvedDns::new(
            std::collections::BTreeMap::from([(
                record.binding.interface.clone(),
                record.binding.index,
            )]),
        )?)
    } else {
        None
    };
    Ok(crate::network::PlatformBackend {
        routes: crate::network_linux::LinuxRoutes,
        dns: OptionalDns(dns),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{Dns, Journal, Route, Snapshot};
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
    fn binding() -> Binding {
        Binding {
            interface: "ppp0".into(),
            index: 12,
            local_address: "10.1.1.2".parse().unwrap(),
            transport_address: "192.0.2.9".parse().unwrap(),
        }
    }
    fn route(destination: &str) -> Resource {
        Resource::Route(Route {
            destination: destination.into(),
            gateway: None,
            interface: "ppp0".into(),
            metric: 0,
            gateway_exception: false,
        })
    }
    fn dns() -> Resource {
        Resource::Dns(Dns {
            interface: "ppp0".into(),
            servers: vec!["10.1.1.53".parse().unwrap()],
            domains: vec!["example.test".into()],
        })
    }
    fn plan(resources: Vec<Resource>) -> Plan {
        Plan {
            attempt_id: "attempt-one".into(),
            profile_id: "profile-one".into(),
            generation: 7,
            network_epoch: 0,
            resources,
        }
    }
    #[derive(Default)]
    struct MemoryJournal {
        durable: Snapshot,
        saves: usize,
        fail_at: Option<usize>,
        rename_before_failure: bool,
    }
    impl Journal for MemoryJournal {
        fn save(&mut self, snapshot: &Snapshot) -> Result<(), ControlError> {
            self.saves += 1;
            if self.fail_at == Some(self.saves) {
                if self.rename_before_failure {
                    self.durable = snapshot.clone();
                }
                return Err(recovery());
            }
            self.durable = snapshot.clone();
            Ok(())
        }
    }
    #[derive(Default)]
    struct FakeTransactions {
        coordinator: Coordinator,
        journal: MemoryJournal,
    }
    impl Transactions for FakeTransactions {
        fn phase(&self, attempt: &str) -> Option<Phase> {
            self.coordinator.phase(attempt).cloned()
        }
        fn plan(&self, attempt: &str) -> Option<&Plan> {
            self.coordinator.plan(attempt)
        }
        fn preview(&self, plan: &Plan) -> Result<(), ControlError> {
            self.coordinator
                .preview(plan, BackendCapabilities { split_dns: true })
        }
        fn prepare(&mut self, plan: Plan, backend: &mut impl Backend) -> Result<(), ControlError> {
            self.coordinator.prepare(
                plan,
                BackendCapabilities { split_dns: true },
                backend,
                &mut self.journal,
            )
        }
        fn apply(&mut self, attempt: &str, backend: &mut impl Backend) -> Result<(), ControlError> {
            self.coordinator
                .apply_or_rollback(attempt, backend, &mut self.journal)
        }
        fn release(
            &mut self,
            attempt: &str,
            backend: &mut impl Backend,
        ) -> Result<(), ControlError> {
            self.coordinator
                .release(attempt, backend, &mut self.journal)
        }
        fn durable_absent(&self, attempt: &str) -> Result<bool, ControlError> {
            Ok(Coordinator::from_snapshot(self.journal.durable.clone())
                .phase(attempt)
                .is_none())
        }
    }
    #[derive(Default)]
    struct FakeRecords {
        durable: Rc<RefCell<BTreeMap<String, BindingRecord>>>,
        fail_save: bool,
        fail_remove: bool,
        removes: usize,
    }
    impl BindingRecords for FakeRecords {
        fn read(&mut self, attempt: &str) -> Result<Option<BindingRecord>, ControlError> {
            Ok(self.durable.borrow().get(attempt).cloned())
        }
        fn save(&mut self, record: &BindingRecord) -> Result<(), ControlError> {
            if self.fail_save {
                return Err(recovery());
            }
            self.durable
                .borrow_mut()
                .insert(record.plan.attempt_id.clone(), record.clone());
            Ok(())
        }
        fn remove(&mut self, record: &BindingRecord) -> Result<(), ControlError> {
            self.removes += 1;
            if self.fail_remove {
                return Err(recovery());
            }
            self.durable.borrow_mut().remove(&record.plan.attempt_id);
            Ok(())
        }
    }
    #[derive(Default)]
    struct BackendState {
        resources: BTreeMap<Resource, String>,
        operations: Vec<(&'static str, Resource)>,
        applies: usize,
        fail_apply_at: Option<usize>,
        uncertain_failure: bool,
    }
    #[derive(Clone)]
    struct FakeBackend {
        state: Rc<RefCell<BackendState>>,
        records: Rc<RefCell<BTreeMap<String, BindingRecord>>>,
    }
    impl FakeBackend {
        fn note(&self, op: &'static str, resource: &Resource) {
            assert!(
                self.records.borrow().contains_key("attempt-one"),
                "binding must be durable before backend inspection or mutation"
            );
            self.state
                .borrow_mut()
                .operations
                .push((op, resource.clone()));
        }
    }
    impl Backend for FakeBackend {
        fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
            self.note("inspect", resource);
            Ok(self.state.borrow().resources.get(resource).cloned())
        }
        fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
            self.note("apply", resource);
            let mut state = self.state.borrow_mut();
            state.applies += 1;
            let fingerprint = format!("created-{}", state.applies);
            if state.fail_apply_at == Some(state.applies) {
                if state.uncertain_failure {
                    state.resources.insert(resource.clone(), fingerprint);
                }
                return Err(recovery());
            }
            state
                .resources
                .insert(resource.clone(), fingerprint.clone());
            Ok(fingerprint)
        }
        fn remove(&mut self, resource: &Resource, fingerprint: &str) -> Result<(), ControlError> {
            self.note("remove", resource);
            let mut state = self.state.borrow_mut();
            if state.resources.get(resource).map(String::as_str) != Some(fingerprint) {
                return Err(recovery());
            }
            state.resources.remove(resource);
            Ok(())
        }
    }
    #[derive(Default)]
    struct FakeVerifier {
        checks: usize,
        fail_at: Option<usize>,
        missing: bool,
    }
    impl BindingVerifier for FakeVerifier {
        fn verify(&mut self, actual: &Binding) -> Result<(), ControlError> {
            self.checks += 1;
            if actual != &binding() || self.missing || self.fail_at == Some(self.checks) {
                return Err(recovery());
            }
            Ok(())
        }
    }
    fn fixture() -> (FakeTransactions, FakeRecords, FakeVerifier, FakeBackend) {
        let records = FakeRecords::default();
        let backend = FakeBackend {
            state: Rc::default(),
            records: records.durable.clone(),
        };
        (
            FakeTransactions::default(),
            records,
            FakeVerifier::default(),
            backend,
        )
    }
    #[test]
    fn binding_is_durable_before_every_platform_call_and_routes_precede_dns() {
        let (mut store, mut files, mut verifier, backend) = fixture();
        let state = backend.state.clone();
        let mut original = plan(vec![dns(), route("10.0.0.0/8")]);
        apply_with(
            original.clone(),
            binding(),
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone()),
        )
        .unwrap();
        assert_eq!(store.phase("attempt-one"), Some(Phase::Active));
        let applies: Vec<_> = state
            .borrow()
            .operations
            .iter()
            .filter(|(op, _)| *op == "apply")
            .map(|(_, resource)| resource.clone())
            .collect();
        assert_eq!(applies, [route("10.0.0.0/8"), dns()]);
        assert_eq!(verifier.checks, state.borrow().operations.len() + 1);
        // The exact same engine plan is idempotent after ordering normalization.
        apply_with(
            original.clone(),
            binding(),
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone()),
        )
        .unwrap();
        assert_eq!(state.borrow().applies, 2);
        original.resources.reverse();
        assert_eq!(files.durable.borrow()["attempt-one"].plan, original);
        release_with("attempt-one", &mut store, &mut files, &mut verifier, |_| {
            Ok(backend)
        })
        .unwrap();
        assert!(state.borrow().resources.is_empty());
        assert!(files.durable.borrow().is_empty());
    }
    #[test]
    fn invalid_interface_transport_full_tunnel_and_unrouted_dns_fail_before_persistence() {
        let bad_resources = vec![
            vec![route("0.0.0.0/0")],
            vec![route("192.0.2.0/24")],
            vec![dns()],
            vec![
                route("10.0.0.0/8"),
                Resource::Dns(Dns {
                    interface: "ppp1".into(),
                    servers: vec!["10.1.1.53".parse().unwrap()],
                    domains: vec!["example.test".into()],
                }),
            ],
            vec![
                route("10.0.0.0/8"),
                Resource::Dns(Dns {
                    interface: "ppp0".into(),
                    servers: vec!["198.51.100.53".parse().unwrap()],
                    domains: vec!["example.test".into()],
                }),
            ],
            vec![
                route("10.0.0.0/8"),
                Resource::Dns(Dns {
                    interface: "ppp0".into(),
                    servers: vec!["10.1.1.53".parse().unwrap()],
                    domains: vec![],
                }),
            ],
            vec![Resource::Route(Route {
                destination: "10.0.0.0/8".into(),
                interface: "eth0".into(),
                gateway: None,
                metric: 0,
                gateway_exception: false,
            })],
            vec![Resource::Route(Route {
                destination: "10.0.0.0/8".into(),
                interface: "ppp0".into(),
                gateway: Some("10.1.1.1".parse().unwrap()),
                metric: 0,
                gateway_exception: false,
            })],
        ];
        for resources in bad_resources {
            let (mut store, mut files, mut verifier, backend) = fixture();
            assert_eq!(
                apply_with(
                    plan(resources),
                    binding(),
                    &mut store,
                    &mut files,
                    &mut verifier,
                    |_| Ok(backend.clone())
                )
                .unwrap_err()
                .code,
                ErrorCode::InvalidInput
            );
            assert_eq!(verifier.checks, 0);
            assert!(files.durable.borrow().is_empty());
            assert!(backend.state.borrow().operations.is_empty());
        }
        for change in ["name", "index", "local"] {
            let mut binding = binding();
            match change {
                "name" => binding.interface = "x".repeat(libc::IFNAMSIZ),
                "index" => binding.index = 0,
                _ => binding.local_address = Ipv4Addr::UNSPECIFIED,
            }
            assert!(validate_plan(&plan(vec![route("10.0.0.0/8")]), &binding).is_err());
        }
    }
    #[test]
    fn failed_binding_save_or_backend_construction_cannot_mutate_resources() {
        for fail_save in [true, false] {
            let (mut store, mut files, mut verifier, backend) = fixture();
            files.fail_save = fail_save;
            let mut factories = 0;
            assert!(apply_with(
                plan(vec![route("10.0.0.0/8")]),
                binding(),
                &mut store,
                &mut files,
                &mut verifier,
                |_| {
                    factories += 1;
                    Err::<FakeBackend, _>(recovery())
                }
            )
            .is_err());
            assert_eq!(factories, usize::from(!fail_save));
            assert!(backend.state.borrow().operations.is_empty());
            assert!(files.durable.borrow().is_empty());
        }
    }
    #[test]
    fn known_partial_apply_rolls_back_but_uncertain_creation_retains_the_binding() {
        for uncertain in [false, true] {
            let (mut store, mut files, mut verifier, backend) = fixture();
            {
                let mut state = backend.state.borrow_mut();
                state.fail_apply_at = Some(2);
                state.uncertain_failure = uncertain;
            }
            assert!(apply_with(
                plan(vec![route("10.0.0.0/8"), route("172.16.0.0/12")]),
                binding(),
                &mut store,
                &mut files,
                &mut verifier,
                |_| Ok(backend.clone())
            )
            .is_err());
            assert_eq!(store.phase("attempt-one").is_some(), uncertain);
            assert_eq!(
                files.durable.borrow().contains_key("attempt-one"),
                uncertain
            );
            assert_eq!(
                backend.state.borrow().resources.len(),
                usize::from(uncertain)
            );
        }
    }
    #[test]
    fn rename_then_failed_fsync_never_unlinks_the_binding_using_only_cached_state() {
        let (mut store, mut files, mut verifier, backend) = fixture();
        store.journal.fail_at = Some(1);
        store.journal.rename_before_failure = true;
        assert!(apply_with(
            plan(vec![route("10.0.0.0/8")]),
            binding(),
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone())
        )
        .is_err());
        assert!(store.phase("attempt-one").is_none());
        assert!(!store.durable_absent("attempt-one").unwrap());
        assert!(files.durable.borrow().contains_key("attempt-one"));
        assert_eq!(files.removes, 0);
        assert!(backend.state.borrow().resources.is_empty());
        // A false success is also forbidden when release sees cached absence.
        assert!(release_with(
            "attempt-one",
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend)
        )
        .is_err());
        assert!(files.durable.borrow().contains_key("attempt-one"));
    }
    #[test]
    fn interface_loss_after_process_death_retains_resources_and_the_durable_binding() {
        let (mut store, mut files, mut verifier, backend) = fixture();
        apply_with(
            plan(vec![route("10.0.0.0/8")]),
            binding(),
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone()),
        )
        .unwrap();
        store.coordinator = Coordinator::from_snapshot(store.journal.durable.clone());
        verifier.missing = true;
        let calls = backend.state.borrow().operations.len();
        assert_eq!(
            release_with(
                "attempt-one",
                &mut store,
                &mut files,
                &mut verifier,
                |_| Ok(backend.clone())
            )
            .unwrap_err()
            .code,
            ErrorCode::RecoveryRequired
        );
        assert_eq!(backend.state.borrow().operations.len(), calls);
        assert!(files.durable.borrow().contains_key("attempt-one"));
        assert_eq!(store.phase("attempt-one"), Some(Phase::Active));
    }
    #[test]
    fn binding_is_rechecked_before_inspect_apply_and_remove_and_never_authorizes_foreign_resources()
    {
        let (mut store, mut files, mut verifier, backend) = fixture();
        let record = BindingRecord {
            schema_version: 1,
            plan: plan(vec![route("10.0.0.0/8")]),
            binding: binding(),
        };
        files.save(&record).unwrap();
        for operation in ["inspect", "apply", "remove"] {
            verifier.missing = true;
            let mut guarded = BoundBackend {
                backend: backend.clone(),
                verifier: &mut verifier,
                record: &record,
            };
            let resource = &record.plan.resources[0];
            let result = match operation {
                "inspect" => guarded.inspect(resource).map(|_| ()),
                "apply" => guarded.apply(resource).map(|_| ()),
                _ => guarded.remove(resource, "identity"),
            };
            assert!(result.is_err());
            assert!(backend.state.borrow().operations.is_empty());
        }
        verifier.missing = false;
        let mut guarded = BoundBackend {
            backend,
            verifier: &mut verifier,
            record: &record,
        };
        assert!(guarded.inspect(&route("172.16.0.0/12")).is_err());
        assert!(store.prepare(record.plan.clone(), &mut guarded).is_ok());
    }
    #[test]
    fn missing_or_mismatched_binding_blocks_cleanup_and_external_replacement_is_preserved() {
        let (mut store, mut files, mut verifier, backend) = fixture();
        let route = route("10.0.0.0/8");
        apply_with(
            plan(vec![route.clone()]),
            binding(),
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone()),
        )
        .unwrap();
        let record = files.durable.borrow_mut().remove("attempt-one").unwrap();
        assert!(release_with(
            "attempt-one",
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone())
        )
        .is_err());
        let mut wrong = record.clone();
        wrong.plan.generation += 1;
        files.save(&wrong).unwrap();
        assert!(release_with(
            "attempt-one",
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone())
        )
        .is_err());
        files.save(&record).unwrap();
        backend
            .state
            .borrow_mut()
            .resources
            .insert(route.clone(), "external-replacement".into());
        assert!(release_with(
            "attempt-one",
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone())
        )
        .is_err());
        assert_eq!(
            backend.state.borrow().resources[&route],
            "external-replacement"
        );
        assert!(files.durable.borrow().contains_key("attempt-one"));
    }
    #[test]
    fn binding_remove_failure_keeps_recovery_anchor_after_network_cleanup_and_retry_is_idempotent()
    {
        let (mut store, mut files, mut verifier, backend) = fixture();
        apply_with(
            plan(vec![route("10.0.0.0/8")]),
            binding(),
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone()),
        )
        .unwrap();
        files.fail_remove = true;
        assert!(release_with(
            "attempt-one",
            &mut store,
            &mut files,
            &mut verifier,
            |_| Ok(backend.clone())
        )
        .is_err());
        assert!(store.durable_absent("attempt-one").unwrap());
        assert!(files.durable.borrow().contains_key("attempt-one"));
        assert!(backend.state.borrow().resources.is_empty());
        files.fail_remove = false;
        release_with("attempt-one", &mut store, &mut files, &mut verifier, |_| {
            Err::<FakeBackend, _>(recovery())
        })
        .unwrap();
        release_with("attempt-one", &mut store, &mut files, &mut verifier, |_| {
            Err::<FakeBackend, _>(recovery())
        })
        .unwrap();
        assert!(files.durable.borrow().is_empty());
    }
    #[test]
    fn filesystem_binding_records_are_private_bounded_and_cannot_follow_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let mut files = Files(directory.path());
        let record = BindingRecord {
            schema_version: 1,
            plan: plan(vec![route("10.0.0.0/8")]),
            binding: binding(),
        };
        files.save(&record).unwrap();
        let path = files.path("attempt-one").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(files.read("attempt-one").unwrap(), Some(record.clone()));
        assert!(files.read("../attempt-one").is_err());
        let foreign = directory.path().join("foreign");
        std::fs::rename(&path, &foreign).unwrap();
        symlink(&foreign, &path).unwrap();
        assert!(files.read("attempt-one").is_err());
        assert!(files.remove(&record).is_err());
        assert!(foreign.exists());
        std::fs::remove_file(&path).unwrap();
        files.save(&record).unwrap();
        files.remove(&record).unwrap();
        assert!(files.read("attempt-one").unwrap().is_none());
    }
    #[test]
    fn durable_store_proof_is_reloaded_and_corrupt_journals_block_binding_removal() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = DurableTransactions {
            store: LockedStore::open(directory.path()).unwrap(),
            directory: directory.path(),
        };
        assert!(store.durable_absent("attempt-one").unwrap());
        crate::atomic_file::write_private(&directory.path().join("network.json"), b"corrupt")
            .unwrap();
        assert!(store.durable_absent("attempt-one").is_err());
    }
    #[tokio::test]
    async fn runtime_threads_cannot_enter_native_transaction_driver_even_as_root() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            LinuxTransactions::new(directory.path().into())
                .epoch()
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
    }

    /// Execute only in a disposable Linux network namespace/container with
    /// /dev/net/tun and CAP_NET_ADMIN. Closing the tun fd destroys its link.
    #[cfg(all(target_os = "linux", feature = "linux-network"))]
    #[test]
    #[ignore = "requires disposable Linux netns, root, CAP_NET_ADMIN and /dev/net/tun"]
    fn namespace_native_transactions_verify_tun_binding_and_release_owned_routes() {
        use std::{
            ffi::CString,
            fs::OpenOptions,
            os::{
                fd::{AsRawFd, FromRawFd, OwnedFd},
                unix::fs::PermissionsExt,
            },
        };
        assert_eq!(
            std::env::var("OFV_ISOLATED_NETWORK_TEST").as_deref(),
            Ok("1"),
            "explicitly enable only inside a disposable network namespace"
        );
        assert_eq!(unsafe { libc::geteuid() }, 0);
        fn request(name: &str) -> libc::ifreq {
            let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
            assert!(name.len() < request.ifr_name.len());
            for (target, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
                *target = byte as libc::c_char;
            }
            request
        }
        fn ioctl(socket: &OwnedFd, operation: libc::c_ulong, request: &mut libc::ifreq) {
            assert_eq!(
                unsafe { libc::ioctl(socket.as_raw_fd(), operation, request) },
                0,
                "fixture ioctl failed: {}",
                std::io::Error::last_os_error()
            );
        }
        fn address(socket: &OwnedFd, name: &str, operation: libc::c_ulong, address: Ipv4Addr) {
            let mut request = request(name);
            let mut ipv4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            ipv4.sin_family = libc::AF_INET as libc::sa_family_t;
            ipv4.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
            request.ifr_ifru.ifru_addr = unsafe {
                std::ptr::read((&ipv4 as *const libc::sockaddr_in).cast::<libc::sockaddr>())
            };
            ioctl(socket, operation, &mut request);
        }
        let name = "ofvwrk0";
        let tun = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .expect("fixture requires /dev/net/tun in its disposable Linux namespace");
        let mut tun_request = request(name);
        // EXCL refuses to attach to any pre-existing link in the test namespace.
        tun_request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
        assert_eq!(
            unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, &mut tun_request) },
            0,
            "fixture needs tun support and CAP_NET_ADMIN: {}",
            std::io::Error::last_os_error()
        );
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0);
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let local: Ipv4Addr = "10.253.254.2".parse().unwrap();
        address(&socket, name, libc::SIOCSIFADDR, local);
        address(&socket, name, libc::SIOCSIFNETMASK, Ipv4Addr::BROADCAST);
        let mut flags = request(name);
        ioctl(&socket, libc::SIOCGIFFLAGS, &mut flags);
        let current_flags = unsafe { flags.ifr_ifru.ifru_flags };
        assert_ne!(current_flags as i32 & libc::IFF_POINTOPOINT, 0);
        flags.ifr_ifru.ifru_flags = current_flags | libc::IFF_UP as libc::c_short;
        ioctl(&socket, libc::SIOCSIFFLAGS, &mut flags);
        let index = unsafe { libc::if_nametoindex(CString::new(name).unwrap().as_ptr()) };
        assert_ne!(index, 0);
        let bound = InterfaceBinding {
            interface: name.into(),
            index,
            local_address: local,
            transport_address: "192.0.2.9".parse().unwrap(),
        };
        NativeBinding.verify(&bound.clone().into()).unwrap();
        let mut wrong = Binding::from(bound.clone());
        wrong.index += 1;
        assert!(NativeBinding.verify(&wrong).is_err());
        wrong.index = index;
        wrong.local_address = "10.253.254.99".parse().unwrap();
        assert!(NativeBinding.verify(&wrong).is_err());

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let driver = LinuxTransactions::new(directory.path().into());
        let resource = Resource::Route(Route {
            destination: "198.18.64.0/24".into(),
            gateway: None,
            interface: name.into(),
            metric: 0,
            gateway_exception: false,
        });
        let mut owned_plan = plan(vec![resource.clone()]);
        owned_plan.network_epoch = driver.epoch().unwrap();
        driver.apply(owned_plan.clone(), bound.clone()).unwrap();
        let snapshot = FileJournal(directory.path().join("network.json"))
            .load()
            .unwrap();
        assert_eq!(
            Coordinator::from_snapshot(snapshot).phase("attempt-one"),
            Some(&Phase::Active)
        );
        let record = Files(directory.path())
            .read("attempt-one")
            .unwrap()
            .unwrap();
        assert_eq!(record.plan, owned_plan);
        assert_eq!(record.binding.index, index);
        assert!(crate::network_linux::LinuxRoutes
            .inspect(&resource)
            .unwrap()
            .is_some());

        // Administratively downing the same point-to-point link revokes the
        // binding. An operator action cannot authorize native cleanup.
        let mut down = request(name);
        ioctl(&socket, libc::SIOCGIFFLAGS, &mut down);
        let up_flags = unsafe { down.ifr_ifru.ifru_flags };
        down.ifr_ifru.ifru_flags = up_flags & !(libc::IFF_UP as libc::c_short);
        ioctl(&socket, libc::SIOCSIFFLAGS, &mut down);
        assert!(NativeBinding.verify(&bound.clone().into()).is_err());
        assert_eq!(
            driver.release("attempt-one").unwrap_err().code,
            ErrorCode::RecoveryRequired
        );
        assert_eq!(
            Files(directory.path()).read("attempt-one").unwrap(),
            Some(record.clone())
        );
        let snapshot = FileJournal(directory.path().join("network.json"))
            .load()
            .unwrap();
        assert_eq!(
            Coordinator::from_snapshot(snapshot).phase("attempt-one"),
            Some(&Phase::Active)
        );
        down.ifr_ifru.ifru_flags = up_flags;
        ioctl(&socket, libc::SIOCSIFFLAGS, &mut down);
        NativeBinding.verify(&bound.clone().into()).unwrap();

        // The link name/index survive, but the launcher-owned IPv4 address no
        // longer matches. Cleanup must retain its lease until identity returns.
        address(
            &socket,
            name,
            libc::SIOCSIFADDR,
            "10.253.254.3".parse().unwrap(),
        );
        assert_eq!(
            driver.release("attempt-one").unwrap_err().code,
            ErrorCode::RecoveryRequired
        );
        assert_eq!(
            Files(directory.path()).read("attempt-one").unwrap(),
            Some(record)
        );
        let snapshot = FileJournal(directory.path().join("network.json"))
            .load()
            .unwrap();
        assert_eq!(
            Coordinator::from_snapshot(snapshot).phase("attempt-one"),
            Some(&Phase::Active)
        );
        // Linux may already remove device routes on DOWN/address replacement.
        // That kernel action does not prove a driver cleanup or authorize
        // clearing its durable ownership while the binding is invalid.
        address(&socket, name, libc::SIOCSIFADDR, local);
        address(&socket, name, libc::SIOCSIFNETMASK, Ipv4Addr::BROADCAST);
        driver.release("attempt-one").unwrap();
        assert!(crate::network_linux::LinuxRoutes
            .inspect(&resource)
            .unwrap()
            .is_none());
        assert!(Files(directory.path())
            .read("attempt-one")
            .unwrap()
            .is_none());
        let snapshot = FileJournal(directory.path().join("network.json"))
            .load()
            .unwrap();
        assert!(Coordinator::from_snapshot(snapshot)
            .phase("attempt-one")
            .is_none());
        driver.release("attempt-one").unwrap();
        drop(tun);
    }
}
