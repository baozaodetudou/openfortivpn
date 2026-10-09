//! Scoped Linux DNS through systemd-resolved D-Bus. Only a launcher-bound VPN
//! interface may be changed. Cleanup uses RevertLink so DHCP is reevaluated.
#![cfg(all(target_os = "linux", feature = "linux-network"))]
use crate::{
    network::{Backend, Dns, Resource},
    ControlError, ErrorCode,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ffi::CString, time::Duration};
use zbus::{zvariant::OwnedObjectPath, Connection, Proxy};
#[derive(Clone, Serialize, PartialEq, Eq)]
struct LinkState {
    index: u32,
    dns: Vec<(i32, Vec<u8>)>,
    domains: Vec<(String, bool)>,
    default_route: bool,
}
fn failed() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "systemd-resolved DNS transaction failed",
    )
}
fn invalid() -> ControlError {
    ControlError::new(
        ErrorCode::InvalidInput,
        "DNS resource is not bound to this VPN interface",
    )
}
pub struct ResolvedDns {
    runtime: tokio::runtime::Runtime,
    connection: Connection,
    interfaces: BTreeMap<String, u32>,
}
impl ResolvedDns {
    /// Run on the privileged worker, never on the HTTP executor. Names and
    /// indices must come from the launcher's verified adapter creation result.
    pub fn new(interfaces: BTreeMap<String, u32>) -> Result<Self, ControlError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| failed())?;
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(failed());
        }
        let connection = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")?
                    .build()
                    .await
            })
            .await
            .map_err(|_| failed())?
            .map_err(|_| failed())
        })?;
        Ok(Self {
            runtime,
            connection,
            interfaces,
        })
    }
    fn spec<'a>(&self, resource: &'a Resource) -> Result<(&'a Dns, u32), ControlError> {
        let Resource::Dns(dns) = resource else {
            return Err(invalid());
        };
        let index = *self.interfaces.get(&dns.interface).ok_or_else(invalid)?;
        let name = CString::new(dns.interface.as_bytes()).map_err(|_| invalid())?;
        if index == 0
            || index > i32::MAX as u32
            || unsafe { libc::if_nametoindex(name.as_ptr()) } != index
        {
            return Err(invalid());
        }
        if dns.servers.is_empty() || dns.servers.len() > 4 || dns.domains.len() > 32 {
            return Err(invalid());
        }
        Ok((dns, index))
    }
    async fn manager(connection: &Connection) -> Result<Proxy<'_>, ControlError> {
        Proxy::new(
            connection,
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
        )
        .await
        .map_err(|_| failed())
    }
    async fn state(connection: &Connection, index: u32) -> Result<LinkState, ControlError> {
        let manager = Self::manager(connection).await?;
        let path: OwnedObjectPath = manager
            .call("GetLink", &(index as i32))
            .await
            .map_err(|_| failed())?;
        if path.as_str() != format!("/org/freedesktop/resolve1/link/_{index}") {
            return Err(failed());
        }
        let link = Proxy::new(
            connection,
            "org.freedesktop.resolve1",
            path,
            "org.freedesktop.resolve1.Link",
        )
        .await
        .map_err(|_| failed())?;
        let dns = link.get_property("DNS").await.map_err(|_| failed())?;
        let domains = link.get_property("Domains").await.map_err(|_| failed())?;
        let default_route = link
            .get_property("DefaultRoute")
            .await
            .map_err(|_| failed())?;
        Ok(LinkState {
            index,
            dns,
            domains,
            default_route,
        })
    }
    fn desired(dns: &Dns, index: u32) -> LinkState {
        LinkState {
            index,
            dns: dns
                .servers
                .iter()
                .map(|ip| (libc::AF_INET, ip.octets().to_vec()))
                .collect(),
            domains: dns
                .domains
                .iter()
                .map(|domain| (domain.clone(), true))
                .collect(),
            default_route: dns.domains.is_empty(),
        }
    }
    fn identity(state: &LinkState) -> Result<String, ControlError> {
        let bytes = serde_json::to_vec(state).map_err(|_| failed())?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    async fn set_recoverable(
        connection: &Connection,
        desired: &LinkState,
        previous: LinkState,
    ) -> Result<(), ControlError> {
        let manager = Self::manager(connection).await?;
        let mut confirmed = previous;
        let result = async {
            manager
                .call::<_, _, ()>("SetLinkDNS", &(desired.index as i32, &desired.dns))
                .await
                .map_err(|_| failed())?;
            let mut expected = confirmed.clone();
            expected.dns = desired.dns.clone();
            if Self::state(connection, desired.index).await? != expected {
                return Err(failed());
            }
            confirmed = expected;
            manager
                .call::<_, _, ()>("SetLinkDomains", &(desired.index as i32, &desired.domains))
                .await
                .map_err(|_| failed())?;
            let mut expected = confirmed.clone();
            expected.domains = desired.domains.clone();
            if Self::state(connection, desired.index).await? != expected {
                return Err(failed());
            }
            confirmed = expected;
            manager
                .call::<_, _, ()>(
                    "SetLinkDefaultRoute",
                    &(desired.index as i32, desired.default_route),
                )
                .await
                .map_err(|_| failed())?;
            if Self::state(connection, desired.index).await? != *desired {
                return Err(failed());
            }
            Ok(())
        }
        .await;
        if result.is_err() && (!confirmed.dns.is_empty() || !confirmed.domains.is_empty()) {
            // Revert only completed, read-back-confirmed steps. A lost reply or
            // an external replacement keeps the uncertain journal reservation.
            if Self::state(connection, desired.index).await? == confirmed {
                manager
                    .call::<_, _, ()>("RevertLink", &(desired.index as i32))
                    .await
                    .map_err(|_| failed())?;
            }
        }
        result
    }
}
impl Backend for ResolvedDns {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        let (dns, index) = self.spec(resource)?;
        let desired = Self::desired(dns, index);
        self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let actual = Self::state(&self.connection, index).await?;
                if actual == desired {
                    Self::identity(&actual).map(Some)
                } else if actual.dns.is_empty() && actual.domains.is_empty() {
                    Ok(None)
                } else {
                    Err(ControlError::new(
                        ErrorCode::NetworkConflict,
                        "VPN interface DNS differs from the requested resource",
                    ))
                }
            })
            .await
            .map_err(|_| failed())?
        })
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        let (dns, index) = self.spec(resource)?;
        let desired = Self::desired(dns, index);
        self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let previous = Self::state(&self.connection, index).await?;
                if !previous.dns.is_empty() || !previous.domains.is_empty() {
                    return Err(ControlError::new(
                        ErrorCode::NetworkConflict,
                        "VPN interface already has DNS configuration",
                    ));
                }
                Self::set_recoverable(&self.connection, &desired, previous).await?;
                let actual = Self::state(&self.connection, index).await?;
                if actual != desired {
                    return Err(failed());
                }
                Self::identity(&actual)
            })
            .await
            .map_err(|_| failed())?
        })
    }
    fn remove(&mut self, resource: &Resource, expected: &str) -> Result<(), ControlError> {
        let (_, index) = self.spec(resource)?;
        self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let current = Self::state(&self.connection, index).await?;
                if current.dns.is_empty() && current.domains.is_empty() {
                    return Ok(());
                }
                if Self::identity(&current)? != expected {
                    return Err(failed());
                }
                let manager = Self::manager(&self.connection).await?;
                manager
                    .call::<_, _, ()>("RevertLink", &(index as i32))
                    .await
                    .map_err(|_| failed())?;
                let actual = Self::state(&self.connection, index).await?;
                if !actual.dns.is_empty() || !actual.domains.is_empty() {
                    return Err(failed());
                }
                Ok(())
            })
            .await
            .map_err(|_| failed())?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    struct Fixture {
        dns: Vec<(i32, Vec<u8>)>,
        domains: Vec<(String, bool)>,
        default_route: bool,
        fail_domains: bool,
        replace_on_failure: bool,
        reverts: usize,
    }
    struct Manager(Arc<Mutex<Fixture>>);
    struct Link(Arc<Mutex<Fixture>>);
    #[zbus::interface(name = "org.freedesktop.resolve1.Manager")]
    impl Manager {
        fn get_link(&self, index: i32) -> zbus::fdo::Result<OwnedObjectPath> {
            OwnedObjectPath::try_from(format!("/org/freedesktop/resolve1/link/_{index}"))
                .map_err(|_| zbus::fdo::Error::Failed("bad index".into()))
        }
        #[zbus(name = "SetLinkDNS")]
        fn set_link_dns(&self, _index: i32, dns: Vec<(i32, Vec<u8>)>) {
            self.0.lock().unwrap().dns = dns;
        }
        fn set_link_domains(
            &self,
            _index: i32,
            domains: Vec<(String, bool)>,
        ) -> zbus::fdo::Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.fail_domains {
                if state.replace_on_failure {
                    state.dns = vec![(libc::AF_INET, vec![192, 0, 2, 99])];
                }
                return Err(zbus::fdo::Error::Failed("injected failure".into()));
            }
            state.domains = domains;
            Ok(())
        }
        fn set_link_default_route(&self, _index: i32, enabled: bool) {
            self.0.lock().unwrap().default_route = enabled;
        }
        fn revert_link(&self, _index: i32) {
            let mut state = self.0.lock().unwrap();
            state.dns.clear();
            state.domains.clear();
            state.default_route = true;
            state.reverts += 1;
        }
    }
    #[zbus::interface(name = "org.freedesktop.resolve1.Link")]
    impl Link {
        #[zbus(property, name = "DNS")]
        fn dns(&self) -> Vec<(i32, Vec<u8>)> {
            self.0.lock().unwrap().dns.clone()
        }
        #[zbus(property)]
        fn domains(&self) -> Vec<(String, bool)> {
            self.0.lock().unwrap().domains.clone()
        }
        #[zbus(property)]
        fn default_route(&self) -> bool {
            self.0.lock().unwrap().default_route
        }
    }
    fn fixture() -> (ResolvedDns, Connection, Arc<Mutex<Fixture>>, Resource) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let state = Arc::new(Mutex::new(Fixture {
            default_route: true,
            ..Fixture::default()
        }));
        let index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(index, 0);
        let (connection, server) = runtime.block_on(async {
            let (client, server) = tokio::net::UnixStream::pair().unwrap();
            let service = zbus::connection::Builder::unix_stream(server)
                .server(zbus::Guid::generate())
                .unwrap()
                .p2p()
                .serve_at("/org/freedesktop/resolve1", Manager(state.clone()))
                .unwrap()
                .serve_at(
                    format!("/org/freedesktop/resolve1/link/_{index}"),
                    Link(state.clone()),
                )
                .unwrap()
                .build();
            let client = zbus::connection::Builder::unix_stream(client).p2p().build();
            let (client, server) = tokio::join!(client, service);
            (client.unwrap(), server.unwrap())
        });
        let resource = Resource::Dns(Dns {
            interface: "lo".into(),
            servers: vec!["192.0.2.53".parse().unwrap()],
            domains: vec!["corp.example".into()],
        });
        (
            ResolvedDns {
                runtime,
                connection,
                interfaces: BTreeMap::from([("lo".into(), index)]),
            },
            server,
            state,
            resource,
        )
    }
    #[test]
    fn dbus_split_dns_roundtrip_external_change_and_interface_binding() {
        let (mut backend, _server, state, resource) = fixture();
        assert_eq!(backend.inspect(&resource).unwrap(), None);
        let fingerprint = backend.apply(&resource).unwrap();
        assert_eq!(
            backend.inspect(&resource).unwrap(),
            Some(fingerprint.clone())
        );
        assert!(!state.lock().unwrap().default_route);
        state.lock().unwrap().dns = vec![(libc::AF_INET, vec![192, 0, 2, 99])];
        assert!(backend.inspect(&resource).is_err());
        assert!(backend.remove(&resource, &fingerprint).is_err());
        assert_eq!(state.lock().unwrap().reverts, 0);
        state.lock().unwrap().dns = vec![(libc::AF_INET, vec![192, 0, 2, 53])];
        backend.remove(&resource, &fingerprint).unwrap();
        backend.remove(&resource, &fingerprint).unwrap();
        assert_eq!(state.lock().unwrap().reverts, 1);
        backend.interfaces.insert("lo".into(), 999_999);
        assert!(backend.apply(&resource).is_err());
    }
    #[test]
    fn dbus_known_partial_failure_rolls_back_but_external_replacement_survives() {
        for external in [false, true] {
            let (mut backend, _server, state, resource) = fixture();
            {
                let mut state = state.lock().unwrap();
                state.fail_domains = true;
                state.replace_on_failure = external;
            }
            assert!(backend.apply(&resource).is_err());
            let state = state.lock().unwrap();
            if external {
                assert_eq!(state.reverts, 0);
                assert_eq!(state.dns, [(libc::AF_INET, vec![192, 0, 2, 99])]);
            } else {
                assert_eq!(state.reverts, 1);
                assert!(state.dns.is_empty());
            }
        }
    }
    #[test]
    #[ignore = "requires a disposable Linux network namespace and CAP_NET_ADMIN"]
    fn namespace_route_and_dbus_failure_roll_back_together_under_durable_lock() {
        use crate::network::{BackendCapabilities, LockedStore, Plan, PlatformBackend, Route};
        use std::os::unix::fs::PermissionsExt;
        let (dns, _server, state, dns_resource) = fixture();
        state.lock().unwrap().fail_domains = true;
        let route = Resource::Route(Route {
            destination: "198.18.0.0/24".into(),
            gateway: None,
            interface: "lo".into(),
            metric: 4242,
            gateway_exception: false,
        });
        let mut backend = PlatformBackend {
            routes: crate::network_linux::LinuxRoutes,
            dns,
        };
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = LockedStore::open(directory.path()).unwrap();
        store
            .prepare(
                Plan {
                    attempt_id: "attempt".into(),
                    profile_id: "profile".into(),
                    generation: 1,
                    network_epoch: 0,
                    resources: vec![route.clone(), dns_resource.clone()],
                },
                BackendCapabilities { split_dns: true },
                &mut backend,
            )
            .unwrap();
        assert!(store.apply("attempt", &mut backend).is_err());
        assert!(store.coordinator().phase("attempt").is_none());
        assert!(backend.inspect(&route).unwrap().is_none());
        assert!(backend.inspect(&dns_resource).unwrap().is_none());
        assert_eq!(state.lock().unwrap().reverts, 1);
        drop(store);
        let mut restarted = LockedStore::open(directory.path()).unwrap();
        restarted.release("attempt", &mut backend).unwrap();
        assert!(restarted.coordinator().phase("attempt").is_none());
    }
}
