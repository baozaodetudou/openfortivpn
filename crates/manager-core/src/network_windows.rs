//! Native IP Helper route transactions. Only launcher-bound adapter LUIDs are
//! accepted. Interface DNS/NRPT is deliberately a separate platform capability.
#![cfg(windows)]
use crate::{
    network::{Backend, Resource, Route},
    ControlError, ErrorCode,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::Ipv4Addr};
use windows_sys::Win32::{
    Foundation::ERROR_NOT_FOUND,
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::*,
};
fn failed() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "Windows IP Helper route transaction failed",
    )
}
fn invalid() -> ControlError {
    ControlError::new(
        ErrorCode::InvalidInput,
        "route is not bound to this VPN adapter",
    )
}
fn address(ip: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip.octets()),
                },
            },
            ..SOCKADDR_IN::default()
        },
    }
}
fn ip(value: SOCKADDR_INET) -> Result<Ipv4Addr, ControlError> {
    if unsafe { value.si_family } != AF_INET {
        return Err(failed());
    }
    Ok(Ipv4Addr::from(
        unsafe { value.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
    ))
}
fn fingerprint(row: &MIB_IPFORWARD_ROW2) -> Result<String, ControlError> {
    // Age is a running counter. Include every other identity/behavior field.
    let identity = serde_json::json!({
        "luid": unsafe { row.InterfaceLuid.Value }, "index":row.InterfaceIndex,
        "destination": ip(row.DestinationPrefix.Prefix)?.to_string(), "prefix":row.DestinationPrefix.PrefixLength,
        "nextHop":ip(row.NextHop)?.to_string(), "sitePrefixLength":row.SitePrefixLength,
        "validLifetime":row.ValidLifetime, "preferredLifetime":row.PreferredLifetime,
        "metric":row.Metric, "protocol":row.Protocol, "loopback":row.Loopback,
        "autoconfigureAddress":row.AutoconfigureAddress, "publish":row.Publish,
        "immortal":row.Immortal, "origin":row.Origin,
    });
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&identity).map_err(|_| failed())?)
    ))
}
pub struct WindowsRoutes {
    adapters: BTreeMap<String, u64>,
}
impl WindowsRoutes {
    /// LUIDs are supplied by the verified Wintun creation result, never profile input.
    pub fn new(adapters: BTreeMap<String, u64>) -> Self {
        Self { adapters }
    }
    fn spec<'a>(&self, resource: &'a Resource) -> Result<&'a Route, ControlError> {
        let Resource::Route(route) = resource else {
            return Err(invalid());
        };
        Ok(route)
    }
    fn row(&self, route: &Route) -> Result<MIB_IPFORWARD_ROW2, ControlError> {
        let bound = *self.adapters.get(&route.interface).ok_or_else(invalid)?;
        if bound == 0 || route.interface.len() > 128 || route.interface.contains('\0') {
            return Err(invalid());
        }
        let name: Vec<_> = route.interface.encode_utf16().chain(Some(0)).collect();
        let mut luid = NET_LUID_LH::default();
        if unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) } != 0
            || unsafe { luid.Value } != bound
        {
            return Err(invalid());
        }
        let (destination, prefix) = route.destination.split_once('/').ok_or_else(invalid)?;
        let destination: Ipv4Addr = destination.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        if prefix > 32
            || route.destination != format!("{destination}/{prefix}")
            || (u32::from(destination)
                & if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                })
                != u32::from(destination)
        {
            return Err(invalid());
        }
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe {
            InitializeIpForwardEntry(&mut row);
        }
        row.InterfaceLuid = luid;
        if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut row.InterfaceIndex) } != 0
            || row.InterfaceIndex == 0
        {
            return Err(invalid());
        }
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: address(destination),
            PrefixLength: prefix,
        };
        row.NextHop = address(route.gateway.unwrap_or(Ipv4Addr::UNSPECIFIED));
        row.Metric = route.metric;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        Ok(row)
    }
    fn query(&self, resource: &Resource) -> Result<Option<MIB_IPFORWARD_ROW2>, ControlError> {
        let mut row = self.row(self.spec(resource)?)?;
        let result = unsafe { GetIpForwardEntry2(&mut row) };
        if result == ERROR_NOT_FOUND {
            return Ok(None);
        }
        if result != 0 {
            return Err(failed());
        }
        Ok(Some(row))
    }
}
impl Backend for WindowsRoutes {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        let desired = self.row(self.spec(resource)?)?;
        let Some(row) = self.query(resource)? else {
            return Ok(None);
        };
        if row.Metric != desired.Metric {
            return Err(ControlError::new(
                ErrorCode::NetworkConflict,
                "existing Windows route has a different metric",
            ));
        }
        fingerprint(&row).map(Some)
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        let row = self.row(self.spec(resource)?)?;
        // Create never replaces an existing route. Any unknown success/readback
        // outcome remains uncertain in the caller's durable transaction journal.
        if unsafe { CreateIpForwardEntry2(&row) } != 0 {
            return Err(failed());
        }
        let actual = self.query(resource)?.ok_or_else(failed)?;
        if actual.Metric != row.Metric || actual.Protocol != row.Protocol {
            return Err(failed());
        }
        fingerprint(&actual)
    }
    fn remove(&mut self, resource: &Resource, expected: &str) -> Result<(), ControlError> {
        let Some(row) = self.query(resource)? else {
            return Ok(());
        };
        if fingerprint(&row)? != expected {
            return Err(failed());
        }
        if unsafe { DeleteIpForwardEntry2(&row) } != 0 {
            return Err(failed());
        }
        if self.query(resource)?.is_some() {
            return Err(failed());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_identity_ignores_age_but_detects_protocol_metric_and_adapter_replacement() {
        let mut row = MIB_IPFORWARD_ROW2 {
            DestinationPrefix: IP_ADDRESS_PREFIX {
                Prefix: address("198.18.0.0".parse().unwrap()),
                PrefixLength: 24,
            },
            NextHop: address(Ipv4Addr::UNSPECIFIED),
            Metric: 42,
            Protocol: MIB_IPPROTO_NETMGMT,
            ..MIB_IPFORWARD_ROW2::default()
        };
        let original = fingerprint(&row).unwrap();
        row.Age = 1000;
        assert_eq!(fingerprint(&row).unwrap(), original);
        row.Metric += 1;
        assert_ne!(fingerprint(&row).unwrap(), original);
        row.Metric -= 1;
        row.InterfaceLuid = NET_LUID_LH { Value: 7 };
        assert_ne!(fingerprint(&row).unwrap(), original);
        row.InterfaceLuid = NET_LUID_LH { Value: 0 };
        row.Protocol = 4;
        assert_ne!(fingerprint(&row).unwrap(), original);
    }
}
