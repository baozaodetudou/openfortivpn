//! Supplemental DNS dictionaries through SystemConfiguration. This backend is
//! kept separate from routes and global DNS until the macOS VM matrix passes.
#![cfg(target_os = "macos")]
use crate::{
    network::{Backend, Dns, Resource},
    ControlError, ErrorCode,
};
use core_foundation::{
    array::CFArray,
    base::{CFAllocatorRef, CFRelease, CFType, CFTypeRef, TCFType},
    dictionary::CFDictionary,
    string::{CFString, CFStringRef},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{c_void, CString},
    ptr,
};
type StoreRef = *const c_void;
#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCDynamicStoreCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        callback: *const c_void,
        context: *const c_void,
    ) -> StoreRef;
    fn SCDynamicStoreCopyValue(store: StoreRef, key: CFStringRef) -> CFTypeRef;
    fn SCDynamicStoreSetValue(store: StoreRef, key: CFStringRef, value: CFTypeRef) -> u8;
    fn SCDynamicStoreRemoveValue(store: StoreRef, key: CFStringRef) -> u8;
    fn SCError() -> i32;
}
fn failed() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "macOS supplemental DNS transaction failed",
    )
}
fn invalid() -> ControlError {
    ControlError::new(
        ErrorCode::InvalidInput,
        "supplemental DNS is not bound to this VPN interface",
    )
}
fn dictionary(dns: &Dns) -> CFDictionary<CFString, CFType> {
    let servers = dns
        .servers
        .iter()
        .map(|ip| CFString::new(&ip.to_string()))
        .collect::<Vec<_>>();
    let domains = dns
        .domains
        .iter()
        .map(|domain| CFString::new(domain))
        .collect::<Vec<_>>();
    CFDictionary::from_CFType_pairs(&[
        (
            CFString::new("ServerAddresses"),
            CFArray::from_CFTypes(&servers).as_CFType(),
        ),
        (
            CFString::new("SupplementalMatchDomains"),
            CFArray::from_CFTypes(&domains).as_CFType(),
        ),
        (
            CFString::new("InterfaceName"),
            CFString::new(&dns.interface).as_CFType(),
        ),
    ])
}
fn identity(dns: &Dns, index: u32) -> Result<String, ControlError> {
    let bytes = serde_json::to_vec(&(dns, index)).map_err(|_| failed())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub struct MacosSupplementalDns {
    store: StoreRef,
    interfaces: BTreeMap<String, u32>,
}
impl Drop for MacosSupplementalDns {
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.store);
        }
    }
}
impl MacosSupplementalDns {
    /// Open only on the privileged platform worker. Launcher-bound indices are
    /// checked again before every write; this does not grant route capability.
    pub fn new(interfaces: BTreeMap<String, u32>) -> Result<Self, ControlError> {
        let name = CFString::new("OpenFortiVPN Manager Network");
        let store = unsafe {
            SCDynamicStoreCreate(
                ptr::null(),
                name.as_concrete_TypeRef(),
                ptr::null(),
                ptr::null(),
            )
        };
        if store.is_null() {
            return Err(failed());
        }
        Ok(Self { store, interfaces })
    }
    fn spec<'a>(&self, resource: &'a Resource) -> Result<(&'a Dns, u32), ControlError> {
        let Resource::Dns(dns) = resource else {
            return Err(invalid());
        };
        let name = CString::new(dns.interface.as_bytes()).map_err(|_| invalid())?;
        let index = *self.interfaces.get(&dns.interface).ok_or_else(invalid)?;
        if index == 0
            || unsafe { libc::if_nametoindex(name.as_ptr()) } != index
            || dns.servers.is_empty()
            || dns.servers.len() > 4
            || dns.domains.is_empty()
            || dns.domains.len() > 32
        {
            return Err(invalid());
        }
        // Reuse the same bounded canonical domain validation as the coordinator.
        crate::network::Plan {
            attempt_id: "check".into(),
            profile_id: "check".into(),
            generation: 1,
            network_epoch: 0,
            resources: vec![resource.clone()],
        }
        .validate(crate::network::BackendCapabilities { split_dns: true })?;
        Ok((dns, index))
    }
    fn key(index: u32) -> CFString {
        CFString::new(&format!(
            "State:/Network/Service/openfortivpn-manager-{index}/DNS"
        ))
    }
    fn value(&self, key: &CFString) -> Result<Option<CFType>, ControlError> {
        let value = unsafe { SCDynamicStoreCopyValue(self.store, key.as_concrete_TypeRef()) };
        if value.is_null() {
            // kSCStatusNoKey is absence; a lost configd session or permission
            // error must never be treated as permission to create/overwrite.
            if unsafe { SCError() } == 1004 {
                Ok(None)
            } else {
                Err(failed())
            }
        } else {
            Ok(Some(unsafe { CFType::wrap_under_create_rule(value) }))
        }
    }
    fn equals(value: &CFType, desired: &CFDictionary<CFString, CFType>) -> bool {
        value.type_of() == unsafe { core_foundation::dictionary::CFDictionaryGetTypeID() }
            && value == &desired.as_CFType()
    }
}
impl Backend for MacosSupplementalDns {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        let (dns, index) = self.spec(resource)?;
        match self.value(&Self::key(index))? {
            None => Ok(None),
            Some(value) if Self::equals(&value, &dictionary(dns)) => identity(dns, index).map(Some),
            Some(_) => Err(ControlError::new(
                ErrorCode::NetworkConflict,
                "macOS VPN DNS dictionary differs from the requested resource",
            )),
        }
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        let (dns, index) = self.spec(resource)?;
        let key = Self::key(index);
        if self.value(&key)?.is_some() {
            return Err(ControlError::new(
                ErrorCode::NetworkConflict,
                "macOS VPN DNS dictionary already exists",
            ));
        }
        let desired = dictionary(dns);
        if unsafe {
            SCDynamicStoreSetValue(
                self.store,
                key.as_concrete_TypeRef(),
                desired.as_CFTypeRef(),
            )
        } == 0
        {
            return Err(failed());
        }
        let actual = self.value(&key)?.ok_or_else(failed)?;
        if !Self::equals(&actual, &desired) {
            return Err(failed());
        }
        identity(dns, index)
    }
    fn remove(&mut self, resource: &Resource, expected: &str) -> Result<(), ControlError> {
        let (dns, index) = self.spec(resource)?;
        let key = Self::key(index);
        let Some(actual) = self.value(&key)? else {
            return Ok(());
        };
        if expected != identity(dns, index)? || !Self::equals(&actual, &dictionary(dns)) {
            return Err(failed());
        }
        if unsafe { SCDynamicStoreRemoveValue(self.store, key.as_concrete_TypeRef()) } == 0
            || self.value(&key)?.is_some()
        {
            return Err(failed());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supplemental_dictionary_is_exact_and_external_properties_change_ownership() {
        let dns = Dns {
            interface: "ppp-test".into(),
            servers: vec!["192.0.2.53".parse().unwrap()],
            domains: vec!["corp.example".into()],
        };
        let desired = dictionary(&dns);
        assert_eq!(desired.len(), 3);
        assert!(MacosSupplementalDns::equals(
            &dictionary(&dns).as_CFType(),
            &desired
        ));
        let mut external = dns.clone();
        external.servers = vec!["192.0.2.99".parse().unwrap()];
        assert!(!MacosSupplementalDns::equals(
            &dictionary(&external).as_CFType(),
            &desired
        ));
        assert_ne!(identity(&dns, 7).unwrap(), identity(&dns, 8).unwrap());
        assert_ne!(identity(&dns, 7).unwrap(), identity(&external, 7).unwrap());
        assert!(!MacosSupplementalDns::equals(
            &CFString::new("wrong type").as_CFType(),
            &desired
        ));
    }
}
