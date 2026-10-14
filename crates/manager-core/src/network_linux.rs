//! Linux IPv4 routes through rtnetlink. No shell commands or stale route-table
//! snapshots. This backend intentionally rejects DNS until a provider is bound.
#![cfg(target_os = "linux")]
use crate::{
    network::{Backend, Resource, Route},
    ControlError, ErrorCode,
};
use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

fn error(message: &str) -> ControlError {
    ControlError::new(ErrorCode::RecoveryRequired, message)
}
fn native_error() -> ControlError {
    error("Linux route operation failed")
}
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
fn align(length: usize) -> usize {
    (length + 3) & !3
}
fn attribute(output: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let length = data.len() + 4;
    output.extend_from_slice(&(length as u16).to_ne_bytes());
    output.extend_from_slice(&kind.to_ne_bytes());
    output.extend_from_slice(data);
    output.resize(align(output.len()), 0);
}
fn route_spec(resource: &Resource) -> Result<&Route, ControlError> {
    match resource {
        Resource::Route(route) => Ok(route),
        Resource::Dns(_) => Err(ControlError::new(
            ErrorCode::InvalidInput,
            "Linux DNS provider is not configured",
        )),
    }
}
fn route_message(route: &Route) -> Result<Vec<u8>, ControlError> {
    let (ip, prefix) = route.destination.split_once('/').ok_or_else(native_error)?;
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| native_error())?;
    let prefix: u8 = prefix.parse().map_err(|_| native_error())?;
    let mask = if prefix == 0 {
        0
    } else if prefix <= 32 {
        u32::MAX << (32 - prefix)
    } else {
        return Err(native_error());
    };
    if u32::from(ip) & mask != u32::from(ip) || route.destination != format!("{ip}/{prefix}") {
        return Err(native_error());
    }
    let interface = CString::new(route.interface.as_bytes()).map_err(|_| native_error())?;
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        return Err(native_error());
    }
    // rtmsg: family, dst/src prefix, TOS, main table, application protocol,
    // link/universe scope, unicast type, flags. Protocol 240 identifies us.
    let mut bytes = vec![
        libc::AF_INET as u8,
        prefix,
        0,
        0,
        254,
        240,
        if route.gateway.is_some() { 0 } else { 253 },
        1,
        0,
        0,
        0,
        0,
    ];
    attribute(&mut bytes, 1, &ip.octets());
    attribute(&mut bytes, 4, &index.to_ne_bytes());
    attribute(&mut bytes, 6, &route.metric.to_ne_bytes());
    if let Some(gateway) = route.gateway {
        attribute(&mut bytes, 5, &gateway.octets());
    }
    Ok(bytes)
}
fn attributes(bytes: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, ControlError> {
    if bytes.len() < 12 {
        return Err(native_error());
    }
    let mut result = Vec::new();
    let mut offset = 12;
    while offset < bytes.len() {
        let length = u16_at(bytes, offset).ok_or_else(native_error)? as usize;
        let kind = u16_at(bytes, offset + 2).ok_or_else(native_error)? & 0x3fff;
        if length < 4 || offset + length > bytes.len() || offset + align(length) > bytes.len() {
            return Err(native_error());
        }
        result.push((kind, bytes[offset + 4..offset + length].to_vec()));
        offset += align(length);
    }
    result.sort();
    if result.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(native_error());
    }
    Ok(result)
}
fn matching(actual: &[u8], desired: &[u8]) -> Result<bool, ControlError> {
    if actual.len() < 12 || desired.len() < 12 {
        return Err(native_error());
    }
    if actual[0] != desired[0]
        || actual[1] != desired[1]
        || actual[2] != 0
        || actual[3] != 0
        || actual[7] != 1
    {
        return Ok(false);
    }
    let actual_attrs = attributes(actual)?;
    let desired_attrs = attributes(desired)?;
    let table = actual_attrs
        .iter()
        .find(|(kind, _)| *kind == 15)
        .map(|(_, value)| u32_at(value, 0).ok_or_else(native_error))
        .transpose()?
        .unwrap_or(actual[4] as u32);
    if table != 254 {
        return Ok(false);
    }
    for kind in [1, 4, 5, 6] {
        let actual_value = actual_attrs
            .iter()
            .find(|(key, _)| *key == kind)
            .map(|(_, value)| value.as_slice());
        let desired_value = desired_attrs
            .iter()
            .find(|(key, _)| *key == kind)
            .map(|(_, value)| value.as_slice());
        let zero = [0; 4];
        // Kernel omits all-zero destination and priority attributes.
        let default = if matches!(kind, 1 | 6) {
            Some(zero.as_slice())
        } else {
            None
        };
        if actual_value.or(default) != desired_value.or(default) {
            return Ok(false);
        }
    }
    // A multipath route is not an exact single-interface resource.
    Ok(!actual_attrs.iter().any(|(kind, _)| *kind == 9))
}
fn fingerprint(bytes: &[u8]) -> Result<String, ControlError> {
    // Route cache statistics change while the route is unchanged. Include all
    // remaining rtmsg/attributes, including protocol, scope and preferred source.
    let mut canonical = bytes.get(..12).ok_or_else(native_error)?.to_vec();
    for (kind, value) in attributes(bytes)? {
        if kind != 12 {
            attribute(&mut canonical, kind, &value);
        }
    }
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in canonical {
        write!(encoded, "{byte:02x}").map_err(|_| native_error())?;
    }
    if encoded.len() > 512 {
        return Err(native_error());
    }
    Ok(encoded)
}
pub struct LinuxRoutes;
impl LinuxRoutes {
    fn exchange(kind: u16, flags: u16, payload: &[u8]) -> Result<Vec<Vec<u8>>, ControlError> {
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(native_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let address_length = std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                address_length,
            )
        } != 0
        {
            return Err(native_error());
        }
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } != 0
        {
            return Err(native_error());
        }
        let mut request = Vec::new();
        request.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        request.extend_from_slice(&kind.to_ne_bytes());
        request.extend_from_slice(&flags.to_ne_bytes());
        request.extend_from_slice(&1u32.to_ne_bytes());
        request.extend_from_slice(&0u32.to_ne_bytes());
        request.extend_from_slice(payload);
        if unsafe {
            libc::sendto(
                socket.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                address_length,
            )
        } != request.len() as isize
        {
            return Err(native_error());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut results = Vec::new();
        let mut total = 0usize;
        while Instant::now() < deadline {
            let mut bytes = [0u8; 65536];
            let mut peer: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut peer_length = std::mem::size_of_val(&peer) as libc::socklen_t;
            let received = unsafe {
                libc::recvfrom(
                    socket.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_TRUNC,
                    (&mut peer as *mut libc::sockaddr_nl).cast(),
                    &mut peer_length,
                )
            };
            if received < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(native_error());
            }
            total += received as usize;
            if peer.nl_pid != 0 || received as usize > bytes.len() || total > 1024 * 1024 {
                return Err(native_error());
            }
            let bytes = &bytes[..received as usize];
            let mut offset = 0;
            while offset < bytes.len() {
                let length = u32_at(bytes, offset).ok_or_else(native_error)? as usize;
                let kind = u16_at(bytes, offset + 4).ok_or_else(native_error)?;
                let flags = u16_at(bytes, offset + 6).ok_or_else(native_error)?;
                if length < 16
                    || offset + length > bytes.len()
                    || u32_at(bytes, offset + 8) != Some(1)
                    || flags & 0x10 != 0
                {
                    return Err(native_error());
                }
                let payload = &bytes[offset + 16..offset + length];
                match kind {
                    2 => {
                        let code = u32_at(payload, 0).ok_or_else(native_error)? as i32;
                        if code != 0 {
                            return Err(native_error());
                        }
                        return Ok(results);
                    }
                    3 => {
                        if !payload.is_empty() && u32_at(payload, 0) != Some(0) {
                            return Err(native_error());
                        }
                        return Ok(results);
                    }
                    24 => results.push(payload.to_vec()),
                    _ => return Err(native_error()),
                }
                offset += align(length);
            }
        }
        Err(error("Linux route operation timed out"))
    }
    fn find(route: &Route) -> Result<Option<Vec<u8>>, ControlError> {
        let desired = route_message(route)?;
        let mut matches = Vec::new();
        for actual in Self::exchange(
            26,
            0x301,
            &[libc::AF_INET as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )? {
            if matching(&actual, &desired)? {
                matches.push(actual);
            }
        }
        if matches.len() > 1 {
            return Err(native_error());
        }
        Ok(matches.pop())
    }
}
impl Backend for LinuxRoutes {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        Self::find(route_spec(resource)?)?
            .map(|bytes| fingerprint(&bytes))
            .transpose()
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        let route = route_spec(resource)?;
        if Self::find(route)?.is_some() {
            return Err(error("Linux route already exists"));
        }
        Self::exchange(24, 0x605, &route_message(route)?)?; // REQUEST|ACK|CREATE|EXCL
        self.inspect(resource)?.ok_or_else(native_error)
    }
    fn remove(&mut self, resource: &Resource, expected: &str) -> Result<(), ControlError> {
        let route = route_spec(resource)?;
        let Some(current) = Self::find(route)? else {
            return Ok(());
        };
        if fingerprint(&current)? != expected {
            return Err(error("Linux route changed externally"));
        }
        Self::exchange(25, 5, &current)?;
        if Self::find(route)?.is_some() {
            return Err(native_error());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_attributes_are_rejected_before_kernel_operations() {
        for bytes in [vec![], vec![0; 11], vec![0; 15], {
            let mut b = vec![0; 12];
            b.extend([3, 0, 1, 0]);
            b
        }] {
            assert!(attributes(&bytes).is_err());
        }
    }
    /// This test must run only in the task's disposable Linux container.
    #[test]
    #[ignore = "requires isolated network namespace and CAP_NET_ADMIN"]
    fn namespace_routes_are_owned_and_external_replacements_survive() {
        let resource = Resource::Route(Route {
            destination: "198.18.0.0/24".into(),
            gateway: None,
            interface: "lo".into(),
            metric: 4242,
            gateway_exception: false,
        });
        let mut backend = LinuxRoutes;
        assert!(backend.inspect(&resource).unwrap().is_none());
        let created = backend.apply(&resource).unwrap();
        assert_eq!(backend.inspect(&resource).unwrap(), Some(created.clone()));
        assert!(backend.remove(&resource, "wrong-fingerprint").is_err());
        assert!(backend.inspect(&resource).unwrap().is_some());
        // Replace the kernel resource with an external static route using the
        // same lookup key. Its protocol is part of the cleanup fingerprint.
        let mut external = route_message(route_spec(&resource).unwrap()).unwrap();
        external[5] = 4;
        LinuxRoutes::exchange(24, 0x505, &external).unwrap(); // REPLACE|CREATE|ACK
        assert_ne!(backend.inspect(&resource).unwrap(), Some(created.clone()));
        assert!(backend.remove(&resource, &created).is_err());
        let external_fingerprint = backend.inspect(&resource).unwrap().unwrap();
        backend.remove(&resource, &external_fingerprint).unwrap();
        let created = backend.apply(&resource).unwrap();
        backend.remove(&resource, &created).unwrap();
        backend.remove(&resource, &created).unwrap();
        assert!(backend.inspect(&resource).unwrap().is_none());
    }
}
