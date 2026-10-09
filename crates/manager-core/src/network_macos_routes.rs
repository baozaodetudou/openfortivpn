#![cfg(target_os = "macos")]
//! Native Darwin route provider. This is deliberately not advertised as an
//! accepted platform capability until its disposable-VM tests pass.
//!
//! PF_ROUTE has no compare-and-delete operation. We revalidate the complete
//! snapshot and include its destination, mask, gateway and bound interface in
//! the delete request, but an external writer can race the final syscall. The
//! privileged authority must serialize its own writers and retain recovery
//! ownership whenever an operation's outcome cannot be proved.
use crate::{
    network::{Backend, BackendCapabilities, Plan, Resource, Route},
    ControlError, ErrorCode,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    io,
    mem::{offset_of, size_of},
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

const HEADER: usize = size_of::<libc::rt_msghdr>();
const FLAGS: usize = offset_of!(libc::rt_msghdr, rtm_flags);
const ADDRS: usize = offset_of!(libc::rt_msghdr, rtm_addrs);
const PID: usize = offset_of!(libc::rt_msghdr, rtm_pid);
const SEQ: usize = offset_of!(libc::rt_msghdr, rtm_seq);
const ERRNO: usize = offset_of!(libc::rt_msghdr, rtm_errno);
const METRICS: usize = offset_of!(libc::rt_msghdr, rtm_rmx);
const VERSION: u8 = 5;
const ADD: u8 = 1;
const DELETE: u8 = 2;
const GET: u8 = 4;
const IFINFO2: u8 = 0x12;
const DST: usize = 0;
const GATEWAY: usize = 1;
const NETMASK: usize = 2;
const IFP: usize = 4;
const MAX_DUMP: usize = 8 * 1024 * 1024;
const MAX_PACKETS: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(2);
// PF_ROUTE broadcasts replies to other sockets in the same process. A local
// counter per provider would let two providers accept each other's ACK.
static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(0);

fn failed() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "macOS route operation is uncertain",
    )
}
fn conflict() -> ControlError {
    ControlError::new(
        ErrorCode::NetworkConflict,
        "macOS route differs from the requested resource",
    )
}
fn invalid() -> ControlError {
    ControlError::new(
        ErrorCode::InvalidInput,
        "macOS route is not bound to this VPN interface",
    )
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ControlError> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(failed)?
            .try_into()
            .map_err(|_| failed())?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ControlError> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(failed)?
            .try_into()
            .map_err(|_| failed())?,
    ))
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}
fn aligned(length: usize) -> usize {
    // Darwin's routing ABI rounds sockaddrs to 32-bit words even on LP64.
    (length.max(1) + 3) & !3
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Interface {
    index: u16,
    link: Vec<u8>,
    // Administrative last-change is conservative: a normal interface change
    // also blocks writes. Darwin exposes no stable public ifnet generation ID.
    last_change: [u8; 8],
}
impl Interface {
    fn identity(&self) -> String {
        let mut bytes = self.index.to_ne_bytes().to_vec();
        bytes.extend_from_slice(&self.last_change);
        bytes.extend_from_slice(&self.link);
        digest(&bytes)
    }
}

fn link_address(bytes: &[u8]) -> Result<(u16, &[u8]), ControlError> {
    if bytes.len() < 8 || bytes[0] as usize != bytes.len() || bytes[1] != libc::AF_LINK as u8 {
        return Err(failed());
    }
    let used = 8 + bytes[5] as usize + bytes[6] as usize + bytes[7] as usize;
    if used > bytes.len() {
        return Err(failed());
    }
    Ok((u16_at(bytes, 2)?, &bytes[8..8 + bytes[5] as usize]))
}

fn sockaddrs(bytes: &[u8], mask: u32) -> Result<BTreeMap<usize, Vec<u8>>, ControlError> {
    if mask & !0xff != 0 {
        return Err(failed());
    }
    let mut result = BTreeMap::new();
    let mut offset = 0;
    for kind in 0..8 {
        if mask & (1 << kind) == 0 {
            continue;
        }
        let length = *bytes.get(offset).ok_or_else(failed)? as usize;
        let padded = aligned(length);
        if offset + padded > bytes.len() || (length < 2 && kind != NETMASK) {
            return Err(failed());
        }
        // sa_len == 0 denotes the default-route mask, not an empty datagram.
        result.insert(kind, bytes[offset..offset + length].to_vec());
        offset += padded;
    }
    if offset != bytes.len() {
        return Err(failed());
    }
    Ok(result)
}
fn encode(header: &[u8], addresses: &BTreeMap<usize, Vec<u8>>) -> Result<Vec<u8>, ControlError> {
    if header.len() != HEADER {
        return Err(failed());
    }
    let mut bytes = header.to_vec();
    let mut mask = 0;
    for (&kind, address) in addresses {
        if kind >= 8
            || address.len() > 255
            || address.first().copied().unwrap_or(0) as usize != address.len()
        {
            return Err(failed());
        }
        mask |= 1 << kind;
        bytes.extend_from_slice(address);
        bytes.resize(bytes.len() + aligned(address.len()) - address.len(), 0);
    }
    let length = u16::try_from(bytes.len()).map_err(|_| failed())?;
    bytes[0..2].copy_from_slice(&length.to_ne_bytes());
    put_u32(&mut bytes, ADDRS, mask);
    Ok(bytes)
}

#[derive(Clone)]
struct Message {
    bytes: Vec<u8>,
    addresses: BTreeMap<usize, Vec<u8>>,
}
impl Message {
    fn parse(bytes: &[u8]) -> Result<Self, ControlError> {
        if bytes.len() < HEADER
            || u16_at(bytes, 0)? as usize != bytes.len()
            || bytes[2] != VERSION
            || !matches!(bytes[3], ADD | DELETE | GET)
        {
            return Err(failed());
        }
        let addresses = sockaddrs(&bytes[HEADER..], u32_at(bytes, ADDRS)?)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            addresses,
        })
    }
    fn flags(&self) -> Result<u32, ControlError> {
        u32_at(&self.bytes, FLAGS)
    }
    fn fingerprint(&self, interface: &Interface) -> Result<String, ControlError> {
        let mut bytes = interface.identity().into_bytes();
        bytes.extend_from_slice(&u16_at(&self.bytes, 4)?.to_ne_bytes());
        // DONE and IFREF are message/reference bookkeeping, not route policy.
        bytes.extend_from_slice(
            &(self.flags()? & !(libc::RTF_DONE | libc::RTF_IFREF) as u32).to_ne_bytes(),
        );
        let mut metrics = self.bytes[METRICS..HEADER].to_vec();
        let packets = offset_of!(libc::rt_metrics, rmx_pksent);
        metrics[packets..packets + 4].fill(0);
        bytes.extend_from_slice(&metrics);
        for (&kind, address) in &self.addresses {
            bytes.push(kind as u8);
            let normalized = if kind == NETMASK {
                ipv4_mask(address)?.octets().to_vec()
            } else {
                address.clone()
            };
            bytes.extend_from_slice(&(normalized.len() as u16).to_ne_bytes());
            bytes.extend_from_slice(&normalized);
        }
        Ok(digest(&bytes))
    }
    fn request(
        &self,
        kind: u8,
        sequence: u32,
        interface: &Interface,
    ) -> Result<Vec<u8>, ControlError> {
        let mut header = self.bytes[..HEADER].to_vec();
        header[3] = kind;
        header[4..6].copy_from_slice(&interface.index.to_ne_bytes());
        put_u32(&mut header, PID, unsafe { libc::getpid() } as u32);
        put_u32(&mut header, SEQ, sequence);
        put_u32(&mut header, ERRNO, 0);
        put_u32(&mut header, offset_of!(libc::rt_msghdr, rtm_use), 0);
        put_u32(
            &mut header,
            FLAGS,
            self.flags()? & !(libc::RTF_DONE | libc::RTF_IFREF) as u32,
        );
        let mut addresses = self.addresses.clone();
        // Table dumps need not include IFP. Always supply our validated binding.
        addresses.insert(IFP, interface.link.clone());
        encode(&header, &addresses)
    }
}

fn ipv4(address: &[u8]) -> Result<Ipv4Addr, ControlError> {
    if address.len() != 16 || address[0] != 16 || address[1] != libc::AF_INET as u8 {
        return Err(failed());
    }
    Ok(Ipv4Addr::new(
        address[4], address[5], address[6], address[7],
    ))
}
fn ipv4_mask(address: &[u8]) -> Result<Ipv4Addr, ControlError> {
    if address.is_empty() {
        return Ok(Ipv4Addr::UNSPECIFIED);
    }
    if address.len() < 2
        || address.len() > 16
        || !matches!(address[1] as i32, libc::AF_UNSPEC | libc::AF_INET)
    {
        return Err(failed());
    }
    let mut octets = [0; 4];
    for (offset, octet) in octets.iter_mut().enumerate() {
        *octet = address.get(4 + offset).copied().unwrap_or(0);
    }
    let mask = u32::from_be_bytes(octets);
    if mask != 0 && mask != u32::MAX << mask.trailing_zeros() {
        return Err(failed());
    }
    Ok(Ipv4Addr::from(octets))
}
fn sockaddr(address: Ipv4Addr, family: u8) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes[0] = 16;
    bytes[1] = family;
    bytes[4..8].copy_from_slice(&address.octets());
    bytes
}
fn destination(route: &Route) -> Result<(Ipv4Addr, Ipv4Addr, u8), ControlError> {
    let (address, prefix) = route.destination.split_once('/').ok_or_else(invalid)?;
    let address: Ipv4Addr = address.parse().map_err(|_| invalid())?;
    let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
    if prefix > 32 {
        return Err(invalid());
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if u32::from(address) & mask != u32::from(address)
        || route.destination != format!("{address}/{prefix}")
    {
        return Err(invalid());
    }
    Ok((address, Ipv4Addr::from(mask), prefix))
}
fn desired(route: &Route, interface: &Interface, sequence: u32) -> Result<Vec<u8>, ControlError> {
    let (destination, mask, prefix) = destination(route)?;
    let mut header = vec![0; HEADER];
    header[2] = VERSION;
    header[3] = ADD;
    header[4..6].copy_from_slice(&interface.index.to_ne_bytes());
    let mut flags = libc::RTF_UP | libc::RTF_STATIC;
    if prefix == 32 {
        flags |= libc::RTF_HOST;
    }
    if route.gateway.is_some() {
        flags |= libc::RTF_GATEWAY;
    }
    put_u32(&mut header, FLAGS, flags as u32);
    put_u32(&mut header, PID, unsafe { libc::getpid() } as u32);
    put_u32(&mut header, SEQ, sequence);
    let addresses = BTreeMap::from([
        (DST, sockaddr(destination, libc::AF_INET as u8)),
        (
            GATEWAY,
            route
                .gateway
                .map(|gateway| sockaddr(gateway, libc::AF_INET as u8))
                .unwrap_or_else(|| interface.link.clone()),
        ),
        (NETMASK, sockaddr(mask, libc::AF_UNSPEC as u8)),
        (IFP, interface.link.clone()),
    ]);
    encode(&header, &addresses)
}
fn messages(bytes: &[u8]) -> Result<Vec<Message>, ControlError> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let length = u16_at(bytes, offset)? as usize;
        if length < HEADER || offset + length > bytes.len() || result.len() == 65536 {
            return Err(failed());
        }
        let message = Message::parse(&bytes[offset..offset + length])?;
        if message.bytes[3] != GET || u32_at(&message.bytes, ERRNO)? != 0 {
            return Err(failed());
        }
        result.push(message);
        offset += length;
    }
    Ok(result)
}

trait Transport {
    fn interface(&mut self, name: &str, index: u16) -> Result<Interface, ControlError>;
    fn dump(&mut self) -> Result<Vec<u8>, ControlError>;
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ControlError>;
}
struct Native;
fn sysctl_dump(mut mib: [i32; 6]) -> Result<Vec<u8>, ControlError> {
    // A growing table can race the length probe. Retry the whole bounded read,
    // never accept partial output from ENOMEM or a truncated final message.
    for _ in 0..3 {
        let mut length = 0;
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                std::ptr::null_mut(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        } != 0
            || length > MAX_DUMP
        {
            return Err(failed());
        }
        let mut bytes = vec![0; length.max(1)];
        let mut actual = length;
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                bytes.as_mut_ptr().cast(),
                &mut actual,
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            if actual > length {
                return Err(failed());
            }
            bytes.truncate(actual);
            return Ok(bytes);
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return Err(failed());
        }
    }
    Err(failed())
}
fn interface_snapshot(bytes: &[u8], name: &str, index: u16) -> Result<Interface, ControlError> {
    let mut offset = 0;
    let mut found = None;
    while offset < bytes.len() {
        let length = u16_at(bytes, offset)? as usize;
        if length < 4 || offset + length > bytes.len() || bytes[offset + 2] != VERSION {
            return Err(failed());
        }
        let message = &bytes[offset..offset + length];
        if message[3] == IFINFO2 {
            let header_size = size_of::<libc::if_msghdr2>();
            if message.len() < header_size {
                return Err(failed());
            }
            let actual_index = u16_at(message, offset_of!(libc::if_msghdr2, ifm_index))?;
            if actual_index == index {
                let addresses = sockaddrs(
                    &message[header_size..],
                    u32_at(message, offset_of!(libc::if_msghdr2, ifm_addrs))?,
                )?;
                let link = addresses.get(&IFP).ok_or_else(failed)?.clone();
                let (link_index, link_name) = link_address(&link)?;
                let last_change = offset_of!(libc::if_msghdr2, ifm_data)
                    + offset_of!(libc::if_data64, ifi_lastchange);
                let last_change: [u8; 8] = message
                    .get(last_change..last_change + 8)
                    .ok_or_else(failed)?
                    .try_into()
                    .map_err(|_| failed())?;
                let seconds =
                    i32::from_ne_bytes(last_change[..4].try_into().map_err(|_| failed())?);
                let micros = i32::from_ne_bytes(last_change[4..].try_into().map_err(|_| failed())?);
                if link_index != index
                    || link_name != name.as_bytes()
                    || seconds <= 0
                    || !(0..1_000_000).contains(&micros)
                    || found.is_some()
                {
                    return Err(failed());
                }
                found = Some(Interface {
                    index,
                    link,
                    last_change,
                });
            }
        }
        offset += length;
    }
    found.ok_or_else(failed)
}

trait PacketSocket {
    fn send(&mut self, request: &[u8], deadline: Instant) -> Result<(), ControlError>;
    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, ControlError>;
}
fn route_exchange(socket: &mut impl PacketSocket, request: &[u8]) -> Result<Vec<u8>, ControlError> {
    let request_message = Message::parse(request)?;
    let deadline = Instant::now() + TIMEOUT;
    socket.send(request, deadline)?;
    let mut total = 0usize;
    for _ in 0..MAX_PACKETS {
        if Instant::now() >= deadline {
            return Err(failed());
        }
        let bytes = socket.receive(deadline)?;
        total = total.checked_add(bytes.len()).ok_or_else(failed)?;
        if bytes.len() < 4
            || bytes.len() != u16_at(&bytes, 0)? as usize
            || bytes[2] != VERSION
            || total > MAX_DUMP
        {
            return Err(failed());
        }
        if !matches!(bytes[3], ADD | DELETE | GET) {
            continue;
        }
        let reply = Message::parse(&bytes)?;
        if u32_at(&reply.bytes, PID)? != u32_at(request, PID)?
            || u32_at(&reply.bytes, SEQ)? != u32_at(request, SEQ)?
        {
            continue;
        }
        if reply.bytes[3] != request_message.bytes[3] {
            return Err(failed());
        }
        let errno = u32_at(&reply.bytes, ERRNO)? as i32;
        if errno != 0 {
            return Err(if errno == libc::EEXIST && request[3] == ADD {
                conflict()
            } else {
                failed()
            });
        }
        return Ok(bytes);
    }
    Err(failed())
}
struct RouteSocket(OwnedFd);
impl RouteSocket {
    fn open() -> Result<Self, ControlError> {
        let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET) };
        if fd < 0 {
            return Err(failed());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::adopt(fd)
    }
    fn adopt(fd: OwnedFd) -> Result<Self, ControlError> {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } != 0
        {
            return Err(failed());
        }
        Ok(Self(fd))
    }
    fn receive_with_capacity(
        &mut self,
        deadline: Instant,
        capacity: usize,
    ) -> Result<Vec<u8>, ControlError> {
        loop {
            self.ready(libc::POLLIN, deadline)?;
            let mut bytes = vec![0; capacity];
            let mut vector = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            let received = unsafe { libc::recvmsg(self.0.as_raw_fd(), &mut message, 0) };
            if received < 0
                && matches!(
                    io::Error::last_os_error().kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                )
            {
                continue;
            }
            if received <= 0
                || received as usize > bytes.len()
                || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            {
                return Err(failed());
            }
            bytes.truncate(received as usize);
            return Ok(bytes);
        }
    }
    fn ready(&self, events: i16, deadline: Instant) -> Result<(), ControlError> {
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(failed)?;
            let mut poll = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events,
                revents: 0,
            };
            let result = unsafe {
                libc::poll(
                    &mut poll,
                    1,
                    left.as_millis().clamp(1, i32::MAX as u128) as i32,
                )
            };
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if result <= 0
                || poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                || poll.revents & events == 0
            {
                return Err(failed());
            }
            return Ok(());
        }
    }
}
impl PacketSocket for RouteSocket {
    fn send(&mut self, request: &[u8], deadline: Instant) -> Result<(), ControlError> {
        loop {
            self.ready(libc::POLLOUT, deadline)?;
            let sent =
                unsafe { libc::write(self.0.as_raw_fd(), request.as_ptr().cast(), request.len()) };
            if sent == request.len() as isize {
                return Ok(());
            }
            if sent < 0
                && matches!(
                    io::Error::last_os_error().kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                )
            {
                continue;
            }
            // Never retry a short write: a mutation may already have happened.
            return Err(failed());
        }
    }
    fn receive(&mut self, deadline: Instant) -> Result<Vec<u8>, ControlError> {
        self.receive_with_capacity(deadline, 65536)
    }
}
impl Transport for Native {
    fn interface(&mut self, name: &str, index: u16) -> Result<Interface, ControlError> {
        let name_c = CString::new(name).map_err(|_| invalid())?;
        if unsafe { libc::if_nametoindex(name_c.as_ptr()) } != u32::from(index) {
            return Err(invalid());
        }
        let bytes = sysctl_dump([
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_UNSPEC,
            libc::NET_RT_IFLIST2,
            i32::from(index),
        ])?;
        interface_snapshot(&bytes, name, index)
    }
    fn dump(&mut self) -> Result<Vec<u8>, ControlError> {
        sysctl_dump([
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_INET,
            libc::NET_RT_DUMP,
            0,
        ])
    }
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ControlError> {
        route_exchange(&mut RouteSocket::open()?, request)
    }
}

struct Routes<T> {
    transport: T,
    interfaces: BTreeMap<String, Interface>,
}
impl<T: Transport> Routes<T> {
    fn new(mut transport: T, interfaces: BTreeMap<String, u32>) -> Result<Self, ControlError> {
        if interfaces.is_empty() || interfaces.len() > 128 {
            return Err(invalid());
        }
        let mut bound = BTreeMap::new();
        for (name, index) in interfaces {
            if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.chars().any(char::is_control)
            {
                return Err(invalid());
            }
            let index = u16::try_from(index).map_err(|_| invalid())?;
            if index == 0 {
                return Err(invalid());
            }
            bound.insert(name.clone(), transport.interface(&name, index)?);
        }
        Ok(Self {
            transport,
            interfaces: bound,
        })
    }
    fn binding(&mut self, name: &str) -> Result<Interface, ControlError> {
        let bound = self.interfaces.get(name).ok_or_else(invalid)?.clone();
        if self.transport.interface(name, bound.index)? != bound {
            return Err(failed());
        }
        Ok(bound)
    }
    fn spec<'a>(&mut self, resource: &'a Resource) -> Result<(&'a Route, Interface), ControlError> {
        let Resource::Route(route) = resource else {
            return Err(invalid());
        };
        Plan {
            attempt_id: "check".into(),
            profile_id: "check".into(),
            generation: 1,
            network_epoch: 0,
            resources: vec![resource.clone()],
        }
        .validate(BackendCapabilities { split_dns: false })?;
        if route.metric != 0 {
            return Err(ControlError::new(
                ErrorCode::InvalidInput,
                "Darwin does not support route priority metrics",
            ));
        }
        Ok((route, self.binding(&route.interface)?))
    }
    fn next_sequence(&mut self) -> Result<u32, ControlError> {
        NEXT_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |sequence| {
                sequence
                    .checked_add(1)
                    .filter(|next| *next <= i32::MAX as u32)
            })
            .map(|previous| previous + 1)
            .map_err(|_| failed())
    }
    fn find(&mut self, route: &Route, bound: &Interface) -> Result<Option<Message>, ControlError> {
        let (destination, mask, prefix) = destination(route)?;
        let mut found = None;
        for message in messages(&self.transport.dump()?)? {
            let flags = message.flags()?;
            // This backend installs global routes. Scoped entries are a
            // different kernel resource and must never be mistaken for ours.
            if flags & libc::RTF_IFSCOPE as u32 != 0 {
                continue;
            }
            let actual_destination = ipv4(message.addresses.get(&DST).ok_or_else(failed)?)?;
            let actual_mask = match message.addresses.get(&NETMASK) {
                Some(mask) => ipv4_mask(mask)?,
                None if flags & libc::RTF_HOST as u32 != 0 => Ipv4Addr::BROADCAST,
                None => return Err(failed()),
            };
            if actual_destination != destination || actual_mask != mask {
                continue;
            }
            let gateway = message.addresses.get(&GATEWAY).ok_or_else(failed)?;
            let gateway_matches = match route.gateway {
                Some(desired) => ipv4(gateway)? == desired && flags & libc::RTF_GATEWAY as u32 != 0,
                None => {
                    link_address(gateway)?.0 == bound.index && flags & libc::RTF_GATEWAY as u32 == 0
                }
            };
            if u16_at(&message.bytes, 4)? != bound.index
                || !gateway_matches
                || (flags & libc::RTF_HOST as u32 != 0) != (prefix == 32)
                || flags & (libc::RTF_UP | libc::RTF_REJECT | libc::RTF_BLACKHOLE) as u32
                    != libc::RTF_UP as u32
                || u32_at(
                    &message.bytes,
                    METRICS + offset_of!(libc::rt_metrics, rmx_hopcount),
                )? != 0
                || found.is_some()
            {
                return Err(conflict());
            }
            if let Some(link) = message.addresses.get(&IFP) {
                let (index, name) = link_address(link)?;
                if index != bound.index || name != route.interface.as_bytes() {
                    return Err(conflict());
                }
            }
            found = Some(message);
        }
        self.binding(&route.interface)?;
        Ok(found)
    }
}
impl<T: Transport> Backend for Routes<T> {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        let (route, bound) = self.spec(resource)?;
        self.find(route, &bound)?
            .map(|message| message.fingerprint(&bound))
            .transpose()
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        let (route, bound) = self.spec(resource)?;
        if self.find(route, &bound)?.is_some() {
            return Err(conflict());
        }
        let sequence = self.next_sequence()?;
        let request = desired(route, &bound, sequence)?;
        self.binding(&route.interface)?;
        self.transport.exchange(&request)?;
        self.binding(&route.interface).map_err(|_| failed())?;
        let actual = self
            .find(route, &bound)
            .map_err(|_| failed())?
            .ok_or_else(failed)?;
        if actual.flags()? & libc::RTF_STATIC as u32 == 0 {
            return Err(failed());
        }
        actual.fingerprint(&bound)
    }
    fn remove(&mut self, resource: &Resource, expected: &str) -> Result<(), ControlError> {
        let (route, bound) = self.spec(resource)?;
        let Some(current) = self.find(route, &bound)? else {
            return Ok(());
        };
        if current.fingerprint(&bound)? != expected {
            return Err(failed());
        }
        let sequence = self.next_sequence()?;
        let request = current.request(DELETE, sequence, &bound)?;
        self.binding(&route.interface)?;
        self.transport.exchange(&request)?;
        self.binding(&route.interface).map_err(|_| failed())?;
        if self.find(route, &bound).map_err(|_| failed())?.is_some() {
            return Err(failed());
        }
        Ok(())
    }
}

/// Open on the privileged platform worker after the launcher has supplied
/// interface indices. Construction only reads interface metadata. Routes and
/// DNS can be composed with `network::PlatformBackend`.
pub struct MacosRoutes(Routes<Native>);
impl MacosRoutes {
    pub fn new(interfaces: BTreeMap<String, u32>) -> Result<Self, ControlError> {
        Ok(Self(Routes::new(Native, interfaces)?))
    }
}
impl Backend for MacosRoutes {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        self.0.inspect(resource)
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        self.0.apply(resource)
    }
    fn remove(&mut self, resource: &Resource, expected: &str) -> Result<(), ControlError> {
        self.0.remove(resource, expected)
    }
}

pub type MacosNetwork =
    crate::network::PlatformBackend<MacosRoutes, crate::network_macos::MacosSupplementalDns>;

/// Construct the route and supplemental-DNS providers on the privileged
/// worker. This performs metadata reads and opens a Dynamic Store session;
/// network changes occur only through explicit Backend apply/remove calls.
pub fn new_backend(interfaces: BTreeMap<String, u32>) -> Result<MacosNetwork, ControlError> {
    Ok(crate::network::PlatformBackend {
        routes: MacosRoutes::new(interfaces.clone())?,
        dns: crate::network_macos::MacosSupplementalDns::new(interfaces)?,
    })
}

#[cfg(test)]
#[path = "network_macos_routes_tests.rs"]
mod tests;
