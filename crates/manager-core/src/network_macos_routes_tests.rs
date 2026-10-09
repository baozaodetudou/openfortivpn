use super::*;
use std::collections::VecDeque;

fn interface() -> Interface {
    let mut link = vec![0; 16];
    link[0] = 16;
    link[1] = libc::AF_LINK as u8;
    link[2..4].copy_from_slice(&42u16.to_ne_bytes());
    link[4] = 23; // IFT_PPP
    link[5] = 8;
    link[8..].copy_from_slice(b"ppp-test");
    let mut last_change = [0; 8];
    last_change[..4].copy_from_slice(&12345i32.to_ne_bytes());
    last_change[4..].copy_from_slice(&678901i32.to_ne_bytes());
    Interface {
        index: 42,
        link,
        last_change,
    }
}
fn resource() -> Resource {
    Resource::Route(Route {
        destination: "198.18.0.0/24".into(),
        gateway: None,
        interface: "ppp-test".into(),
        metric: 0,
        gateway_exception: false,
    })
}
fn route(resource: &Resource) -> &Route {
    match resource {
        Resource::Route(route) => route,
        _ => unreachable!(),
    }
}
fn table_entry(resource: &Resource) -> Vec<u8> {
    let mut bytes = desired(route(resource), &interface(), 7).unwrap();
    bytes[3] = GET;
    // Table output includes kernel-derived MTU and an interface address.
    put_u32(
        &mut bytes,
        METRICS + offset_of!(libc::rt_metrics, rmx_mtu),
        1400,
    );
    let message = Message::parse(&bytes).unwrap();
    let mut addresses = message.addresses;
    addresses.insert(
        5,
        sockaddr("198.18.0.1".parse().unwrap(), libc::AF_INET as u8),
    );
    encode(&bytes[..HEADER], &addresses).unwrap()
}
struct Packets {
    sent: Vec<Vec<u8>>,
    replies: VecDeque<Result<Vec<u8>, ControlError>>,
    send_fails: bool,
}
impl PacketSocket for Packets {
    fn send(&mut self, request: &[u8], _deadline: Instant) -> Result<(), ControlError> {
        self.sent.push(request.to_vec());
        if self.send_fails {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn receive(&mut self, _deadline: Instant) -> Result<Vec<u8>, ControlError> {
        self.replies.pop_front().unwrap_or_else(|| Err(failed()))
    }
}
impl Packets {
    fn replies(replies: Vec<Vec<u8>>) -> Self {
        Self {
            sent: vec![],
            replies: replies.into_iter().map(Ok).collect(),
            send_fails: false,
        }
    }
}
struct Fake {
    dumps: VecDeque<Result<Vec<u8>, ControlError>>,
    requests: Vec<Vec<u8>>,
    interface_reads: usize,
    changed_at: Option<usize>,
    exchange_fails: bool,
}
impl Fake {
    fn with_dumps(dumps: Vec<Vec<u8>>) -> Self {
        Self {
            dumps: dumps.into_iter().map(Ok).collect(),
            requests: vec![],
            interface_reads: 0,
            changed_at: None,
            exchange_fails: false,
        }
    }
}
impl Transport for Fake {
    fn interface(&mut self, name: &str, index: u16) -> Result<Interface, ControlError> {
        assert_eq!(name, "ppp-test");
        assert_eq!(index, 42);
        self.interface_reads += 1;
        let mut interface = interface();
        if self.changed_at.is_some_and(|at| self.interface_reads >= at) {
            // Same name and index after recreation, different native epoch.
            interface.last_change[4..].copy_from_slice(&678902i32.to_ne_bytes());
        }
        Ok(interface)
    }
    fn dump(&mut self) -> Result<Vec<u8>, ControlError> {
        self.dumps.pop_front().expect("unexpected extra table read")
    }
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ControlError> {
        self.requests.push(request.to_vec());
        let mut packets = Packets::replies(vec![request.to_vec()]);
        packets.send_fails = self.exchange_fails;
        route_exchange(&mut packets, request)
    }
}
fn backend(fake: Fake) -> Routes<Fake> {
    Routes::new(fake, BTreeMap::from([("ppp-test".into(), 42)])).unwrap()
}
fn assert_code<T>(result: Result<T, ControlError>, code: ErrorCode) {
    assert!(matches!(result, Err(error) if error.code == code));
}

// These tests exercise the real nonblocking write/poll/recvmsg transport over
// local IPC datagrams. They never open PF_ROUTE or touch a network resource.
fn datagram_pair() -> (RouteSocket, RouteSocket) {
    let mut descriptors = [-1; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, descriptors.as_mut_ptr()) },
        0
    );
    let left = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let right = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    (
        RouteSocket::adopt(left).unwrap(),
        RouteSocket::adopt(right).unwrap(),
    )
}

#[test]
fn native_datagram_transport_enforces_deadline_truncation_and_close_on_exec() {
    let (mut left, mut right) = datagram_pair();
    for socket in [&left, &right] {
        assert_ne!(
            unsafe { libc::fcntl(socket.0.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(socket.0.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
    }
    assert_code(
        left.receive(Instant::now() + Duration::from_millis(5)),
        ErrorCode::RecoveryRequired,
    );
    let deadline = Instant::now() + TIMEOUT;
    right.send(&[7; 32], deadline).unwrap();
    assert_code(
        left.receive_with_capacity(deadline, 8),
        ErrorCode::RecoveryRequired,
    );
    right.send(&[8; 16], deadline).unwrap();
    assert_eq!(left.receive(deadline).unwrap(), vec![8; 16]);
    drop(right);
    assert_code(left.send(&[9; 16], deadline), ErrorCode::RecoveryRequired);
}

#[test]
fn native_datagram_reply_loop_uses_full_pid_and_sequence_match() {
    let (mut socket, mut peer) = datagram_pair();
    let resource = resource();
    let request = desired(route(&resource), &interface(), 71).unwrap();
    let responder = std::thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT;
        let request = peer.receive(deadline).unwrap();
        let mut other = request.clone();
        put_u32(&mut other, SEQ, 72);
        peer.send(&other, deadline).unwrap();
        peer.send(&request, deadline).unwrap();
    });
    assert_eq!(route_exchange(&mut socket, &request).unwrap(), request);
    responder.join().unwrap();
}

#[test]
fn sequence_identity_is_unique_across_provider_instances() {
    let mut first = backend(Fake::with_dumps(vec![]));
    let mut second = backend(Fake::with_dumps(vec![]));
    assert_ne!(
        first.next_sequence().unwrap(),
        second.next_sequence().unwrap()
    );
}

#[test]
fn codec_uses_darwin_abi_and_validates_all_sockaddr_boundaries() {
    assert_eq!(HEADER, 92);
    assert_eq!(METRICS, 36);
    let bytes = table_entry(&resource());
    let parsed = Message::parse(&bytes).unwrap();
    assert_eq!(parsed.addresses.len(), 5);
    for end in 0..bytes.len() {
        assert!(
            Message::parse(&bytes[..end]).is_err(),
            "truncation at {end}"
        );
    }
    let mut malformed = bytes.clone();
    malformed[HEADER] = 255;
    assert!(Message::parse(&malformed).is_err());
    let mut unknown_mask = bytes.clone();
    put_u32(&mut unknown_mask, ADDRS, 0x100);
    assert!(Message::parse(&unknown_mask).is_err());
    let mut trailing = bytes.clone();
    trailing.extend([0, 0, 0, 0]);
    let length = trailing.len() as u16;
    trailing[..2].copy_from_slice(&length.to_ne_bytes());
    assert!(Message::parse(&trailing).is_err());
    let mut bad_version = bytes;
    bad_version[2] = 4;
    assert!(messages(&bad_version).is_err());
}
#[test]
fn masks_accept_darwin_compaction_and_reject_noncontiguous_networks() {
    assert_eq!(ipv4_mask(&[]).unwrap(), Ipv4Addr::UNSPECIFIED);
    let mut mask = sockaddr("255.255.255.0".parse().unwrap(), 0);
    mask.truncate(7);
    mask[0] = 7;
    assert_eq!(
        ipv4_mask(&mask).unwrap(),
        "255.255.255.0".parse::<Ipv4Addr>().unwrap()
    );
    assert!(ipv4_mask(&sockaddr("255.0.255.0".parse().unwrap(), 0)).is_err());
    let mut resource = resource();
    if let Resource::Route(route) = &mut resource {
        route.destination = "0.0.0.0/0".into();
    }
    let mut message = Message::parse(&table_entry(&resource)).unwrap();
    message.addresses.insert(NETMASK, vec![]);
    let encoded = encode(&message.bytes[..HEADER], &message.addresses).unwrap();
    assert!(Message::parse(&encoded).unwrap().addresses[&NETMASK].is_empty());
    let mut provider = backend(Fake::with_dumps(vec![encoded]));
    assert!(provider.inspect(&resource).unwrap().is_some());

    let bytes = table_entry(&self::resource());
    let mut compact = Message::parse(&bytes).unwrap();
    let mut mask = compact.addresses[&NETMASK].clone();
    mask.truncate(7);
    mask[0] = 7;
    compact.addresses.insert(NETMASK, mask);
    compact.bytes = encode(&compact.bytes[..HEADER], &compact.addresses).unwrap();
    assert_eq!(
        compact.fingerprint(&interface()).unwrap(),
        Message::parse(&bytes)
            .unwrap()
            .fingerprint(&interface())
            .unwrap()
    );
}

#[test]
fn gateway_exception_host_routes_keep_ipv4_gateway_and_bound_interface() {
    let mut resource = resource();
    if let Resource::Route(route) = &mut resource {
        route.destination = "203.0.113.10/32".into();
        route.gateway = Some("192.0.2.1".parse().unwrap());
        route.gateway_exception = true;
    }
    let request = Message::parse(&desired(route(&resource), &interface(), 1).unwrap()).unwrap();
    assert_eq!(
        request.flags().unwrap() & (libc::RTF_HOST | libc::RTF_GATEWAY) as u32,
        (libc::RTF_HOST | libc::RTF_GATEWAY) as u32
    );
    assert_eq!(
        ipv4(&request.addresses[&GATEWAY]).unwrap(),
        "192.0.2.1".parse::<Ipv4Addr>().unwrap()
    );
    let mut actual = Message::parse(&table_entry(&resource)).unwrap();
    // Darwin can omit the mask of a host route; RTF_HOST implies /32.
    actual.addresses.remove(&NETMASK);
    let entry = encode(&actual.bytes[..HEADER], &actual.addresses).unwrap();
    let mut provider = backend(Fake::with_dumps(vec![vec![], entry.clone(), entry, vec![]]));
    let fingerprint = provider.apply(&resource).unwrap();
    provider.remove(&resource, &fingerprint).unwrap();
    let deleted = Message::parse(&provider.transport.requests[1]).unwrap();
    assert_eq!(deleted.addresses[&GATEWAY], request.addresses[&GATEWAY]);
    assert_eq!(deleted.addresses[&IFP], interface().link);
}
#[test]
fn native_interface_epoch_includes_seconds_and_microseconds() {
    let bound = interface();
    let header = size_of::<libc::if_msghdr2>();
    let mut bytes = vec![0; header + aligned(bound.link.len())];
    let length = bytes.len() as u16;
    bytes[..2].copy_from_slice(&length.to_ne_bytes());
    bytes[2] = VERSION;
    bytes[3] = IFINFO2;
    let index_offset = offset_of!(libc::if_msghdr2, ifm_index);
    bytes[index_offset..index_offset + 2].copy_from_slice(&bound.index.to_ne_bytes());
    put_u32(
        &mut bytes,
        offset_of!(libc::if_msghdr2, ifm_addrs),
        1 << IFP,
    );
    let last_change =
        offset_of!(libc::if_msghdr2, ifm_data) + offset_of!(libc::if_data64, ifi_lastchange);
    bytes[last_change..last_change + 8].copy_from_slice(&bound.last_change);
    bytes[header..header + bound.link.len()].copy_from_slice(&bound.link);
    assert_eq!(interface_snapshot(&bytes, "ppp-test", 42).unwrap(), bound);
    for end in 0..bytes.len() {
        assert!(interface_snapshot(&bytes[..end], "ppp-test", 42).is_err());
    }
    let mut next = bytes.clone();
    put_u32(&mut next, last_change + 4, 678902);
    assert_ne!(
        interface_snapshot(&next, "ppp-test", 42)
            .unwrap()
            .identity(),
        bound.identity()
    );
    let mut next = bytes.clone();
    put_u32(&mut next, last_change, 12346);
    assert_ne!(
        interface_snapshot(&next, "ppp-test", 42)
            .unwrap()
            .identity(),
        bound.identity()
    );
    assert!(interface_snapshot(&bytes, "recycled", 42).is_err());
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&bytes);
    assert!(interface_snapshot(&duplicate, "ppp-test", 42).is_err());
    put_u32(&mut bytes, last_change + 4, 1_000_000);
    assert!(interface_snapshot(&bytes, "ppp-test", 42).is_err());
}
#[test]
fn reply_matching_ignores_other_sequences_and_rejects_malformed_or_missing_ack() {
    let request = desired(route(&resource()), &interface(), 51).unwrap();
    let mut other_sequence = request.clone();
    put_u32(&mut other_sequence, SEQ, 52);
    let mut other_process = request.clone();
    put_u32(
        &mut other_process,
        PID,
        unsafe { libc::getpid() } as u32 + 1,
    );
    let mut socket = Packets::replies(vec![other_sequence, other_process, request.clone()]);
    assert_eq!(route_exchange(&mut socket, &request).unwrap(), request);
    assert_eq!(socket.sent.len(), 1);
    for reply in [
        vec![],
        vec![0; 4],
        request[..request.len() - 1].to_vec(),
        {
            let mut reply = request.clone();
            reply[3] = DELETE;
            reply
        },
        {
            let mut reply = request.clone();
            put_u32(&mut reply, ERRNO, libc::EPERM as u32);
            reply
        },
    ] {
        assert_code(
            route_exchange(&mut Packets::replies(vec![reply]), &request),
            ErrorCode::RecoveryRequired,
        );
    }
    let mut exists = request.clone();
    put_u32(&mut exists, ERRNO, libc::EEXIST as u32);
    assert_code(
        route_exchange(&mut Packets::replies(vec![exists]), &request),
        ErrorCode::NetworkConflict,
    );
    assert_code(
        route_exchange(&mut Packets::replies(vec![]), &request),
        ErrorCode::RecoveryRequired,
    );
}
#[test]
fn reply_flood_and_partial_send_do_not_trigger_mutation_retries() {
    let request = desired(route(&resource()), &interface(), 51).unwrap();
    let mut other = request.clone();
    put_u32(&mut other, SEQ, 52);
    let mut socket = Packets::replies(vec![other; MAX_PACKETS]);
    assert_code(
        route_exchange(&mut socket, &request),
        ErrorCode::RecoveryRequired,
    );
    assert_eq!(socket.sent.len(), 1);
    let mut socket = Packets::replies(vec![request.clone()]);
    socket.send_fails = true;
    assert_code(
        route_exchange(&mut socket, &request),
        ErrorCode::RecoveryRequired,
    );
    assert_eq!(socket.sent.len(), 1);
    assert_eq!(socket.replies.len(), 1);
}
#[test]
fn apply_verifies_kernel_snapshot_and_delete_preserves_exact_selectors() {
    let resource = resource();
    let entry = table_entry(&resource);
    let mut provider = backend(Fake::with_dumps(vec![
        vec![],
        entry.clone(),
        entry.clone(),
        vec![],
        vec![],
    ]));
    let fingerprint = provider.apply(&resource).unwrap();
    provider.remove(&resource, &fingerprint).unwrap();
    provider.remove(&resource, &fingerprint).unwrap();
    assert_eq!(provider.transport.requests.len(), 2);
    assert_eq!(provider.transport.requests[0][3], ADD);
    let deleted = Message::parse(&provider.transport.requests[1]).unwrap();
    assert_eq!(deleted.bytes[3], DELETE);
    assert_eq!(deleted.addresses, Message::parse(&entry).unwrap().addresses);
    assert_eq!(u16_at(&deleted.bytes, 4).unwrap(), 42);
    assert_ne!(
        u32_at(&deleted.bytes, SEQ).unwrap(),
        u32_at(&provider.transport.requests[0], SEQ).unwrap()
    );
}
#[test]
fn exact_fingerprint_ignores_use_counts_and_detects_changed_route_policy() {
    let entry = table_entry(&resource());
    let original = Message::parse(&entry)
        .unwrap()
        .fingerprint(&interface())
        .unwrap();
    let mut changed = entry.clone();
    put_u32(&mut changed, offset_of!(libc::rt_msghdr, rtm_use), 1000);
    put_u32(
        &mut changed,
        METRICS + offset_of!(libc::rt_metrics, rmx_pksent),
        2000,
    );
    assert_eq!(
        Message::parse(&changed)
            .unwrap()
            .fingerprint(&interface())
            .unwrap(),
        original
    );
    for offset in [
        METRICS,
        METRICS + offset_of!(libc::rt_metrics, rmx_mtu),
        METRICS + offset_of!(libc::rt_metrics, rmx_expire),
        METRICS + offset_of!(libc::rt_metrics, rmx_rtt),
        FLAGS,
    ] {
        let mut changed = entry.clone();
        let value = u32_at(&changed, offset).unwrap() ^ 0x8000;
        put_u32(&mut changed, offset, value);
        assert_ne!(
            Message::parse(&changed)
                .unwrap()
                .fingerprint(&interface())
                .unwrap(),
            original
        );
    }
    let mut replacement = interface();
    replacement.last_change[0] ^= 1;
    assert_ne!(
        Message::parse(&entry)
            .unwrap()
            .fingerprint(&replacement)
            .unwrap(),
        original
    );
}
#[test]
fn changed_fingerprint_or_reused_interface_never_sends_delete() {
    let resource = resource();
    let entry = table_entry(&resource);
    let original = Message::parse(&entry)
        .unwrap()
        .fingerprint(&interface())
        .unwrap();
    let mut changed = entry.clone();
    put_u32(
        &mut changed,
        METRICS + offset_of!(libc::rt_metrics, rmx_mtu),
        1300,
    );
    let mut provider = backend(Fake::with_dumps(vec![changed]));
    assert_code(
        provider.remove(&resource, &original),
        ErrorCode::RecoveryRequired,
    );
    assert!(provider.transport.requests.is_empty());
    let mut fake = Fake::with_dumps(vec![entry.clone()]);
    fake.changed_at = Some(2);
    let mut provider = backend(fake);
    assert_code(
        provider.remove(&resource, &original),
        ErrorCode::RecoveryRequired,
    );
    assert!(provider.transport.requests.is_empty());
    let mut fake = Fake::with_dumps(vec![entry]);
    fake.changed_at = Some(3); // Replaced during the route snapshot read.
    let mut provider = backend(fake);
    assert_code(
        provider.remove(&resource, &original),
        ErrorCode::RecoveryRequired,
    );
    assert!(provider.transport.requests.is_empty());
}
#[test]
fn apply_failures_after_send_retain_uncertainty_and_do_not_guess_cleanup() {
    let resource = resource();
    let entry = table_entry(&resource);
    let mut fake = Fake::with_dumps(vec![vec![]]);
    fake.exchange_fails = true;
    let mut provider = backend(fake);
    assert_code(provider.apply(&resource), ErrorCode::RecoveryRequired);
    assert_eq!(provider.transport.requests.len(), 1);
    let mut fake = Fake::with_dumps(vec![vec![]]);
    fake.dumps.push_back(Err(failed()));
    let mut provider = backend(fake);
    assert_code(provider.apply(&resource), ErrorCode::RecoveryRequired);
    assert_eq!(provider.transport.requests.len(), 1);
    let mut provider = backend(Fake::with_dumps(vec![vec![], vec![]]));
    assert_code(provider.apply(&resource), ErrorCode::RecoveryRequired);
    assert_eq!(provider.transport.requests.len(), 1);
    let mut provider = backend(Fake::with_dumps(vec![entry]));
    assert_code(provider.apply(&resource), ErrorCode::NetworkConflict);
    assert!(provider.transport.requests.is_empty());
}
#[test]
fn interface_change_after_ack_requires_recovery() {
    let resource = resource();
    let mut fake = Fake::with_dumps(vec![vec![]]);
    fake.changed_at = Some(5); // ctor/spec/find/write preflight then ACK.
    let mut provider = backend(fake);
    assert_code(provider.apply(&resource), ErrorCode::RecoveryRequired);
    assert_eq!(provider.transport.requests.len(), 1);
}
#[test]
fn conflicting_global_route_duplicate_and_malformed_table_fail_closed() {
    let resource = resource();
    let entry = table_entry(&resource);
    let mut other = entry.clone();
    other[4..6].copy_from_slice(&43u16.to_ne_bytes());
    let mut provider = backend(Fake::with_dumps(vec![other]));
    assert_code(provider.apply(&resource), ErrorCode::NetworkConflict);
    assert!(provider.transport.requests.is_empty());
    let mut duplicate = entry.clone();
    duplicate.extend_from_slice(&entry);
    let mut provider = backend(Fake::with_dumps(vec![duplicate]));
    assert_code(provider.inspect(&resource), ErrorCode::NetworkConflict);
    let mut truncated = entry;
    truncated.pop();
    let mut provider = backend(Fake::with_dumps(vec![truncated]));
    assert_code(provider.apply(&resource), ErrorCode::RecoveryRequired);
    assert!(provider.transport.requests.is_empty());
}
#[test]
fn scoped_routes_do_not_authorize_global_route_deletion_and_metrics_are_explicit() {
    let resource = resource();
    let mut scoped = table_entry(&resource);
    let flags = u32_at(&scoped, FLAGS).unwrap();
    put_u32(&mut scoped, FLAGS, flags | libc::RTF_IFSCOPE as u32);
    let mut provider = backend(Fake::with_dumps(vec![scoped]));
    assert!(provider.inspect(&resource).unwrap().is_none());
    let mut metric = resource.clone();
    if let Resource::Route(route) = &mut metric {
        route.metric = 1;
    }
    assert_code(provider.apply(&metric), ErrorCode::InvalidInput);
    assert!(provider.transport.requests.is_empty());
    let mut noncanonical = resource;
    if let Resource::Route(route) = &mut noncanonical {
        route.destination = "198.18.0.1/24".into();
    }
    assert_code(provider.apply(&noncanonical), ErrorCode::InvalidInput);
}
