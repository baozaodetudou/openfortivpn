//! Scoped DNS through the protected, local Windows DnsClient NRPT cmdlets.
//! This is an OS command backend, not a claim that Windows runtime acceptance
//! has passed. Global adapter DNS and old global snapshots are never changed.
#![cfg(windows)]
use crate::{
    network::{Backend, Dns, Resource},
    network_windows_dns_policy::{self as policy, Desired, Policy},
    ControlError, ErrorCode,
};
use base64::Engine;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    os::windows::{io::AsRawHandle, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    NetworkManagement::{
        IpHelper::{ConvertInterfaceAliasToLuid, GetBestRoute2, MIB_IPFORWARD_ROW2},
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
            JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
            TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        SystemInformation::GetSystemDirectoryW,
        Threading::{
            OpenThread, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
        },
        IO::CancelSynchronousIo,
    },
};

const SCRIPT: &str = include_str!("network_windows_dns.ps1");
const OUTPUT_LIMIT: usize = 1024 * 1024;
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Job(Handle);
impl Job {
    fn new() -> Result<Self, ControlError> {
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(policy::recovery());
        }
        let job = Self(Handle(raw));
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(policy::recovery());
        }
        Ok(job)
    }
    fn terminate(&self) {
        unsafe {
            TerminateJobObject(self.0 .0, 1);
        }
    }
    fn empty(&self) -> Result<bool, ControlError> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe {
            QueryInformationJobObject(
                self.0 .0,
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(policy::recovery());
        }
        Ok(info.ActiveProcesses == 0)
    }
}
fn resume(pid: u32) -> Result<(), ControlError> {
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(policy::recovery());
    }
    let snapshot = Handle(raw);
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut found = unsafe { Thread32First(snapshot.0, &mut entry) };
    let mut ids = Vec::new();
    while found != 0 {
        if entry.th32OwnerProcessID == pid {
            ids.push(entry.th32ThreadID);
        }
        found = unsafe { Thread32Next(snapshot.0, &mut entry) };
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(18) || ids.len() != 1 {
        return Err(policy::recovery());
    }
    let raw = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, ids[0]) };
    if raw.is_null() {
        return Err(policy::recovery());
    }
    let handle = Handle(raw);
    if unsafe { ResumeThread(handle.0) } != 1 {
        return Err(policy::recovery());
    }
    Ok(())
}
fn system_directory() -> Result<PathBuf, ControlError> {
    let mut path = vec![0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if length == 0 || length >= path.len() {
        return Err(policy::recovery());
    }
    Ok(PathBuf::from(
        String::from_utf16(&path[..length]).map_err(|_| policy::recovery())?,
    ))
}
fn protect_module(
    directory: &Path,
    system_root: &Path,
    handles: &mut Vec<File>,
) -> Result<(), ControlError> {
    let mut pending = vec![directory.to_owned()];
    let mut count = 0;
    while let Some(directory) = pending.pop() {
        handles.extend(crate::windows_network_authority::hold_trusted_system_path(
            &directory,
            system_root,
        )?);
        for entry in std::fs::read_dir(directory).map_err(|_| policy::recovery())? {
            count += 1;
            if count > 4096 {
                return Err(policy::recovery());
            }
            let entry = entry.map_err(|_| policy::recovery())?;
            let kind = entry.file_type().map_err(|_| policy::recovery())?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                handles.extend(crate::windows_network_authority::hold_trusted_system_path(
                    &entry.path(),
                    system_root,
                )?);
            } else {
                return Err(policy::recovery());
            }
        }
    }
    Ok(())
}
fn reader<R: crate::process_output::Pipe + Send + 'static>(
    pipe: R,
    cancelled: Arc<AtomicBool>,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<Result<Vec<u8>, ()>> {
    thread::spawn(move || {
        let mut pipe = crate::process_output::CancellablePipe::new(pipe, cancelled.clone());
        let mut output = Vec::new();
        let mut bytes = [0u8; 4096];
        loop {
            let size = pipe.read(&mut bytes).map_err(|_| ())?;
            if size == 0 {
                return if cancelled.load(Ordering::Acquire) {
                    Err(())
                } else {
                    Ok(output)
                };
            }
            if output.len().saturating_add(size) > OUTPUT_LIMIT {
                overflow.store(true, Ordering::Release);
            } else {
                output.extend_from_slice(&bytes[..size]);
            }
        }
    })
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Request<'a> {
    operation: &'a str,
    desired: &'a Desired,
    expected_hash: Option<&'a str>,
}

pub struct WindowsNrpt {
    adapters: BTreeMap<String, u64>,
}
impl WindowsNrpt {
    /// Adapter identities must come from verified Wintun creation, never user
    /// profile input. Activation rechecks alias→LUID and actual DNS routing;
    /// cleanup retains the original binding even after the adapter disappears.
    pub fn new(adapters: BTreeMap<String, u64>) -> Self {
        Self { adapters }
    }
    fn desired(&self, resource: &Resource) -> Result<Desired, ControlError> {
        let Resource::Dns(dns) = resource else {
            return Err(ControlError::new(
                ErrorCode::InvalidInput,
                "NRPT accepts DNS resources only",
            ));
        };
        self.bound(dns)
    }
    fn bound(&self, dns: &Dns) -> Result<Desired, ControlError> {
        let wanted = self.mapped(dns)?;
        let alias: Vec<_> = dns.interface.encode_utf16().chain(Some(0)).collect();
        let mut current = NET_LUID_LH::default();
        if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut current) } != 0
            || unsafe { current.Value } != wanted.luid
        {
            return Err(policy::recovery());
        }
        Ok(wanted)
    }
    fn mapped(&self, dns: &Dns) -> Result<Desired, ControlError> {
        let luid = *self
            .adapters
            .get(&dns.interface)
            .ok_or_else(policy::recovery)?;
        if dns.interface.is_empty()
            || dns.interface.len() > 128
            || dns.interface.chars().any(char::is_control)
        {
            return Err(policy::recovery());
        }
        policy::desired(dns, luid)
    }
    fn routed(&self, resource: &Resource) -> Result<(), ControlError> {
        let Resource::Dns(dns) = resource else {
            return Err(policy::recovery());
        };
        let wanted = self.bound(dns)?;
        for server in &dns.servers {
            let destination = SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(server.octets()),
                        },
                    },
                    ..Default::default()
                },
            };
            let mut route = MIB_IPFORWARD_ROW2::default();
            let mut source = SOCKADDR_INET::default();
            if unsafe {
                GetBestRoute2(
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &destination,
                    0,
                    &mut route,
                    &mut source,
                )
            } != 0
                || unsafe { route.InterfaceLuid.Value } != wanted.luid
            {
                return Err(ControlError::new(
                    ErrorCode::NetworkConflict,
                    "DNS server does not route through the verified VPN adapter",
                ));
            }
        }
        Ok(())
    }
    fn run(
        &self,
        operation: &str,
        desired: &Desired,
        expected_hash: Option<&str>,
    ) -> Result<Policy, ControlError> {
        let request = serde_json::to_vec(&Request {
            operation,
            desired,
            expected_hash,
        })
        .map_err(|_| policy::recovery())?;
        if request.len() > 16384 {
            return Err(policy::recovery());
        }
        let system = system_directory()?;
        let root = system.parent().ok_or_else(policy::recovery)?;
        let ps_home = system.join("WindowsPowerShell").join("v1.0");
        let executable = ps_home.join("powershell.exe");
        let mut trusted =
            crate::windows_network_authority::hold_trusted_system_path(&executable, root)?;
        for module in ["DnsClient", "Microsoft.PowerShell.Utility"] {
            protect_module(&ps_home.join("Modules").join(module), root, &mut trusted)?;
        }
        let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut command = Command::new(&executable);
        command
            .env_clear()
            .env("SystemRoot", root)
            .env("WINDIR", root)
            .env("PSModulePath", "")
            .current_dir(&ps_home)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
            ])
            .arg(base64::engine::general_purpose::STANDARD.encode(utf16))
            .creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let job = Job::new()?;
        let child = command.spawn().map_err(|_| policy::recovery())?;
        let process = crate::supervisor::OwnedProcess::new(child);
        let setup = (|| {
            let child = process.lock().map_err(|_| policy::recovery())?;
            if unsafe { AssignProcessToJobObject(job.0 .0, child.as_raw_handle()) } == 0 {
                return Err(policy::recovery());
            }
            resume(child.id())
        })();
        if setup.is_err() {
            job.terminate();
            if let Ok(mut child) = process.lock() {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(policy::recovery());
        }
        let mut child = process.lock().map_err(|_| policy::recovery())?;
        let mut stdin = child.stdin.take().ok_or_else(policy::recovery)?;
        let stdout = child.stdout.take().ok_or_else(policy::recovery)?;
        let stderr = child.stderr.take().ok_or_else(policy::recovery)?;
        drop(child);
        let writer = thread::spawn(move || stdin.write_all(&request));
        let cancelled = Arc::new(AtomicBool::new(false));
        let overflow = Arc::new(AtomicBool::new(false));
        let output = reader(stdout, cancelled.clone(), overflow.clone());
        let errors = reader(stderr, cancelled.clone(), overflow.clone());
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut success = false;
        loop {
            match process.try_wait() {
                Ok(Some(status)) => {
                    success = status.success();
                    break;
                }
                Ok(None) if Instant::now() < deadline && !overflow.load(Ordering::Acquire) => {
                    thread::sleep(Duration::from_millis(10))
                }
                _ => break,
            }
        }
        // Job termination includes descendants that could retain a pipe or keep
        // mutating policy after the PowerShell parent exits. Wait is separate.
        job.terminate();
        let reaped = process
            .lock()
            .map_err(|_| policy::recovery())?
            .wait()
            .is_ok();
        let drain_deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < drain_deadline
            && (!output.is_finished()
                || !errors.is_finished()
                || !writer.is_finished()
                || !matches!(job.empty(), Ok(true)))
        {
            thread::sleep(Duration::from_millis(10));
        }
        let drained = output.is_finished() && errors.is_finished() && writer.is_finished();
        let empty = matches!(job.empty(), Ok(true));
        cancelled.store(!drained, Ordering::Release);
        if !writer.is_finished() {
            unsafe {
                CancelSynchronousIo(writer.as_raw_handle());
            }
        }
        let written = matches!(writer.join(), Ok(Ok(())));
        let output = output
            .join()
            .map_err(|_| policy::recovery())?
            .map_err(|_| policy::recovery())?;
        let errors = errors
            .join()
            .map_err(|_| policy::recovery())?
            .map_err(|_| policy::recovery())?;
        if !success
            || !reaped
            || !drained
            || !empty
            || !written
            || !errors.is_empty()
            || overflow.load(Ordering::Acquire)
        {
            return Err(policy::recovery());
        }
        serde_json::from_slice(&output).map_err(|_| policy::recovery())
    }
}
impl Backend for WindowsNrpt {
    fn inspect(&mut self, resource: &Resource) -> Result<Option<String>, ControlError> {
        let wanted = self.desired(resource)?;
        let state = self.run("inspect", &wanted, None)?;
        policy::inspect(&state, &wanted)?
            .map(|rule| policy::fingerprint(rule, wanted.luid))
            .transpose()
    }
    fn apply(&mut self, resource: &Resource) -> Result<String, ControlError> {
        let wanted = self.desired(resource)?;
        let before = self.run("inspect", &wanted, None)?;
        if policy::inspect(&before, &wanted)?.is_some() {
            return Err(policy::recovery());
        }
        // prepare only inspects: planned routes need not be installed yet.
        // Activate DNS after route apply has established the verified egress.
        self.routed(resource)?;
        let after = self.run("apply", &wanted, None)?;
        // Revalidate the adapter and actual name-server routes after mutation.
        self.routed(resource)?;
        policy::fingerprint(
            policy::inspect(&after, &wanted)?.ok_or_else(policy::recovery)?,
            wanted.luid,
        )
    }
    fn remove(&mut self, resource: &Resource, expected: &str) -> Result<(), ControlError> {
        let Resource::Dns(dns) = resource else {
            return Err(policy::recovery());
        };
        // NRPT outlives Wintun interfaces. The original verified LUID remains
        // part of the ownership marker; exact GUID/property fingerprint guards
        // deletion even when this adapter and its routes no longer exist.
        let wanted = self.mapped(dns)?;
        let before = self.run("inspect", &wanted, None)?;
        let Some(rule) = policy::inspect(&before, &wanted)? else {
            return Ok(());
        };
        if policy::fingerprint(rule, wanted.luid)? != expected {
            return Err(policy::recovery());
        }
        let hash = policy::expected_hash(expected, wanted.luid)?;
        let after = self.run("remove", &wanted, Some(hash))?;
        if policy::inspect(&after, &wanted)?.is_some() {
            return Err(policy::recovery());
        }
        Ok(())
    }
}
pub struct WindowsNetwork {
    routes: crate::network_windows::WindowsRoutes,
    dns: WindowsNrpt,
}
impl WindowsNetwork {
    pub fn new(adapters: BTreeMap<String, u64>) -> Self {
        Self {
            routes: crate::network_windows::WindowsRoutes::new(adapters.clone()),
            dns: WindowsNrpt::new(adapters),
        }
    }
}
impl Backend for WindowsNetwork {
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
    fn remove(&mut self, resource: &Resource, expected: &str) -> Result<(), ControlError> {
        match resource {
            Resource::Route(_) => self.routes.remove(resource, expected),
            Resource::Dns(_) => self.dns.remove(resource, expected),
        }
    }
}
