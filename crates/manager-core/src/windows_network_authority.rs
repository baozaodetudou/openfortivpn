//! Fixed machine-wide reservation. This is deliberately independent of the
//! per-user credential store: every elevated manager uses ProgramData and a
//! SYSTEM/Administrators ACL, including managers launched by different users.
#![cfg(windows)]

use crate::{windows_process::WindowsProcessIdentity, ControlError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        CreateWellKnownSid, EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation,
        TokenElevation, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, TOKEN_ELEVATION,
        TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, MoveFileExW,
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
    },
    System::{
        Com::CoTaskMemFree,
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
    UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
};

fn recovery() -> ControlError {
    ControlError::new(
        ErrorCode::RecoveryRequired,
        "Windows machine network authority requires recovery",
    )
}
fn conflict() -> ControlError {
    ControlError::new(
        ErrorCode::NetworkConflict,
        "another manager owns the machine network",
    )
}
struct Local(*mut std::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Token(windows_sys::Win32::Foundation::HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn wide(path: &Path) -> Result<Vec<u16>, ControlError> {
    let mut name: Vec<_> = path.as_os_str().encode_wide().collect();
    if name.is_empty() || name.contains(&0) {
        return Err(recovery());
    }
    name.push(0);
    Ok(name)
}
fn descriptor() -> Result<Local, ControlError> {
    let sddl: Vec<_> = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut value = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut value,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(recovery());
    }
    Ok(Local(value))
}
type SidBuffer = [usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<usize>())];
fn principals() -> Result<(SidBuffer, SidBuffer), ControlError> {
    let mut system = SidBuffer::default();
    let mut admins = SidBuffer::default();
    for (kind, sid) in [
        (WinLocalSystemSid, &mut system),
        (WinBuiltinAdministratorsSid, &mut admins),
    ] {
        let mut size = SECURITY_MAX_SID_SIZE;
        if unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0
        {
            return Err(recovery());
        }
    }
    Ok((system, admins))
}
/// Validate security on the opened object, never a second path lookup. An
/// attacker-created directory is rejected rather than "fixed" with chmod.
fn verify_machine(file: &File) -> Result<(), ControlError> {
    let (mut system, mut admins) = principals()?;
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    if unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    } != 0
    {
        return Err(recovery());
    }
    let _sd = Local(sd);
    let mut control = 0;
    let mut revision = 0;
    if owner.is_null()
        || dacl.is_null()
        || (unsafe { EqualSid(owner, system.as_mut_ptr().cast()) } == 0
            && unsafe { EqualSid(owner, admins.as_mut_ptr().cast()) } == 0)
        || unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || unsafe { (*dacl).AceCount } != 2
    {
        return Err(recovery());
    }
    let mut seen = [false; 2];
    for index in 0..2 {
        let mut ptr = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ptr) } == 0 {
            return Err(recovery());
        }
        let header = unsafe { &*ptr.cast::<ACE_HEADER>() };
        if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags != 0
            || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(recovery());
        }
        let ace = unsafe { &*ptr.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Mask != FILE_ALL_ACCESS {
            return Err(recovery());
        }
        let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        let position = if unsafe { EqualSid(sid, system.as_mut_ptr().cast()) } != 0 {
            0
        } else if unsafe { EqualSid(sid, admins.as_mut_ptr().cast()) } != 0 {
            1
        } else {
            return Err(recovery());
        };
        if seen[position] {
            return Err(recovery());
        }
        seen[position] = true;
    }
    Ok(())
}
fn open_object(path: &Path, directory: bool, create: bool) -> Result<File, ControlError> {
    open_object_access(path, directory, create, !directory)
}
fn open_object_access(
    path: &Path,
    directory: bool,
    create: bool,
    write: bool,
) -> Result<File, ControlError> {
    let sd = create.then(descriptor).transpose()?;
    let sa = sd.as_ref().map(|sd| SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    });
    let name = wide(path)?;
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | if write { GENERIC_WRITE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            sa.as_ref().map_or(std::ptr::null(), |sa| sa),
            if create { CREATE_NEW } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(recovery());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(recovery());
    }
    Ok(file)
}
fn mkdir(path: &Path) -> Result<File, ControlError> {
    let sd = descriptor()?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path)?.as_ptr(), &sa) } == 0
        && std::io::Error::last_os_error().raw_os_error() != Some(183)
    {
        return Err(recovery());
    }
    let file = open_object(path, true, false)?;
    verify_machine(&file)?;
    Ok(file)
}
/// All ancestor handles disallow FILE_SHARE_DELETE. Reparse points are rejected
/// at every component; the final directory cannot be renamed under an operation.
fn hold_path(path: &Path) -> Result<Vec<File>, ControlError> {
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix)
                if matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                ) =>
            {
                current.push(component.as_os_str())
            }
            Component::RootDir => {
                current.push(component.as_os_str());
                handles.push(open_object(&current, true, false)?);
            }
            Component::Normal(_) => {
                current.push(component.as_os_str());
                handles.push(open_object(&current, true, false)?);
            }
            _ => return Err(recovery()),
        }
    }
    if !path.is_absolute() || handles.is_empty() {
        return Err(recovery());
    }
    Ok(handles)
}
fn current_sid() -> Result<String, ControlError> {
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(recovery());
    }
    let token = Token(raw);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    } == 0
        || elevation.TokenIsElevated == 0
    {
        return Err(recovery());
    }
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut size);
    }
    if size == 0 || size > 16384 {
        return Err(recovery());
    }
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(recovery());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
        return Err(recovery());
    }
    let _sid = Local(sid.cast());
    let mut length = 0;
    while length < 256 && unsafe { *sid.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(recovery());
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(sid, length) }).map_err(|_| recovery())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Owner {
    pub attempt_id: String,
    pub manager: String,
    pub principal_sid: String,
    pub executable: String,
    #[serde(default, deserialize_with = "deserialize_identity")]
    pub identity: Option<WindowsProcessIdentity>,
}
fn deserialize_identity<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<WindowsProcessIdentity>, D::Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Identity {
        pid: u32,
        created_at: u64,
        executable: String,
    }
    Ok(
        Option::<Identity>::deserialize(deserializer)?.map(|identity| WindowsProcessIdentity {
            pid: identity.pid,
            created_at: identity.created_at,
            executable: identity.executable,
        }),
    )
}
impl Owner {
    pub fn new(
        attempt_id: String,
        manager: String,
        executable: String,
    ) -> Result<Self, ControlError> {
        let owner = Self {
            attempt_id,
            manager,
            executable,
            principal_sid: current_sid()?,
            identity: None,
        };
        validate(&owner)?;
        Ok(owner)
    }
}
fn validate(owner: &Owner) -> Result<(), ControlError> {
    if !matches!(owner.manager.as_str(), "desktop" | "headless" | "helper")
        || owner.attempt_id.is_empty()
        || owner.attempt_id.len() > 128
        || !owner
            .attempt_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || owner.principal_sid.len() > 256
        || !owner.principal_sid.starts_with("S-1-")
        || !owner
            .principal_sid
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'S' | b'-'))
        || owner.executable.len() > 16384
        || !Path::new(&owner.executable).is_absolute()
        || Path::new(&owner.executable)
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || owner.executable.chars().any(char::is_control)
        || owner.identity.as_ref().is_some_and(|id| {
            id.pid == 0
                || id.created_at == 0
                || !crate::windows_process::same_executable(&id.executable, &owner.executable)
        })
    {
        return Err(recovery());
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schema_version: u32,
    owner: Owner,
}

pub struct MachineAuthority {
    directory: PathBuf,
    _ancestors: Vec<File>,
}
impl MachineAuthority {
    pub fn open_system() -> Result<Self, ControlError> {
        let _ = current_sid()?;
        let mut name = std::ptr::null_mut();
        if unsafe {
            SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut name)
        } < 0
        {
            return Err(recovery());
        }
        let mut length = 0;
        while length < 32768 && unsafe { *name.add(length) } != 0 {
            length += 1;
        }
        let value = if length == 32768 {
            Err(recovery())
        } else {
            String::from_utf16(unsafe { std::slice::from_raw_parts(name, length) })
                .map_err(|_| recovery())
        };
        unsafe {
            CoTaskMemFree(name.cast());
        }
        let root = PathBuf::from(value?);
        let mut ancestors = hold_path(&root)?;
        let parent = root.join("OpenFortiVPNManager");
        ancestors.push(mkdir(&parent)?);
        let directory = parent.join("NetworkAuthority");
        ancestors.push(mkdir(&directory)?);
        Ok(Self {
            directory,
            _ancestors: ancestors,
        })
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    fn lock(&self) -> Result<File, ControlError> {
        let path = self.directory.join("authority.lock");
        let file = match open_object(&path, false, true) {
            Ok(file) => {
                file.sync_all().map_err(|_| recovery())?;
                file
            }
            Err(_) => open_object(&path, false, false)?,
        };
        verify_machine(&file)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock
                || matches!(e.raw_os_error(), Some(32 | 33))
            {
                conflict()
            } else {
                recovery()
            }
        })?;
        Ok(file)
    }
    pub fn inspect(&self) -> Result<Option<Owner>, ControlError> {
        let path = self.directory.join("active.json");
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(recovery()),
            Ok(_) => {}
        }
        let mut file = open_object(&path, false, false)?;
        verify_machine(&file)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| recovery())?;
        if bytes.len() > 65536 {
            return Err(recovery());
        }
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| recovery())?;
        if record.schema_version != 1 {
            return Err(recovery());
        }
        validate(&record.owner)?;
        Ok(Some(record.owner))
    }
    fn save(&self, owner: &Owner) -> Result<(), ControlError> {
        validate(owner)?;
        match std::fs::symlink_metadata(self.directory.join("active.json")) {
            Ok(_) => {
                let file = open_object(&self.directory.join("active.json"), false, false)?;
                verify_machine(&file)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(recovery()),
        }
        let bytes = serde_json::to_vec(&Record {
            schema_version: 1,
            owner: owner.clone(),
        })
        .map_err(|_| recovery())?;
        if bytes.len() > 65536 {
            return Err(recovery());
        }
        // A fixed temporary name is protected by the machine lock. A previous
        // interrupted write is inspected before reuse, never silently unlinked.
        let temporary = self.directory.join("active.pending");
        if std::fs::symlink_metadata(&temporary).is_ok() {
            let file = open_object(&temporary, false, false)?;
            verify_machine(&file)?;
            drop(file);
            std::fs::remove_file(&temporary).map_err(|_| recovery())?;
        }
        let mut file = open_object(&temporary, false, true)?;
        verify_machine(&file)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| recovery())?;
        drop(file);
        if unsafe {
            MoveFileExW(
                wide(&temporary)?.as_ptr(),
                wide(&self.directory.join("active.json"))?.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(recovery());
        }
        if self.inspect()?.as_ref() != Some(owner) {
            return Err(recovery());
        }
        Ok(())
    }
    pub fn acquire(self, owner: Owner) -> Result<WindowsLease, ControlError> {
        validate(&owner)?;
        if owner.identity.is_some() || owner.principal_sid != current_sid()? {
            return Err(recovery());
        }
        let lock = self.lock()?;
        if self.inspect()?.is_some() {
            return Err(recovery());
        }
        self.save(&owner)?;
        Ok(WindowsLease {
            authority: self,
            owner,
            _lock: lock,
        })
    }
    pub fn maintenance_guard(self) -> Result<MaintenanceGuard, ControlError> {
        let lock = self.lock()?;
        if self.inspect()?.is_some() {
            return Err(recovery());
        }
        Ok(MaintenanceGuard {
            _authority: self,
            _lock: lock,
        })
    }
    /// Quiescence includes descendants and platform resources; only the trusted
    /// local adapter supplies this proof. No remote "acknowledge" can bypass it.
    pub fn acknowledge(
        &self,
        attempt: &str,
        principal_sid: &str,
        quiescent: impl FnOnce() -> Result<bool, ControlError>,
    ) -> Result<(), ControlError> {
        let _lock = self.lock()?;
        let owner = self.inspect()?.ok_or_else(recovery)?;
        if owner.attempt_id != attempt
            || owner.principal_sid != principal_sid
            || principal_sid != current_sid()?
        {
            return Err(recovery());
        }
        if let Some(identity) = &owner.identity {
            // A live PID, including a reused PID, remains ambiguous.
            if crate::windows_process::inspect(identity.pid)
                .map_err(|_| recovery())?
                .is_some()
            {
                return Err(recovery());
            }
        }
        if crate::windows_process::engine_is_running(Path::new(&owner.executable))
            .map_err(|_| recovery())?
            || !quiescent()?
        {
            return Err(recovery());
        }
        self.remove(&owner)
    }
    fn remove(&self, owner: &Owner) -> Result<(), ControlError> {
        if self.inspect()?.as_ref() != Some(owner) {
            return Err(recovery());
        }
        // Keep a durable cleared record until deletion finishes. An interrupted
        // deletion may leave an unnecessary reservation, never a false absence.
        // NTFS has no portable directory-fsync equivalent. A power failure may
        // resurrect this completed reservation and conservatively block work.
        // Subsequent reservations always flush data and replace write-through.
        std::fs::remove_file(self.directory.join("active.json")).map_err(|_| recovery())?;
        if self.inspect()?.is_some() {
            return Err(recovery());
        }
        Ok(())
    }
}
pub struct MaintenanceGuard {
    _authority: MachineAuthority,
    _lock: File,
}
pub struct WindowsLease {
    authority: MachineAuthority,
    owner: Owner,
    _lock: File,
}
impl WindowsLease {
    pub fn owner(&self) -> &Owner {
        &self.owner
    }
    pub fn bind_process(&mut self, identity: WindowsProcessIdentity) -> Result<(), ControlError> {
        if self.owner.identity.is_some()
            || identity.pid == 0
            || identity.created_at == 0
            || !crate::windows_process::same_executable(
                &identity.executable,
                &self.owner.executable,
            )
            || crate::windows_process::inspect(identity.pid)
                .map_err(|_| recovery())?
                .as_ref()
                != Some(&identity)
            || self.authority.inspect()?.as_ref() != Some(&self.owner)
        {
            return Err(recovery());
        }
        let mut next = self.owner.clone();
        next.identity = Some(identity);
        self.authority.save(&next)?;
        self.owner = next;
        Ok(())
    }
    pub fn finish(self, reaped: bool, cleanup_confirmed: bool) -> Result<(), ControlError> {
        if !reaped || !cleanup_confirmed {
            return Err(recovery());
        }
        if let Some(identity) = &self.owner.identity {
            if crate::windows_process::inspect(identity.pid)
                .map_err(|_| recovery())?
                .is_some()
            {
                return Err(recovery());
            }
        }
        if crate::windows_process::engine_is_running(Path::new(&self.owner.executable))
            .map_err(|_| recovery())?
        {
            return Err(recovery());
        }
        self.authority.remove(&self.owner)
    }
}

/// Used by the fixed-system NRPT command runner. Read permissions may be broad,
/// but only SYSTEM, Administrators or TrustedInstaller may own/write the object.
pub(crate) fn hold_trusted_system_path(
    path: &Path,
    system_root: &Path,
) -> Result<Vec<File>, ControlError> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    let directory = path.parent().ok_or_else(recovery)?;
    let target_directory = std::fs::symlink_metadata(path)
        .map_err(|_| recovery())?
        .is_dir();
    let mut handles = hold_path(directory)?;
    handles.push(open_object_access(path, target_directory, false, false)?);
    let (mut system, mut admins) = principals()?;
    let sid: Vec<_> = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut installer = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid.as_ptr(), &mut installer) } == 0 {
        return Err(recovery());
    }
    let _installer = Local(installer);
    let mut paths = Vec::new();
    for ancestor in directory.ancestors() {
        if ancestor.starts_with(system_root) {
            paths.push(ancestor);
        }
    }
    paths.reverse();
    paths.push(path);
    for checked in paths {
        let file = open_object_access(checked, checked != path || target_directory, false, false)?;
        let mut owner = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        if unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        } != 0
        {
            return Err(recovery());
        }
        let _sd = Local(sd);
        let mut trusted = |sid| unsafe {
            EqualSid(sid, system.as_mut_ptr().cast()) != 0
                || EqualSid(sid, admins.as_mut_ptr().cast()) != 0
                || EqualSid(sid, installer) != 0
        };
        if owner.is_null() || dacl.is_null() || !trusted(owner) {
            return Err(recovery());
        }
        for index in 0..unsafe { (*dacl).AceCount } {
            let mut ptr = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index as u32, &mut ptr) } == 0 {
                return Err(recovery());
            }
            let header = unsafe { &*ptr.cast::<ACE_HEADER>() };
            if header.AceType as u32 == ACCESS_DENIED_ACE_TYPE || header.AceFlags & 8 != 0 {
                continue;
            }
            if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE
                || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(recovery());
            }
            let ace = unsafe { &*ptr.cast::<ACCESS_ALLOWED_ACE>() };
            // Write data, append, EA, attributes, DELETE, WRITE_DAC, WRITE_OWNER,
            // GENERIC_WRITE and GENERIC_ALL. Read-only user ACEs are allowed.
            if ace.Mask & 0x500d0116 != 0
                && !trusted(std::ptr::addr_of!(ace.SidStart).cast_mut().cast())
            {
                return Err(recovery());
            }
        }
        handles.push(file);
    }
    Ok(handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_and_owner_are_strict_before_any_machine_write() {
        let mut owner = Owner {
            attempt_id: "attempt-1".into(),
            manager: "desktop".into(),
            principal_sid: "S-1-5-21-42".into(),
            executable: r"C:\Windows\engine.exe".into(),
            identity: None,
        };
        assert!(validate(&owner).is_ok());
        owner.identity = Some(WindowsProcessIdentity {
            pid: 22,
            created_at: 1,
            executable: r"C:\Windows\other.exe".into(),
        });
        assert!(validate(&owner).is_err());
        owner.identity = None;
        owner.principal_sid = "S-1-5-21\n".into();
        assert!(validate(&owner).is_err());
        owner.principal_sid = "S-1-5-21".into();
        owner.attempt_id = "../escape".into();
        assert!(validate(&owner).is_err());
    }
    #[test]
    fn invalid_schema_and_unknown_fields_cannot_gain_reservation_proof() {
        assert!(serde_json::from_str::<Record>(r#"{"schemaVersion":1,"owner":{"attemptId":"a","manager":"desktop","principalSid":"S-1-5-18","executable":"C:\\engine.exe","identity":null,"trusted":true}}"#).is_err());
        assert!(serde_json::from_str::<Record>(r#"{"schemaVersion":1,"owner":{"attemptId":"a","manager":"desktop","principalSid":"S-1-5-18","executable":"C:\\engine.exe","identity":{"pid":2,"createdAt":1,"executable":"C:\\engine.exe","trusted":true}}}"#).is_err());
    }
    fn isolated(path: &Path) -> MachineAuthority {
        let _ = current_sid().expect("requires elevated isolated Windows");
        let mut ancestors = hold_path(path.parent().unwrap()).unwrap();
        ancestors.push(mkdir(path).unwrap());
        MachineAuthority {
            directory: path.into(),
            _ancestors: ancestors,
        }
    }
    fn synthetic_owner(directory: &Path, id: &str) -> Owner {
        Owner::new(
            id.into(),
            "desktop".into(),
            directory
                .join("synthetic-never-launched.exe")
                .to_string_lossy()
                .into_owned(),
        )
        .unwrap()
    }
    #[test]
    #[ignore = "requires an isolated elevated Windows test environment"]
    fn machine_lock_and_durable_reservation_outlive_the_manager() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("machine");
        let owner = synthetic_owner(&path, "first");
        let lease = isolated(&path).acquire(owner.clone()).unwrap();
        assert!(matches!(
            isolated(&path)
                .acquire(synthetic_owner(&path, "second"))
                .err()
                .unwrap()
                .code,
            ErrorCode::NetworkConflict
        ));
        drop(lease);
        let authority = isolated(&path);
        assert_eq!(authority.inspect().unwrap().as_ref(), Some(&owner));
        assert!(isolated(&path)
            .acquire(synthetic_owner(&path, "second"))
            .is_err());
        assert!(authority
            .acknowledge("first", "S-1-5-18", || panic!(
                "wrong principal must not run callback"
            ))
            .is_err());
        assert!(authority
            .acknowledge("first", &owner.principal_sid, || Ok(false))
            .is_err());
        authority
            .acknowledge("first", &owner.principal_sid, || Ok(true))
            .unwrap();
        isolated(&path)
            .acquire(synthetic_owner(&path, "second"))
            .unwrap()
            .finish(true, true)
            .unwrap();
        assert!(authority.inspect().unwrap().is_none());
    }
    #[test]
    #[ignore = "requires an isolated elevated Windows test environment"]
    fn counterfeit_acl_reparse_and_corrupt_records_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("machine");
        let authority = isolated(&path);
        // A plain inherited lock is not accepted merely because this admin can
        // open it. The protected two-principal DACL is mandatory.
        std::fs::write(path.join("authority.lock"), []).unwrap();
        assert!(authority.lock().is_err());
        std::fs::remove_file(path.join("authority.lock")).unwrap();
        let lease = isolated(&path)
            .acquire(synthetic_owner(&path, "first"))
            .unwrap();
        drop(lease);
        std::fs::write(path.join("active.json"), b"{corrupt").unwrap();
        assert!(authority.inspect().is_err());
        assert!(authority
            .acknowledge("first", &current_sid().unwrap(), || panic!(
                "corrupt record must not run callback"
            ))
            .is_err());
        std::fs::remove_file(path.join("active.json")).unwrap();
        std::os::windows::fs::symlink_file(temp.path().join("outside"), path.join("active.json"))
            .unwrap();
        assert!(authority.inspect().is_err());
        assert!(isolated(&path)
            .acquire(synthetic_owner(&path, "second"))
            .is_err());
    }
    #[test]
    #[ignore = "requires an isolated elevated Windows test environment"]
    fn exact_child_identity_is_bound_before_process_exit_is_acknowledged() {
        use std::os::windows::process::CommandExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("machine");
        let engine = temp.path().join("synthetic-owned-engine.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &engine).unwrap();
        let owner = Owner::new(
            "child".into(),
            "desktop".into(),
            engine.to_string_lossy().into_owned(),
        )
        .unwrap();
        let mut lease = isolated(&path).acquire(owner.clone()).unwrap();
        // Suspended copied test executable never runs code or contacts a gateway.
        let mut child = std::process::Command::new(&engine)
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED)
            .spawn()
            .unwrap();
        let identity = crate::windows_process::inspect(child.id())
            .unwrap()
            .unwrap();
        let mut wrong = identity.clone();
        wrong.created_at += 1;
        assert!(lease.bind_process(wrong).is_err());
        lease.bind_process(identity.clone()).unwrap();
        assert_eq!(
            isolated(&path).inspect().unwrap().unwrap().identity,
            Some(identity)
        );
        assert!(lease.finish(true, true).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        isolated(&path)
            .acknowledge("child", &owner.principal_sid, || Ok(true))
            .unwrap();
    }
}
