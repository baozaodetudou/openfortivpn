//! Private Windows files have an explicit, protected DACL. Inheriting the
//! parent directory's ACL is insufficient for temporary VPN passwords.
#[cfg(windows)]
pub fn validate_private(file: &std::fs::File) -> std::io::Result<()> {
    use std::{io, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE},
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            CreateWellKnownSid, EqualSid, GetAce, GetSecurityDescriptorControl,
            GetTokenInformation, TokenUser, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
            DACL_SECURITY_INFORMATION, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::{
            SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Descriptor(*mut std::ffi::c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(token);
    let mut length = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut length);
    }
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut user = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*user.as_ptr().cast::<TOKEN_USER>() };
    let mut system =
        [0usize; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut system_length = std::mem::size_of_val(&system) as u32;
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            system.as_mut_ptr().cast(),
            &mut system_length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut descriptor = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = Descriptor(descriptor);
    let mut control = 0;
    let mut revision = 0;
    if dacl.is_null()
        || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(io::Error::other("private file must have a protected DACL"));
    }
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType as u32 == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE
            || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(io::Error::other("unsupported ACE in private file"));
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        if unsafe { EqualSid(sid, user.User.Sid) } == 0
            && unsafe { EqualSid(sid, system.as_mut_ptr().cast()) } == 0
        {
            return Err(io::Error::other(
                "private file grants access to another principal",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::{
        io,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
        Security::Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        Security::{GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER},
        Storage::FileSystem::{
            CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Local(*mut std::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(token);
    let mut length = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut length);
    }
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    // Token structures require pointer alignment, unlike an arbitrary Vec<u8>.
    let mut information = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            information.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*information.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_memory = Local(sid.cast());
    let mut sid_length = 0;
    while unsafe { *sid.add(sid_length) } != 0 {
        sid_length += 1;
    }
    let sid_string = String::from_utf16(unsafe { std::slice::from_raw_parts(sid, sid_length) })
        .map_err(|_| io::Error::other("invalid SID encoding"))?;
    drop(sid_memory);
    let sddl: Vec<u16> = format!("D:P(A;;FA;;;SY)(A;;FA;;;{sid_string})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor_memory = Local(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if name[..name.len() - 1].contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    let file = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let result = if file == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_handle(file) })
    };
    drop(descriptor_memory);
    result
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        os::windows::ffi::OsStrExt,
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
        Security::{GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED},
    };
    #[test]
    fn atomic_replacements_keep_a_protected_two_principal_dacl() {
        let root = std::env::temp_dir().join(format!(
            "ofv-acl-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let file = root.join("private.conf");
        for contents in [b"synthetic-old".as_slice(), b"synthetic-new".as_slice()] {
            crate::atomic_file::write_private(&file, contents).unwrap();
            assert_eq!(std::fs::read(&file).unwrap(), contents);
            assert_eq!(crate::private_file::read(&file, 1024).unwrap(), contents);
            let name: Vec<_> = file.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut descriptor = std::ptr::null_mut();
            let mut dacl = std::ptr::null_mut();
            let error = unsafe {
                GetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut dacl,
                    std::ptr::null_mut(),
                    &mut descriptor,
                )
            };
            assert_eq!(error, 0);
            let mut control = 0;
            let mut revision = 0;
            let ok =
                unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
            let count = if dacl.is_null() {
                0
            } else {
                unsafe { (*dacl).AceCount }
            };
            unsafe {
                LocalFree(descriptor);
            }
            assert_ne!(ok, 0);
            assert_ne!(control & SE_DACL_PROTECTED, 0);
            assert_eq!(count, 2);
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn inherited_private_file_permissions_are_rejected_before_reading() {
        let root = std::env::temp_dir().join(format!(
            "ofv-inherited-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("unsafe.conf");
        std::fs::write(&path, b"synthetic-private-content").unwrap();
        assert!(crate::private_file::read(&path, 1024).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
