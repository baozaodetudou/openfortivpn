//! Open before validating, then read the same handle. No symlink-following
//! metadata/read race and no unbounded allocation for private repository files.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    path::Path,
};

pub fn verify_directory(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "private repository directory is not a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "private repository directory has unsafe ownership or permissions",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(io::Error::other(
                "private repository directory is a reparse point",
            ));
        }
    }
    Ok(())
}

pub fn open(path: &Path, write: bool) -> io::Result<File> {
    open_checked(path, write, true)
}
fn open_checked(path: &Path, write: bool, secret: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other(
            "private repository entry is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & if secret { 0o077 } else { 0o022 } != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::other(
                "private repository entry has unsafe ownership or permissions",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(io::Error::other(
                "private repository entry is a reparse point",
            ));
        }
    }
    #[cfg(windows)]
    if secret {
        crate::windows_file::validate_private(&file)?;
    }
    Ok(file)
}

pub fn read(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut contents = Vec::new();
    open(path, false)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > limit {
        return Err(io::Error::other(
            "private repository entry exceeds its size limit",
        ));
    }
    Ok(contents)
}
/// Legacy profile metadata may be readable by others or inherit its Windows
/// DACL. This is never used for credentials, keys, tokens or intent journals.
pub fn read_metadata(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut contents = Vec::new();
    open_checked(path, false, false)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > limit {
        return Err(io::Error::other("metadata exceeds its size limit"));
    }
    Ok(contents)
}

/// Callers keep the file alive for the complete read/modify/write transaction.
fn lock_file(path: &Path) -> io::Result<File> {
    // Creating the stable lock file with atomic replacement would let a second
    // process lock a different inode. Create once, then always reopen it.
    #[cfg(unix)]
    let creation = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    #[cfg(windows)]
    let creation = crate::windows_file::create_private(path);
    match creation {
        Ok(file) => file.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let file = open(path, true)?;
    Ok(file)
}

pub fn lock(path: &Path) -> io::Result<File> {
    let file = lock_file(path)?;
    fs2::FileExt::lock_exclusive(&file)?;
    Ok(file)
}

/// Run workers hold shared guards through reap; installers require an exclusive
/// guard and fail immediately when another process owns the fixed components.
pub fn try_lock(path: &Path, shared: bool) -> io::Result<File> {
    let file = lock_file(path)?;
    if shared {
        fs2::FileExt::try_lock_shared(&file)?;
    } else {
        fs2::FileExt::try_lock_exclusive(&file)?;
    }
    Ok(file)
}

#[cfg(all(test, unix))]
mod locking_tests {
    use super::*;
    #[test]
    fn live_shared_component_guards_exclude_installers_until_every_worker_exits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("components.lock");
        let a = try_lock(&path, true).unwrap();
        let b = try_lock(&path, true).unwrap();
        assert!(try_lock(&path, false).is_err());
        drop(a);
        assert!(try_lock(&path, false).is_err());
        drop(b);
        let installer = try_lock(&path, false).unwrap();
        assert!(try_lock(&path, true).is_err());
        drop(installer);
        assert!(try_lock(&path, true).is_ok());
    }
}
