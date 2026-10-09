use std::fs;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

/// Export without overwriting an existing destination, including a symlink.
pub fn write_new_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    #[cfg(not(windows))]
    let mut file = {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?
    };
    #[cfg(windows)]
    let mut file = crate::windows_file::create_private(path)?;
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        #[cfg(unix)]
        fs::File::open(
            path.parent()
                .ok_or_else(|| io::Error::other("export has no parent"))?,
        )?
        .sync_all()?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

/// Durable same-directory replacement. On Windows fs::rename cannot replace
/// an existing file, so use the explicit replace + write-through OS operation.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    write_mode(path, contents, 0o600)
}

/// Mode is set on the temporary inode before atomic replacement, so executable
/// bundles never expose an incomplete file or a non-executable installed file.
pub fn write_mode(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    if !matches!(mode, 0o440 | 0o600 | 0o644 | 0o700 | 0o755) {
        return Err(io::Error::other("unsupported installation mode"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("path has no parent"))?;
    let temporary = parent.join(format!(
        ".manager-{}-{}.tmp",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    #[cfg(not(windows))]
    let mut file = {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        options.open(&temporary)?
    };
    #[cfg(windows)]
    let mut file = crate::windows_file::create_private(&temporary)?;
    let result = (|| {
        file.write_all(contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.sync_all()?;
        drop(file);
        replace(&temporary, path)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(windows))]
fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
