//! Read-only Windows process identity for crash journals. Never authorize a
//! signal from a persisted PID alone; creation time and executable must match.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProcessIdentity {
    pub pid: u32,
    pub created_at: u64,
    pub executable: String,
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{io, path::Path};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub fn inspect(pid: u32) -> io::Result<Option<WindowsProcessIdentity>> {
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            let error = io::Error::last_os_error();
            // ERROR_INVALID_PARAMETER means this PID no longer exists.
            return if error.raw_os_error() == Some(87) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let handle = Handle(raw);
        let mut code = 0;
        if unsafe { GetExitCodeProcess(handle.0, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if code != 259 {
            return Ok(None);
        } // STILL_ACTIVE
        let mut times = [FILETIME::default(); 4];
        if unsafe {
            GetProcessTimes(
                handle.0,
                &mut times[0],
                &mut times[1],
                &mut times[2],
                &mut times[3],
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut executable = vec![0u16; 32768];
        let mut length = executable.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle.0, 0, executable.as_mut_ptr(), &mut length) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let executable = String::from_utf16(&executable[..length as usize])
            .map_err(|_| io::Error::other("invalid executable path encoding"))?;
        Ok(Some(WindowsProcessIdentity {
            pid,
            created_at: ((times[0].dwHighDateTime as u64) << 32) | times[0].dwLowDateTime as u64,
            executable,
        }))
    }

    pub fn same_executable(a: &str, b: &str) -> bool {
        a.trim_start_matches(r"\\?\")
            .eq_ignore_ascii_case(b.trim_start_matches(r"\\?\"))
    }

    /// A pre-spawn journal may have no PID. Refuse acknowledgement while any
    /// process with this executable is alive; inspection failures also refuse.
    pub fn engine_is_running(engine: &Path) -> io::Result<bool> {
        let name = engine
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| io::Error::other("invalid engine filename"))?;
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let snapshot = Handle(raw);
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        while found != 0 {
            let end = entry
                .szExeFile
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(entry.szExeFile.len());
            let process_name = String::from_utf16_lossy(&entry.szExeFile[..end]);
            if process_name.eq_ignore_ascii_case(name) {
                if let Some(identity) = inspect(entry.th32ProcessID)? {
                    if same_executable(&identity.executable, &engine.to_string_lossy()) {
                        return Ok(true);
                    }
                }
            }
            found = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(18) {
            return Err(error);
        } // ERROR_NO_MORE_FILES
        Ok(false)
    }
}

#[cfg(windows)]
pub use platform::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_reused_pid_is_a_different_process() {
        let identity = WindowsProcessIdentity {
            pid: 12,
            created_at: 10,
            executable: "engine.exe".into(),
        };
        let reused = WindowsProcessIdentity {
            created_at: 11,
            ..identity.clone()
        };
        assert_ne!(identity, reused);
        assert_eq!(
            identity,
            serde_json::from_slice(&serde_json::to_vec(&identity).unwrap()).unwrap()
        );
    }
}
