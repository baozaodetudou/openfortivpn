//! Shared rules that do not depend on Tauri, HTTP, or privileged platform APIs.
pub mod actor;
pub mod atomic_file;
pub mod bundle;
pub mod connection_service;
pub mod control;
pub mod credential_journal;
pub mod diagnostics;
pub mod domain;
pub mod engine;
pub mod json_buffer;
pub mod lifecycle;
pub mod log_buffer;
pub mod network;
pub mod network_authority;
pub mod network_control;
#[cfg(target_os = "linux")]
pub mod network_linux;
#[cfg(any(all(target_os = "linux", feature = "linux-network"), all(test, unix)))]
pub mod network_linux_worker;
#[cfg(target_os = "macos")]
pub mod network_macos;
#[cfg(target_os = "macos")]
pub mod network_macos_routes;
#[cfg(all(target_os = "linux", feature = "linux-network"))]
pub mod network_resolved;
#[cfg(windows)]
pub mod network_windows;
#[cfg(windows)]
pub mod network_windows_dns;
#[cfg(any(windows, test))]
pub(crate) mod network_windows_dns_policy;
pub mod private_file;
pub mod private_input;
pub mod process_output;
pub mod profile_service;
pub mod protocol;
pub mod repository;
pub mod retention;
pub mod saml;
pub mod saml_broker;
pub mod supervisor;
#[cfg(feature = "tls")]
pub mod tls_identity;
pub mod validation;
pub mod windows_file;
#[cfg(windows)]
pub mod windows_network_authority;
pub mod windows_process;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    InvalidInput,
    ProfileBusy,
    ProfileNotFound,
    NetworkConflict,
    ShuttingDown,
    RecoveryRequired,
    RevisionConflict,
}

#[derive(Debug)]
pub struct ControlError {
    pub code: ErrorCode,
    pub message: String,
}

impl ControlError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ControlError {}
