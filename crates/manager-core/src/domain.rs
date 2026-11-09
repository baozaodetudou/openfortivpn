use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_port() -> u16 {
    443
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnProfile {
    pub id: String,
    #[serde(default)]
    pub revision: u64,
    pub name: String,
    pub host: String,
    /// Empty uses system DNS. Otherwise query this IPv4 resolver over TCP 53.
    #[serde(default)]
    pub gateway_dns: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub trusted_cert: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    #[serde(default = "default_true")]
    pub set_routes: bool,
    #[serde(default = "default_true")]
    pub set_dns: bool,
    #[serde(default)]
    pub pppd_use_peerdns: bool,
    #[serde(default)]
    pub half_internet_routes: bool,
    #[serde(default = "default_true")]
    pub use_sudo: bool,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveProfileInput {
    pub profile: VpnProfile,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_true")]
    pub remember_password: bool,
    #[serde(default)]
    pub expected_revision: Option<u64>,
}

impl Drop for SaveProfileInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(password) = &mut self.password {
            password.zeroize();
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileView {
    pub profile: VpnProfile,
    pub has_secret: bool,
    pub password_stored: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceStatus {
    Starting,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceView<S = InstanceStatus> {
    pub id: String,
    pub profile_generation: u64,
    pub attempt_sequence: u64,
    pub profile_id: String,
    pub profile_name: String,
    pub adapter_name: String,
    pub status: S,
    pub message: String,
    pub pid: u32,
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub exit_code: Option<i32>,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    pub id: u64,
    pub instance_id: String,
    pub stream: String,
    pub line: String,
    pub timestamp: u64,
}

/// Immutable shared log entries keep full API snapshots from cloning every
/// retained message. Serialization retains the v1 wire shape.
pub type LogSnapshot = Vec<std::sync::Arc<LogEvent>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSettings {
    pub bind_address: String,
    pub port: u16,
    #[serde(default)]
    pub certificate_name: Option<String>,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 18_443,
            certificate_name: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineInfo {
    pub platform: String,
    pub path: String,
    pub available: bool,
    pub version: String,
    pub event_protocol: Option<u8>,
    /// Adapter-only launch contract; preserve the v1 EngineInfo wire shape.
    #[serde(skip_serializing)]
    pub manager_launch_gate: bool,
    pub requires_elevation: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegeStatus {
    pub required: bool,
    pub ready: bool,
    pub platform: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub profiles: Vec<ProfileView>,
    pub instances: Vec<InstanceView>,
    pub logs: LogSnapshot,
    pub engine: EngineInfo,
    pub privilege: PrivilegeStatus,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub api_versions: Vec<u8>,
    pub authentication: Vec<&'static str>,
    pub concurrent_network_connections: usize,
    pub coordinated_network: bool,
    pub session_passwords: bool,
    pub incremental_log_ids: bool,
    pub privilege_setup: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            api_versions: vec![1, 2],
            authentication: vec!["password"],
            concurrent_network_connections: 1,
            coordinated_network: false,
            session_passwords: true,
            incremental_log_ids: true,
            privilege_setup: false,
        }
    }
}
