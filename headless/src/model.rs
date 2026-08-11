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
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub trusted_cert: String,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveProfileInput {
    pub profile: VpnProfile,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_true")]
    pub remember_password: bool,
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
pub struct InstanceView {
    pub id: String,
    pub profile_generation: u64,
    pub profile_id: String,
    pub profile_name: String,
    pub adapter_name: String,
    pub status: InstanceStatus,
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
    pub instance_id: String,
    pub stream: String,
    pub line: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerSettings {
    pub bind_address: String,
    pub port: u16,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            port: 18_443,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ServerSettings;

    #[test]
    fn remote_access_is_loopback_only_by_default() {
        let settings = ServerSettings::default();
        assert_eq!(settings.bind_address, "127.0.0.1");
        assert_eq!(settings.port, 18_443);
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineInfo {
    pub platform: String,
    pub path: String,
    pub available: bool,
    pub version: String,
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
    pub logs: Vec<LogEvent>,
    pub engine: EngineInfo,
    pub privilege: PrivilegeStatus,
}
