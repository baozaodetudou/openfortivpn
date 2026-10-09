pub mod api;
pub mod install;
pub mod manager;
pub mod model;
pub mod native_network;
pub mod storage;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::api::{router, ApiState};
use crate::manager::VpnManager;
use crate::storage::Storage;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A read-only export. It never starts engines, signals children, rewrites
/// recovery records or exports credentials.
pub async fn offline_diagnostics(
    storage: Storage,
    engine: std::path::PathBuf,
) -> Result<serde_json::Value> {
    let manager = Arc::new(VpnManager::new(storage, engine));
    manager.restore_recovery().await?;
    let probe = if !manager.engine_info().available {
        "unavailable"
    } else if manager.probe_engine().await.is_ok() {
        "passed"
    } else {
        "failed"
    };
    let mut snapshot = serde_json::to_value(manager.snapshot().await?)?;
    snapshot["runJournal"] = serde_json::to_value(manager.recovery_records()?)?;
    let capabilities = crate::model::Capabilities {
        api_versions: vec![1, 2],
        ..Default::default()
    };
    let mut report = openfortivpn_manager_core::diagnostics::report(
        &snapshot,
        &serde_json::to_value(capabilities)?,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    );
    report["source"] = serde_json::json!("offlineRepository");
    report["engineProbe"] = serde_json::json!(probe);
    Ok(report)
}

pub async fn serve(
    storage: Storage,
    engine: std::path::PathBuf,
    bind_address: Option<String>,
    port: Option<u16>,
    experimental_control: bool,
) -> Result<()> {
    serve_with_network(
        storage,
        engine,
        bind_address,
        port,
        experimental_control,
        false,
    )
    .await
}

pub async fn serve_with_network(
    storage: Storage,
    engine: std::path::PathBuf,
    bind_address: Option<String>,
    port: Option<u16>,
    experimental_control: bool,
    experimental_native_network: bool,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    storage.ensure_layout()?;
    let mut settings = storage.load_or_create_settings()?;
    if let Some(bind_address) = bind_address {
        settings.bind_address = bind_address;
    }
    if let Some(port) = port {
        settings.port = port;
    }
    let _service_lock = storage.service_lock()?;
    let token = storage.load_or_create_token()?;
    let (certificate, private_key) = storage.ensure_certificate(
        settings
            .certificate_name
            .as_deref()
            .unwrap_or(&settings.bind_address),
    )?;
    let address = SocketAddr::new(
        settings
            .bind_address
            .parse::<IpAddr>()
            .context("invalid HTTPS bind address")?,
        settings.port,
    );

    let tls = RustlsConfig::from_pem_file(certificate, private_key)
        .await
        .context("failed to load HTTPS certificate")?;
    // Bind and load the identity before starting any VPN child.
    let listener = std::net::TcpListener::bind(address).context("failed to bind HTTPS listener")?;
    let server = axum_server::from_tcp_rustls(listener, tls)
        .context("failed to initialize HTTPS listener")?;
    let manager = VpnManager::new(storage.clone(), engine)
        .with_experimental_control(experimental_control)
        .with_network_authority(std::path::PathBuf::from(
            openfortivpn_manager_core::network_authority::SYSTEM_DIRECTORY,
        ));
    let manager = Arc::new(if experimental_native_network {
        manager.with_system_native_network()?
    } else {
        manager
    });
    manager.restore_recovery().await?;
    manager
        .probe_engine()
        .await
        .context("engine capability verification failed")?;
    let state = ApiState {
        manager: manager.clone(),
        token: Arc::new(token),
        auth_storage: Some(storage.clone()),
    };

    eprintln!(
        "openfortivpn-manager-headless {} listening on https://{}",
        VERSION, address
    );
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let signals = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });
    manager.auto_connect().await;
    let result = server
        .handle(handle)
        .serve(router(state).into_make_service())
        .await
        .context("HTTPS server stopped unexpectedly");
    manager.shutdown().await;
    signals.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn offline_diagnostics_never_exports_credentials_or_profile_identity() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        let identity = "synthetic-private-identity";
        let profile: crate::model::VpnProfile = serde_json::from_value(
            serde_json::json!({"id":identity,"name":identity,"host":identity,"username":identity}),
        )
        .unwrap();
        storage
            .save_profile(profile, Some("synthetic-password".into()), true)
            .unwrap();
        let report = offline_diagnostics(storage, root.path().join("missing-engine"))
            .await
            .unwrap();
        let encoded = report.to_string();
        assert!(!encoded.contains(identity));
        assert!(!encoded.contains("synthetic-password"));
        assert_eq!(report["source"], "offlineRepository");
        assert_eq!(report["engineProbe"], "unavailable");
        assert_eq!(report["profiles"]["count"], 1);
    }

    #[tokio::test]
    async fn occupied_https_port_never_starts_auto_connect() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::new(
            root.path().join("etc"),
            root.path().join("state"),
            root.path().join("run"),
        );
        let input: crate::model::VpnProfile = serde_json::from_value(serde_json::json!({"id":"office","name":"Office","host":"vpn.example.com","username":"test","autoConnect":true})).unwrap();
        storage
            .save_profile(input, Some("synthetic-secret".into()), true)
            .unwrap();
        let counter = root.path().join("starts");
        let engine = root.path().join("engine");
        std::fs::write(
            &engine,
            format!(
                "#!/bin/sh\necho started > '{}'\nsleep 2\n",
                counter.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o700)).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let result = serve(
            storage,
            engine,
            Some("127.0.0.1".into()),
            Some(listener.local_addr().unwrap().port()),
            false,
        )
        .await;
        assert!(result.is_err());
        tokio::task::yield_now().await;
        assert!(!counter.exists());
    }

    #[test]
    fn ipv6_bind_uses_socket_address_formatting() {
        let address = SocketAddr::new("::1".parse().unwrap(), 18443);
        assert_eq!(address.to_string(), "[::1]:18443");
    }
}
