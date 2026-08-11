pub mod api;
pub mod install;
pub mod manager;
pub mod model;
pub mod storage;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::api::{router, ApiState};
use crate::manager::VpnManager;
use crate::storage::Storage;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn serve(
    storage: Storage,
    engine: std::path::PathBuf,
    bind_address: Option<String>,
    port: Option<u16>,
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
    let token = storage.load_or_create_token()?;
    let (certificate, private_key) = storage.ensure_certificate(&settings.bind_address)?;
    let address: SocketAddr = format!("{}:{}", settings.bind_address, settings.port)
        .parse()
        .context("invalid HTTPS bind address")?;

    let manager = Arc::new(VpnManager::new(storage.clone(), engine));
    manager.auto_connect().await;
    let tls = RustlsConfig::from_pem_file(certificate, private_key)
        .await
        .context("failed to load HTTPS certificate")?;
    let state = ApiState {
        manager: manager.clone(),
        token: Arc::new(token),
    };

    eprintln!(
        "openfortivpn-manager-headless {} listening on https://{}",
        VERSION, address
    );
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
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
    axum_server::bind_rustls(address, tls)
        .handle(handle)
        .serve(router(state).into_make_service())
        .await
        .context("HTTPS server stopped unexpectedly")?;
    manager.shutdown().await;
    Ok(())
}
