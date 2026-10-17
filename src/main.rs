use std::path::PathBuf;
use tokio::sync::broadcast;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use vine::config::Config;
use vine::proxy::ProxyServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,vine=debug")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("vine.toml"));

    info!("Loading configuration from '{}'...", config_path.display());
    let config = match Config::load_or_create(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(
                "Failed to load configuration file '{}': {}",
                config_path.display(),
                e
            );
            std::process::exit(1);
        }
    };

    let server = ProxyServer::new(config)?;

    let (shutdown_tx, _) = broadcast::channel(1);
    let signal_tx = shutdown_tx.clone();

    tokio::spawn(async move {
        match shutdown_signal().await {
            Ok(signal) => {
                info!("Received shutdown signal ({signal}). Initiating graceful shutdown...");
                let _ = signal_tx.send(());
            }
            Err(err) => error!("Failed to listen for shutdown signal: {}", err),
        }
    });

    if let Err(e) = server.run(shutdown_tx).await {
        error!("Fatal proxy error: {}", e);
        std::process::exit(1);
    }

    info!("Vine proxy shut down successfully.");
    std::process::exit(0);
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map(|()| "Ctrl+C"),
        _ = terminate.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<&'static str> {
    tokio::signal::ctrl_c().await.map(|()| "Ctrl+C")
}
