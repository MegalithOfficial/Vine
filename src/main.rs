use std::path::PathBuf;
use tokio::sync::broadcast;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use vine::backend::forwarding::ForwardingHelper;
use vine::config::{Config, ForwardingMode};
use vine::proxy::ProxyServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,vine=debug")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // `--init` writes the default files and exits without starting the proxy
    let mut args = std::env::args().skip(1).peekable();
    let init_only = args.next_if(|arg| arg == "--init").is_some();
    let config_path = args
        .next()
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

    let lang_dir = config_path
        .parent()
        .unwrap_or(std::path::Path::new(""))
        .join("lang");
    if let Err(e) = vine::i18n::init(&lang_dir, &config.server.default_locale) {
        error!(
            "Failed to load translations from '{}': {}",
            lang_dir.display(),
            e
        );
    }

    if init_only {
        info!(
            "Wrote the default files next to '{}'",
            config_path.display()
        );
        for (name, server) in &config.servers {
            if server.forwarding == ForwardingMode::Vine
                && let Some(key) = server
                    .secret
                    .as_deref()
                    .and_then(|secret| ForwardingHelper::get_vine_public_key_hex(secret).ok())
            {
                info!(
                    "Vine public key for '{name}': {key} (networking.proxy.vine.public_key on Pumpkin)"
                );
            }
        }
        return Ok(());
    }

    let server = ProxyServer::new(config)?;

    let (shutdown_tx, _) = broadcast::channel(1);
    let signal_tx = shutdown_tx.clone();

    tokio::spawn(async move {
        match shutdown_signal().await {
            Ok(signal) => {
                info!("Shutting down ({signal})");
                let _ = signal_tx.send(());
            }
            Err(err) => error!("Failed to listen for shutdown signal: {}", err),
        }
    });

    if let Err(e) = server.run(shutdown_tx).await {
        error!("Fatal proxy error: {}", e);
        std::process::exit(1);
    }

    info!("Stopped");
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
