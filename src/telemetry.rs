use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::config::Config;

/// Filename used to persist the telemetry identity key across restarts.
pub const IDENTITY_KEY_PATH: &str = ".vine/identity.key";

const LEGACY_IDENTITY_KEY_PATHS: &[&str] = &[
    ".pumpkin/identity.key",
    "telemetry_key.bin",
    "data/.pumpkin/identity.key",
    "data/.vine/identity.key",
    "data/telemetry_key.bin",
];

/// HTTP header name for the Ed25519 public key in lowercase hex format.
pub const HEADER_PUBLIC_KEY: &str = "X-Telemetry-Public-Key";

/// HTTP header name for the Ed25519 signature in lowercase hex format.
pub const HEADER_SIGNATURE: &str = "X-Telemetry-Signature";

/// HTTP header name for the request timestamp in Unix seconds.
pub const HEADER_TIMESTAMP: &str = "X-Telemetry-Timestamp";

/// Maximum allowable clock drift between telemetry client and server (300 seconds / 5 minutes).
pub const MAX_CLOCK_DRIFT_SECS: u64 = 300;

/// Information about an active plugin on the proxy / server.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PluginInfo {
    /// The name of the plugin.
    pub name: String,
    /// The version of the plugin.
    pub version: String,
}

/// Type alias for plugin telemetry information.
pub type PluginTelemetryInfo = PluginInfo;

/// The telemetry heartbeat payload transmitted to the backend.
/// Matches the Pumpkin Market API schema: https://market.pumpkinmc.org/api/docs/#/
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HeartbeatPayload {
    /// The server software implementation type ("vine").
    pub server_type: String,
    /// The Vine proxy software version.
    pub server_version: String,
    /// The Minecraft game version string.
    pub minecraft_version: String,
    /// The network protocol version number.
    pub protocol_version: i32,
    /// Current number of connected players.
    pub online_players: usize,
    /// Maximum number of players allowed.
    pub max_players: u32,
    /// Host operating system name.
    pub os: String,
    /// Host CPU architecture.
    pub arch: String,
    /// Number of available CPU cores.
    pub cpu_cores: usize,
    /// CPU model name or brand.
    pub cpu_model: String,
    /// RAM allocated/used by the system in MiB.
    pub ram_allocated_mb: u64,
    /// Total physical RAM available to the system in MiB.
    pub total_ram_mb: u64,
    /// List of active plugins.
    pub plugins: Vec<PluginInfo>,
    /// Whether the server has opted into public directory listing.
    pub is_public: bool,
    /// Public name of the server if opted into public directory listing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_name: Option<String>,
}

/// The response payload received from the telemetry backend.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HeartbeatResponse {
    /// Response status ("ok", "throttled", etc.).
    pub status: String,
    /// Status or error message from the backend.
    #[serde(default)]
    pub message: String,
    /// Confirmed server public key acknowledged by the backend.
    #[serde(default)]
    pub server_public_key: String,
    /// Recommended seconds to wait before the next heartbeat.
    #[serde(default)]
    pub next_ping_seconds: u32,
}

/// Computes the signed data byte layout: `[timestamp_ascii_bytes] + [b'.'] + [raw_json_body_bytes]`.
#[must_use]
pub fn compute_signed_data(timestamp_str: &str, body_bytes: &[u8]) -> Vec<u8> {
    let mut signed_data = Vec::with_capacity(timestamp_str.len() + 1 + body_bytes.len());
    signed_data.extend_from_slice(timestamp_str.as_bytes());
    signed_data.push(b'.');
    signed_data.extend_from_slice(body_bytes);
    signed_data
}

/// Signs telemetry message data using an Ed25519 signing key and returns `(public_key_hex, signature_hex)`.
#[must_use]
pub fn sign_telemetry_payload(
    signing_key: &SigningKey,
    timestamp_str: &str,
    body_bytes: &[u8],
) -> (String, String) {
    let signed_data = compute_signed_data(timestamp_str, body_bytes);
    let signature = signing_key.sign(&signed_data);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let sig_hex = hex::encode(signature.to_bytes());
    (pubkey_hex, sig_hex)
}

/// Errors that can occur during telemetry request signature verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TelemetryVerificationError {
    #[error("Invalid timestamp string format")]
    InvalidTimestamp,
    #[error(
        "Timestamp drift exceeded: drift was {drift}s (max allowed is {MAX_CLOCK_DRIFT_SECS}s)"
    )]
    ClockDriftExceeded { drift: u64 },
    #[error("Invalid public key hex encoding")]
    InvalidPublicKeyHex,
    #[error("Invalid public key bytes: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature hex encoding")]
    InvalidSignatureHex,
    #[error("Invalid signature bytes: {0}")]
    InvalidSignature(String),
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
}

/// Verifies a signed telemetry request against an Ed25519 public key and timestamp.
///
/// Ensures clock drift between `current_time_secs` and `timestamp_str` does not exceed `±300` seconds.
pub fn verify_telemetry_request(
    pubkey_hex: &str,
    sig_hex: &str,
    timestamp_str: &str,
    body_bytes: &[u8],
    current_time_secs: u64,
) -> Result<(), TelemetryVerificationError> {
    let ts: u64 = timestamp_str
        .parse()
        .map_err(|_| TelemetryVerificationError::InvalidTimestamp)?;

    let drift = current_time_secs.abs_diff(ts);
    if drift > MAX_CLOCK_DRIFT_SECS {
        return Err(TelemetryVerificationError::ClockDriftExceeded { drift });
    }

    let pubkey_bytes =
        hex::decode(pubkey_hex).map_err(|_| TelemetryVerificationError::InvalidPublicKeyHex)?;
    let vk = VerifyingKey::try_from(pubkey_bytes.as_slice())
        .map_err(|e| TelemetryVerificationError::InvalidPublicKey(e.to_string()))?;

    let sig_bytes =
        hex::decode(sig_hex).map_err(|_| TelemetryVerificationError::InvalidSignatureHex)?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| TelemetryVerificationError::InvalidSignature(e.to_string()))?;

    let signed_data = compute_signed_data(timestamp_str, body_bytes);
    vk.verify(&signed_data, &sig)
        .map_err(|e| TelemetryVerificationError::VerificationFailed(e.to_string()))?;

    Ok(())
}

/// Client for communicating with the Pumpkin Marketplace telemetry backend.
pub struct TelemetryClient {
    pub signing_key: SigningKey,
    pub http_client: reqwest::Client,
    pub endpoint: String,
    pub api_base_url: String,
}

impl TelemetryClient {
    /// Creates a new `TelemetryClient` instance.
    #[must_use]
    pub fn new(signing_key: SigningKey, http_client: reqwest::Client, endpoint: String) -> Self {
        let api_base_url = endpoint
            .strip_suffix("/api/v1/rest/telemetry/heartbeat")
            .unwrap_or_else(|| {
                endpoint
                    .strip_suffix("/heartbeat")
                    .unwrap_or_else(|| endpoint.trim_end_matches('/'))
            })
            .to_string();

        Self {
            signing_key,
            http_client,
            endpoint,
            api_base_url,
        }
    }

    /// Returns the 64-character lowercase hexadecimal representation of the client's Ed25519 public key.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Loads an existing Ed25519 private key/seed from the given path or generates and persists a new one.
    pub fn load_or_generate_key(key_path: &Path) -> Result<SigningKey, std::io::Error> {
        if key_path.exists() {
            let bytes = std::fs::read(key_path)?;
            if bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return Ok(SigningKey::from_bytes(&seed));
            }
            tracing::warn!(
                "Failed to read valid 32-byte identity key from {}, generating a new one",
                key_path.display()
            );
        }

        // Generate new key
        let seed: [u8; 32] = rand::random();
        let key = SigningKey::from_bytes(&seed);

        if let Some(parent) = key_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(key_path, seed)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(key)
    }

    /// Sends a signed heartbeat request to the telemetry backend.
    pub async fn send_heartbeat(
        &self,
        payload: &HeartbeatPayload,
    ) -> Result<HeartbeatResponse, reqwest::Error> {
        let body_bytes = serde_json::to_vec(payload).expect("Serialization failed");
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let timestamp_str = timestamp.to_string();

        let (pubkey_hex, sig_hex) =
            sign_telemetry_payload(&self.signing_key, &timestamp_str, &body_bytes);

        let response = self
            .http_client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header(HEADER_PUBLIC_KEY, pubkey_hex)
            .header(HEADER_SIGNATURE, sig_hex)
            .header(HEADER_TIMESTAMP, timestamp_str)
            .body(body_bytes)
            .send()
            .await?
            .error_for_status()?
            .json::<HeartbeatResponse>()
            .await?;

        Ok(response)
    }

    /// Sends a signed server shutdown notice to the telemetry backend.
    pub async fn send_shutdown(&self, reason: Option<&str>) -> Result<(), reqwest::Error> {
        let payload = serde_json::json!({
            "reason": reason.unwrap_or("server shutdown")
        });
        let body_bytes = serde_json::to_vec(&payload).expect("Serialization failed");
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let timestamp_str = timestamp.to_string();

        let (pubkey_hex, sig_hex) =
            sign_telemetry_payload(&self.signing_key, &timestamp_str, &body_bytes);

        self.http_client
            .post(format!(
                "{}/api/v1/rest/telemetry/shutdown",
                self.api_base_url
            ))
            .header("Content-Type", "application/json")
            .header(HEADER_PUBLIC_KEY, pubkey_hex)
            .header(HEADER_SIGNATURE, sig_hex)
            .header(HEADER_TIMESTAMP, timestamp_str)
            .body(body_bytes)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}

/// Resolves the server identity key by checking default locations or generating a new one.
#[must_use]
pub fn resolve_identity_key() -> SigningKey {
    let path = std::iter::once(IDENTITY_KEY_PATH)
        .chain(LEGACY_IDENTITY_KEY_PATHS.iter().copied())
        .map(Path::new)
        .find(|path| path.exists())
        .unwrap_or(Path::new(IDENTITY_KEY_PATH));

    TelemetryClient::load_or_generate_key(path).unwrap_or_else(|err| {
        tracing::warn!(
            "Failed to persist telemetry identity key at {}: {err}, using ephemeral key",
            path.display()
        );
        let seed: [u8; 32] = rand::random();
        SigningKey::from_bytes(&seed)
    })
}

/// Helper function to load or create an identity key at a specified path.
#[must_use]
pub fn get_or_create_identity_key(path: &Path) -> SigningKey {
    TelemetryClient::load_or_generate_key(path).unwrap_or_else(|err| {
        tracing::warn!(
            "Failed to save identity key to {}: {err}, using ephemeral key",
            path.display()
        );
        let seed: [u8; 32] = rand::random();
        SigningKey::from_bytes(&seed)
    })
}

/// Builds the telemetry heartbeat payload from current proxy runtime state.
#[must_use]
pub fn build_heartbeat_payload(config: &Config, online_players: usize) -> HeartbeatPayload {
    let os = sysinfo::System::long_os_version().unwrap_or_else(|| {
        let name = sysinfo::System::name().unwrap_or_else(|| std::env::consts::OS.to_string());
        sysinfo::System::os_version().map_or(name.clone(), |ver| format!("{name} {ver}"))
    });
    let arch = std::env::consts::ARCH.to_string();
    let cpu_cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);

    let (ram_allocated_mb, total_ram_mb, cpu_model) = if sysinfo::IS_SUPPORTED_SYSTEM {
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        sys.refresh_cpu_all();
        let ram_allocated = sys.used_memory() / (1024 * 1024);
        let total_ram = sys.total_memory() / (1024 * 1024);
        let cpu_model = sys.cpus().first().map_or_else(
            || "Unknown".to_string(),
            |c| {
                let brand = c.brand().trim();
                if brand.is_empty() {
                    "Unknown".to_string()
                } else {
                    brand.to_string()
                }
            },
        );
        (ram_allocated, total_ram, cpu_model)
    } else {
        (0, 0, "Unknown".to_string())
    };

    let mc_ver = crate::protocol::ProtocolVersion(config.motd.protocol_version.max(0) as u32);
    let minecraft_version = if mc_ver.is_known() {
        mc_ver.name()
    } else {
        "26.2".to_string()
    };

    let is_public = config.telemetry.public;
    let public_name = if is_public {
        config.telemetry.server_name.clone()
    } else {
        None
    };

    HeartbeatPayload {
        server_type: "vine".to_string(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        minecraft_version,
        protocol_version: config.motd.protocol_version,
        online_players,
        max_players: config.motd.max_players,
        os,
        arch,
        cpu_cores,
        cpu_model,
        ram_allocated_mb,
        total_ram_mb,
        plugins: Vec::new(),
        is_public,
        public_name,
    }
}

pub fn start_telemetry(
    config: Arc<Config>,
    online_players: Arc<AtomicUsize>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.telemetry.enabled {
        tracing::trace!("Telemetry is disabled in configuration.");
        return None;
    }

    tracing::info!(
        "Anonymous server telemetry is enabled. Sending periodic heartbeats to {}",
        config.telemetry.endpoint
    );

    let user_agent = format!("Vine-Proxy/{}", env!("CARGO_PKG_VERSION"));
    let client = match pumpkin_auth::client_builder()
        .timeout(Duration::from_secs(10))
        .user_agent(&user_agent)
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            tracing::debug!("Failed to create telemetry HTTP client: {err}");
            return None;
        }
    };

    let signing_key = resolve_identity_key();
    let telemetry_client = Arc::new(TelemetryClient::new(
        signing_key,
        client,
        config.telemetry.endpoint.clone(),
    ));

    let interval_secs = config.telemetry.interval_secs.max(60);

    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let online = online_players.load(Ordering::Relaxed);
                    let payload = build_heartbeat_payload(&config, online);

                    match telemetry_client.send_heartbeat(&payload).await {
                        Ok(resp) => {
                            tracing::trace!(
                                "Telemetry heartbeat successfully transmitted (status: {}, public_key: {})",
                                resp.status,
                                resp.server_public_key
                            );
                        }
                        Err(err) => {
                            tracing::debug!("Telemetry heartbeat failed to send: {err}");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::trace!("Telemetry task received shutdown signal.");
                    break;
                }
            }
        }

        // Trigger shutdown telemetry on server termination / SIGTERM
        tracing::info!("Sending server shutdown notice to telemetry backend...");
        match telemetry_client
            .send_shutdown(Some("server shutdown"))
            .await
        {
            Ok(()) => {
                tracing::info!(
                    "Telemetry shutdown notification successfully acknowledged by backend."
                );
            }
            Err(err) => {
                tracing::warn!("Telemetry shutdown message failed to send: {err}");
            }
        }
    });

    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_key_generation_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(IDENTITY_KEY_PATH);

        assert!(!key_path.exists());
        let key1 = TelemetryClient::load_or_generate_key(&key_path).unwrap();
        assert!(key_path.exists());

        // Check key file has 32 bytes
        let file_bytes = std::fs::read(&key_path).unwrap();
        assert_eq!(file_bytes.len(), 32);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&key_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        // Reload existing key
        let key2 = TelemetryClient::load_or_generate_key(&key_path).unwrap();
        assert_eq!(
            key1.verifying_key().to_bytes(),
            key2.verifying_key().to_bytes()
        );

        // Corrupted file test (not 32 bytes)
        std::fs::write(&key_path, b"corrupted-key-data").unwrap();
        let key3 = TelemetryClient::load_or_generate_key(&key_path).unwrap();
        assert_ne!(
            key1.verifying_key().to_bytes(),
            key3.verifying_key().to_bytes()
        );
        let new_file_bytes = std::fs::read(&key_path).unwrap();
        assert_eq!(new_file_bytes.len(), 32);
    }

    #[test]
    fn heartbeat_payload_serialization() {
        let payload = HeartbeatPayload {
            server_type: "vine".to_string(),
            server_version: "0.1.0".to_string(),
            minecraft_version: "26.2".to_string(),
            protocol_version: 776,
            online_players: 15,
            max_players: 100,
            os: "Linux 6.8.0".to_string(),
            arch: "x86_64".to_string(),
            cpu_cores: 8,
            cpu_model: "AMD Ryzen 7".to_string(),
            ram_allocated_mb: 2048,
            total_ram_mb: 16384,
            plugins: vec![],
            is_public: true,
            public_name: Some("My Vine Proxy".to_string()),
        };

        let json_str = serde_json::to_string_pretty(&payload).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // server_id must be completely removed
        assert!(parsed.get("server_id").is_none());

        assert_eq!(parsed["server_type"], "vine");
        assert_eq!(parsed["server_version"], "0.1.0");
        assert_eq!(parsed["minecraft_version"], "26.2");
        assert_eq!(parsed["protocol_version"], 776);
        assert_eq!(parsed["online_players"], 15);
        assert_eq!(parsed["max_players"], 100);
        assert_eq!(parsed["os"], "Linux 6.8.0");
        assert_eq!(parsed["arch"], "x86_64");
        assert_eq!(parsed["cpu_cores"], 8);
        assert_eq!(parsed["cpu_model"], "AMD Ryzen 7");
        assert_eq!(parsed["ram_allocated_mb"], 2048);
        assert_eq!(parsed["total_ram_mb"], 16384);
        assert_eq!(parsed["is_public"], true);
        assert_eq!(parsed["public_name"], "My Vine Proxy");
        assert_eq!(parsed["plugins"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn heartbeat_response_deserialization() {
        let json_data = r#"{
            "status": "ok",
            "message": "Heartbeat accepted",
            "server_public_key": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "next_ping_seconds": 300
        }"#;

        let resp: HeartbeatResponse = serde_json::from_str(json_data).unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.message, "Heartbeat accepted");
        assert_eq!(
            resp.server_public_key,
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        );
        assert_eq!(resp.next_ping_seconds, 300);
    }

    #[test]
    fn message_signing_and_verification() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let timestamp_str = "1757185000";
        let body = br#"{"server_type":"vine","online_players":5}"#;

        // Verify signed data format: "{timestamp}.{body}"
        let signed_data = compute_signed_data(timestamp_str, body);
        let expected_prefix = format!("{timestamp_str}.");
        assert!(signed_data.starts_with(expected_prefix.as_bytes()));
        assert_eq!(&signed_data[expected_prefix.len()..], body);

        // Sign payload
        let (pubkey_hex, sig_hex) = sign_telemetry_payload(&signing_key, timestamp_str, body);
        assert_eq!(pubkey_hex.len(), 64);
        assert_eq!(sig_hex.len(), 128);

        // All hex chars must be lowercase
        assert_eq!(pubkey_hex, pubkey_hex.to_lowercase());
        assert_eq!(sig_hex, sig_hex.to_lowercase());

        // Verify with matching timestamp
        let current_time: u64 = 1757185100; // 100s drift (within 300s)
        let verify_result =
            verify_telemetry_request(&pubkey_hex, &sig_hex, timestamp_str, body, current_time);
        assert!(verify_result.is_ok());

        // Drift exceeded (> 300s)
        let expired_time: u64 = 1757185000 + 301;
        let expired_result =
            verify_telemetry_request(&pubkey_hex, &sig_hex, timestamp_str, body, expired_time);
        assert!(matches!(
            expired_result,
            Err(TelemetryVerificationError::ClockDriftExceeded { .. })
        ));

        // Corrupted signature
        let mut corrupted_sig = sig_hex.clone();
        let flipped_char = if corrupted_sig.starts_with('0') {
            '1'
        } else {
            '0'
        };
        corrupted_sig.replace_range(0..1, &flipped_char.to_string());
        let corrupted_result = verify_telemetry_request(
            &pubkey_hex,
            &corrupted_sig,
            timestamp_str,
            body,
            current_time,
        );
        assert!(matches!(
            corrupted_result,
            Err(TelemetryVerificationError::VerificationFailed(_))
        ));

        // Corrupted body
        let tampered_body = br#"{"server_type":"vine","online_players":6}"#;
        let tampered_result = verify_telemetry_request(
            &pubkey_hex,
            &sig_hex,
            timestamp_str,
            tampered_body,
            current_time,
        );
        assert!(matches!(
            tampered_result,
            Err(TelemetryVerificationError::VerificationFailed(_))
        ));
    }

    #[tokio::test]
    async fn telemetry_client_send_heartbeat_and_shutdown() {
        use axum::Router;
        use axum::extract::Request;
        use axum::http::StatusCode;
        use axum::http::header::CONTENT_TYPE;
        use axum::response::IntoResponse;
        use axum::routing::post;

        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let expected_pubkey = hex::encode(signing_key.verifying_key().to_bytes());

        // Set up mock axum server
        let app = Router::new()
            .route(
                "/api/v1/rest/telemetry/heartbeat",
                post(move |req: Request| async move {
                    let headers = req.headers().clone();
                    let pubkey = headers.get(HEADER_PUBLIC_KEY).and_then(|v| v.to_str().ok());
                    let signature = headers.get(HEADER_SIGNATURE).and_then(|v| v.to_str().ok());
                    let timestamp = headers.get(HEADER_TIMESTAMP).and_then(|v| v.to_str().ok());

                    let (Some(pubkey), Some(sig), Some(ts)) = (pubkey, signature, timestamp) else {
                        return (StatusCode::UNAUTHORIZED, "Missing required headers")
                            .into_response();
                    };

                    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
                        .await
                        .unwrap();

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    if verify_telemetry_request(pubkey, sig, ts, &body, now).is_err() {
                        return (StatusCode::UNAUTHORIZED, "Invalid signature").into_response();
                    }

                    let response = HeartbeatResponse {
                        status: "ok".to_string(),
                        message: "Heartbeat accepted".to_string(),
                        server_public_key: pubkey.to_string(),
                        next_ping_seconds: 300,
                    };
                    let json_bytes = serde_json::to_vec(&response).unwrap();
                    (
                        StatusCode::OK,
                        [(CONTENT_TYPE, "application/json")],
                        json_bytes,
                    )
                        .into_response()
                }),
            )
            .route(
                "/api/v1/rest/telemetry/shutdown",
                post(move |req: Request| async move {
                    let headers = req.headers().clone();
                    let pubkey = headers.get(HEADER_PUBLIC_KEY).and_then(|v| v.to_str().ok());
                    let signature = headers.get(HEADER_SIGNATURE).and_then(|v| v.to_str().ok());
                    let timestamp = headers.get(HEADER_TIMESTAMP).and_then(|v| v.to_str().ok());

                    let (Some(pubkey), Some(sig), Some(ts)) = (pubkey, signature, timestamp) else {
                        return (StatusCode::UNAUTHORIZED, "Missing headers").into_response();
                    };

                    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
                        .await
                        .unwrap();

                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    if verify_telemetry_request(pubkey, sig, ts, &body, now).is_err() {
                        return (StatusCode::UNAUTHORIZED, "Invalid signature").into_response();
                    }

                    (StatusCode::OK, "Shutdown received").into_response()
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let endpoint = format!("http://127.0.0.1:{port}/api/v1/rest/telemetry/heartbeat");
        let http_client = pumpkin_auth::client();
        let client = TelemetryClient::new(signing_key, http_client, endpoint);

        let payload = HeartbeatPayload {
            server_type: "vine".to_string(),
            server_version: "0.1.0".to_string(),
            minecraft_version: "26.2".to_string(),
            protocol_version: 776,
            online_players: 1,
            max_players: 20,
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            cpu_cores: 4,
            cpu_model: "Test CPU".to_string(),
            ram_allocated_mb: 1024,
            total_ram_mb: 2048,
            plugins: vec![],
            is_public: false,
            public_name: None,
        };

        // Send valid heartbeat -> 200 OK
        let resp = client.send_heartbeat(&payload).await.unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.message, "Heartbeat accepted");
        assert_eq!(resp.server_public_key, expected_pubkey);
        assert_eq!(resp.next_ping_seconds, 300);

        // Send valid shutdown -> 200 OK
        let shutdown_res = client.send_shutdown(Some("maintenance")).await;
        assert!(shutdown_res.is_ok());

        // Test invalid signature / unauthorized
        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let timestamp_str = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let response = pumpkin_auth::client()
            .post(format!(
                "http://127.0.0.1:{port}/api/v1/rest/telemetry/heartbeat"
            ))
            .header("Content-Type", "application/json")
            .header(HEADER_PUBLIC_KEY, &expected_pubkey)
            .header(HEADER_SIGNATURE, "00".repeat(64)) // invalid signature
            .header(HEADER_TIMESTAMP, timestamp_str)
            .body(body_bytes)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
}
