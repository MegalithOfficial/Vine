use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::auth::AuthenticatedPlayer;
use crate::protocol::wire::WriteExt;

type HmacSha256 = Hmac<Sha256>;

pub const VELOCITY_PLAYER_INFO_CHANNEL: &str = "velocity:player_info";
pub const VELOCITY_FORWARDING_VERSION: i32 = 4;

pub const VINE_PLAYER_INFO_CHANNEL: &str = "vine:player_info";
pub const VINE_FORWARDING_VERSION: i32 = 1;

#[derive(Error, Debug)]
pub enum ForwardingError {
    #[error("Velocity secret is required for Velocity modern forwarding")]
    MissingVelocitySecret,
    #[error("Vine secret is required for Vine modern forwarding")]
    MissingVineSecret,
    #[error("HMAC initialization failed: {0}")]
    HmacError(String),
}

pub struct ForwardingHelper;

impl ForwardingHelper {
    /// Builds the BungeeCord virtual host handshake string for Bukkit / Spigot / PaperMC:
    /// Format: `"{host}\0{client_ip}\0{uuid_without_hyphens}\0{json_properties}"`
    pub fn build_bungeecord_host(
        original_host: &str,
        client_ip: &IpAddr,
        player: &AuthenticatedPlayer,
    ) -> String {
        let uuid_str = player.id.simple().to_string();

        let json_properties =
            serde_json::to_string(&player.properties).unwrap_or_else(|_| "[]".to_string());

        format!(
            "{}\0{}\0{}\0{}",
            original_host, client_ip, uuid_str, json_properties
        )
    }

    /// Builds the Velocity player info plugin response data for PaperMC / Purpur / Pumpkin:
    /// Contains:
    /// - 32-byte HMAC-SHA256 signature
    /// - Forwarding version (VarInt 4)
    /// - Client IP address string
    /// - Player UUID (16 raw bytes)
    /// - Player username string
    /// - Properties list (name, value, optional signature)
    pub fn build_velocity_payload(
        secret: &str,
        client_ip: &IpAddr,
        player: &AuthenticatedPlayer,
    ) -> Result<Vec<u8>, ForwardingError> {
        if secret.is_empty() {
            return Err(ForwardingError::MissingVelocitySecret);
        }

        let mut payload = Vec::new();

        payload.write_varint(VELOCITY_FORWARDING_VERSION);

        let ip_str = client_ip.to_string();
        payload.write_string(&ip_str);

        payload.extend_from_slice(player.id.as_bytes());

        payload.write_string(&player.username);

        payload.write_varint(player.properties.len() as i32);
        for prop in &player.properties {
            payload.write_string(&prop.name);
            payload.write_string(&prop.value);
            if let Some(sig) = &prop.signature {
                payload.write_bool(true);
                payload.write_string(sig);
            } else {
                payload.write_bool(false);
            }
        }

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| ForwardingError::HmacError(e.to_string()))?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();

        let mut full_data = Vec::with_capacity(signature.len() + payload.len());
        full_data.extend_from_slice(&signature);
        full_data.extend_from_slice(&payload);

        Ok(full_data)
    }

    /// Derives the 32-byte Ed25519 signing key from secret.
    /// If secret is 64 hex chars, decodes hex directly to 32-byte seed.
    /// Otherwise hashes the secret with SHA-256 to produce a 32-byte seed.
    pub fn get_vine_signing_key(secret: &str) -> Result<SigningKey, ForwardingError> {
        let secret = secret.trim();
        if secret.is_empty() {
            return Err(ForwardingError::MissingVineSecret);
        }
        let seed: [u8; 32] = if secret.len() == 64 && hex::decode(secret).is_ok() {
            let mut s = [0u8; 32];
            let decoded = hex::decode(secret).map_err(|_| ForwardingError::MissingVineSecret)?;
            s.copy_from_slice(&decoded);
            s
        } else {
            Sha256::digest(secret.as_bytes()).into()
        };
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Returns the 64-character hex Ed25519 public key corresponding to the secret.
    /// This public key can be configured directly on Pumpkin backend servers.
    pub fn get_vine_public_key_hex(secret: &str) -> Result<String, ForwardingError> {
        let signing_key = Self::get_vine_signing_key(secret)?;
        Ok(hex::encode(signing_key.verifying_key().to_bytes()))
    }

    /// Builds the Vine player info plugin response data for Pumpkin:
    /// Contains:
    /// - 64-byte Ed25519 signature
    /// - Forwarding version (VarInt 1)
    /// - Timestamp (u64 big-endian seconds since UNIX epoch)
    /// - Challenge nonce ([u8; 16] echoed from backend request)
    /// - Client IP address string
    /// - Player UUID (16 raw bytes)
    /// - Player username string
    /// - Properties list (name, value, optional signature)
    pub fn build_vine_payload(
        secret: &str,
        client_ip: &IpAddr,
        player: &AuthenticatedPlayer,
        challenge: &[u8; 16],
    ) -> Result<Vec<u8>, ForwardingError> {
        let signing_key = Self::get_vine_signing_key(secret)?;

        let mut payload = Vec::new();
        payload.write_varint(VINE_FORWARDING_VERSION);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        payload.extend_from_slice(&now.to_be_bytes());
        payload.extend_from_slice(challenge);

        let ip_str = client_ip.to_string();
        payload.write_string(&ip_str);

        payload.extend_from_slice(player.id.as_bytes());
        payload.write_string(&player.username);

        payload.write_varint(player.properties.len() as i32);
        for prop in &player.properties {
            payload.write_string(&prop.name);
            payload.write_string(&prop.value);
            if let Some(sig) = &prop.signature {
                payload.write_bool(true);
                payload.write_string(sig);
            } else {
                payload.write_bool(false);
            }
        }

        let signature = signing_key.sign(&payload);

        let mut full_data = Vec::with_capacity(64 + payload.len());
        full_data.extend_from_slice(&signature.to_bytes());
        full_data.extend_from_slice(&payload);

        Ok(full_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use uuid::Uuid;

    #[test]
    fn test_bungeecord_host_formatting() {
        let player = AuthenticatedPlayer {
            id: Uuid::parse_str("d8f4a1e0-0f1b-4c3a-9f2e-1a2b3c4d5e6f").unwrap(),
            username: "Steve".to_string(),
            properties: vec![],
        };
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let host = ForwardingHelper::build_bungeecord_host("play.example.com", &ip, &player);

        let parts: Vec<&str> = host.split('\0').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "play.example.com");
        assert_eq!(parts[1], "192.0.2.1");
        assert_eq!(parts[2], "d8f4a1e00f1b4c3a9f2e1a2b3c4d5e6f");
        assert_eq!(parts[3], "[]");
    }

    #[test]
    fn test_velocity_payload_generation() {
        let player = AuthenticatedPlayer {
            id: Uuid::parse_str("d8f4a1e0-0f1b-4c3a-9f2e-1a2b3c4d5e6f").unwrap(),
            username: "Alex".to_string(),
            properties: vec![],
        };
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let secret = "test-secret-key";

        let result = ForwardingHelper::build_velocity_payload(secret, &ip, &player);
        assert!(result.is_ok());
        let data = result.unwrap();

        assert!(data.len() > 32);
    }

    #[test]
    fn test_vine_payload_generation_and_verification() {
        let player = AuthenticatedPlayer {
            id: Uuid::parse_str("d8f4a1e0-0f1b-4c3a-9f2e-1a2b3c4d5e6f").unwrap(),
            username: "Alex".to_string(),
            properties: vec![],
        };
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let secret = "test-vine-secret-phrase";
        let challenge = [7u8; 16];

        let result = ForwardingHelper::build_vine_payload(secret, &ip, &player, &challenge);
        assert!(result.is_ok());
        let data = result.unwrap();

        // 64-byte signature + payload
        assert!(data.len() > 64);
        let (sig_bytes, payload_bytes) = data.split_at(64);

        let signing_key = ForwardingHelper::get_vine_signing_key(secret).unwrap();
        let verifying_key = signing_key.verifying_key();

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        assert!(verifying_key.verify(payload_bytes, &signature).is_ok());

        let pub_hex = ForwardingHelper::get_vine_public_key_hex(secret).unwrap();
        assert_eq!(pub_hex.len(), 64);
    }
}
