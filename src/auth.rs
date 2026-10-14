use num_bigint::BigInt;
use pumpkin_protocol::Property;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, pkcs8::EncodePublicKey};
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::{net::IpAddr, time::Duration};
use thiserror::Error;
use tracing::{debug, error, info};
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Failed to decrypt RSA payload: {0}")]
    DecryptError(String),
    #[error("Verify token mismatch")]
    VerifyTokenMismatch,
    #[error("Mojang authentication failed (status: {0})")]
    MojangAuthFailed(u16),
    #[error("Failed to contact Mojang session service: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Failed to parse Mojang response JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid UUID from authentication server: {0}")]
    InvalidUuid(#[from] uuid::Error),
}

pub struct KeyStore {
    private_key: RsaPrivateKey,
    public_key_der: Box<[u8]>,
}

impl KeyStore {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = rand::rng();
        info!("Generating 1024-bit RSA keypair for proxy encryption...");
        let private_key = RsaPrivateKey::new(&mut rng, 1024)?;
        let public_key = private_key.to_public_key();
        let public_key_der = public_key
            .to_public_key_der()
            .map(|der| der.into_vec().into_boxed_slice())?;

        Ok(Self {
            private_key,
            public_key_der,
        })
    }

    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, AuthError> {
        self.private_key
            .decrypt(Pkcs1v15Encrypt, data)
            .map_err(|e| AuthError::DecryptError(e.to_string()))
    }

    /// Computes Minecraft's custom hex SHA-1 server hash
    pub fn auth_digest(&self, server_id: &str, shared_secret: &[u8]) -> String {
        let mut sha1 = Sha1::new();
        sha1.update(server_id.as_bytes());
        sha1.update(shared_secret);
        sha1.update(&self.public_key_der);
        let digest = sha1.finalize();

        BigInt::from_signed_bytes_be(&digest).to_str_radix(16)
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedPlayer {
    pub id: Uuid,
    pub username: String,
    pub properties: Vec<Property>,
}

impl AuthenticatedPlayer {
    pub fn offline(username: &str) -> Self {
        let id = Uuid::new_v3(&Uuid::nil(), format!("OfflinePlayer:{username}").as_bytes());
        Self {
            id,
            username: username.to_string(),
            properties: Vec::new(),
        }
    }
}

#[derive(Deserialize, Debug)]
struct MojangSessionResponse {
    id: String,
    name: String,
    #[serde(default)]
    properties: Vec<MojangProperty>,
}

#[derive(Deserialize, Debug)]
struct MojangProperty {
    name: String,
    value: String,
    signature: Option<String>,
}

pub struct Authenticator {
    client: reqwest::Client,
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator {
    pub fn new() -> Self {
        let client = pumpkin_auth::client_builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// Builds the `hasJoined` URL with every query parameter percent-encoded
    fn has_joined_url(
        username: &str,
        server_hash: &str,
        client_ip: &IpAddr,
        prevent_proxy_connections: bool,
    ) -> reqwest::Url {
        let mut url =
            reqwest::Url::parse("https://sessionserver.mojang.com/session/minecraft/hasJoined")
                .expect("static URL is valid");
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("username", username)
                .append_pair("serverId", server_hash);
            if prevent_proxy_connections {
                query.append_pair("ip", &client_ip.to_string());
            }
        }
        url
    }

    /// Authenticate a player with Mojang's session servers
    pub async fn authenticate(
        &self,
        username: &str,
        server_hash: &str,
        client_ip: &IpAddr,
        prevent_proxy_connections: bool,
    ) -> Result<AuthenticatedPlayer, AuthError> {
        let url = Self::has_joined_url(username, server_hash, client_ip, prevent_proxy_connections);

        debug!("Querying Mojang authentication service for '{}'", username);
        let resp = self.client.get(url).send().await?;

        if !resp.status().is_success() {
            error!(
                "Mojang authentication failed for '{}': status {}",
                username,
                resp.status()
            );
            return Err(AuthError::MojangAuthFailed(resp.status().as_u16()));
        }

        let body = resp.text().await?;
        let data: MojangSessionResponse = serde_json::from_str(&body)?;

        let uuid = Uuid::parse_str(&data.id)?;

        let properties = data
            .properties
            .into_iter()
            .map(|p| Property {
                name: p.name.into_boxed_str(),
                value: p.value.into_boxed_str(),
                signature: p.signature.map(String::into_boxed_str),
            })
            .collect();

        Ok(AuthenticatedPlayer {
            id: uuid,
            username: data.name,
            properties,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_joined_url_encodes_parameters() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let url = Authenticator::has_joined_url("evil&ip=1.1.1.1", "-1a2b", &ip, true);

        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("username".to_string(), "evil&ip=1.1.1.1".to_string()),
                ("serverId".to_string(), "-1a2b".to_string()),
                ("ip".to_string(), "203.0.113.7".to_string()),
            ]
        );

        let url = Authenticator::has_joined_url("Steve", "abc", &ip, false);
        assert_eq!(url.query(), Some("username=Steve&serverId=abc"));
    }
}
