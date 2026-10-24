use num_bigint::BigInt;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::signature::Verifier;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::protocol::ProtocolVersion;
use crate::protocol::packets::login::ProfileKey;

const YGGDRASIL_SESSION_KEY: &[u8] = include_bytes!("yggdrasil_session_pubkey.der");

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Failed to decrypt RSA payload: {0}")]
    DecryptError(String),
    #[error("player has not joined this server through Mojang's session service")]
    NotJoined,
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

// 1.19-1.19.2 clients sign `verify_token ++ salt` with their profile key (SHA256withRSA)
pub fn verify_signed_token(
    public_key_der: &[u8],
    verify_token: &[u8],
    salt: i64,
    signature: &[u8],
) -> bool {
    let Ok(key) = RsaPublicKey::from_public_key_der(public_key_der) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature) else {
        return false;
    };
    let mut message = verify_token.to_vec();
    message.extend_from_slice(&salt.to_be_bytes());
    VerifyingKey::<sha2::Sha256>::new(key)
        .verify(&message, &signature)
        .is_ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRevision {
    GenericV1,
    LinkedV2,
}

#[derive(Clone, Debug)]
pub struct IdentifiedKey {
    pub key: ProfileKey,
    pub revision: KeyRevision,
    pub holder: Option<Uuid>,
}

impl IdentifiedKey {
    pub fn new(key: ProfileKey, version: ProtocolVersion) -> Self {
        let revision = if version >= ProtocolVersion::V1_19_1 {
            KeyRevision::LinkedV2
        } else {
            KeyRevision::GenericV1
        };
        Self {
            key,
            revision,
            holder: None,
        }
    }

    pub fn has_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        self.key.expires_at < now
    }

    pub fn is_signature_valid(&self) -> bool {
        self.verify(self.holder)
    }

    pub fn add_holder(&mut self, holder: Option<Uuid>) -> bool {
        let Some(holder) = holder else {
            return false;
        };
        match self.holder {
            Some(current) => current == holder && self.verify(Some(current)),
            None if self.verify(Some(holder)) => {
                self.holder = Some(holder);
                true
            }
            None => false,
        }
    }

    fn verify(&self, holder: Option<Uuid>) -> bool {
        let message = match self.revision {
            KeyRevision::GenericV1 => format!(
                "{}{}",
                self.key.expires_at,
                pem_public_key(&self.key.public_key)
            )
            .into_bytes(),
            KeyRevision::LinkedV2 => {
                let Some(holder) = holder else {
                    return false;
                };
                let mut message = holder.as_bytes().to_vec();
                message.extend_from_slice(&self.key.expires_at.to_be_bytes());
                message.extend_from_slice(&self.key.public_key);
                message
            }
        };
        let (Ok(mojang), Ok(signature)) = (
            RsaPublicKey::from_public_key_der(YGGDRASIL_SESSION_KEY),
            Signature::try_from(self.key.key_signature.as_slice()),
        ) else {
            return false;
        };
        VerifyingKey::<Sha1>::new(mojang)
            .verify(&message, &signature)
            .is_ok()
    }
}

// Mojang signs the key in this exact PEM form, wrapped at 76 columns with bare newlines
fn pem_public_key(der: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN RSA PUBLIC KEY-----\n{body}\n-----END RSA PUBLIC KEY-----\n")
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileProperty {
    pub name: String,
    pub value: String,
    pub signature: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedPlayer {
    pub id: Uuid,
    pub username: String,
    pub properties: Vec<ProfileProperty>,
    pub profile_key: Option<IdentifiedKey>,
}

impl AuthenticatedPlayer {
    pub fn offline(username: &str) -> Self {
        let id = Uuid::new_v3(&Uuid::nil(), format!("OfflinePlayer:{username}").as_bytes());
        Self {
            id,
            username: username.to_string(),
            properties: Vec::new(),
            profile_key: None,
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
    client: std::sync::OnceLock<reqwest::Client>,
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator {
    pub fn new() -> Self {
        Self {
            client: std::sync::OnceLock::new(),
        }
    }

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
                query.append_pair("ip", &client_ip.to_canonical().to_string());
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
        let client = self.client.get_or_init(|| {
            pumpkin_auth::client_builder()
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default()
        });
        let resp = client.get(url).send().await?;

        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Err(AuthError::NotJoined);
        }
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
            .map(|p| ProfileProperty {
                name: p.name,
                value: p.value,
                signature: p.signature,
            })
            .collect();

        Ok(AuthenticatedPlayer {
            id: uuid,
            username: data.name,
            properties,
            profile_key: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mojang_signed_key() -> ProfileKey {
        use base64::Engine;
        ProfileKey {
            expires_at: 1656753467181,
            public_key: base64::engine::general_purpose::STANDARD
                .decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxUXtDearoxW4mxLy3FEcNg/7ghAIvCqv9YyzcWncg/hqdh/YW6f8XpmtwVLs7yvupUTwjXAQzjSPIyViLlvu1klFNbdslVbpsw+64YSm9wA6v12XF6cZhHmJzOjr67u1wx+nZiQxYxbpBdoH9NZpkbVq+lsNa6D6P/4owZ5s4bQM1MMhk0GNlCM+CGIUxNbBTei1Sev8fCMrOIWqyaOsWam+2+TOc53NeTkJOjiOsJ2y0mjIxDTpffOvkITjA4g5P3qZ82DYtcm33pi/P4qcr3tWbHeXFXq8wwTG1IeD0waNHdNtqo7IMC5tjhFpaQa1jgH/bnStqUjZanQ0b0fKcwIDAQAB")
                .unwrap(),
            key_signature: hex::decode(
                "b0a40bba8d210cd65baf6231c262e030a91ee6e3422fb3101b31554cc686a697218176c948fb0441f1330bc932df2c6baca732ff7c5ec66119b1b3ee7563b09064e84875f5ca1fa1d29d1475793d71a258a3e15ae27538c0f3dc845c9c660b589dea710238f88eb725f0e2465307164d8db78e4f6965859d3bf3db187017766effe180a211e946a5239c01231618eef2aebf492e019d499a807f3b4da5d6b4dd8b473c5668f7a6c1659047c3f97a99b5703f202b11c30282cff172a537f38133c30b48730f72b7ba149f07a512fd73a43c8fd55ee96e29e8c2fd4d31ec423d196c2f7d1cc5db5865259921bc821fec9529a0b2d448765c1e838a97154769e2ef7e4fde656da1fd37bd79cfe63917074edfb5fb7c7c654a63712e614ab2888c2ad974a5586e512ab099c2c1146f11fb5905d37f4e0c373f95062d572977c060c3591c4046bafe6666fdc78526e2380d73c7524314cf1f1a68de0165d455a37b2747c21ae42d279e6a00a4649fafe1f09b981d7ed554f6fb55d25a9d81d06fe44ccf7d0b8b916ffbe50b0051c463ec2c93cfa92a87e157cd66881aeea431408f1558a2419bc5f874ed2054fa366654672fcb56bd1fe4e971686bab61955d0ae884638da91d2a00548ca08526b0958e069a5c88c5e5e6abd7a7edf4ba6f48ded0db61b3e4ec7dc98091b013140dd00c191f661cfe590824818fc1fd71c078cb656b",
            )
            .unwrap(),
        }
    }

    #[test]
    fn test_generic_profile_key_signature() {
        let key = IdentifiedKey::new(mojang_signed_key(), ProtocolVersion::V1_19);
        assert!(key.is_signature_valid());
        assert!(key.has_expired());

        let mut tampered = mojang_signed_key();
        tampered.expires_at += 1;
        assert!(!IdentifiedKey::new(tampered, ProtocolVersion::V1_19).is_signature_valid());
    }

    #[test]
    fn test_linked_profile_key_needs_matching_holder() {
        let mut key = IdentifiedKey::new(mojang_signed_key(), ProtocolVersion::V1_19_1);
        assert!(!key.is_signature_valid());
        assert!(!key.add_holder(None));
        assert!(!key.add_holder(Some(Uuid::new_v4())));
        assert_eq!(key.holder, None);
    }

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
