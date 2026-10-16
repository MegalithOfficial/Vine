use uuid::Uuid;

use super::{Packet, PacketKind};
use crate::protocol::wire::{ReadExt, WriteExt};
use crate::protocol::{ProtocolError, ProtocolVersion};

const V1_19_2: ProtocolVersion = ProtocolVersion(760);

// Sent by 1.19-1.19.2 clients that have a Mojang-issued chat signing key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileKey {
    pub expires_at: i64,
    pub public_key: Vec<u8>,
    pub key_signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct LoginStart {
    pub name: String,
    pub uuid: Option<Uuid>,
    pub profile_key: Option<ProfileKey>,
}

impl Packet for LoginStart {
    const KIND: PacketKind = PacketKind::LoginStart;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let name = buf.read_string_bounded(16)?;
        let mut uuid = None;
        let mut profile_key = None;
        if (ProtocolVersion::V1_19..=V1_19_2).contains(&version) && buf.read_bool()? {
            profile_key = Some(ProfileKey {
                expires_at: buf.read_i64()?,
                public_key: buf.read_byte_array()?,
                key_signature: buf.read_byte_array()?,
            });
        }
        if version >= ProtocolVersion::V1_20_2
            || (version >= ProtocolVersion::V1_19_1 && buf.read_bool()?)
        {
            uuid = Some(buf.read_uuid()?);
        }
        Ok(Self {
            name,
            uuid,
            profile_key,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_string(&self.name);
        if (ProtocolVersion::V1_19..=V1_19_2).contains(&version) {
            buf.write_bool(self.profile_key.is_some());
            if let Some(key) = &self.profile_key {
                buf.write_i64(key.expires_at);
                buf.write_byte_array(&key.public_key);
                buf.write_byte_array(&key.key_signature);
            }
        }
        if version >= ProtocolVersion::V1_20_2 {
            buf.write_uuid(&self.uuid.unwrap_or_default());
        } else if version >= ProtocolVersion::V1_19_1 {
            buf.write_bool(self.uuid.is_some());
            if let Some(uuid) = &self.uuid {
                buf.write_uuid(uuid);
            }
        }
        Ok(())
    }
}

fn read_login_bytes(buf: &mut &[u8], version: ProtocolVersion) -> Result<Vec<u8>, ProtocolError> {
    if version < ProtocolVersion::V1_8 {
        buf.read_short_byte_array()
    } else {
        buf.read_byte_array()
    }
}

fn write_login_bytes(buf: &mut Vec<u8>, bytes: &[u8], version: ProtocolVersion) {
    if version < ProtocolVersion::V1_8 {
        buf.write_short_byte_array(bytes);
    } else {
        buf.write_byte_array(bytes);
    }
}

#[derive(Clone, Debug)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
    pub should_authenticate: bool,
}

impl Packet for EncryptionRequest {
    const KIND: PacketKind = PacketKind::EncryptionRequest;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            server_id: buf.read_string_bounded(20)?,
            public_key: read_login_bytes(buf, version)?,
            verify_token: read_login_bytes(buf, version)?,
            should_authenticate: version < ProtocolVersion::V1_20_5 || buf.read_bool()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_string(&self.server_id);
        write_login_bytes(buf, &self.public_key, version);
        write_login_bytes(buf, &self.verify_token, version);
        if version >= ProtocolVersion::V1_20_5 {
            buf.write_bool(self.should_authenticate);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verification {
    Token(Vec<u8>),
    Signature { salt: i64, signature: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct EncryptionResponse {
    pub shared_secret: Vec<u8>,
    pub verification: Verification,
}

impl Packet for EncryptionResponse {
    const KIND: PacketKind = PacketKind::EncryptionResponse;

    fn read(buf: &mut &[u8], version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let shared_secret = read_login_bytes(buf, version)?;
        let verification =
            if (ProtocolVersion::V1_19..=V1_19_2).contains(&version) && !buf.read_bool()? {
                Verification::Signature {
                    salt: buf.read_i64()?,
                    signature: buf.read_byte_array()?,
                }
            } else {
                Verification::Token(read_login_bytes(buf, version)?)
            };
        Ok(Self {
            shared_secret,
            verification,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, version: ProtocolVersion) -> Result<(), ProtocolError> {
        write_login_bytes(buf, &self.shared_secret, version);
        let legacy_signing = (ProtocolVersion::V1_19..=V1_19_2).contains(&version);
        match &self.verification {
            Verification::Token(token) => {
                if legacy_signing {
                    buf.write_bool(true);
                }
                write_login_bytes(buf, token, version);
            }
            Verification::Signature { salt, signature } if legacy_signing => {
                buf.write_bool(false);
                buf.write_i64(*salt);
                buf.write_byte_array(signature);
            }
            Verification::Signature { .. } => {
                return Err(ProtocolError::Encode(format!(
                    "signed verify tokens do not exist in {version}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SetCompression {
    pub threshold: i32,
}

impl Packet for SetCompression {
    const KIND: PacketKind = PacketKind::SetCompression;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            threshold: buf.read_varint()?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_varint(self.threshold);
        Ok(())
    }
}

// Always JSON, even on versions that use NBT components elsewhere
#[derive(Clone, Debug)]
pub struct LoginDisconnect {
    pub reason_json: String,
}

impl Packet for LoginDisconnect {
    const KIND: PacketKind = PacketKind::LoginDisconnect;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason_json: buf.read_string_bounded(262_144)?,
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_string(&self.reason_json);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct LoginPluginRequest {
    pub message_id: i32,
    pub channel: String,
    pub data: Vec<u8>,
}

impl Packet for LoginPluginRequest {
    const KIND: PacketKind = PacketKind::LoginPluginRequest;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self {
            message_id: buf.read_varint()?,
            channel: buf.read_string()?,
            data: std::mem::take(buf).to_vec(),
        })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_varint(self.message_id);
        buf.write_string(&self.channel);
        buf.extend_from_slice(&self.data);
        Ok(())
    }
}

// `data: None` tells the backend the channel is not understood
#[derive(Clone, Debug)]
pub struct LoginPluginResponse {
    pub message_id: i32,
    pub data: Option<Vec<u8>>,
}

impl Packet for LoginPluginResponse {
    const KIND: PacketKind = PacketKind::LoginPluginResponse;

    fn read(buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        let message_id = buf.read_varint()?;
        let data = if buf.read_bool()? {
            Some(std::mem::take(buf).to_vec())
        } else {
            None
        };
        Ok(Self { message_id, data })
    }

    fn write(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        buf.write_varint(self.message_id);
        buf.write_bool(self.data.is_some());
        if let Some(data) = &self.data {
            buf.extend_from_slice(data);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoginAcknowledged;

impl Packet for LoginAcknowledged {
    const KIND: PacketKind = PacketKind::LoginAcknowledged;

    fn read(_buf: &mut &[u8], _version: ProtocolVersion) -> Result<Self, ProtocolError> {
        Ok(Self)
    }

    fn write(&self, _buf: &mut Vec<u8>, _version: ProtocolVersion) -> Result<(), ProtocolError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{decode_packet, encode_packet};

    fn round_trip<P: Packet>(packet: &P, version: ProtocolVersion) -> P {
        let bytes = encode_packet(packet, version).unwrap();
        let mut cur = &bytes[..];
        assert_eq!(cur.read_varint().unwrap(), P::KIND.id(version).unwrap());
        decode_packet(cur, version).unwrap()
    }

    #[test]
    fn test_login_start_layouts() {
        let uuid = Uuid::from_u128(0x1234);
        for (protocol, expect_uuid) in [
            (47, false),
            (759, false),
            (760, true),
            (761, true),
            (764, true),
            (777, true),
        ] {
            let version = ProtocolVersion(protocol);
            let packet = LoginStart {
                name: "Steve".into(),
                uuid: Some(uuid),
                profile_key: None,
            };
            let decoded = round_trip(&packet, version);
            assert_eq!(decoded.name, "Steve");
            assert_eq!(
                decoded.uuid,
                expect_uuid.then_some(uuid),
                "protocol {protocol}"
            );
        }
    }

    #[test]
    fn test_login_start_reads_1_19_profile_key() {
        let version = ProtocolVersion::V1_19;
        let mut payload = Vec::new();
        payload.write_string("Alex");
        payload.write_bool(true);
        payload.write_i64(42);
        payload.write_byte_array(&[1, 2, 3]);
        payload.write_byte_array(&[4, 5]);
        let decoded: LoginStart = decode_packet(&payload, version).unwrap();
        assert_eq!(
            decoded.profile_key,
            Some(ProfileKey {
                expires_at: 42,
                public_key: vec![1, 2, 3],
                key_signature: vec![4, 5],
            })
        );
    }

    #[test]
    fn test_login_start_writes_profile_key_and_holder() {
        let version = ProtocolVersion::V1_19_1;
        let holder = Uuid::from_u128(7);
        let packet = LoginStart {
            name: "Alex".to_string(),
            uuid: Some(holder),
            profile_key: Some(ProfileKey {
                expires_at: 42,
                public_key: vec![1, 2, 3],
                key_signature: vec![4, 5],
            }),
        };
        let mut payload = Vec::new();
        packet.write(&mut payload, version).unwrap();
        let decoded: LoginStart = decode_packet(&payload, version).unwrap();
        assert_eq!(decoded.profile_key, packet.profile_key);
        assert_eq!(decoded.uuid, Some(holder));
    }

    #[test]
    fn test_encryption_packets_per_version() {
        for protocol in [5, 47, 759, 760, 761, 766, 777] {
            let version = ProtocolVersion(protocol);
            let request = EncryptionRequest {
                server_id: String::new(),
                public_key: vec![1; 162],
                verify_token: vec![2; 4],
                should_authenticate: true,
            };
            let decoded = round_trip(&request, version);
            assert_eq!(decoded.public_key, request.public_key);
            assert_eq!(decoded.verify_token, request.verify_token);

            let response = EncryptionResponse {
                shared_secret: vec![3; 128],
                verification: Verification::Token(vec![4; 128]),
            };
            let decoded = round_trip(&response, version);
            assert_eq!(decoded.shared_secret, response.shared_secret);
            assert_eq!(decoded.verification, response.verification);
        }

        let version = ProtocolVersion(760);
        let response = EncryptionResponse {
            shared_secret: vec![3; 128],
            verification: Verification::Signature {
                salt: -7,
                signature: vec![9; 256],
            },
        };
        assert_eq!(
            round_trip(&response, version).verification,
            response.verification
        );
        assert!(encode_packet(&response, ProtocolVersion(761)).is_err());
    }

    #[test]
    fn test_1_7_uses_short_prefixed_arrays() {
        let request = EncryptionRequest {
            server_id: String::new(),
            public_key: vec![1, 2],
            verify_token: vec![3],
            should_authenticate: true,
        };
        let bytes = encode_packet(&request, ProtocolVersion(5)).unwrap();
        assert_eq!(&bytes[..], &[0x01, 0x00, 0x00, 0x02, 1, 2, 0x00, 0x01, 3]);
    }
}
