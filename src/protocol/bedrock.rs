use std::io::Cursor;

use pumpkin_protocol::bedrock::status::{
    CUnconnectedPong, OFFLINE_MESSAGE_MAGIC, SUnconnectedPing, SUnconnectedPingOpenConnections,
};
use pumpkin_protocol::serial::{PacketRead, PacketWrite};

pub const UNCONNECTED_PING_ID: u8 = 0x01;
pub const UNCONNECTED_PING_OPEN_CONNECTIONS_ID: u8 = 0x02;
pub const UNCONNECTED_PONG_ID: u8 = 0x1c;
pub const OFFLINE_MAGIC: [u8; 16] = OFFLINE_MESSAGE_MAGIC;

#[derive(Clone, Copy, Debug)]
pub struct UnconnectedPing {
    pub time: u64,
    pub magic: [u8; 16],
}

impl UnconnectedPing {
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (&id, payload) = datagram.split_first()?;
        let mut cursor = Cursor::new(payload);
        let (time, magic) = match id {
            UNCONNECTED_PING_ID => {
                let ping = SUnconnectedPing::read(&mut cursor).ok()?;
                (ping.time, ping.magic)
            }
            UNCONNECTED_PING_OPEN_CONNECTIONS_ID => {
                let ping = SUnconnectedPingOpenConnections::read(&mut cursor).ok()?;
                (ping.time, ping.magic)
            }
            _ => return None,
        };
        Some(Self { time, magic })
    }
}

pub fn encode_unconnected_pong(
    time: u64,
    server_guid: u64,
    advertisement: String,
) -> Option<Vec<u8>> {
    let pong = CUnconnectedPong::new(time, server_guid, advertisement);
    let mut out = vec![UNCONNECTED_PONG_ID];
    pong.write(&mut out).ok()?;
    Some(out)
}
