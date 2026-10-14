pub const UNCONNECTED_PING_ID: u8 = 0x01;
pub const UNCONNECTED_PING_OPEN_CONNECTIONS_ID: u8 = 0x02;
pub const UNCONNECTED_PONG_ID: u8 = 0x1c;
pub const OFFLINE_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

#[derive(Clone, Copy, Debug)]
pub struct UnconnectedPing {
    pub time: u64,
    pub magic: [u8; 16],
}

impl UnconnectedPing {
    pub fn parse(datagram: &[u8]) -> Option<Self> {
        let (&id, payload) = datagram.split_first()?;
        if id != UNCONNECTED_PING_ID && id != UNCONNECTED_PING_OPEN_CONNECTIONS_ID {
            return None;
        }
        if payload.len() < 8 + 16 + 8 {
            return None;
        }
        Some(Self {
            time: u64::from_be_bytes(payload[..8].try_into().ok()?),
            magic: payload[8..24].try_into().ok()?,
        })
    }
}

pub fn encode_unconnected_pong(
    time: u64,
    server_guid: u64,
    advertisement: String,
) -> Option<Vec<u8>> {
    let len = u16::try_from(advertisement.len()).ok()?;
    let mut out = Vec::with_capacity(35 + advertisement.len());
    out.push(UNCONNECTED_PONG_ID);
    out.extend_from_slice(&time.to_be_bytes());
    out.extend_from_slice(&server_guid.to_be_bytes());
    out.extend_from_slice(&OFFLINE_MAGIC);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(advertisement.as_bytes());
    Some(out)
}
