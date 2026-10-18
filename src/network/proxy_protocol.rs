use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const PROXY_V2_MAGIC: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    network: IpAddr,
    prefix_len: u8,
}

impl IpRange {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (network, prefix_len) = match s.split_once('/') {
            Some((addr, prefix)) => (addr.parse::<IpAddr>().ok()?, Some(prefix.parse().ok()?)),
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let network = network.to_canonical();
        let max_len = if network.is_ipv4() { 32 } else { 128 };
        let prefix_len = prefix_len.unwrap_or(max_len);
        if prefix_len > max_len {
            return None;
        }
        Some(Self {
            network,
            prefix_len,
        })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(addr) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix_len))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(addr) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProxyHeaderResult {
    pub client_addr: SocketAddr,
    pub leftover_bytes: Vec<u8>,
}

/// Reads and parses HAProxy PROXY protocol (v1 or v2) from an incoming stream.
/// Returns the client address and any leftover bytes read past the header.
pub async fn parse_proxy_protocol<R: AsyncRead + Unpin>(
    reader: &mut R,
    fallback_addr: SocketAddr,
) -> Result<ProxyHeaderResult, io::Error> {
    let mut initial_buf = [0u8; 512];
    let mut n = 0;
    // A header can arrive split over several reads; keep reading while what we have could
    // still be the start of one, so a short first read isn't mistaken for a bad header
    loop {
        let read = reader.read(&mut initial_buf[n..]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Stream closed before reading PROXY header",
            ));
        }
        n += read;
        let v2_prefix = n < PROXY_V2_MAGIC.len() && PROXY_V2_MAGIC.starts_with(&initial_buf[..n]);
        let v1_prefix = n < 6 && b"PROXY ".starts_with(&initial_buf[..n]);
        if !v2_prefix && !v1_prefix {
            break;
        }
    }

    if n >= 12 && initial_buf[..12] == PROXY_V2_MAGIC {
        return parse_proxy_v2(reader, fallback_addr, &initial_buf[..n]).await;
    }

    if n >= 6 && &initial_buf[..6] == b"PROXY " {
        return parse_proxy_v1(reader, fallback_addr, &initial_buf[..n]).await;
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Unknown or invalid PROXY protocol header",
    ))
}

/// Parse PROXY protocol version 1 (text format)
async fn parse_proxy_v1<R: AsyncRead + Unpin>(
    reader: &mut R,
    fallback_addr: SocketAddr,
    initial: &[u8],
) -> Result<ProxyHeaderResult, io::Error> {
    let mut buffer = initial.to_vec();

    while !buffer.windows(2).any(|w| w == b"\r\n") {
        if buffer.len() >= 108 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PROXY v1 header exceeded maximum length (107 bytes)",
            ));
        }
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF reached while reading PROXY v1 header",
            ));
        }
        buffer.push(byte[0]);
    }

    let crlf_pos = buffer
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("CRLf checked in loop");

    let line = std::str::from_utf8(&buffer[..crlf_pos]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY v1 header is not valid UTF-8",
        )
    })?;

    let leftover_bytes = buffer[crlf_pos + 2..].to_vec();

    let parts: Vec<&str> = line.split(' ').collect();
    if parts.is_empty() || parts[0] != "PROXY" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid PROXY v1 prefix",
        ));
    }

    if parts.len() == 2 && parts[1] == "UNKNOWN" {
        return Ok(ProxyHeaderResult {
            client_addr: fallback_addr,
            leftover_bytes,
        });
    }

    if parts.len() < 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Incomplete PROXY v1 header: '{}'", line),
        ));
    }

    let proto = parts[1];
    let src_ip_str = parts[2];
    let src_port_str = parts[4];

    match proto {
        "TCP4" | "TCP6" => {
            let ip: IpAddr = src_ip_str.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid PROXY v1 IP '{}': {}", src_ip_str, e),
                )
            })?;
            let port: u16 = src_port_str.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid PROXY v1 port '{}': {}", src_port_str, e),
                )
            })?;
            Ok(ProxyHeaderResult {
                client_addr: SocketAddr::new(ip, port),
                leftover_bytes,
            })
        }
        "UNKNOWN" => Ok(ProxyHeaderResult {
            client_addr: fallback_addr,
            leftover_bytes,
        }),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported PROXY v1 protocol: '{}'", other),
        )),
    }
}

/// Parse PROXY protocol version 2 (binary format)
async fn parse_proxy_v2<R: AsyncRead + Unpin>(
    reader: &mut R,
    fallback_addr: SocketAddr,
    initial: &[u8],
) -> Result<ProxyHeaderResult, io::Error> {
    let mut header = initial.to_vec();

    while header.len() < 16 {
        let mut buf = [0u8; 16];
        let needed = 16 - header.len();
        let n = reader.read(&mut buf[..needed]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF reached while reading PROXY v2 fixed header",
            ));
        }
        header.extend_from_slice(&buf[..n]);
    }

    let ver_cmd = header[12];
    let fam_proto = header[13];
    let addr_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    let version = ver_cmd >> 4;
    let command = ver_cmd & 0x0F;

    if version != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported PROXY v2 version: {}", version),
        ));
    }

    let total_required = 16 + addr_len;
    while header.len() < total_required {
        let mut buf = [0u8; 512];
        let needed = (total_required - header.len()).min(buf.len());
        let n = reader.read(&mut buf[..needed]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF reached while reading PROXY v2 address body",
            ));
        }
        header.extend_from_slice(&buf[..n]);
    }

    let leftover_bytes = header[total_required..].to_vec();
    let body = &header[16..total_required];

    if command == 0x00 {
        return Ok(ProxyHeaderResult {
            client_addr: fallback_addr,
            leftover_bytes,
        });
    }

    if command != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported PROXY v2 command: {}", command),
        ));
    }

    let family = fam_proto >> 4;
    let protocol = fam_proto & 0x0F;

    if family == 0x1 && protocol == 0x1 {
        if body.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Truncated PROXY v2 IPv4 address block",
            ));
        }
        let src_ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
        let src_port = u16::from_be_bytes([body[8], body[9]]);
        return Ok(ProxyHeaderResult {
            client_addr: SocketAddr::new(IpAddr::V4(src_ip), src_port),
            leftover_bytes,
        });
    }

    if family == 0x2 && protocol == 0x1 {
        if body.len() < 36 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Truncated PROXY v2 IPv6 address block",
            ));
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&body[0..16]);
        let src_ip = Ipv6Addr::from(ip_bytes);
        let src_port = u16::from_be_bytes([body[32], body[33]]);
        return Ok(ProxyHeaderResult {
            client_addr: SocketAddr::new(IpAddr::V6(src_ip), src_port),
            leftover_bytes,
        });
    }

    Ok(ProxyHeaderResult {
        client_addr: fallback_addr,
        leftover_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_ip_range_matching() {
        let single = IpRange::parse("10.0.0.5").unwrap();
        assert!(single.contains(&"10.0.0.5".parse().unwrap()));
        assert!(!single.contains(&"10.0.0.6".parse().unwrap()));

        let v4 = IpRange::parse("10.0.0.0/8").unwrap();
        assert!(v4.contains(&"10.200.1.1".parse().unwrap()));
        assert!(v4.contains(&"::ffff:10.1.2.3".parse().unwrap()));
        assert!(!v4.contains(&"11.0.0.1".parse().unwrap()));

        let any = IpRange::parse("0.0.0.0/0").unwrap();
        assert!(any.contains(&"203.0.113.9".parse().unwrap()));

        let v6 = IpRange::parse("fd00::/8").unwrap();
        assert!(v6.contains(&"fd12::1".parse().unwrap()));
        assert!(!v6.contains(&"fe80::1".parse().unwrap()));
        assert!(!v6.contains(&"10.0.0.1".parse().unwrap()));

        assert!(IpRange::parse("10.0.0.0/33").is_none());
        assert!(IpRange::parse("not-an-ip").is_none());
        assert!(IpRange::parse("10.0.0.0/").is_none());
    }

    #[tokio::test]
    async fn test_proxy_v1_ipv4() {
        let mut data = Cursor::new(b"PROXY TCP4 198.51.100.22 192.0.2.1 54321 25565\r\nHello");
        let fallback = "127.0.0.1:1234".parse().unwrap();
        let res = parse_proxy_protocol(&mut data, fallback).await.unwrap();

        assert_eq!(
            res.client_addr,
            "198.51.100.22:54321".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(res.leftover_bytes, b"Hello");
    }

    #[tokio::test]
    async fn test_proxy_header_split_across_reads() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(1024);
        let header = b"PROXY TCP4 198.51.100.22 192.0.2.1 54321 25565\r\nHello";
        let writer = tokio::spawn(async move {
            client.write_all(&header[..3]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            client.write_all(&header[3..]).await.unwrap();
            client
        });
        let fallback = "127.0.0.1:1234".parse().unwrap();
        let res = parse_proxy_protocol(&mut server, fallback).await.unwrap();
        assert_eq!(
            res.client_addr,
            "198.51.100.22:54321".parse::<SocketAddr>().unwrap()
        );
        drop(writer.await);
    }

    #[tokio::test]
    async fn test_proxy_v1_unknown() {
        let mut data = Cursor::new(b"PROXY UNKNOWN\r\nMinecraftPayload");
        let fallback = "127.0.0.1:1234".parse().unwrap();
        let res = parse_proxy_protocol(&mut data, fallback).await.unwrap();

        assert_eq!(res.client_addr, fallback);
        assert_eq!(res.leftover_bytes, b"MinecraftPayload");
    }

    #[tokio::test]
    async fn test_proxy_v2_ipv4() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&PROXY_V2_MAGIC);
        payload.push(0x21);
        payload.push(0x11);
        payload.extend_from_slice(&12u16.to_be_bytes());
        payload.extend_from_slice(&[10, 0, 0, 99]);
        payload.extend_from_slice(&[192, 168, 1, 1]);
        payload.extend_from_slice(&45678u16.to_be_bytes());
        payload.extend_from_slice(&25565u16.to_be_bytes());
        payload.extend_from_slice(b"MC_PACKET");

        let mut cursor = Cursor::new(payload);
        let fallback = "127.0.0.1:1234".parse().unwrap();
        let res = parse_proxy_protocol(&mut cursor, fallback).await.unwrap();

        assert_eq!(
            res.client_addr,
            "10.0.0.99:45678".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(res.leftover_bytes, b"MC_PACKET");
    }
}
