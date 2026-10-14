use std::io::{Read, Write};

use aes::cipher::KeyIvInit;
use bytes::{Buf, Bytes, BytesMut};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ProtocolError;
use super::wire::{ReadExt, WriteExt, varint_len};

pub const MAX_FRAME_LEN: usize = 2_097_151;
pub const MAX_PACKET_DATA_LEN: usize = 8_388_608;

type Encryptor = cfb8::Encryptor<aes::Aes128>;
type Decryptor = cfb8::Decryptor<aes::Aes128>;

#[derive(Clone, Debug)]
pub struct RawPacket {
    pub id: i32,
    pub payload: Bytes,
}

impl RawPacket {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(5 + self.payload.len());
        buf.write_varint(self.id);
        buf.extend_from_slice(&self.payload);
        buf.into()
    }

    fn parse(data: Bytes) -> Result<Self, ProtocolError> {
        let mut cur = &data[..];
        let id = cur.read_varint()?;
        let id_len = data.len() - cur.len();
        Ok(Self {
            id,
            payload: data.slice(id_len..),
        })
    }
}

fn cipher_error() -> ProtocolError {
    ProtocolError::Malformed("invalid shared secret".into())
}

// Cancel-safe: bytes are decrypted as they arrive and only consumed once a whole frame is buffered
pub struct PacketReader<R> {
    inner: R,
    buf: BytesMut,
    compression: Option<usize>,
    decryptor: Option<Decryptor>,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            buf: BytesMut::with_capacity(4096),
            compression: None,
            decryptor: None,
        }
    }

    pub async fn read_packet(&mut self) -> Result<RawPacket, ProtocolError> {
        loop {
            if let Some(frame) = self.next_frame()? {
                return self.decode_frame(frame);
            }

            let start = self.buf.len();
            let n = self.inner.read_buf(&mut self.buf).await?;
            if n == 0 {
                return Err(if start == 0 {
                    ProtocolError::ConnectionClosed
                } else {
                    ProtocolError::Malformed("connection closed mid-packet".into())
                });
            }
            if let Some(decryptor) = &mut self.decryptor {
                decryptor.decrypt(&mut self.buf[start..]);
            }
        }
    }

    fn next_frame(&mut self) -> Result<Option<Bytes>, ProtocolError> {
        let mut cur = &self.buf[..];
        let len = match cur.read_varint() {
            Ok(len) => len,
            Err(_) if self.buf.len() < 3 => return Ok(None),
            Err(e) => return Err(e),
        };
        let len = usize::try_from(len)
            .ok()
            .filter(|len| (1..=MAX_FRAME_LEN).contains(len))
            .ok_or_else(|| ProtocolError::Malformed(format!("invalid frame length {len}")))?;
        let header = self.buf.len() - cur.len();
        if cur.len() < len {
            self.buf.reserve(header + len - self.buf.len());
            return Ok(None);
        }
        self.buf.advance(header);
        Ok(Some(self.buf.split_to(len).freeze()))
    }

    fn decode_frame(&self, frame: Bytes) -> Result<RawPacket, ProtocolError> {
        let Some(threshold) = self.compression else {
            return RawPacket::parse(frame);
        };

        let mut cur = &frame[..];
        let data_len = cur.read_varint()?;
        let body = frame.slice(frame.len() - cur.len()..);
        if data_len == 0 {
            return RawPacket::parse(body);
        }

        let data_len = usize::try_from(data_len)
            .ok()
            .filter(|len| *len <= MAX_PACKET_DATA_LEN)
            .ok_or_else(|| {
                ProtocolError::Malformed(format!("invalid uncompressed length {data_len}"))
            })?;
        if data_len < threshold {
            return Err(ProtocolError::Malformed(format!(
                "compressed packet of {data_len} bytes is below the threshold of {threshold}"
            )));
        }

        let mut data = Vec::with_capacity(data_len);
        ZlibDecoder::new(&body[..])
            .take(data_len as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|e| ProtocolError::Malformed(format!("invalid zlib data: {e}")))?;
        if data.len() != data_len {
            return Err(ProtocolError::Malformed(format!(
                "decompressed {} bytes but the header announced {data_len}",
                data.len()
            )));
        }
        RawPacket::parse(data.into())
    }

    pub fn set_compression(&mut self, threshold: usize) {
        self.compression = Some(threshold);
    }

    pub fn enable_encryption(&mut self, key: &[u8; 16]) -> Result<(), ProtocolError> {
        let mut decryptor = Decryptor::new_from_slices(key, key).map_err(|_| cipher_error())?;
        // Bytes already buffered arrived after the key exchange and are still ciphertext
        decryptor.decrypt(&mut self.buf[..]);
        self.decryptor = Some(decryptor);
        Ok(())
    }
}

// Cancel-safe: packets are fully encoded into `out` up front and `flush` only drains it
pub struct PacketWriter<W> {
    inner: W,
    out: BytesMut,
    compression: Option<(usize, u32)>,
    encryptor: Option<Encryptor>,
}

impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            out: BytesMut::with_capacity(4096),
            compression: None,
            encryptor: None,
        }
    }

    pub fn queue(&mut self, packet: &[u8]) -> Result<(), ProtocolError> {
        let start = self.out.len();
        match self.compression {
            Some((threshold, level)) if packet.len() >= threshold => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
                encoder.write_all(packet)?;
                let compressed = encoder.finish()?;
                let data_len = packet.len() as i32;
                self.write_frame(varint_len(data_len) + compressed.len(), |out| {
                    out.write_varint(data_len);
                    out.extend_from_slice(&compressed);
                })?;
            }
            Some(_) => {
                self.write_frame(1 + packet.len(), |out| {
                    out.write_varint(0);
                    out.extend_from_slice(packet);
                })?;
            }
            None => self.write_frame(packet.len(), |out| out.extend_from_slice(packet))?,
        }
        if let Some(encryptor) = &mut self.encryptor {
            encryptor.encrypt(&mut self.out[start..]);
        }
        Ok(())
    }

    fn write_frame(
        &mut self,
        len: usize,
        body: impl FnOnce(&mut Vec<u8>),
    ) -> Result<(), ProtocolError> {
        if len > MAX_FRAME_LEN {
            return Err(ProtocolError::Encode(format!(
                "packet of {len} bytes exceeds the maximum frame size"
            )));
        }
        let mut frame = Vec::with_capacity(3 + len);
        frame.write_varint(len as i32);
        body(&mut frame);
        self.out.extend_from_slice(&frame);
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), ProtocolError> {
        while !self.out.is_empty() {
            let n = self.inner.write(&self.out).await?;
            if n == 0 {
                return Err(ProtocolError::Io(std::io::ErrorKind::WriteZero.into()));
            }
            self.out.advance(n);
        }
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn send(&mut self, packet: Bytes) -> Result<(), ProtocolError> {
        self.queue(&packet)?;
        self.flush().await
    }

    pub fn set_compression(&mut self, threshold: usize, level: u32) {
        self.compression = Some((threshold, level.min(9)));
    }

    pub fn enable_encryption(&mut self, key: &[u8; 16]) -> Result<(), ProtocolError> {
        self.encryptor = Some(Encryptor::new_from_slices(key, key).map_err(|_| cipher_error())?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    struct Chunked {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl AsyncRead for Chunked {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let end = (self.pos + self.chunk).min(self.data.len());
            let start = self.pos;
            buf.put_slice(&self.data[start..end]);
            self.pos = end;
            Poll::Ready(Ok(()))
        }
    }

    fn packet(id: i32, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_varint(id);
        buf.extend_from_slice(payload);
        buf
    }

    async fn round_trip(
        packets: &[Vec<u8>],
        compression: Option<usize>,
        key: Option<[u8; 16]>,
        chunk: usize,
    ) -> Vec<RawPacket> {
        let mut writer = PacketWriter::new(Vec::new());
        if let Some(threshold) = compression {
            writer.set_compression(threshold, 6);
        }
        if let Some(key) = &key {
            writer.enable_encryption(key).unwrap();
        }
        for p in packets {
            writer.queue(p).unwrap();
        }
        writer.flush().await.unwrap();

        let mut reader = PacketReader::new(Chunked {
            data: writer.inner,
            pos: 0,
            chunk,
        });
        if let Some(threshold) = compression {
            reader.set_compression(threshold);
        }
        if let Some(key) = &key {
            reader.enable_encryption(key).unwrap();
        }
        let mut out = Vec::new();
        for _ in packets {
            out.push(reader.read_packet().await.unwrap());
        }
        assert!(matches!(
            reader.read_packet().await,
            Err(ProtocolError::ConnectionClosed)
        ));
        out
    }

    #[tokio::test]
    async fn test_round_trip_all_modes() {
        let big = vec![7u8; 70_000];
        let packets = vec![packet(0x00, b""), packet(0x2A, b"hello"), packet(300, &big)];
        for compression in [None, Some(256)] {
            for key in [None, Some([9u8; 16])] {
                for chunk in [1, 7, 4096] {
                    let decoded = round_trip(&packets, compression, key, chunk).await;
                    assert_eq!(decoded[0].id, 0);
                    assert!(decoded[0].payload.is_empty());
                    assert_eq!(decoded[1].id, 0x2A);
                    assert_eq!(&decoded[1].payload[..], b"hello");
                    assert_eq!(decoded[2].id, 300);
                    assert_eq!(&decoded[2].payload[..], &big[..]);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_rejects_oversized_frame_and_bad_compression() {
        let mut data = Vec::new();
        data.write_varint(MAX_FRAME_LEN as i32 + 1);
        let mut reader = PacketReader::new(&data[..]);
        assert!(reader.read_packet().await.is_err());

        let mut frame = Vec::new();
        frame.write_varint(10);
        frame.extend_from_slice(&[0u8; 4]);
        let mut data = Vec::new();
        data.write_varint(frame.len() as i32);
        data.extend_from_slice(&frame);
        let mut reader = PacketReader::new(&data[..]);
        reader.set_compression(256);
        assert!(reader.read_packet().await.is_err());
    }

    #[tokio::test]
    async fn test_read_is_cancel_safe() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut reader = PacketReader::new(client);

        let mut writer = PacketWriter::new(Vec::new());
        writer.queue(&packet(5, b"abcdef")).unwrap();
        writer.flush().await.unwrap();
        let bytes = writer.inner;

        server.write_all(&bytes[..3]).await.unwrap();
        let first =
            tokio::time::timeout(std::time::Duration::from_millis(20), reader.read_packet()).await;
        assert!(first.is_err());

        server.write_all(&bytes[3..]).await.unwrap();
        let packet = reader.read_packet().await.unwrap();
        assert_eq!(packet.id, 5);
        assert_eq!(&packet.payload[..], b"abcdef");
    }
}
