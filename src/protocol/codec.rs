use std::cell::RefCell;

use aes::cipher::KeyIvInit;
use bytes::{Buf, Bytes, BytesMut};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ProtocolError;
use super::wire::{ReadExt, WriteExt, varint_len};

pub const MAX_FRAME_LEN: usize = 2_097_151;
pub const MAX_PACKET_DATA_LEN: usize = 8_388_608;
// Larger packets grow the buffer as their bytes arrive instead of up front
const MAX_PREALLOC: usize = 64 * 1024;
// An emptied buffer bigger than this is let go, so a burst doesn't stay with every connection
const BUFFER_KEEP: usize = 16 * 1024;
// Writes that fit in BUFFER_KEEP in a row before a bigger write buffer is let go
const QUIET_WRITES: u8 = 8;

type Encryptor = cfb8::Encryptor<aes::Aes128>;
type Decryptor = cfb8::Decryptor<aes::Aes128>;

struct Deflater {
    level: u32,
    state: Compress,
    out: Vec<u8>,
}

thread_local! {
    // Setting up a deflate state costs more than compressing a small packet, and one per
    // connection would hold a few hundred KiB each, so each thread keeps one and resets it
    static DEFLATER: RefCell<Option<Deflater>> = const { RefCell::new(None) };
    // Every packet is a zlib stream of its own, so inflating needs no state between them either
    static INFLATER: RefCell<Option<Decompress>> = const { RefCell::new(None) };
}

fn with_inflater<T>(f: impl FnOnce(&mut Decompress) -> T) -> T {
    INFLATER.with_borrow_mut(|slot| {
        let inflater = slot.get_or_insert_with(|| Decompress::new(true));
        inflater.reset(true);
        f(inflater)
    })
}

/// Compresses `data` as a zlib stream and hands the result to `f`
fn deflate<T>(data: &[u8], level: u32, f: impl FnOnce(&[u8]) -> T) -> Result<T, ProtocolError> {
    DEFLATER.with_borrow_mut(|slot| {
        let deflater = match slot {
            Some(d) if d.level == level => d,
            _ => slot.insert(Deflater {
                level,
                state: Compress::new(Compression::new(level), true),
                out: Vec::new(),
            }),
        };
        deflater.state.reset();
        deflater.out.clear();
        loop {
            deflater.out.reserve(data.len() / 2 + 64);
            let read = deflater.state.total_in() as usize;
            let status = deflater
                .state
                .compress_vec(&data[read..], &mut deflater.out, FlushCompress::Finish)
                .map_err(|e| ProtocolError::Encode(format!("zlib: {e}")))?;
            if status == Status::StreamEnd {
                break;
            }
        }
        let result = f(&deflater.out);
        if deflater.out.capacity() > MAX_PREALLOC * 4 {
            deflater.out = Vec::new();
        }
        Ok(result)
    })
}

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

/// A packet as read: decoded, or kept as the frame it arrived in, length prefix included, possibly
/// with more kept frames behind it
pub enum Frame {
    Packet(RawPacket),
    Raw(Bytes),
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
    max_frame: usize,
    max_data: usize,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            buf: BytesMut::with_capacity(4096),
            compression: None,
            decryptor: None,
            max_frame: MAX_FRAME_LEN,
            max_data: MAX_PACKET_DATA_LEN,
        }
    }

    pub fn set_limits(&mut self, max_frame: usize, max_data: usize) {
        self.max_frame = max_frame.min(MAX_FRAME_LEN);
        self.max_data = max_data.min(MAX_PACKET_DATA_LEN);
    }

    pub async fn read_packet(&mut self) -> Result<RawPacket, ProtocolError> {
        let (header, len) = self.next_frame().await?;
        let frame = self.buf.split_to(header + len).freeze();
        self.decode_frame(frame.slice(header..))
    }

    /// Like `read_packet`, but a packet whose id `keep` accepts is returned as the frame it arrived
    /// in, without decompressing more of it than its id. Kept frames right behind it that have
    /// arrived too come along in the same piece, up to about `MAX_PREALLOC` bytes.
    pub async fn read_frame(&mut self, keep: impl Fn(i32) -> bool) -> Result<Frame, ProtocolError> {
        let (header, len) = self.next_frame().await?;
        if !keep(self.peek_id(0, header + len)?) {
            let frame = self.buf.split_to(header + len).freeze();
            return self.decode_frame(frame.slice(header..)).map(Frame::Packet);
        }
        let mut end = header + len;
        while end < MAX_PREALLOC {
            // Anything wrong with the next frame is for the next read to report
            let Ok(Some((header, len))) = self.frame_header(end) else {
                break;
            };
            let next = end + header + len;
            if next > self.buf.len() || !self.peek_id(end, next).is_ok_and(&keep) {
                break;
            }
            end = next;
        }
        Ok(Frame::Raw(self.buf.split_to(end).freeze()))
    }

    /// Reads until a whole frame is buffered; the length of its length prefix and its own length
    async fn next_frame(&mut self) -> Result<(usize, usize), ProtocolError> {
        loop {
            if let Some((header, len)) = self.frame_header(0)? {
                if self.buf.len() >= header + len {
                    return Ok((header, len));
                }
                self.buf
                    .reserve((header + len - self.buf.len()).min(MAX_PREALLOC));
            }

            if self.buf.is_empty() && self.buf.capacity() > BUFFER_KEEP {
                self.buf = BytesMut::with_capacity(4096);
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

    /// The length prefix of the frame buffered from `at`: its own length and the frame's
    fn frame_header(&self, at: usize) -> Result<Option<(usize, usize)>, ProtocolError> {
        let mut cur = &self.buf[at..];
        let len = match cur.read_varint() {
            Ok(len) => len,
            Err(_) if self.buf.len() - at < 3 => return Ok(None),
            Err(e) => return Err(e),
        };
        let len = usize::try_from(len)
            .ok()
            .filter(|len| (1..=self.max_frame).contains(len))
            .ok_or_else(|| ProtocolError::Malformed(format!("invalid frame length {len}")))?;
        Ok(Some((self.buf.len() - at - cur.len(), len)))
    }

    /// The packet's announced length, 0 if it is not compressed, and where its data starts
    fn unwrap_frame(&self, frame: &[u8]) -> Result<(usize, usize), ProtocolError> {
        let Some(threshold) = self.compression else {
            return Ok((0, 0));
        };

        let mut cur = frame;
        let data_len = cur.read_varint()?;
        let at = frame.len() - cur.len();
        if data_len == 0 {
            return Ok((0, at));
        }

        let data_len = usize::try_from(data_len)
            .ok()
            .filter(|len| *len <= self.max_data)
            .ok_or_else(|| {
                ProtocolError::Malformed(format!("invalid uncompressed length {data_len}"))
            })?;
        if data_len < threshold {
            return Err(ProtocolError::Malformed(format!(
                "compressed packet of {data_len} bytes is below the threshold of {threshold}"
            )));
        }
        Ok((data_len, at))
    }

    fn decode_frame(&mut self, frame: Bytes) -> Result<RawPacket, ProtocolError> {
        let (data_len, at) = self.unwrap_frame(&frame)?;
        let body = frame.slice(at..);
        if data_len == 0 {
            return RawPacket::parse(body);
        }

        // One byte past the announced length is enough to tell it was wrong
        let limit = data_len + 1;
        let mut data = Vec::with_capacity(data_len.min(MAX_PREALLOC));
        with_inflater(|inflater| -> Result<(), ProtocolError> {
            loop {
                if data.len() == data.capacity() {
                    data.reserve_exact((limit - data.len()).min(MAX_PREALLOC));
                }
                let (read, written) = (inflater.total_in() as usize, data.len());
                let status = inflater
                    .decompress_vec(&body[read..], &mut data, FlushDecompress::None)
                    .map_err(|e| ProtocolError::Malformed(format!("invalid zlib data: {e}")))?;
                if status == Status::StreamEnd
                    || data.len() >= limit
                    || (inflater.total_in() as usize, data.len()) == (read, written)
                {
                    return Ok(());
                }
            }
        })?;
        if data.len() != data_len {
            return Err(ProtocolError::Malformed(format!(
                "decompressed {} bytes but the header announced {data_len}",
                data.len()
            )));
        }
        RawPacket::parse(data.into())
    }

    /// The id of the packet in the frame buffered from `start` to `end`
    fn peek_id(&mut self, start: usize, end: usize) -> Result<i32, ProtocolError> {
        let header = self.frame_header(start)?.map_or(0, |(header, _)| header);
        let (data_len, at) = self.unwrap_frame(&self.buf[start + header..end])?;
        let body = &self.buf[start + header + at..end];
        if data_len == 0 {
            return (&body[..]).read_varint();
        }

        let mut id = [0u8; 5];
        let want = id.len().min(data_len);
        with_inflater(|inflater| -> Result<(), ProtocolError> {
            loop {
                let (read, written) = (inflater.total_in(), inflater.total_out());
                let status = inflater
                    .decompress(
                        &body[read as usize..],
                        &mut id[written as usize..want],
                        FlushDecompress::None,
                    )
                    .map_err(|e| ProtocolError::Malformed(format!("invalid zlib data: {e}")))?;
                let done = inflater.total_out() as usize;
                if done == want {
                    return Ok(());
                }
                if status == Status::StreamEnd
                    || (inflater.total_in(), done as u64) == (read, written)
                {
                    return Err(ProtocolError::Malformed(format!(
                        "decompressed {done} bytes but the header announced {data_len}"
                    )));
                }
            }
        })?;
        (&id[..want]).read_varint()
    }

    pub fn compression(&self) -> Option<usize> {
        self.compression
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
    quiet: u8,
}

impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: writer,
            out: BytesMut::with_capacity(4096),
            compression: None,
            encryptor: None,
            quiet: 0,
        }
    }

    pub fn queue(&mut self, packet: &[u8]) -> Result<(), ProtocolError> {
        let start = self.out.len();
        match self.compression {
            Some((threshold, level)) if packet.len() >= threshold => {
                let data_len = packet.len() as i32;
                deflate(packet, level, |compressed| {
                    self.write_frame(varint_len(data_len) + compressed.len(), |out| {
                        out.write_varint(data_len);
                        out.extend_from_slice(compressed);
                    })
                })??;
            }
            Some(_) => {
                self.write_frame(1 + packet.len(), |out| {
                    out.write_varint(0);
                    out.extend_from_slice(packet);
                })?;
            }
            None => self.write_frame(packet.len(), |out| out.extend_from_slice(packet))?,
        }
        self.encrypt_from(start);
        Ok(())
    }

    /// Queues a frame read off a connection compressed the same way, as it is
    pub fn queue_frame(&mut self, frame: &[u8]) {
        let start = self.out.len();
        self.out.extend_from_slice(frame);
        self.encrypt_from(start);
    }

    fn encrypt_from(&mut self, start: usize) {
        if let Some(encryptor) = &mut self.encryptor {
            encryptor.encrypt(&mut self.out[start..]);
        }
    }

    fn write_frame(
        &mut self,
        len: usize,
        body: impl FnOnce(&mut BytesMut),
    ) -> Result<(), ProtocolError> {
        if len > MAX_FRAME_LEN {
            return Err(ProtocolError::Encode(format!(
                "packet of {len} bytes exceeds the maximum frame size"
            )));
        }
        self.out.reserve(3 + len);
        self.out.write_varint(len as i32);
        body(&mut self.out);
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), ProtocolError> {
        let (allocated, queued) = (self.out.capacity(), self.out.len());
        while !self.out.is_empty() {
            let n = self.inner.write(&self.out).await?;
            if n == 0 {
                return Err(ProtocolError::Io(std::io::ErrorKind::WriteZero.into()));
            }
            self.out.advance(n);
        }
        // Kept while big writes keep coming, so a busy connection doesn't allocate it every time
        if queued > BUFFER_KEEP {
            self.quiet = 0;
        } else if allocated > BUFFER_KEEP {
            self.quiet += 1;
            if self.quiet >= QUIET_WRITES {
                self.out = BytesMut::new();
                self.quiet = 0;
            }
        }
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn send(&mut self, packet: Bytes) -> Result<(), ProtocolError> {
        self.queue(&packet)?;
        self.flush().await
    }

    pub fn compression_threshold(&self) -> Option<usize> {
        self.compression.map(|(threshold, _)| threshold)
    }

    pub fn set_compression(&mut self, threshold: usize, level: i32) {
        let level = u32::try_from(level).map_or(Compression::default().level(), |l| l.min(9));
        self.compression = Some((threshold, level));
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
    async fn test_frames_passed_on_reach_an_encrypted_client() {
        let big: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let packets = vec![
            packet(0x00, b""),
            packet(0x2A, b"hello"),
            packet(300, &big),
            packet(0x07, &[1u8; 254]),
        ];
        let mut backend = PacketWriter::new(Vec::new());
        backend.set_compression(256, 1);
        for p in &packets {
            backend.queue(p).unwrap();
        }
        backend.flush().await.unwrap();
        let sent = backend.inner;

        let mut proxy = PacketReader::new(&sent[..]);
        proxy.set_compression(256);
        let mut client = PacketWriter::new(Vec::new());
        client.set_compression(256, 6);
        client.enable_encryption(&[9u8; 16]).unwrap();
        let mut raw = Vec::new();
        let mut pieces = 0;
        while raw.len() < sent.len() {
            pieces += 1;
            match proxy.read_frame(|id| id != 0x2A).await.unwrap() {
                Frame::Raw(frame) => {
                    raw.extend_from_slice(&frame);
                    client.queue_frame(&frame);
                }
                Frame::Packet(p) => {
                    assert_eq!(p.id, 0x2A);
                    raw.extend_from_slice(&sent[raw.len()..raw.len() + 8]);
                    client.queue(&p.to_bytes()).unwrap();
                }
            }
        }
        assert_eq!(raw, sent);
        // the two frames behind the decoded packet arrive as one piece
        assert_eq!(pieces, 3);

        let mut reader = PacketReader::new(&client.out[..]);
        reader.set_compression(256);
        reader.enable_encryption(&[9u8; 16]).unwrap();
        for p in &packets {
            assert_eq!(reader.read_packet().await.unwrap().to_bytes(), &p[..]);
        }

        let mut frame = Vec::new();
        frame.write_varint(MAX_PACKET_DATA_LEN as i32 + 1);
        frame.extend_from_slice(
            &flate2::write::ZlibEncoder::new(Vec::new(), Compression::fast())
                .finish()
                .unwrap(),
        );
        let mut data = Vec::new();
        data.write_varint(frame.len() as i32);
        data.extend_from_slice(&frame);
        let mut reader = PacketReader::new(&data[..]);
        reader.set_compression(256);
        assert!(reader.read_frame(|_| true).await.is_err());
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
    async fn test_announced_length_does_not_allocate_up_front() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut reader = PacketReader::new(client);
        let mut header = Vec::new();
        header.write_varint(MAX_FRAME_LEN as i32);
        server.write_all(&header).await.unwrap();
        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(20), reader.read_packet()).await;
        assert!(pending.is_err());
        assert!(reader.buf.capacity() <= 2 * MAX_PREALLOC);

        let mut reader = PacketReader::new(&header[..]);
        reader.set_limits(8192, 8192);
        assert!(matches!(
            reader.read_packet().await,
            Err(ProtocolError::Malformed(_))
        ));
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
