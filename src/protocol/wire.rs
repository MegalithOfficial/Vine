use uuid::Uuid;

use super::ProtocolError;

pub const MAX_STRING_LEN: usize = 32767;

const SEGMENT_BITS: u32 = 0x7F;
const CONTINUE_BIT: u8 = 0x80;

fn eof(what: &str) -> ProtocolError {
    ProtocolError::Malformed(format!("unexpected end of packet while reading {what}"))
}

pub fn varint_len(value: i32) -> usize {
    let value = value as u32;
    match value {
        0..=0x7F => 1,
        0x80..=0x3FFF => 2,
        0x4000..=0x1F_FFFF => 3,
        0x20_0000..=0x0FFF_FFFF => 4,
        _ => 5,
    }
}

pub trait ReadExt {
    fn read_u8(&mut self) -> Result<u8, ProtocolError>;
    fn read_bytes(&mut self, len: usize) -> Result<&[u8], ProtocolError>;

    fn read_bool(&mut self) -> Result<bool, ProtocolError> {
        Ok(self.read_u8()? != 0)
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_i16(&mut self) -> Result<i16, ProtocolError> {
        Ok(self.read_u16()? as i16)
    }

    fn read_i32(&mut self) -> Result<i32, ProtocolError> {
        let bytes = self.read_bytes(4)?;
        Ok(i32::from_be_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn read_i64(&mut self) -> Result<i64, ProtocolError> {
        let bytes = self.read_bytes(8)?;
        Ok(i64::from_be_bytes(
            bytes.try_into().expect("length checked"),
        ))
    }

    fn read_varint(&mut self) -> Result<i32, ProtocolError> {
        let mut value: u32 = 0;
        for i in 0..5 {
            let byte = self.read_u8().map_err(|_| eof("VarInt"))?;
            value |= (u32::from(byte) & SEGMENT_BITS) << (7 * i);
            if byte & CONTINUE_BIT == 0 {
                return Ok(value as i32);
            }
        }
        Err(ProtocolError::Malformed("VarInt is too long".into()))
    }

    fn read_uuid(&mut self) -> Result<Uuid, ProtocolError> {
        let bytes = self.read_bytes(16)?;
        Ok(Uuid::from_bytes(bytes.try_into().expect("length checked")))
    }

    fn read_string_bounded(&mut self, max_len: usize) -> Result<String, ProtocolError> {
        let len = self.read_varint()?;
        let len = usize::try_from(len)
            .map_err(|_| ProtocolError::Malformed("negative string length".into()))?;
        if len > max_len * 3 {
            return Err(ProtocolError::Malformed(format!(
                "string of {len} bytes exceeds the limit of {max_len} characters"
            )));
        }
        let bytes = self.read_bytes(len)?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ProtocolError::Malformed("string is not valid UTF-8".into()))?;
        if text.encode_utf16().count() > max_len {
            return Err(ProtocolError::Malformed(format!(
                "string exceeds the limit of {max_len} characters"
            )));
        }
        Ok(text.to_owned())
    }

    fn read_string(&mut self) -> Result<String, ProtocolError> {
        self.read_string_bounded(MAX_STRING_LEN)
    }

    fn read_byte_array(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let len = self.read_varint()?;
        let len = usize::try_from(len)
            .map_err(|_| ProtocolError::Malformed("negative byte array length".into()))?;
        Ok(self.read_bytes(len)?.to_vec())
    }

    // 1.7 login packets
    fn read_short_byte_array(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let len = self.read_i16()?;
        let len = usize::try_from(len)
            .map_err(|_| ProtocolError::Malformed("negative byte array length".into()))?;
        Ok(self.read_bytes(len)?.to_vec())
    }
}

impl ReadExt for &[u8] {
    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        let (&byte, rest) = self.split_first().ok_or_else(|| eof("byte"))?;
        *self = rest;
        Ok(byte)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&[u8], ProtocolError> {
        if self.len() < len {
            return Err(eof(&format!("{len} bytes")));
        }
        let (head, rest) = self.split_at(len);
        *self = rest;
        Ok(head)
    }
}

pub trait WriteExt {
    fn write_u8(&mut self, value: u8);
    fn write_slice(&mut self, bytes: &[u8]);

    fn write_bool(&mut self, value: bool) {
        self.write_u8(u8::from(value));
    }

    fn write_u16(&mut self, value: u16) {
        self.write_slice(&value.to_be_bytes());
    }

    fn write_i16(&mut self, value: i16) {
        self.write_slice(&value.to_be_bytes());
    }

    fn write_i32(&mut self, value: i32) {
        self.write_slice(&value.to_be_bytes());
    }

    fn write_i64(&mut self, value: i64) {
        self.write_slice(&value.to_be_bytes());
    }

    fn write_varint(&mut self, value: i32) {
        let mut value = value as u32;
        loop {
            if value & !SEGMENT_BITS == 0 {
                self.write_u8(value as u8);
                return;
            }
            self.write_u8((value & SEGMENT_BITS) as u8 | CONTINUE_BIT);
            value >>= 7;
        }
    }

    fn write_uuid(&mut self, value: &Uuid) {
        self.write_slice(value.as_bytes());
    }

    fn write_string(&mut self, value: &str) {
        self.write_varint(value.len() as i32);
        self.write_slice(value.as_bytes());
    }

    fn write_byte_array(&mut self, value: &[u8]) {
        self.write_varint(value.len() as i32);
        self.write_slice(value);
    }

    fn write_short_byte_array(&mut self, value: &[u8]) {
        self.write_i16(value.len() as i16);
        self.write_slice(value);
    }
}

impl WriteExt for Vec<u8> {
    fn write_u8(&mut self, value: u8) {
        self.push(value);
    }

    fn write_slice(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_round_trip() {
        for value in [
            0,
            1,
            127,
            128,
            255,
            25565,
            2_097_151,
            i32::MAX,
            -1,
            i32::MIN,
        ] {
            let mut buf = Vec::new();
            buf.write_varint(value);
            assert_eq!(buf.len(), varint_len(value), "length of {value}");
            let mut cur = &buf[..];
            assert_eq!(cur.read_varint().unwrap(), value);
            assert!(cur.is_empty());
        }
    }

    #[test]
    fn test_varint_known_encodings() {
        let mut buf = Vec::new();
        buf.write_varint(300);
        assert_eq!(buf, [0xAC, 0x02]);

        let mut buf = Vec::new();
        buf.write_varint(-1);
        assert_eq!(buf, [0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
    }

    #[test]
    fn test_varint_rejects_overlong_encoding() {
        let mut cur: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        assert!(cur.read_varint().is_err());
    }

    #[test]
    fn test_string_round_trip_and_limits() {
        let mut buf = Vec::new();
        buf.write_string("héllo");
        let mut cur = &buf[..];
        assert_eq!(cur.read_string().unwrap(), "héllo");

        let mut cur = &buf[..];
        assert!(cur.read_string_bounded(3).is_err());

        let mut truncated: &[u8] = &[5, b'a', b'b'];
        assert!(truncated.read_string().is_err());
    }
}
