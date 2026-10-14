use pumpkin_util::text::TextComponent;
use pumpkin_util::version::JavaMinecraftVersion;
use serde_json::{Map, Value};

use super::wire::{ReadExt, WriteExt};
use super::{ProtocolError, ProtocolVersion};

const MAX_JSON_LEN: usize = 262_144;
const MAX_NBT_DEPTH: usize = 512;

const TAG_END: u8 = 0;
const TAG_BYTE: u8 = 1;
const TAG_SHORT: u8 = 2;
const TAG_INT: u8 = 3;
const TAG_LONG: u8 = 4;
const TAG_FLOAT: u8 = 5;
const TAG_DOUBLE: u8 = 6;
const TAG_BYTE_ARRAY: u8 = 7;
const TAG_STRING: u8 = 8;
const TAG_LIST: u8 = 9;
const TAG_COMPOUND: u8 = 10;
const TAG_INT_ARRAY: u8 = 11;
const TAG_LONG_ARRAY: u8 = 12;

pub fn component_json(component: &TextComponent, version: ProtocolVersion) -> Value {
    component.to_json_value_for_version(&JavaMinecraftVersion::from_protocol(version.0))
}

pub fn write_component(buf: &mut Vec<u8>, component: &Value, version: ProtocolVersion) {
    if version < ProtocolVersion::V1_20_3 {
        buf.write_string(&component.to_string());
    } else {
        write_nbt_root(buf, component);
    }
}

pub fn read_component(buf: &mut &[u8], version: ProtocolVersion) -> Result<Value, ProtocolError> {
    if version < ProtocolVersion::V1_20_3 {
        let raw = buf.read_string_bounded(MAX_JSON_LEN)?;
        Ok(serde_json::from_str(&raw).unwrap_or(Value::String(raw)))
    } else {
        read_nbt_root(buf)
    }
}

pub fn plain_text(component: &Value) -> String {
    let mut out = String::new();
    append_plain(component, &mut out);
    out
}

fn append_plain(component: &Value, out: &mut String) {
    match component {
        Value::String(s) => out.push_str(s),
        Value::Array(parts) => parts.iter().for_each(|p| append_plain(p, out)),
        Value::Object(map) => {
            if let Some(text) = map.get("text").and_then(Value::as_str) {
                out.push_str(text);
            } else if let Some(key) = map.get("translate").and_then(Value::as_str) {
                out.push_str(key);
                if let Some(Value::Array(args)) = map.get("with") {
                    let args: Vec<String> = args.iter().map(plain_text).collect();
                    out.push_str(&format!(" [{}]", args.join(", ")));
                }
            }
            if let Some(extra) = map.get("extra") {
                append_plain(extra, out);
            }
        }
        other => out.push_str(&other.to_string()),
    }
}

fn write_nbt_root(buf: &mut Vec<u8>, value: &Value) {
    let tag = tag_type(value);
    buf.push(tag);
    write_nbt_payload(buf, tag, value);
}

fn tag_type(value: &Value) -> u8 {
    match value {
        Value::Null | Value::Object(_) => TAG_COMPOUND,
        Value::Bool(_) => TAG_BYTE,
        Value::Number(n) if n.is_i64() || n.is_u64() => match n.as_i64() {
            Some(v) if i32::try_from(v).is_ok() => TAG_INT,
            _ => TAG_LONG,
        },
        Value::Number(_) => TAG_DOUBLE,
        Value::String(_) => TAG_STRING,
        Value::Array(_) => TAG_LIST,
    }
}

fn write_nbt_payload(buf: &mut Vec<u8>, tag: u8, value: &Value) {
    match value {
        Value::Null => buf.push(TAG_END),
        Value::Bool(b) => buf.push(u8::from(*b)),
        Value::Number(n) => match tag {
            TAG_INT => buf.write_i32(n.as_i64().unwrap_or_default() as i32),
            TAG_LONG => buf.write_i64(n.as_i64().unwrap_or(i64::MAX)),
            _ => buf.extend_from_slice(&n.as_f64().unwrap_or_default().to_be_bytes()),
        },
        Value::String(s) => write_nbt_string(buf, s),
        Value::Object(map) => {
            for (key, value) in map {
                let tag = tag_type(value);
                buf.push(tag);
                write_nbt_string(buf, key);
                write_nbt_payload(buf, tag, value);
            }
            buf.push(TAG_END);
        }
        Value::Array(items) => {
            let first = items.first().map(tag_type).unwrap_or(TAG_END);
            if items.iter().all(|item| tag_type(item) == first) {
                buf.push(first);
                buf.write_i32(items.len() as i32);
                for item in items {
                    write_nbt_payload(buf, first, item);
                }
            } else {
                // Heterogeneous lists are stored as compounds keyed by "", like vanilla does
                buf.push(TAG_COMPOUND);
                buf.write_i32(items.len() as i32);
                for item in items {
                    if item.is_object() {
                        write_nbt_payload(buf, TAG_COMPOUND, item);
                    } else {
                        let mut wrapper = Map::new();
                        wrapper.insert(String::new(), item.clone());
                        write_nbt_payload(buf, TAG_COMPOUND, &Value::Object(wrapper));
                    }
                }
            }
        }
    }
}

fn write_nbt_string(buf: &mut Vec<u8>, s: &str) {
    let encoded = encode_modified_utf8(s);
    buf.write_u16(encoded.len().min(u16::MAX as usize) as u16);
    buf.extend_from_slice(&encoded[..encoded.len().min(u16::MAX as usize)]);
}

fn read_nbt_root(buf: &mut &[u8]) -> Result<Value, ProtocolError> {
    let tag = buf.read_u8()?;
    if tag == TAG_END {
        return Ok(Value::Null);
    }
    read_nbt_payload(buf, tag, 0)
}

fn read_len(buf: &mut &[u8]) -> Result<usize, ProtocolError> {
    let len = buf.read_i32()?;
    let len = usize::try_from(len)
        .map_err(|_| ProtocolError::Malformed(format!("negative NBT length {len}")))?;
    if len > buf.len() {
        return Err(ProtocolError::Malformed("NBT length exceeds packet".into()));
    }
    Ok(len)
}

fn read_nbt_payload(buf: &mut &[u8], tag: u8, depth: usize) -> Result<Value, ProtocolError> {
    if depth > MAX_NBT_DEPTH {
        return Err(ProtocolError::Malformed("NBT nested too deeply".into()));
    }
    Ok(match tag {
        TAG_BYTE => match buf.read_u8()? as i8 {
            0 => Value::Bool(false),
            1 => Value::Bool(true),
            v => Value::from(v),
        },
        TAG_SHORT => Value::from(buf.read_i16()?),
        TAG_INT => Value::from(buf.read_i32()?),
        TAG_LONG => Value::from(buf.read_i64()?),
        TAG_FLOAT => Value::from(f32::from_bits(buf.read_i32()? as u32)),
        TAG_DOUBLE => Value::from(f64::from_bits(buf.read_i64()? as u64)),
        TAG_BYTE_ARRAY => {
            let len = read_len(buf)?;
            Value::Array(
                buf.read_bytes(len)?
                    .iter()
                    .map(|b| Value::from(*b as i8))
                    .collect(),
            )
        }
        TAG_STRING => {
            let len = buf.read_u16()? as usize;
            Value::String(decode_modified_utf8(buf.read_bytes(len)?)?)
        }
        TAG_LIST => {
            let item_tag = buf.read_u8()?;
            let len = read_len(buf)?;
            let mut items = Vec::with_capacity(len.min(1024));
            for _ in 0..len {
                let item = read_nbt_payload(buf, item_tag, depth + 1)?;
                items.push(match item {
                    Value::Object(mut map) if map.len() == 1 && map.contains_key("") => {
                        map.remove("").unwrap_or_default()
                    }
                    other => other,
                });
            }
            Value::Array(items)
        }
        TAG_COMPOUND => {
            let mut map = Map::new();
            loop {
                let field_tag = buf.read_u8()?;
                if field_tag == TAG_END {
                    break;
                }
                let len = buf.read_u16()? as usize;
                let key = decode_modified_utf8(buf.read_bytes(len)?)?;
                map.insert(key, read_nbt_payload(buf, field_tag, depth + 1)?);
            }
            Value::Object(map)
        }
        TAG_INT_ARRAY => {
            let len = read_len(buf)?;
            (0..len)
                .map(|_| buf.read_i32().map(Value::from))
                .collect::<Result<_, _>>()?
        }
        TAG_LONG_ARRAY => {
            let len = read_len(buf)?;
            (0..len)
                .map(|_| buf.read_i64().map(Value::from))
                .collect::<Result<_, _>>()?
        }
        other => return Err(ProtocolError::Malformed(format!("unknown NBT tag {other}"))),
    })
}

// Java's "modified UTF-8": NUL is two bytes and supplementary characters are surrogate pairs
fn encode_modified_utf8(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for unit in s.encode_utf16() {
        match unit {
            0x0001..=0x007F => out.push(unit as u8),
            0x0000 | 0x0080..=0x07FF => {
                out.push(0xC0 | (unit >> 6) as u8);
                out.push(0x80 | (unit & 0x3F) as u8);
            }
            _ => {
                out.push(0xE0 | (unit >> 12) as u8);
                out.push(0x80 | ((unit >> 6) & 0x3F) as u8);
                out.push(0x80 | (unit & 0x3F) as u8);
            }
        }
    }
    out
}

fn decode_modified_utf8(bytes: &[u8]) -> Result<String, ProtocolError> {
    let invalid = || ProtocolError::Malformed("invalid modified UTF-8 string".into());
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let (unit, width) = if b & 0x80 == 0 {
            (u16::from(b), 1)
        } else if b & 0xE0 == 0xC0 {
            let b2 = *bytes.get(i + 1).ok_or_else(invalid)?;
            ((u16::from(b & 0x1F) << 6) | u16::from(b2 & 0x3F), 2)
        } else if b & 0xF0 == 0xE0 {
            let b2 = *bytes.get(i + 1).ok_or_else(invalid)?;
            let b3 = *bytes.get(i + 2).ok_or_else(invalid)?;
            (
                (u16::from(b & 0x0F) << 12) | (u16::from(b2 & 0x3F) << 6) | u16::from(b3 & 0x3F),
                3,
            )
        } else {
            return Err(invalid());
        };
        units.push(unit);
        i += width;
    }
    Ok(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pumpkin_util::text::color::NamedColor;
    use serde_json::json;

    #[test]
    fn test_json_components_before_1_20_3() {
        let version = ProtocolVersion(764);
        let component = json!({"text": "hi", "color": "red"});
        let mut buf = Vec::new();
        write_component(&mut buf, &component, version);

        let mut cur = &buf[..];
        let raw = cur.read_string().unwrap();
        assert_eq!(serde_json::from_str::<Value>(&raw).unwrap(), component);

        let mut cur = &buf[..];
        assert_eq!(read_component(&mut cur, version).unwrap(), component);
    }

    #[test]
    fn test_nbt_round_trip() {
        let version = ProtocolVersion::V1_20_3;
        let component = json!({
            "text": "a\u{0}b ünï 😀",
            "bold": true,
            "extra": ["plain", {"text": "x", "italic": false}],
            "with": [1, 2],
        });
        let mut buf = Vec::new();
        write_component(&mut buf, &component, version);
        assert_eq!(buf[0], TAG_COMPOUND);

        let mut cur = &buf[..];
        assert_eq!(read_component(&mut cur, version).unwrap(), component);
        assert!(cur.is_empty());
    }

    #[test]
    fn test_modified_utf8_matches_java() {
        assert_eq!(encode_modified_utf8("\u{0}"), [0xC0, 0x80]);
        assert_eq!(
            encode_modified_utf8("😀"),
            [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]
        );
        assert_eq!(
            decode_modified_utf8(&[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]).unwrap(),
            "😀"
        );
    }

    #[test]
    fn test_nbt_rejects_garbage() {
        let mut cur: &[u8] = &[TAG_LIST, TAG_INT, 0x7F, 0xFF, 0xFF, 0xFF];
        assert!(read_component(&mut cur, ProtocolVersion::V1_20_3).is_err());
        let mut cur: &[u8] = &[42];
        assert!(read_component(&mut cur, ProtocolVersion::V1_20_3).is_err());
    }

    #[test]
    fn test_plain_text_and_component_json() {
        let component = TextComponent::text("Kicked").color_named(NamedColor::Red);
        let value = component_json(&component, ProtocolVersion(769));
        assert_eq!(value["text"], "Kicked");
        assert_eq!(plain_text(&value), "Kicked");

        let translated = json!({"translate": "multiplayer.disconnect.kicked", "extra": [" now"]});
        assert_eq!(plain_text(&translated), "multiplayer.disconnect.kicked now");
    }
}
