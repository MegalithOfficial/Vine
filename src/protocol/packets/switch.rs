use std::collections::HashSet;

use bytes::Bytes;
use uuid::Uuid;

use super::PacketKind;
use crate::protocol::text::skip_named_nbt;
use crate::protocol::wire::{ReadExt, WriteExt};
use crate::protocol::{ProtocolError, ProtocolVersion, RawPacket};

const V1_9_1: ProtocolVersion = ProtocolVersion(108);
const V1_11: ProtocolVersion = ProtocolVersion(315);
const V1_14: ProtocolVersion = ProtocolVersion(477);
const V1_15: ProtocolVersion = ProtocolVersion(573);
const V1_16_2: ProtocolVersion = ProtocolVersion(751);
const V1_17: ProtocolVersion = ProtocolVersion(755);
const V1_18: ProtocolVersion = ProtocolVersion(757);
const V1_20: ProtocolVersion = ProtocolVersion(763);

const HARDCORE_BIT: u8 = 0x08;
const DIMENSION_OFFSET: usize = 5;

pub fn join_game_sequence(
    join_game: &RawPacket,
    version: ProtocolVersion,
) -> Result<Vec<Bytes>, ProtocolError> {
    let respawn_id = PacketKind::Respawn
        .id(version)
        .ok_or(ProtocolError::UnsupportedPacket(
            PacketKind::Respawn,
            version,
        ))?;
    let respawn = RawPacket {
        id: respawn_id,
        payload: respawn_from_join_game(&join_game.payload, version)?.into(),
    };
    if version >= ProtocolVersion::V1_16 {
        return Ok(vec![join_game.to_bytes(), respawn.to_bytes()]);
    }
    // Older clients ignore a respawn into the dimension they are already in
    let join_game = RawPacket {
        id: join_game.id,
        payload: with_other_dimension(&join_game.payload, version)?.into(),
    };
    Ok(vec![join_game.to_bytes(), respawn.to_bytes()])
}

fn with_other_dimension(
    payload: &[u8],
    version: ProtocolVersion,
) -> Result<Vec<u8>, ProtocolError> {
    let mut out = payload.to_vec();
    if version >= V1_9_1 {
        let field = out
            .get_mut(DIMENSION_OFFSET..DIMENSION_OFFSET + 4)
            .ok_or_else(|| ProtocolError::Malformed("JoinGame too short".into()))?;
        let dimension = i32::from_be_bytes([field[0], field[1], field[2], field[3]]);
        field.copy_from_slice(&if dimension == 0 { -1i32 } else { 0 }.to_be_bytes());
    } else {
        let field = out
            .get_mut(DIMENSION_OFFSET)
            .ok_or_else(|| ProtocolError::Malformed("JoinGame too short".into()))?;
        *field = if *field == 0 { 0xff } else { 0 };
    }
    Ok(out)
}

fn respawn_from_join_game(
    payload: &[u8],
    version: ProtocolVersion,
) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = payload;
    let mut out = Vec::new();
    buf.read_i32()?;
    if version >= V1_16_2 {
        buf.read_bool()?;
    }
    let mut gamemode = buf.read_u8()?;
    if version < V1_16_2 {
        gamemode &= !HARDCORE_BIT;
    }

    if version < ProtocolVersion::V1_16 {
        let dimension = if version >= V1_9_1 {
            buf.read_i32()?
        } else {
            i32::from(buf.read_u8()? as i8)
        };
        let difficulty = if version < V1_14 {
            Some(buf.read_u8()?)
        } else {
            None
        };
        let hashed_seed = if version >= V1_15 {
            Some(buf.read_i64()?)
        } else {
            None
        };
        buf.read_u8()?;
        let level_type = buf.read_string_bounded(16)?;

        out.write_i32(dimension);
        if let Some(difficulty) = difficulty {
            out.write_u8(difficulty);
        }
        if let Some(seed) = hashed_seed {
            out.write_i64(seed);
        }
        out.write_u8(gamemode);
        out.write_string(&level_type);
        return Ok(out);
    }

    let previous_gamemode = buf.read_u8()?;
    for _ in 0..buf.read_varint()? {
        buf.read_string()?;
    }
    skip_named_nbt(&mut buf)?;
    if (V1_16_2..ProtocolVersion::V1_19).contains(&version) {
        let start = buf;
        skip_named_nbt(&mut buf)?;
        out.extend_from_slice(&start[..start.len() - buf.len()]);
    } else {
        out.write_string(&buf.read_string()?);
    }
    out.write_string(&buf.read_string()?);
    out.write_i64(buf.read_i64()?);
    out.write_u8(gamemode);
    out.write_u8(previous_gamemode);

    if version < V1_16_2 {
        buf.read_u8()?;
    } else {
        buf.read_varint()?;
    }
    buf.read_varint()?;
    if version >= V1_18 {
        buf.read_varint()?;
    }
    buf.read_bool()?;
    buf.read_bool()?;
    out.write_bool(buf.read_bool()?);
    out.write_bool(buf.read_bool()?);
    out.write_bool(false);

    if version >= ProtocolVersion::V1_19 {
        let start = buf;
        if buf.read_bool()? {
            buf.read_string()?;
            buf.read_i64()?;
        }
        out.extend_from_slice(&start[..start.len() - buf.len()]);
    }
    if version >= V1_20 {
        out.write_varint(buf.read_varint()?);
    }
    Ok(out)
}

// Before 1.20.2 the client keeps tab list entries and boss bars across a JoinGame
#[derive(Debug, Default)]
pub struct Leftovers {
    players: HashSet<Uuid>,
    legacy_players: HashSet<String>,
    boss_bars: HashSet<Uuid>,
}

impl Leftovers {
    pub fn observe(&mut self, packet: &RawPacket, version: ProtocolVersion) {
        let mut buf = &packet.payload[..];
        let _ = if PacketKind::PlayerInfo.matches(packet.id, version) {
            self.observe_player_info(&mut buf, version)
        } else if PacketKind::PlayerInfoRemove.matches(packet.id, version) {
            read_uuids(&mut buf).map(|uuids| {
                for uuid in uuids {
                    self.players.remove(&uuid);
                }
            })
        } else if PacketKind::BossBar.matches(packet.id, version) {
            self.observe_boss_bar(&mut buf)
        } else {
            Ok(())
        };
    }

    fn observe_player_info(
        &mut self,
        buf: &mut &[u8],
        version: ProtocolVersion,
    ) -> Result<(), ProtocolError> {
        if version < ProtocolVersion::V1_8 {
            let name = buf.read_string()?;
            if buf.read_bool()? {
                self.legacy_players.insert(name);
            } else {
                self.legacy_players.remove(&name);
            }
            return Ok(());
        }
        if version >= ProtocolVersion::V1_19_3 {
            let actions = buf.read_u8()?;
            if actions & 0x01 == 0 {
                return Ok(());
            }
            for _ in 0..buf.read_varint()? {
                self.players.insert(buf.read_uuid()?);
                skip_player_update(buf, actions)?;
            }
            return Ok(());
        }
        let action = buf.read_varint()?;
        for _ in 0..buf.read_varint()? {
            let uuid = buf.read_uuid()?;
            match action {
                0 => {
                    self.players.insert(uuid);
                    skip_player_add(buf, version)?;
                }
                1 | 2 => {
                    buf.read_varint()?;
                }
                3 => {
                    if buf.read_bool()? {
                        buf.read_string()?;
                    }
                }
                4 => {
                    self.players.remove(&uuid);
                }
                _ => {
                    return Err(ProtocolError::Malformed(format!(
                        "player info action {action}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn observe_boss_bar(&mut self, buf: &mut &[u8]) -> Result<(), ProtocolError> {
        let uuid = buf.read_uuid()?;
        match buf.read_varint()? {
            0 => {
                self.boss_bars.insert(uuid);
            }
            1 => {
                self.boss_bars.remove(&uuid);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn clear_players(&mut self, version: ProtocolVersion) -> Vec<Bytes> {
        let mut packets = Vec::new();
        let Some(info_id) = PacketKind::PlayerInfo.id(version) else {
            return packets;
        };
        for name in self.legacy_players.drain() {
            let mut payload = Vec::new();
            payload.write_string(&name);
            payload.write_bool(false);
            payload.write_i16(0);
            packets.push(raw(info_id, payload));
        }
        if self.players.is_empty() {
            return packets;
        }
        let mut payload = Vec::new();
        let id = if version >= ProtocolVersion::V1_19_3 {
            PacketKind::PlayerInfoRemove.id(version)
        } else {
            payload.write_varint(4);
            Some(info_id)
        };
        payload.write_varint(self.players.len() as i32);
        for uuid in self.players.drain() {
            payload.write_uuid(&uuid);
        }
        packets.extend(id.map(|id| raw(id, payload)));
        packets
    }

    pub fn clear_overlays(&mut self, version: ProtocolVersion) -> Vec<Bytes> {
        let mut packets = Vec::new();
        if let Some(id) = PacketKind::BossBar.id(version) {
            for uuid in self.boss_bars.drain() {
                let mut payload = Vec::new();
                payload.write_uuid(&uuid);
                payload.write_varint(1);
                packets.push(raw(id, payload));
            }
        }
        if version >= V1_17 {
            if let Some(id) = PacketKind::ClearTitles.id(version) {
                packets.push(raw(id, vec![1]));
            }
        } else if let Some(id) = PacketKind::Title.id(version) {
            let mut payload = Vec::new();
            payload.write_varint(if version < V1_11 { 4 } else { 5 });
            packets.push(raw(id, payload));
        }
        packets
    }
}

fn raw(id: i32, payload: Vec<u8>) -> Bytes {
    RawPacket {
        id,
        payload: payload.into(),
    }
    .to_bytes()
}

fn read_uuids(buf: &mut &[u8]) -> Result<Vec<Uuid>, ProtocolError> {
    (0..buf.read_varint()?).map(|_| buf.read_uuid()).collect()
}

fn skip_properties(buf: &mut &[u8]) -> Result<(), ProtocolError> {
    for _ in 0..buf.read_varint()? {
        buf.read_string()?;
        buf.read_string()?;
        if buf.read_bool()? {
            buf.read_string()?;
        }
    }
    Ok(())
}

fn skip_player_add(buf: &mut &[u8], version: ProtocolVersion) -> Result<(), ProtocolError> {
    buf.read_string()?;
    skip_properties(buf)?;
    buf.read_varint()?;
    buf.read_varint()?;
    if buf.read_bool()? {
        buf.read_string()?;
    }
    if version >= ProtocolVersion::V1_19 && buf.read_bool()? {
        buf.read_i64()?;
        buf.read_byte_array()?;
        buf.read_byte_array()?;
    }
    Ok(())
}

fn skip_player_update(buf: &mut &[u8], actions: u8) -> Result<(), ProtocolError> {
    if actions & 0x01 != 0 {
        buf.read_string()?;
        skip_properties(buf)?;
    }
    if actions & 0x02 != 0 && buf.read_bool()? {
        buf.read_uuid()?;
        buf.read_i64()?;
        buf.read_byte_array()?;
        buf.read_byte_array()?;
    }
    if actions & 0x04 != 0 {
        buf.read_varint()?;
    }
    if actions & 0x08 != 0 {
        buf.read_bool()?;
    }
    if actions & 0x10 != 0 {
        buf.read_varint()?;
    }
    if actions & 0x20 != 0 && buf.read_bool()? {
        buf.read_string()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_nbt(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[10, 0, 0, 0]);
    }

    fn packet(kind: PacketKind, version: ProtocolVersion, payload: Vec<u8>) -> RawPacket {
        RawPacket {
            id: kind.id(version).unwrap(),
            payload: payload.into(),
        }
    }

    #[test]
    fn test_legacy_join_game_flips_dimension_and_respawns() {
        let version = ProtocolVersion(340);
        let mut join = Vec::new();
        join.write_i32(7);
        join.write_u8(1 | HARDCORE_BIT);
        join.write_i32(0);
        join.write_u8(2);
        join.write_u8(20);
        join.write_string("flat");
        join.write_bool(false);

        let flipped = with_other_dimension(&join, version).unwrap();
        assert_eq!(&flipped[5..9], &(-1i32).to_be_bytes());

        let mut expected = Vec::new();
        expected.write_i32(0);
        expected.write_u8(2);
        expected.write_u8(1);
        expected.write_string("flat");
        assert_eq!(respawn_from_join_game(&join, version).unwrap(), expected);

        let mut old = join.clone();
        old.splice(5..9, [0xff]);
        let flipped = with_other_dimension(&old, ProtocolVersion::V1_8).unwrap();
        assert_eq!(flipped[5], 0);
    }

    #[test]
    fn test_respawn_copies_dimension_nbt_before_1_19() {
        let version = ProtocolVersion(754);
        let mut join = Vec::new();
        join.write_i32(7);
        join.write_bool(false);
        join.write_u8(0);
        join.write_u8(0xff);
        join.write_varint(1);
        join.write_string("minecraft:overworld");
        empty_nbt(&mut join);
        join.extend_from_slice(&[10, 0, 1, b'd', 1, 0, 1, b'x', 5, 0]);
        join.write_string("minecraft:overworld");
        join.write_i64(42);
        join.write_varint(20);
        join.write_varint(10);
        join.write_bool(false);
        join.write_bool(true);
        join.write_bool(false);
        join.write_bool(true);

        let mut expected = vec![10, 0, 1, b'd', 1, 0, 1, b'x', 5, 0];
        expected.write_string("minecraft:overworld");
        expected.write_i64(42);
        expected.write_u8(0);
        expected.write_u8(0xff);
        expected.write_bool(false);
        expected.write_bool(true);
        expected.write_bool(false);
        assert_eq!(respawn_from_join_game(&join, version).unwrap(), expected);
    }

    #[test]
    fn test_respawn_keeps_death_location_and_portal_cooldown() {
        let version = V1_20;
        let mut join = Vec::new();
        join.write_i32(7);
        join.write_bool(false);
        join.write_u8(1);
        join.write_u8(0xff);
        join.write_varint(0);
        empty_nbt(&mut join);
        join.write_string("minecraft:the_nether");
        join.write_string("minecraft:the_nether");
        join.write_i64(-5);
        join.write_varint(20);
        join.write_varint(10);
        join.write_varint(10);
        join.write_bool(false);
        join.write_bool(true);
        join.write_bool(false);
        join.write_bool(false);
        join.write_bool(true);
        join.write_string("minecraft:overworld");
        join.write_i64(99);
        join.write_varint(3);

        let mut expected = Vec::new();
        expected.write_string("minecraft:the_nether");
        expected.write_string("minecraft:the_nether");
        expected.write_i64(-5);
        expected.write_u8(1);
        expected.write_u8(0xff);
        expected.write_bool(false);
        expected.write_bool(false);
        expected.write_bool(false);
        expected.write_bool(true);
        expected.write_string("minecraft:overworld");
        expected.write_i64(99);
        expected.write_varint(3);
        assert_eq!(respawn_from_join_game(&join, version).unwrap(), expected);
    }

    #[test]
    fn test_leftovers_are_cleared_for_the_next_backend() {
        let version = ProtocolVersion(340);
        let (alex, steve, bar) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let mut leftovers = Leftovers::default();

        let mut add = Vec::new();
        add.write_varint(0);
        add.write_varint(2);
        for (uuid, name) in [(alex, "Alex"), (steve, "Steve")] {
            add.write_uuid(&uuid);
            add.write_string(name);
            add.write_varint(0);
            add.write_varint(0);
            add.write_varint(5);
            add.write_bool(false);
        }
        leftovers.observe(&packet(PacketKind::PlayerInfo, version, add), version);
        let mut remove = Vec::new();
        remove.write_varint(4);
        remove.write_varint(1);
        remove.write_uuid(&steve);
        leftovers.observe(&packet(PacketKind::PlayerInfo, version, remove), version);
        let mut boss = Vec::new();
        boss.write_uuid(&bar);
        boss.write_varint(0);
        leftovers.observe(&packet(PacketKind::BossBar, version, boss), version);

        let mut expected = Vec::new();
        expected.write_varint(PacketKind::PlayerInfo.id(version).unwrap());
        expected.write_varint(4);
        expected.write_varint(1);
        expected.write_uuid(&alex);
        assert_eq!(
            leftovers.clear_players(version),
            vec![Bytes::from(expected)]
        );

        let overlays = leftovers.clear_overlays(version);
        assert_eq!(overlays.len(), 2);
        assert!(overlays[0].ends_with(&[1]));
        assert_eq!(overlays[1].last(), Some(&5));

        assert!(leftovers.clear_players(version).is_empty());
        assert_eq!(leftovers.clear_overlays(version).len(), 1);
    }

    #[test]
    fn test_player_info_update_and_remove_from_1_19_3() {
        let version = ProtocolVersion::V1_19_3;
        let uuid = Uuid::from_u128(1);
        let mut leftovers = Leftovers::default();

        let mut update = vec![0x01 | 0x10];
        update.write_varint(1);
        update.write_uuid(&uuid);
        update.write_string("Alex");
        update.write_varint(0);
        update.write_varint(30);
        leftovers.observe(&packet(PacketKind::PlayerInfo, version, update), version);
        assert!(leftovers.players.contains(&uuid));

        let mut remove = Vec::new();
        remove.write_varint(1);
        remove.write_uuid(&uuid);
        leftovers.observe(
            &packet(PacketKind::PlayerInfoRemove, version, remove),
            version,
        );
        assert!(leftovers.clear_players(version).is_empty());
    }

    #[test]
    fn test_1_7_tab_list_is_cleared_by_name() {
        let version = ProtocolVersion(5);
        let mut leftovers = Leftovers::default();
        let mut add = Vec::new();
        add.write_string("Alex");
        add.write_bool(true);
        add.write_i16(10);
        leftovers.observe(&packet(PacketKind::PlayerInfo, version, add), version);

        let mut expected = Vec::new();
        expected.write_varint(PacketKind::PlayerInfo.id(version).unwrap());
        expected.write_string("Alex");
        expected.write_bool(false);
        expected.write_i16(0);
        assert_eq!(
            leftovers.clear_players(version),
            vec![Bytes::from(expected)]
        );
        assert!(leftovers.clear_overlays(version).is_empty());
    }
}
