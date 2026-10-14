use pumpkin_protocol::ser::NetworkReadSliceExt;
use pumpkin_util::text::TextComponent;

use super::{ProtocolError, ProtocolVersion};

pub fn read_component(
    buf: &mut &[u8],
    version: ProtocolVersion,
) -> Result<TextComponent, ProtocolError> {
    buf.get_component(&version.to_pumpkin())
        .map_err(|e| ProtocolError::Malformed(e.to_string()))
}
