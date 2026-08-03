use std::{error::Error, fmt, str};

/// The only VLESS flow accepted by the production inbound.
pub const VISION_FLOW: &str = "xtls-rprx-vision";

/// A borrowed view of the VLESS Addons protobuf used by Xray-core.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Addons<'a> {
    flow: Option<&'a str>,
    seed: Option<&'a [u8]>,
}

impl<'a> Addons<'a> {
    /// Parses the bounded protobuf payload carried in a VLESS request header.
    ///
    /// Xray-core defines field 1 as the flow string and field 2 as an opaque
    /// seed. Unknown protobuf fields are skipped for forward compatibility.
    pub fn parse(input: &'a [u8]) -> Result<Self, AddonsDecodeError> {
        let mut cursor = 0;
        let mut addons = Self::default();

        while cursor < input.len() {
            let key = read_varint(input, &mut cursor)?;
            let field = key >> 3;
            let wire_type = (key & 0x07) as u8;
            if field == 0 {
                return Err(AddonsDecodeError::InvalidFieldNumber);
            }

            match (field, wire_type) {
                (1, 2) => {
                    let value = read_length_delimited(input, &mut cursor)?;
                    addons.flow = Some(
                        str::from_utf8(value).map_err(|_| AddonsDecodeError::InvalidFlowUtf8)?,
                    );
                }
                (2, 2) => {
                    addons.seed = Some(read_length_delimited(input, &mut cursor)?);
                }
                (_, _) => skip_field(input, &mut cursor, wire_type)?,
            }
        }

        Ok(addons)
    }

    /// Returns the requested VLESS flow, if present.
    pub const fn flow(self) -> Option<&'a str> {
        self.flow
    }

    /// Returns the optional opaque seed.
    pub const fn seed(self) -> Option<&'a [u8]> {
        self.seed
    }
}

/// An error produced while parsing a VLESS Addons protobuf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddonsDecodeError {
    /// A protobuf varint exceeded 64 bits.
    VarintOverflow,

    /// A protobuf value ended before its declared length.
    Truncated,

    /// Protobuf field number zero is invalid.
    InvalidFieldNumber,

    /// The flow field was not valid UTF-8.
    InvalidFlowUtf8,

    /// Deprecated protobuf groups are not accepted.
    UnsupportedWireType(u8),
}

impl fmt::Display for AddonsDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarintOverflow => formatter.write_str("VLESS Addons varint exceeds 64 bits"),
            Self::Truncated => formatter.write_str("VLESS Addons protobuf is truncated"),
            Self::InvalidFieldNumber => formatter.write_str("VLESS Addons uses field number zero"),
            Self::InvalidFlowUtf8 => formatter.write_str("VLESS Addons flow is not valid UTF-8"),
            Self::UnsupportedWireType(wire_type) => {
                write!(
                    formatter,
                    "VLESS Addons wire type {wire_type} is unsupported"
                )
            }
        }
    }
}

impl Error for AddonsDecodeError {}

fn read_varint(input: &[u8], cursor: &mut usize) -> Result<u64, AddonsDecodeError> {
    let mut value = 0_u64;

    for shift in (0..=63).step_by(7) {
        let byte = *input.get(*cursor).ok_or(AddonsDecodeError::Truncated)?;
        *cursor += 1;

        if shift == 63 && byte > 1 {
            return Err(AddonsDecodeError::VarintOverflow);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }

    Err(AddonsDecodeError::VarintOverflow)
}

fn read_length_delimited<'a>(
    input: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], AddonsDecodeError> {
    let length =
        usize::try_from(read_varint(input, cursor)?).map_err(|_| AddonsDecodeError::Truncated)?;
    let end = cursor
        .checked_add(length)
        .ok_or(AddonsDecodeError::Truncated)?;
    let value = input
        .get(*cursor..end)
        .ok_or(AddonsDecodeError::Truncated)?;
    *cursor = end;
    Ok(value)
}

fn skip_field(input: &[u8], cursor: &mut usize, wire_type: u8) -> Result<(), AddonsDecodeError> {
    match wire_type {
        0 => {
            let _ = read_varint(input, cursor)?;
        }
        1 => skip_bytes(input, cursor, 8)?,
        2 => {
            let _ = read_length_delimited(input, cursor)?;
        }
        5 => skip_bytes(input, cursor, 4)?,
        _ => return Err(AddonsDecodeError::UnsupportedWireType(wire_type)),
    }

    Ok(())
}

fn skip_bytes(input: &[u8], cursor: &mut usize, length: usize) -> Result<(), AddonsDecodeError> {
    let end = cursor
        .checked_add(length)
        .ok_or(AddonsDecodeError::Truncated)?;
    if end > input.len() {
        return Err(AddonsDecodeError::Truncated);
    }
    *cursor = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Addons, AddonsDecodeError, VISION_FLOW};

    #[test]
    fn decodes_xray_vision_flow_and_seed() {
        let mut encoded = vec![0x0a, 0x10];
        encoded.extend_from_slice(VISION_FLOW.as_bytes());
        encoded.extend_from_slice(&[0x12, 0x03, 0xaa, 0xbb, 0xcc]);

        let addons = Addons::parse(&encoded).expect("Xray Addons should decode");

        assert_eq!(addons.flow(), Some(VISION_FLOW));
        assert_eq!(addons.seed(), Some([0xaa, 0xbb, 0xcc].as_slice()));
    }

    #[test]
    fn uses_last_repeated_scalar_like_protobuf() {
        let encoded = [0x0a, 0x03, b'o', b'l', b'd', 0x0a, 0x03, b'n', b'e', b'w'];

        let addons = Addons::parse(&encoded).expect("repeated protobuf scalar should decode");

        assert_eq!(addons.flow(), Some("new"));
    }

    #[test]
    fn skips_supported_unknown_wire_fields() {
        let encoded = [
            0x18, 0x96, 0x01, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a, 0x02, 1, 2, 0x35, 0, 0, 0, 0,
        ];

        let addons = Addons::parse(&encoded).expect("unknown protobuf fields should be skipped");

        assert_eq!(addons, Addons::default());
    }

    #[test]
    fn rejects_truncated_length_delimited_value() {
        assert_eq!(
            Addons::parse(&[0x0a, 0x04, b'f', b'l']),
            Err(AddonsDecodeError::Truncated)
        );
    }
}
