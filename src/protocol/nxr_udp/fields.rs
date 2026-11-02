//! Address and big-endian integer field codecs shared by NXR UDP frames and
//! authenticated opens.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::super::vless::{Address, Destination};
use super::error::NxrUdpError;
use super::layout::{ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_IPV6, MAX_DOMAIN_LEN};

pub(super) fn decode_destination(input: &[u8]) -> Result<(Destination, usize), NxrUdpError> {
    if input.len() < 5 {
        return Err(NxrUdpError::Truncated);
    }
    let address_type = input[0];
    let address_len = usize::from(u16::from_be_bytes([input[1], input[2]]));
    let port = u16::from_be_bytes([input[3], input[4]]);
    if port == 0 {
        return Err(NxrUdpError::Port);
    }
    let total = 5usize.checked_add(address_len).ok_or(NxrUdpError::Length)?;
    if input.len() < total {
        return Err(NxrUdpError::Truncated);
    }
    let address = parse_address(address_type, &input[5..total])?;
    Ok((Destination::new(address, port), total))
}

pub(super) fn address_shape(address: &Address) -> Result<(u8, usize), NxrUdpError> {
    match address {
        Address::Ipv4(_) => Ok((ADDRESS_IPV4, 4)),
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
                return Err(NxrUdpError::Address);
            }
            Ok((ADDRESS_DOMAIN, domain.len()))
        }
        Address::Ipv6(_) => Ok((ADDRESS_IPV6, 16)),
    }
}

pub(super) fn parse_address(address_type: u8, address: &[u8]) -> Result<Address, NxrUdpError> {
    match address_type {
        ADDRESS_IPV4 => {
            let bytes: [u8; 4] = address.try_into().map_err(|_| NxrUdpError::Address)?;
            Ok(Address::Ipv4(Ipv4Addr::from(bytes)))
        }
        ADDRESS_DOMAIN => std::str::from_utf8(address)
            .map(str::to_owned)
            .map(Address::Domain)
            .map_err(|_| NxrUdpError::Address),
        ADDRESS_IPV6 => {
            let bytes: [u8; 16] = address.try_into().map_err(|_| NxrUdpError::Address)?;
            Ok(Address::Ipv6(Ipv6Addr::from(bytes)))
        }
        _ => Err(NxrUdpError::Address),
    }
}

pub(super) fn read_u16(input: &[u8], offset: usize) -> Result<u16, NxrUdpError> {
    read_u16_at(input, offset)
}

pub(super) fn read_u16_at(input: &[u8], offset: usize) -> Result<u16, NxrUdpError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(NxrUdpError::Length)?
        .try_into()
        .map_err(|_| NxrUdpError::Length)?;
    Ok(u16::from_be_bytes(bytes))
}

pub(super) fn read_u64(input: &[u8], offset: usize) -> Result<u64, NxrUdpError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(NxrUdpError::Length)?
        .try_into()
        .map_err(|_| NxrUdpError::Length)?;
    Ok(u64::from_be_bytes(bytes))
}
