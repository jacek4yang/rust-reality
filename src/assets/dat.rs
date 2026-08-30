// GeoIP/GeoSite dat-file domain model: wire-format parsing and the compiled
// matcher structures. Pure data-in/data-out; I/O, caching, and ownership of
// published snapshots live in the parent module.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str,
    sync::Arc,
};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{Regex, RegexBuilder};

use super::AssetLoadError;
pub(super) fn parse_geosite_list(
    input: &[u8],
    required: &HashSet<String>,
) -> Result<HashMap<String, DomainSet>, AssetLoadError> {
    let mut labels = HashMap::new();
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        if let FieldValue::Bytes(message) = field.value
            && field.number == 1
        {
            let (code, entries) = scan_geosite(message)?;
            if required.contains(&code) {
                let set = DomainSet::compile(&entries)?;
                if labels.insert(code.clone(), set).is_some() {
                    return Err(AssetLoadError::DuplicateLabel(code));
                }
            }
        }
    }
    ensure_required_labels(required, &labels)?;
    Ok(labels)
}

pub(super) fn scan_geosite(input: &[u8]) -> Result<(String, Vec<&[u8]>), AssetLoadError> {
    let mut code = None;
    let mut entries = Vec::new();
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => code = Some(utf8(value)?.to_ascii_lowercase()),
            (2, FieldValue::Bytes(value)) => entries.push(value),
            _ => {}
        }
    }
    let code = code
        .filter(|value| !value.is_empty())
        .ok_or(AssetLoadError::MissingCode)?;
    Ok((code, entries))
}

pub(super) fn parse_domain(input: &[u8]) -> Result<(u64, &str), AssetLoadError> {
    let mut kind = 0;
    let mut value = None;
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        match (field.number, field.value) {
            (1, FieldValue::Varint(raw)) => kind = raw,
            (2, FieldValue::Bytes(raw)) => value = Some(utf8(raw)?),
            _ => {}
        }
    }
    let value = value
        .filter(|value| !value.is_empty())
        .ok_or(AssetLoadError::MissingValue)?;
    Ok((kind, value))
}

pub(super) fn parse_geoip_list(
    input: &[u8],
    required: &HashSet<String>,
) -> Result<HashMap<String, IpSet>, AssetLoadError> {
    let mut labels = HashMap::new();
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        if let FieldValue::Bytes(message) = field.value
            && field.number == 1
        {
            let (code, networks, reverse) = scan_geoip(message)?;
            if required.contains(&code) {
                let set = IpSet::compile(&networks, reverse)?;
                if labels.insert(code.clone(), set).is_some() {
                    return Err(AssetLoadError::DuplicateLabel(code));
                }
            }
        }
    }
    ensure_required_labels(required, &labels)?;
    Ok(labels)
}

pub(super) fn scan_geoip(input: &[u8]) -> Result<(String, Vec<&[u8]>, bool), AssetLoadError> {
    let mut code = None;
    let mut networks = Vec::new();
    let mut reverse = false;
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => code = Some(utf8(value)?.to_ascii_lowercase()),
            (2, FieldValue::Bytes(value)) => networks.push(value),
            (3, FieldValue::Varint(value)) => reverse = value != 0,
            _ => {}
        }
    }
    let code = code
        .filter(|value| !value.is_empty())
        .ok_or(AssetLoadError::MissingCode)?;
    Ok((code, networks, reverse))
}

fn ensure_required_labels<T>(
    required: &HashSet<String>,
    parsed: &HashMap<String, T>,
) -> Result<(), AssetLoadError> {
    if let Some(missing) = required.iter().find(|label| !parsed.contains_key(*label)) {
        return Err(AssetLoadError::MissingLabel(missing.clone()));
    }
    Ok(())
}

pub(super) fn parse_cidr(input: &[u8]) -> Result<IpNetwork, AssetLoadError> {
    let mut address = None;
    let mut prefix = 0;
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => address = Some(value),
            (2, FieldValue::Varint(value)) => prefix = value,
            _ => {}
        }
    }
    IpNetwork::new(address.ok_or(AssetLoadError::InvalidCidr)?, prefix)
}

pub(super) fn utf8(input: &[u8]) -> Result<&str, AssetLoadError> {
    str::from_utf8(input).map_err(|_| AssetLoadError::InvalidUtf8)
}

pub(super) struct ProtoReader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> ProtoReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn next(&mut self) -> Result<Option<ProtoField<'a>>, AssetLoadError> {
        if self.cursor == self.input.len() {
            return Ok(None);
        }
        let key = read_varint(self.input, &mut self.cursor)?;
        let number = key >> 3;
        if number == 0 {
            return Err(AssetLoadError::InvalidProtobuf);
        }
        let value = match key & 7 {
            0 => FieldValue::Varint(read_varint(self.input, &mut self.cursor)?),
            1 => {
                skip(self.input, &mut self.cursor, 8)?;
                FieldValue::Ignored
            }
            2 => {
                let length = usize::try_from(read_varint(self.input, &mut self.cursor)?)
                    .map_err(|_| AssetLoadError::InvalidProtobuf)?;
                let end = self
                    .cursor
                    .checked_add(length)
                    .ok_or(AssetLoadError::InvalidProtobuf)?;
                let bytes = self
                    .input
                    .get(self.cursor..end)
                    .ok_or(AssetLoadError::TruncatedProtobuf)?;
                self.cursor = end;
                FieldValue::Bytes(bytes)
            }
            5 => {
                skip(self.input, &mut self.cursor, 4)?;
                FieldValue::Ignored
            }
            _ => return Err(AssetLoadError::InvalidProtobuf),
        };
        Ok(Some(ProtoField { number, value }))
    }
}

pub(super) struct ProtoField<'a> {
    number: u64,
    value: FieldValue<'a>,
}

pub(super) enum FieldValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Ignored,
}

pub(super) fn read_varint(input: &[u8], cursor: &mut usize) -> Result<u64, AssetLoadError> {
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        let byte = *input
            .get(*cursor)
            .ok_or(AssetLoadError::TruncatedProtobuf)?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(AssetLoadError::InvalidProtobuf);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(AssetLoadError::InvalidProtobuf)
}

pub(super) fn skip(input: &[u8], cursor: &mut usize, length: usize) -> Result<(), AssetLoadError> {
    let end = cursor
        .checked_add(length)
        .ok_or(AssetLoadError::InvalidProtobuf)?;
    if end > input.len() {
        return Err(AssetLoadError::TruncatedProtobuf);
    }
    *cursor = end;
    Ok(())
}

/// Loading a complete asset generation failed.
#[derive(Debug)]
pub(super) struct DomainSet {
    substrings: Option<AhoCorasick>,
    regexes: Arc<[Regex]>,
    suffixes: HashSet<String>,
    full: HashSet<String>,
}

impl DomainSet {
    fn compile(entries: &[&[u8]]) -> Result<Self, AssetLoadError> {
        let mut substrings = Vec::new();
        let mut regexes = Vec::new();
        let mut suffixes = HashSet::new();
        let mut full = HashSet::new();
        for entry in entries {
            let (kind, value) = parse_domain(entry)?;
            match kind {
                0 => substrings.push(value.to_ascii_lowercase()),
                1 => regexes.push(
                    RegexBuilder::new(value)
                        .case_insensitive(true)
                        .size_limit(2 * 1024 * 1024)
                        .dfa_size_limit(2 * 1024 * 1024)
                        .build()
                        .map_err(|error| match error {
                            regex::Error::CompiledTooBig(_) => AssetLoadError::RegexTooLarge,
                            _ => AssetLoadError::InvalidRegexSyntax,
                        })?,
                ),
                2 => {
                    suffixes.insert(value.trim_start_matches('.').to_ascii_lowercase());
                }
                3 => {
                    full.insert(value.to_ascii_lowercase());
                }
                _ => return Err(AssetLoadError::InvalidDomainType(kind)),
            }
        }
        let substrings = if substrings.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .build(substrings)
                    .map_err(|_| AssetLoadError::InvalidSubstringSet)?,
            )
        };
        Ok(Self {
            substrings,
            regexes: regexes.into(),
            suffixes,
            full,
        })
    }

    pub(super) fn matches(&self, domain: &str) -> bool {
        let normalized = if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(domain.to_ascii_lowercase())
        } else {
            Cow::Borrowed(domain)
        };
        let domain = normalized.as_ref();
        self.full.contains(domain)
            || suffix_set_matches(&self.suffixes, domain)
            || self
                .substrings
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(domain))
            || self.regexes.iter().any(|regex| regex.is_match(domain))
    }
}

pub(super) fn suffix_set_matches(suffixes: &HashSet<String>, domain: &str) -> bool {
    suffixes.contains(domain)
        || domain
            .match_indices('.')
            .any(|(index, _)| suffixes.contains(&domain[index + 1..]))
}

pub(super) struct IpSet {
    ipv4: PrefixTrie,
    ipv6: PrefixTrie,
    reverse: bool,
}

impl IpSet {
    fn compile(networks: &[&[u8]], reverse: bool) -> Result<Self, AssetLoadError> {
        let mut ipv4 = PrefixTrie::new(32);
        let mut ipv6 = PrefixTrie::new(128);
        for encoded in networks {
            match parse_cidr(encoded)? {
                IpNetwork::V4 { network, prefix } => {
                    ipv4.insert(u128::from(network), prefix)?;
                }
                IpNetwork::V6 { network, prefix } => ipv6.insert(network, prefix)?,
            }
        }
        Ok(Self {
            ipv4,
            ipv6,
            reverse,
        })
    }

    pub(super) fn matches(&self, address: IpAddr) -> bool {
        let matched = match address {
            IpAddr::V4(address) => self.ipv4.contains(u128::from(u32::from(address))),
            IpAddr::V6(address) => self.ipv6.contains(u128::from(address)),
        };
        matched ^ self.reverse
    }
}

pub(super) struct PrefixTrie {
    width: u8,
    nodes: Vec<PrefixNode>,
}

impl PrefixTrie {
    fn new(width: u8) -> Self {
        Self {
            width,
            nodes: vec![PrefixNode::default()],
        }
    }

    fn insert(&mut self, value: u128, prefix: u8) -> Result<(), AssetLoadError> {
        let mut node_index = 0_usize;
        for offset in 0..prefix {
            let branch = usize::from(((value >> (self.width - offset - 1)) & 1) != 0);
            let child = if let Some(child) = self.nodes[node_index].children[branch] {
                usize::try_from(child).map_err(|_| AssetLoadError::TooManyNetworks)?
            } else {
                let child =
                    u32::try_from(self.nodes.len()).map_err(|_| AssetLoadError::TooManyNetworks)?;
                self.nodes.push(PrefixNode::default());
                self.nodes[node_index].children[branch] = Some(child);
                usize::try_from(child).map_err(|_| AssetLoadError::TooManyNetworks)?
            };
            node_index = child;
        }
        self.nodes[node_index].terminal = true;
        Ok(())
    }

    fn contains(&self, value: u128) -> bool {
        let mut node_index = 0_usize;
        for offset in 0..self.width {
            let Some(node) = self.nodes.get(node_index) else {
                return false;
            };
            if node.terminal {
                return true;
            }
            let branch = usize::from(((value >> (self.width - offset - 1)) & 1) != 0);
            let Some(child) = node.children[branch] else {
                return false;
            };
            let Ok(child) = usize::try_from(child) else {
                return false;
            };
            node_index = child;
        }
        self.nodes.get(node_index).is_some_and(|node| node.terminal)
    }
}

#[derive(Default)]
pub(super) struct PrefixNode {
    children: [Option<u32>; 2],
    terminal: bool,
}

#[derive(Clone, Copy)]
pub(super) enum IpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpNetwork {
    fn new(address: &[u8], prefix: u64) -> Result<Self, AssetLoadError> {
        match address {
            [a, b, c, d] if prefix <= 32 => {
                let prefix = u8::try_from(prefix).map_err(|_| AssetLoadError::InvalidCidr)?;
                let address = u32::from(Ipv4Addr::new(*a, *b, *c, *d));
                Ok(Self::V4 {
                    network: address & mask_u32(prefix),
                    prefix,
                })
            }
            bytes if bytes.len() == 16 && prefix <= 128 => {
                let octets: [u8; 16] = bytes.try_into().map_err(|_| AssetLoadError::InvalidCidr)?;
                let prefix = u8::try_from(prefix).map_err(|_| AssetLoadError::InvalidCidr)?;
                let address = u128::from(Ipv6Addr::from(octets));
                Ok(Self::V6 {
                    network: address & mask_u128(prefix),
                    prefix,
                })
            }
            _ => Err(AssetLoadError::InvalidCidr),
        }
    }
}

const fn mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}
