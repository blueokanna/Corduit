//! Self-implemented DNS wire format codec (RFC 1035 + common extensions).
//!
//! A dependency-free replacement for `hickory-proto`'s message codec covering
//! exactly what Corduit's DNS client and servers need: message header,
//! questions, resource records, name compression and the `RData` types the
//! engine emits (A, AAAA) plus the ones it must skip or surface (CNAME, NS,
//! PTR, TXT, MX, SOA, SRV, SVCB/HTTPS, OPT).
//!
//! Safety: every read is bounds-checked and name-compression pointers are
//! followed with a strict hop limit, so a hostile or corrupt message can never
//! cause an out-of-bounds access or an infinite loop.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Maximum name-compression indirection hops tolerated while decoding.
const MAX_COMPRESSION_HOPS: usize = 128;
/// Maximum labels in a decoded name.
const MAX_NAME_LABELS: usize = 128;
/// Maximum total encoded size of a decoded name.
const MAX_NAME_LENGTH: usize = 255;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// An error produced while encoding or decoding a DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError {
    message: String,
}

impl WireError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WireError {}

// ---------------------------------------------------------------------------
// Codec traits (small subset of hickory-proto's API surface)
// ---------------------------------------------------------------------------

/// Types that can be serialized into the DNS wire format.
pub trait BinEncodable {
    fn to_bytes(&self) -> Result<Vec<u8>, WireError>;

    /// Alias kept for call-site compatibility.
    fn to_vec(&self) -> Result<Vec<u8>, WireError> {
        self.to_bytes()
    }
}

/// Types that can be deserialized from the DNS wire format.
pub trait BinDecodable: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, WireError>;
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Message type: query or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Query,
    Response,
}

/// DNS opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Unknown(u8),
}

impl OpCode {
    fn from_u8(code: u8) -> Self {
        match code {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            other => OpCode::Unknown(other),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Notify => 4,
            OpCode::Update => 5,
            OpCode::Unknown(other) => other,
        }
    }
}

/// DNS response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    Unknown(u8),
}

impl ResponseCode {
    fn from_u8(code: u8) -> Self {
        match code {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            other => ResponseCode::Unknown(other),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            ResponseCode::NoError => 0,
            ResponseCode::FormErr => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NXDomain => 3,
            ResponseCode::NotImp => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Unknown(other) => other,
        }
    }
}

/// DNS record class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    IN,
    CH,
    HS,
    NONE,
    ANY,
    Unknown(u16),
}

impl RecordClass {
    fn from_u16(class: u16) -> Self {
        match class {
            1 => RecordClass::IN,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            254 => RecordClass::NONE,
            255 => RecordClass::ANY,
            other => RecordClass::Unknown(other),
        }
    }

    fn to_u16(self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::NONE => 254,
            RecordClass::ANY => 255,
            RecordClass::Unknown(other) => other,
        }
    }
}

/// DNS record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    OPT,
    SVCB,
    HTTPS,
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(rt: u16) -> Self {
        match rt {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            41 => RecordType::OPT,
            64 => RecordType::SVCB,
            65 => RecordType::HTTPS,
            other => RecordType::Unknown(other),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::OPT => 41,
            RecordType::SVCB => 64,
            RecordType::HTTPS => 65,
            RecordType::Unknown(other) => other,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RecordType::A => "A",
            RecordType::NS => "NS",
            RecordType::CNAME => "CNAME",
            RecordType::SOA => "SOA",
            RecordType::PTR => "PTR",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::AAAA => "AAAA",
            RecordType::SRV => "SRV",
            RecordType::OPT => "OPT",
            RecordType::SVCB => "SVCB",
            RecordType::HTTPS => "HTTPS",
            RecordType::Unknown(rt) => return write!(f, "TYPE{rt}"),
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Name
// ---------------------------------------------------------------------------

/// A DNS domain name as an ordered list of labels (without the root label).
///
/// `Display` renders with a trailing dot (`"example.com."`), matching the
/// convention consumers of this module expect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// The root name (`"."`).
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    /// Parse a name from an ASCII string such as `"example.com"` or
    /// `"example.com."`.
    pub fn from_ascii(s: &str) -> Result<Self, WireError> {
        if !s.is_ascii() {
            return Err(WireError::new("domain name is not ASCII"));
        }
        if s.is_empty() {
            return Err(WireError::new("domain name is empty"));
        }
        if s == "." {
            return Ok(Self::root());
        }
        let trimmed = s.strip_suffix('.').unwrap_or(s);

        let mut labels = Vec::new();
        let mut total = 0usize;
        for label in trimmed.split('.') {
            if label.is_empty() {
                return Err(WireError::new(format!(
                    "domain name '{s}' contains an empty label"
                )));
            }
            if label.len() > 63 {
                return Err(WireError::new(format!(
                    "domain name '{s}' has a label longer than 63 bytes"
                )));
            }
            total += 1 + label.len();
            labels.push(label.as_bytes().to_vec());
        }
        total += 1; // root terminator
        if total > MAX_NAME_LENGTH {
            return Err(WireError::new(format!(
                "domain name '{s}' exceeds 255 bytes"
            )));
        }
        Ok(Self { labels })
    }

    /// Number of labels (root has zero).
    pub fn num_labels(&self) -> usize {
        self.labels.len()
    }

    /// `true` when this is the root name.
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }
}

impl FromStr for Name {
    type Err = WireError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Name::from_ascii(s)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for label in &self.labels {
            // Labels are ASCII by construction; lossless conversion is fine.
            f.write_str(&String::from_utf8_lossy(label))?;
            f.write_str(".")?;
        }
        if self.labels.is_empty() {
            f.write_str(".")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

/// A single question section entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    name: Name,
    query_type: RecordType,
    query_class: RecordClass,
}

impl Query {
    /// Build an IN-class query for `name`/`query_type`.
    ///
    /// The name mirrors the `hickory_proto` API this module replaces.
    #[allow(clippy::self_named_constructors)]
    pub fn query(name: Name, query_type: RecordType) -> Self {
        Self {
            name,
            query_type,
            query_class: RecordClass::IN,
        }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn query_type(&self) -> RecordType {
        self.query_type
    }

    pub fn query_class(&self) -> RecordClass {
        self.query_class
    }
}

// ---------------------------------------------------------------------------
// RData
// ---------------------------------------------------------------------------

/// Record-data payload wrappers (mirrors `hickory_proto::rr::rdata`).
pub mod rdata {
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct A(pub Ipv4Addr);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AAAA(pub Ipv6Addr);
}

/// Decoded resource-record data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(rdata::A),
    AAAA(rdata::AAAA),
    CNAME(crate::dns::wire::Name),
    NS(crate::dns::wire::Name),
    PTR(crate::dns::wire::Name),
    TXT(Vec<String>),
    MX {
        preference: u16,
        exchange: crate::dns::wire::Name,
    },
    SOA {
        mname: crate::dns::wire::Name,
        rname: crate::dns::wire::Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: crate::dns::wire::Name,
    },
    /// SVCB/HTTPS priority + target + raw parameter bytes.
    SvcParams {
        priority: u16,
        target: crate::dns::wire::Name,
        params: Vec<u8>,
    },
    /// Any type we do not decode structurally; raw RDATA bytes.
    Unknown(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

/// A resource record (answer, authority or additional section entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub record_type: RecordType,
    pub class: RecordClass,
    pub ttl: u32,
    pub data: RData,
}

impl Record {
    /// Build a record from a name, TTL and RDATA (class defaults to IN).
    pub fn from_rdata(name: Name, ttl: u32, rdata: RData) -> Self {
        let record_type = match &rdata {
            RData::A(_) => RecordType::A,
            RData::AAAA(_) => RecordType::AAAA,
            RData::CNAME(_) => RecordType::CNAME,
            RData::NS(_) => RecordType::NS,
            RData::PTR(_) => RecordType::PTR,
            RData::TXT(_) => RecordType::TXT,
            RData::MX { .. } => RecordType::MX,
            RData::SOA { .. } => RecordType::SOA,
            RData::SRV { .. } => RecordType::SRV,
            RData::SvcParams { .. } => RecordType::Unknown(0),
            RData::Unknown(_) => RecordType::Unknown(0),
        };
        Self {
            name,
            record_type,
            class: RecordClass::IN,
            ttl,
            data: rdata,
        }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    pub fn data(&self) -> &RData {
        &self.data
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// DNS message header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMetadata {
    pub id: u16,
    pub message_type: MessageType,
    pub op_code: OpCode,
    pub authoritative: bool,
    pub truncation: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
}

impl MessageMetadata {
    fn new(id: u16, message_type: MessageType, op_code: OpCode) -> Self {
        Self {
            id,
            message_type,
            op_code,
            authoritative: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            response_code: ResponseCode::NoError,
        }
    }
}

/// A complete DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub metadata: MessageMetadata,
    pub queries: Vec<Query>,
    pub answers: Vec<Record>,
    pub name_servers: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    /// Build an empty message with the given id/type/opcode.
    pub fn new(id: u16, message_type: MessageType, op_code: OpCode) -> Self {
        Self {
            metadata: MessageMetadata::new(id, message_type, op_code),
            queries: Vec::new(),
            answers: Vec::new(),
            name_servers: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Build an empty response echoing the request id and opcode.
    pub fn response(id: u16, op_code: OpCode) -> Self {
        Self::new(id, MessageType::Response, op_code)
    }

    pub fn add_query(&mut self, query: Query) {
        self.queries.push(query);
    }

    pub fn add_answer(&mut self, record: Record) {
        self.answers.push(record);
    }

    pub fn add_name_server(&mut self, record: Record) {
        self.name_servers.push(record);
    }

    pub fn add_additional(&mut self, record: Record) {
        self.additionals.push(record);
    }
}

impl BinEncodable for Message {
    fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        let mut buf = Vec::with_capacity(512);
        // Header
        buf.extend_from_slice(&self.metadata.id.to_be_bytes());
        let flags = (if self.metadata.message_type == MessageType::Response {
            1u16 << 15
        } else {
            0
        }) | ((self.metadata.op_code.to_u8() as u16) << 11)
            | (if self.metadata.authoritative {
                1 << 10
            } else {
                0
            })
            | (if self.metadata.truncation { 1 << 9 } else { 0 })
            | (if self.metadata.recursion_desired {
                1 << 8
            } else {
                0
            })
            | (if self.metadata.recursion_available {
                1 << 7
            } else {
                0
            })
            | (self.metadata.response_code.to_u8() as u16);
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&(self.queries.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.name_servers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        let mut compressor = NameCompressor::new();
        for query in &self.queries {
            compressor.write_name(&mut buf, &query.name)?;
            buf.extend_from_slice(&query.query_type.to_u16().to_be_bytes());
            buf.extend_from_slice(&query.query_class.to_u16().to_be_bytes());
        }
        for record in self
            .answers
            .iter()
            .chain(&self.name_servers)
            .chain(&self.additionals)
        {
            encode_record(&mut compressor, &mut buf, record)?;
        }
        Ok(buf)
    }
}

impl BinDecodable for Message {
    fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 12 {
            return Err(WireError::new("DNS message shorter than header"));
        }
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;

        let metadata = MessageMetadata {
            id,
            message_type: if flags & 0x8000 != 0 {
                MessageType::Response
            } else {
                MessageType::Query
            },
            op_code: OpCode::from_u8(((flags >> 11) & 0x0F) as u8),
            authoritative: flags & 0x0400 != 0,
            truncation: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            recursion_available: flags & 0x0080 != 0,
            response_code: ResponseCode::from_u8((flags & 0x000F) as u8),
        };

        let mut decoder = Decoder::new(bytes, 12);
        let mut queries = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let name = decoder.read_name()?;
            let qtype = RecordType::from_u16(decoder.read_u16()?);
            let qclass = RecordClass::from_u16(decoder.read_u16()?);
            queries.push(Query {
                name,
                query_type: qtype,
                query_class: qclass,
            });
        }

        let answers = decoder.read_records(ancount)?;
        let name_servers = decoder.read_records(nscount)?;
        let additionals = decoder.read_records(arcount)?;

        Ok(Self {
            metadata,
            queries,
            answers,
            name_servers,
            additionals,
        })
    }
}

// ---------------------------------------------------------------------------
// Low-level encode helpers
// ---------------------------------------------------------------------------

/// RFC 1035 name compressor: remembers the message offset of every label
/// suffix already written so a repeated name (or a shared suffix such as
/// `.example.com`) is emitted as a 2-byte pointer instead of duplicated bytes.
/// This keeps large multi-record responses inside the 512-byte UDP budget.
///
/// Pointers are only emitted for offsets that fit the 14-bit pointer field;
/// anything beyond 0x3FFF falls back to the literal form.
struct NameCompressor {
    offsets: std::collections::HashMap<Vec<u8>, usize>,
}

impl NameCompressor {
    fn new() -> Self {
        Self {
            offsets: std::collections::HashMap::new(),
        }
    }

    fn write_name(&mut self, buf: &mut Vec<u8>, name: &Name) -> Result<(), WireError> {
        if name.labels.is_empty() {
            buf.push(0);
            return Ok(());
        }
        // Longest-suffix first: the best compression wins.
        for start in 0..name.labels.len() {
            let key = Self::suffix_key(&name.labels[start..]);
            if let Some(&off) = self.offsets.get(&key) {
                if off <= 0x3FFF {
                    for label in &name.labels[..start] {
                        Self::push_label(buf, label)?;
                    }
                    let ptr = 0xC000u16 | off as u16;
                    buf.extend_from_slice(&ptr.to_be_bytes());
                    return Ok(());
                }
            }
        }
        // Nothing reusable: write the full name and index every suffix.
        for i in 0..name.labels.len() {
            let key = Self::suffix_key(&name.labels[i..]);
            self.offsets.entry(key).or_insert(buf.len());
            Self::push_label(buf, &name.labels[i])?;
        }
        buf.push(0);
        Ok(())
    }

    /// Wire encoding of a label sequence, used as the compression key.
    fn suffix_key(labels: &[Vec<u8>]) -> Vec<u8> {
        let mut key = Vec::with_capacity(labels.iter().map(|l| l.len() + 1).sum());
        for label in labels {
            key.push(label.len() as u8);
            key.extend_from_slice(label);
        }
        key
    }

    fn push_label(buf: &mut Vec<u8>, label: &[u8]) -> Result<(), WireError> {
        if label.is_empty() || label.len() > 63 {
            return Err(WireError::new("invalid label length while encoding name"));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label);
        Ok(())
    }
}

fn encode_record(
    compressor: &mut NameCompressor,
    buf: &mut Vec<u8>,
    record: &Record,
) -> Result<(), WireError> {
    compressor.write_name(buf, &record.name)?;
    let record_type = if record.record_type == RecordType::Unknown(0) {
        rdata_record_type(&record.data)
    } else {
        record.record_type
    };
    buf.extend_from_slice(&record_type.to_u16().to_be_bytes());
    buf.extend_from_slice(&record.class.to_u16().to_be_bytes());
    buf.extend_from_slice(&record.ttl.to_be_bytes());

    let rdata_start = buf.len();
    buf.extend_from_slice(&[0, 0]); // rdlength placeholder
    encode_rdata(compressor, buf, &record.data)?;
    let rdata_len = buf.len() - rdata_start - 2;
    if rdata_len > u16::MAX as usize {
        return Err(WireError::new("RDATA exceeds 65535 bytes"));
    }
    let len = (rdata_len as u16).to_be_bytes();
    buf[rdata_start] = len[0];
    buf[rdata_start + 1] = len[1];
    Ok(())
}

fn rdata_record_type(data: &RData) -> RecordType {
    match data {
        RData::A(_) => RecordType::A,
        RData::AAAA(_) => RecordType::AAAA,
        RData::CNAME(_) => RecordType::CNAME,
        RData::NS(_) => RecordType::NS,
        RData::PTR(_) => RecordType::PTR,
        RData::TXT(_) => RecordType::TXT,
        RData::MX { .. } => RecordType::MX,
        RData::SOA { .. } => RecordType::SOA,
        RData::SRV { .. } => RecordType::SRV,
        RData::SvcParams { .. } => RecordType::Unknown(0),
        RData::Unknown(_) => RecordType::Unknown(0),
    }
}

fn encode_rdata(
    compressor: &mut NameCompressor,
    buf: &mut Vec<u8>,
    data: &RData,
) -> Result<(), WireError> {
    match data {
        RData::A(a) => buf.extend_from_slice(&a.0.octets()),
        RData::AAAA(aaaa) => buf.extend_from_slice(&aaaa.0.octets()),
        RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => {
            compressor.write_name(buf, name)?
        }
        RData::TXT(strings) => {
            for s in strings {
                let bytes = s.as_bytes();
                if bytes.len() > 255 {
                    return Err(WireError::new("TXT string longer than 255 bytes"));
                }
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
            }
        }
        RData::MX {
            preference,
            exchange,
        } => {
            buf.extend_from_slice(&preference.to_be_bytes());
            compressor.write_name(buf, exchange)?;
        }
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            compressor.write_name(buf, mname)?;
            compressor.write_name(buf, rname)?;
            for v in [serial, refresh, retry, expire, minimum] {
                buf.extend_from_slice(&v.to_be_bytes());
            }
        }
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            buf.extend_from_slice(&priority.to_be_bytes());
            buf.extend_from_slice(&weight.to_be_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
            compressor.write_name(buf, target)?;
        }
        RData::SvcParams {
            priority,
            target,
            params,
        } => {
            buf.extend_from_slice(&priority.to_be_bytes());
            compressor.write_name(buf, target)?;
            buf.extend_from_slice(params);
        }
        RData::Unknown(raw) => buf.extend_from_slice(raw),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Low-level decode helpers
// ---------------------------------------------------------------------------

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    fn read_u16(&mut self) -> Result<u16, WireError> {
        if self.pos + 2 > self.buf.len() {
            return Err(WireError::new("unexpected end of DNS message"));
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, WireError> {
        if self.pos + 4 > self.buf.len() {
            return Err(WireError::new("unexpected end of DNS message"));
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        if self.pos + len > self.buf.len() {
            return Err(WireError::new("unexpected end of DNS message"));
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Read a (possibly compressed) name, advancing the stream position past
    /// the name's first occurrence. Pointer hops are capped.
    fn read_name(&mut self) -> Result<Name, WireError> {
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut pos = self.pos;
        let mut jumped = false;
        let mut hops = 0usize;

        loop {
            if pos >= self.buf.len() {
                return Err(WireError::new("unexpected end of DNS message in name"));
            }
            let len = self.buf[pos];

            if len & 0xC0 == 0xC0 {
                // Compression pointer: 14-bit offset into the message.
                if pos + 1 >= self.buf.len() {
                    return Err(WireError::new("truncated compression pointer"));
                }
                let pointer = (((len & 0x3F) as usize) << 8) | (self.buf[pos + 1] as usize);
                if pointer >= self.buf.len() {
                    return Err(WireError::new("compression pointer out of bounds"));
                }
                if !jumped {
                    self.pos = pos + 2;
                    jumped = true;
                }
                pos = pointer;
                hops += 1;
                if hops > MAX_COMPRESSION_HOPS {
                    return Err(WireError::new("too many compression pointer hops"));
                }
                continue;
            }

            if len & 0xC0 != 0 {
                // Extended label types (0x40/0x80 prefixes) are not supported.
                return Err(WireError::new(format!(
                    "unsupported label type 0x{len:02x}"
                )));
            }

            pos += 1;
            if len == 0 {
                break;
            }
            if pos + len as usize > self.buf.len() {
                return Err(WireError::new("unexpected end of DNS message in label"));
            }
            labels.push(self.buf[pos..pos + len as usize].to_vec());
            pos += len as usize;
            if labels.len() > MAX_NAME_LABELS {
                return Err(WireError::new("too many labels in name"));
            }
        }

        if !jumped {
            self.pos = pos;
        }
        Ok(Name { labels })
    }

    /// Read a name from an exact offset (used for RDATA names that contain a
    /// pointer). Never advances the stream position.
    fn read_name_at(&self, offset: usize) -> Result<Name, WireError> {
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut pos = offset;
        let mut hops = 0usize;

        loop {
            if pos >= self.buf.len() {
                return Err(WireError::new("unexpected end of DNS message in name"));
            }
            let len = self.buf[pos];
            if len & 0xC0 == 0xC0 {
                if pos + 1 >= self.buf.len() {
                    return Err(WireError::new("truncated compression pointer"));
                }
                let pointer = (((len & 0x3F) as usize) << 8) | (self.buf[pos + 1] as usize);
                if pointer >= self.buf.len() {
                    return Err(WireError::new("compression pointer out of bounds"));
                }
                pos = pointer;
                hops += 1;
                if hops > MAX_COMPRESSION_HOPS {
                    return Err(WireError::new("too many compression pointer hops"));
                }
                continue;
            }
            if len & 0xC0 != 0 {
                return Err(WireError::new(format!(
                    "unsupported label type 0x{len:02x}"
                )));
            }
            pos += 1;
            if len == 0 {
                break;
            }
            if pos + len as usize > self.buf.len() {
                return Err(WireError::new("unexpected end of DNS message in label"));
            }
            labels.push(self.buf[pos..pos + len as usize].to_vec());
            pos += len as usize;
            if labels.len() > MAX_NAME_LABELS {
                return Err(WireError::new("too many labels in name"));
            }
        }

        Ok(Name { labels })
    }

    fn read_records(&mut self, count: usize) -> Result<Vec<Record>, WireError> {
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let name = self.read_name()?;
            let record_type = RecordType::from_u16(self.read_u16()?);
            let class = RecordClass::from_u16(self.read_u16()?);
            let ttl = self.read_u32()?;
            let rdlength = self.read_u16()? as usize;
            let rdata_offset = self.pos;
            let rdata_bytes = self.take(rdlength)?;
            let data = self.decode_rdata(record_type, rdata_offset, rdata_bytes)?;
            records.push(Record {
                name,
                record_type,
                class,
                ttl,
                data,
            });
        }
        Ok(records)
    }

    /// Decode RDATA given the record type. `rdata_offset` is the absolute
    /// position of the RDATA within the message, so name-bearing types can
    /// resolve compression pointers against the whole message.
    fn decode_rdata(
        &self,
        record_type: RecordType,
        rdata_offset: usize,
        rdata: &'a [u8],
    ) -> Result<RData, WireError> {
        match record_type {
            RecordType::A => {
                if rdata.len() != 4 {
                    return Err(WireError::new("A record must be 4 bytes"));
                }
                Ok(RData::A(rdata::A(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))))
            }
            RecordType::AAAA => {
                if rdata.len() != 16 {
                    return Err(WireError::new("AAAA record must be 16 bytes"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                Ok(RData::AAAA(rdata::AAAA(Ipv6Addr::from(octets))))
            }
            RecordType::CNAME => Ok(RData::CNAME(self.read_name_at(rdata_offset)?)),
            RecordType::NS => Ok(RData::NS(self.read_name_at(rdata_offset)?)),
            RecordType::PTR => Ok(RData::PTR(self.read_name_at(rdata_offset)?)),
            RecordType::TXT => {
                let mut strings = Vec::new();
                let mut pos = 0usize;
                while pos < rdata.len() {
                    let len = rdata[pos] as usize;
                    pos += 1;
                    if pos + len > rdata.len() {
                        return Err(WireError::new("truncated TXT record"));
                    }
                    strings.push(String::from_utf8_lossy(&rdata[pos..pos + len]).into_owned());
                    pos += len;
                }
                Ok(RData::TXT(strings))
            }
            RecordType::MX => {
                if rdata.len() < 2 {
                    return Err(WireError::new("truncated MX record"));
                }
                let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
                let exchange = self.read_name_at(rdata_offset + 2)?;
                Ok(RData::MX {
                    preference,
                    exchange,
                })
            }
            RecordType::SOA => {
                let mname = self.read_name_at(rdata_offset)?;
                let mname_len = self.name_len_at(rdata_offset);
                let rname = self.read_name_at(rdata_offset + mname_len)?;
                let rname_len = self.name_len_at(rdata_offset + mname_len);
                // `name_len_at` measures against the whole message, so the
                // combined name length may exceed the declared RDATA length on
                // a malformed record. Reject before slicing.
                let names_len = mname_len.saturating_add(rname_len);
                if names_len > rdata.len() {
                    return Err(WireError::new("SOA names exceed RDATA length"));
                }
                let tail = &rdata[names_len..];
                if tail.len() < 20 {
                    return Err(WireError::new("truncated SOA record"));
                }
                let serial = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
                let refresh = u32::from_be_bytes([tail[4], tail[5], tail[6], tail[7]]);
                let retry = u32::from_be_bytes([tail[8], tail[9], tail[10], tail[11]]);
                let expire = u32::from_be_bytes([tail[12], tail[13], tail[14], tail[15]]);
                let minimum = u32::from_be_bytes([tail[16], tail[17], tail[18], tail[19]]);
                Ok(RData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            RecordType::SRV => {
                if rdata.len() < 6 {
                    return Err(WireError::new("truncated SRV record"));
                }
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                let target = self.read_name_at(rdata_offset + 6)?;
                Ok(RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                })
            }
            RecordType::SVCB | RecordType::HTTPS => {
                if rdata.len() < 2 {
                    return Err(WireError::new("truncated SVCB/HTTPS record"));
                }
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let target = self.read_name_at(rdata_offset + 2)?;
                let target_len = self.name_len_at(rdata_offset + 2);
                let params_start = 2usize.saturating_add(target_len);
                if params_start > rdata.len() {
                    return Err(WireError::new("SVCB/HTTPS target exceeds RDATA length"));
                }
                let params = rdata[params_start..].to_vec();
                Ok(RData::SvcParams {
                    priority,
                    target,
                    params,
                })
            }
            // OPT and anything else: keep raw bytes (boundary is known).
            _ => Ok(RData::Unknown(rdata.to_vec())),
        }
    }

    /// Byte length of the name's first occurrence at `offset` in the message:
    /// label bytes plus terminator, or 2 for a compression pointer.
    fn name_len_at(&self, offset: usize) -> usize {
        let mut pos = offset;
        let mut hops = 0usize;
        loop {
            if pos >= self.buf.len() {
                return pos.saturating_sub(offset);
            }
            let len = self.buf[pos];
            if len & 0xC0 == 0xC0 {
                return pos + 2 - offset;
            }
            if len & 0xC0 != 0 {
                return pos + 1 - offset;
            }
            pos += 1;
            if len == 0 {
                return pos - offset;
            }
            if pos + len as usize > self.buf.len() {
                return self.buf.len() - offset;
            }
            pos += len as usize;
            hops += 1;
            if hops > MAX_NAME_LABELS {
                return pos - offset;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_query_message() -> Message {
        let name = Name::from_ascii("example.com").unwrap();
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(name, RecordType::A));
        message
    }

    #[test]
    fn name_parse_and_display() {
        let name = Name::from_ascii("example.com").unwrap();
        assert_eq!(name.to_string(), "example.com.");
        assert_eq!(Name::from_ascii("example.com.").unwrap(), name);
        assert_eq!(Name::from_ascii(".").unwrap(), Name::root());
        assert!(Name::from_ascii("").is_err());
        assert!(Name::from_ascii("a..b").is_err());
        assert!(Name::from_ascii(&"a".repeat(64)).is_err());
        assert!(Name::from_ascii("你好.example").is_err());
    }

    #[test]
    fn record_type_round_trips() {
        for rt in [
            RecordType::A,
            RecordType::NS,
            RecordType::CNAME,
            RecordType::SOA,
            RecordType::PTR,
            RecordType::MX,
            RecordType::TXT,
            RecordType::AAAA,
            RecordType::SRV,
            RecordType::OPT,
            RecordType::SVCB,
            RecordType::HTTPS,
            RecordType::Unknown(99),
        ] {
            assert_eq!(RecordType::from_u16(rt.to_u16()), rt);
        }
    }

    #[test]
    fn query_message_round_trips() {
        let message = sample_query_message();
        let bytes = message.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.metadata.id, 0x1234);
        assert_eq!(decoded.metadata.message_type, MessageType::Query);
        assert_eq!(decoded.metadata.op_code, OpCode::Query);
        assert!(decoded.metadata.recursion_desired);
        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].name().to_string(), "example.com.");
        assert_eq!(decoded.queries[0].query_type(), RecordType::A);
        assert_eq!(decoded.queries[0].query_class(), RecordClass::IN);
    }

    #[test]
    fn response_with_answers_round_trips() {
        let name = Name::from_ascii("example.com").unwrap();
        let mut response = Message::response(0x4321, OpCode::Query);
        response.metadata.recursion_desired = true;
        response.metadata.recursion_available = true;
        response.add_query(Query::query(name.clone(), RecordType::A));

        let a_record = Record::from_rdata(
            name.clone(),
            300,
            RData::A(rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        let aaaa_record = Record::from_rdata(
            name,
            300,
            RData::AAAA(rdata::AAAA(
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
            )),
        );
        response.add_answer(a_record);
        response.add_answer(aaaa_record);

        let bytes = response.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.metadata.id, 0x4321);
        assert_eq!(decoded.metadata.message_type, MessageType::Response);
        assert!(decoded.metadata.recursion_available);
        assert_eq!(decoded.answers.len(), 2);
        match &decoded.answers[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("expected A, got {other:?}"),
        }
        match &decoded.answers[1].data {
            RData::AAAA(aaaa) => {
                assert_eq!(
                    aaaa.0,
                    "2606:2800:220:1:248:1893:25c8:1946"
                        .parse::<Ipv6Addr>()
                        .unwrap()
                )
            }
            other => panic!("expected AAAA, got {other:?}"),
        }
    }

    #[test]
    fn parses_compressed_name_pointers() {
        // Hand-crafted response using name compression:
        // header (id=0x0001, flags=response+RD+RA, 1 question, 1 answer)
        // question: example.com A IN (labels at offset 12)
        // answer: name is a pointer back to offset 12 (0xC00C)
        let mut msg = vec![0u8; 12];
        msg[0..2].copy_from_slice(&[0x00, 0x01]);
        msg[2..4].copy_from_slice(&[0x81, 0x80]); // QR+RD+RA
        msg[4..6].copy_from_slice(&[0x00, 0x01]);
        msg[6..8].copy_from_slice(&[0x00, 0x01]);

        // Question name: 7 example 3 com 0
        msg.extend_from_slice(&[7]);
        msg.extend_from_slice(b"example");
        msg.extend_from_slice(&[3]);
        msg.extend_from_slice(b"com");
        msg.push(0);
        // QTYPE A, QCLASS IN
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // Answer: pointer to offset 12 (0xC00C)
        msg.extend_from_slice(&[0xC0, 0x0C]);
        // TYPE A, CLASS IN, TTL 300, RDLENGTH 4
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        msg.extend_from_slice(&[0x00, 0x04]);
        msg.extend_from_slice(&[93, 184, 216, 34]);

        let decoded = Message::from_bytes(&msg).unwrap();
        assert_eq!(decoded.queries[0].name().to_string(), "example.com.");
        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.answers[0].name().to_string(), "example.com.");
        match &decoded.answers[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn rejects_pointer_loops() {
        // Two pointers chasing each other: 0xC00C -> 0xC00C (self-loop).
        let mut msg = vec![0u8; 12];
        msg[2..4].copy_from_slice(&[0x81, 0x80]);
        msg[4..6].copy_from_slice(&[0x00, 0x01]);
        msg.extend_from_slice(&[0xC0, 0x0C]); // question name points to itself
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert!(Message::from_bytes(&msg).is_err());
    }

    #[test]
    fn rejects_truncated_messages() {
        assert!(Message::from_bytes(&[]).is_err());
        assert!(Message::from_bytes(&[0u8; 11]).is_err());

        // Header claims one question but the message ends early.
        let mut msg = vec![0u8; 12];
        msg[4..6].copy_from_slice(&[0x00, 0x01]);
        assert!(Message::from_bytes(&msg).is_err());
    }

    #[test]
    fn decodes_cname_and_txt_rdata() {
        let name = Name::from_ascii("www.example.com").unwrap();
        let mut response = Message::response(7, OpCode::Query);
        response.add_answer(Record::from_rdata(
            name,
            60,
            RData::CNAME(Name::from_ascii("example.com").unwrap()),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            60,
            RData::TXT(vec!["hello world".to_string(), "second".to_string()]),
        ));

        let bytes = response.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.answers.len(), 2);
        match &decoded.answers[0].data {
            RData::CNAME(target) => assert_eq!(target.to_string(), "example.com."),
            other => panic!("expected CNAME, got {other:?}"),
        }
        match &decoded.answers[1].data {
            RData::TXT(strings) => {
                assert_eq!(
                    strings,
                    &vec!["hello world".to_string(), "second".to_string()]
                )
            }
            other => panic!("expected TXT, got {other:?}"),
        }
    }

    #[test]
    fn rejects_soa_names_exceeding_rdata() {
        // A hostile SOA whose RDATA claims a 1-byte body but whose mname label
        // runs past the RDATA boundary (still inside the message). Previously
        // this panicked on `&rdata[mname_len + rname_len..]`.
        let mut msg = vec![0u8; 12];
        msg[0..2].copy_from_slice(&[0x00, 0x02]);
        msg[2..4].copy_from_slice(&[0x81, 0x80]);
        msg[6..8].copy_from_slice(&[0x00, 0x01]); // 1 answer
        msg.push(0x00); // answer name: root
        msg.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]); // TYPE SOA, CLASS IN
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60
        msg.extend_from_slice(&[0x00, 0x01]); // RDLENGTH 1
        msg.push(0x05); // rdata: mname label-length byte (declared RDATA = 1 byte)
        msg.extend_from_slice(b"aaaaa"); // mname label overruns the RDATA
        msg.push(0x00); // mname terminator
        msg.push(0x05); // rname label length
        msg.extend_from_slice(b"bbbbb"); // rname label overruns the RDATA
        msg.push(0x00); // rname terminator
        assert!(Message::from_bytes(&msg).is_err());
    }

    #[test]
    fn rejects_svcb_target_exceeding_rdata() {
        // A hostile HTTPS record whose RDATA declares only the 2-byte priority
        // but whose target name runs past the RDATA boundary. Previously this
        // panicked on `rdata[2 + target_len..]`.
        let mut msg = vec![0u8; 12];
        msg[0..2].copy_from_slice(&[0x00, 0x03]);
        msg[2..4].copy_from_slice(&[0x81, 0x80]);
        msg[6..8].copy_from_slice(&[0x00, 0x01]); // 1 answer
        msg.push(0x00); // answer name: root
        msg.extend_from_slice(&[0x00, 0x41, 0x00, 0x01]); // TYPE HTTPS, CLASS IN
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60
        msg.extend_from_slice(&[0x00, 0x02]); // RDLENGTH 2
        msg.extend_from_slice(&[0x00, 0x01]); // priority
        msg.push(0x05); // target label length
        msg.extend_from_slice(b"ccccc"); // target label overruns the RDATA
        msg.push(0x00); // target terminator
        assert!(Message::from_bytes(&msg).is_err());
    }

    #[test]
    fn preserves_additional_sections() {
        let mut response = Message::response(9, OpCode::Query);
        response.add_additional(Record::from_rdata(
            Name::root(),
            0,
            RData::Unknown(vec![0x00, 0x01, 0x02]),
        ));
        let bytes = response.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.additionals.len(), 1);
        assert_eq!(
            decoded.additionals[0].data,
            RData::Unknown(vec![0x00, 0x01, 0x02])
        );
    }

    #[test]
    fn compression_round_trips_and_shrinks() {
        // Several records sharing the same owner name must (a) round-trip and
        // (b) be emitted with a compression pointer instead of duplicated
        // labels, so the message fits the 512-byte UDP budget.
        let name = Name::from_ascii("www.example.com").unwrap();
        let mut response = Message::response(42, OpCode::Query);
        response.add_query(Query::query(name.clone(), RecordType::A));
        for octet in [[93u8, 184, 216, 34], [93, 184, 216, 35], [93, 184, 216, 36]] {
            response.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::A(rdata::A(Ipv4Addr::new(
                    octet[0], octet[1], octet[2], octet[3],
                ))),
            ));
        }
        response.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::AAAA(rdata::AAAA(
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
            )),
        ));

        let bytes = response.to_bytes().unwrap();

        // The second answer's owner name must be a pointer to the first.
        let header_len = 12;
        let qname_len = 1 + 3 + 1 + 7 + 1 + 3 + 1; // www.example.com + root
        let first_answer_name_offset = header_len + qname_len + 4; // + qtype/qclass
        assert_eq!(bytes[first_answer_name_offset] & 0xC0, 0xC0);

        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.answers.len(), 4);
        for answer in &decoded.answers {
            assert_eq!(answer.name(), &name);
        }

        // Compare against the uncompressed size: four identical 17-byte owner
        // names would alone cost 68 bytes; with compression they cost 8, so
        // the whole response stays well under 128 bytes.
        assert!(bytes.len() < 128, "expected compression to shrink message");
    }

    #[test]
    fn compression_handles_shared_suffixes() {
        let a = Name::from_ascii("alpha.example.com").unwrap();
        let b = Name::from_ascii("beta.example.com").unwrap();
        let mut response = Message::response(7, OpCode::Query);
        response.add_answer(Record::from_rdata(a.clone(), 60, RData::CNAME(b.clone())));
        response.add_answer(Record::from_rdata(
            b,
            60,
            RData::A(rdata::A(Ipv4Addr::new(1, 2, 3, 4))),
        ));

        let bytes = response.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.answers.len(), 2);
        match &decoded.answers[0].data {
            RData::CNAME(target) => assert_eq!(target.to_string(), "beta.example.com."),
            other => panic!("expected CNAME, got {other:?}"),
        }
        match &decoded.answers[1].data {
            RData::A(ip) => assert_eq!(ip.0, Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn compression_never_emits_forward_pointer() {
        // The first name in a message has nothing to point at yet: it must be
        // written literally, with no 0xC0 byte anywhere in the query section.
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
        ));
        let bytes = query.to_bytes().unwrap();
        assert!(!bytes[12..].contains(&0xC0));
    }

    proptest::proptest! {
        #[test]
        fn prop_name_encode_round_trip(
            label_count in 1usize..=8,
            label_len in 1usize..=63,
        ) {
            let mut labels = Vec::new();
            for i in 0..label_count {
                let len = (label_len + i) % 63 + 1;
                labels.push(vec![b'a' + (i % 26) as u8; len]);
            }
            let name = Name { labels };
            let mut compressor = NameCompressor::new();
            let mut buf = Vec::new();
            compressor.write_name(&mut buf, &name).unwrap();
            let decoded = super::Decoder::new(&buf, 0).read_name().expect("decodes");
            assert_eq!(decoded.to_string(), name.to_string());
        }
    }
}
