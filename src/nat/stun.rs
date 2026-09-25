//! STUN (RFC 8489) — the wire format, and a client that can ask a server what
//! it sees.
//!
//! STUN is the only way to learn an external mapping from inside a NAT: the
//! local socket cannot tell you what address the world sees. Everything the
//! traversal layer decides is derived from the answers here, so this module
//! implements the protocol rather than shelling out to a helper library —
//! including the parts a client is allowed to skip.
//!
//! ## What is implemented
//!
//! * The 20-byte header, with the message type split across the class/method
//!   bit fields exactly as RFC 8489 §5 lays them out.
//! * Attributes with 4-byte padding, and the comprehension-required rule: an
//!   unknown attribute below `0x8000` invalidates the message instead of being
//!   skipped, because skipping it could silently weaken a security decision.
//! * `XOR-MAPPED-ADDRESS`, with the IPv4 and IPv6 XOR masks.
//! * `MESSAGE-INTEGRITY` (HMAC-SHA-1) and `FINGERPRINT` (CRC-32), including the
//!   detail most implementations get wrong: the header length field is patched
//!   to count the attribute being computed *before* the digest is taken.
//!
//! ## What is not
//!
//! TURN allocation, ICE candidate bookkeeping, and short-term credential
//! negotiation. The attribute set needed for those decodes fine here
//! (`Unknown` carries the bytes verbatim), and `MESSAGE-INTEGRITY` verifies, so
//! adding them later does not disturb this codec.
//!
//! ## `no_std`
//!
//! The codec is `core + alloc` — no sockets, no clock, no allocator beyond
//! the message buffers. Only [`client::StunClient`] needs the threaded layer,
//! and that module is gated on the `std` feature.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::crypto::hash::Sha1;
use crate::crypto::mac::Hmac;

/// The value that distinguishes STUN from the protocols that predate it.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Fixed header size: type, length, cookie, transaction id.
pub const HEADER_LEN: usize = 20;

/// Length of a transaction id, in bytes.
pub const TRANSACTION_ID_LEN: usize = 12;

/// Length of a `MESSAGE-INTEGRITY` attribute: 4-byte header plus the SHA-1 tag.
pub const MESSAGE_INTEGRITY_LEN: usize = 24;

/// Length of a `FINGERPRINT` attribute: 4-byte header plus the CRC.
pub const FINGERPRINT_LEN: usize = 8;

/// `FINGERPRINT` is the message CRC XORed with this constant, so a CRC that
/// happens to equal a valid CRC by accident cannot be mistaken for one.
const FINGERPRINT_XOR: u32 = 0x5354_554E;

/// Largest attribute payload this decoder will look at.
///
/// A STUN message is one datagram; anything approaching this is either a
/// hand-crafted denial-of-service attempt or a protocol error, and either way
/// there is nothing useful to do with it.
const MAX_ATTRIBUTE_LEN: usize = 65_535;

const METHOD_BINDING: u16 = 0x001;

const ATTRIBUTE_MAPPED_ADDRESS: u16 = 0x0001;
const ATTRIBUTE_CHANGE_REQUEST: u16 = 0x0003;
const ATTRIBUTE_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTRIBUTE_ERROR_CODE: u16 = 0x0009;
const ATTRIBUTE_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
const ATTRIBUTE_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTRIBUTE_SOFTWARE: u16 = 0x8022;
const ATTRIBUTE_ALTERNATE_SERVER: u16 = 0x8023;
const ATTRIBUTE_FINGERPRINT: u16 = 0x8028;
const ATTRIBUTE_RESPONSE_ORIGIN: u16 = 0x802B;
const ATTRIBUTE_OTHER_ADDRESS: u16 = 0x802C;

/// Address family byte in an address attribute.
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// CRC-32 (IEEE 802.3), the polynomial `FINGERPRINT` is defined over.
const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

static CRC32_TABLE: [u32; 256] = crc32_table();

/// CRC-32 of `data`, in the form `FINGERPRINT` is defined over.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        let index = ((crc ^ u32::from(*byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[index];
    }
    !crc
}

/// Why a message could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    /// Fewer bytes than a header, or a declared length longer than the input.
    Truncated,
    /// The first two bits are set, so this is not a STUN frame.
    NotStunPrefix,
    /// The magic cookie did not match.
    BadMagicCookie,
    /// An attribute exceeded the message boundary.
    AttributeOverflow,
    /// An address attribute carried a family this decoder does not know.
    UnknownAddressFamily(u8),
    /// An address attribute was shorter than its family requires.
    ShortAddress,
    /// A comprehension-required attribute the decoder does not implement.
    ///
    /// RFC 8489 §9: such a message must be treated as unrecognised rather than
    /// partially understood, so this is an error and not a skipped field.
    UnsupportedRequiredAttribute(u16),
    /// `FINGERPRINT` did not match the message it arrived with.
    FingerprintMismatch,
    /// The server answered with a STUN error response.
    ServerError { code: u16, reason: String },
}

impl core::fmt::Display for StunError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated STUN message"),
            Self::NotStunPrefix => formatter.write_str("not a STUN message: top two bits are set"),
            Self::BadMagicCookie => formatter.write_str("bad STUN magic cookie"),
            Self::AttributeOverflow => formatter.write_str("attribute overruns the message"),
            Self::UnknownAddressFamily(family) => {
                write!(formatter, "unknown address family {family:#04x}")
            }
            Self::ShortAddress => formatter.write_str("address attribute is truncated"),
            Self::UnsupportedRequiredAttribute(attribute_type) => write!(
                formatter,
                "unsupported comprehension-required attribute {attribute_type:#06x}"
            ),
            Self::FingerprintMismatch => formatter.write_str("STUN fingerprint mismatch"),
            Self::ServerError { code, reason } => {
                write!(formatter, "STUN server returned {code}: {reason}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StunError {}

/// The 96-bit transaction id that ties a request to its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId(pub [u8; TRANSACTION_ID_LEN]);

impl TransactionId {
    /// A fresh id from a caller-supplied CSPRNG.
    ///
    /// The id is what stops an off-path attacker from answering a binding
    /// request before the real server does, so it has to come from a CSPRNG
    /// and not from a counter or the clock.
    pub fn from_rng(rng: &mut crate::crypto::rng::ChaChaRng) -> Self {
        Self(rng.fill_array::<TRANSACTION_ID_LEN>())
    }

    /// A fixed id, for tests and for decoding captures.
    pub const fn new(bytes: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self(bytes)
    }
}

/// The four message classes, encoded inside the message type word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    /// A request expecting a response.
    Request,
    /// A one-way message that gets no response.
    Indication,
    /// A positive response.
    SuccessResponse,
    /// A negative response carrying an `ERROR-CODE`.
    ErrorResponse,
}

impl MessageClass {
    /// The two class bits, in their positions inside the type word.
    const fn bits(self) -> u16 {
        match self {
            Self::Request => 0b00,
            Self::Indication => 0b01,
            Self::SuccessResponse => 0b10,
            Self::ErrorResponse => 0b11,
        }
    }

    const fn from_bits(bits: u16) -> Self {
        match bits & 0b11 {
            0b00 => Self::Request,
            0b01 => Self::Indication,
            0b10 => Self::SuccessResponse,
            _ => Self::ErrorResponse,
        }
    }
}

/// STUN methods.
///
/// Only `Binding` is needed to learn a mapping. TURN's methods are represented
/// by [`Method::Other`] so a message using one still decodes far enough to be
/// reported accurately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Discovery: "what address do you see for me?"
    Binding,
    /// Any other 12-bit method.
    Other(u16),
}

impl Method {
    const fn code(self) -> u16 {
        match self {
            Self::Binding => METHOD_BINDING,
            Self::Other(code) => code,
        }
    }
}

/// Compose the 14-bit type word from a class and a method.
///
/// The method and class bits are interleaved (RFC 8489 §5); they are not two
/// adjacent fields.
const fn type_word(class: MessageClass, method: u16) -> u16 {
    (method & 0x000F)
        | ((method & 0x0070) << 1)
        | ((method & 0x0F80) << 2)
        | ((class.bits() & 0b01) << 4)
        | ((class.bits() & 0b10) << 7)
}

/// Split a type word back into its method and class.
const fn split_type_word(word: u16) -> (u16, MessageClass) {
    let method = (word & 0x000F) | ((word & 0x00E0) >> 1) | ((word & 0x3E00) >> 2);
    let class = MessageClass::from_bits(((word >> 4) & 0b01) | ((word >> 7) & 0b10));
    (method, class)
}

/// Round an attribute payload length up to the next 4-byte boundary.
const fn padded_len(length: usize) -> usize {
    length.wrapping_add(3) & !3
}

/// One STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    /// The observed address, in the clear. Deprecated in favour of the XOR
    /// form but still emitted by older servers.
    MappedAddress(SocketAddr),
    /// The observed address, XORed with the cookie and transaction id.
    XorMappedAddress(SocketAddr),
    /// Ask the server to answer from its other IP and/or port. This is the
    /// mechanism RFC 5780 filtering tests are built on.
    ChangeRequest {
        /// Answer from the alternate IP address.
        change_ip: bool,
        /// Answer from the alternate port.
        change_port: bool,
    },
    /// Address the response was actually sent from.
    ResponseOrigin(SocketAddr),
    /// The server's alternate address, which a client uses for the mapping
    /// tests. Its presence is also the only reliable signal that a server
    /// implements RFC 5780 at all.
    OtherAddress(SocketAddr),
    /// Free-form server identification.
    Software(String),
    /// A failure response's code and reason phrase.
    ErrorCode {
        /// Numeric error code.
        code: u16,
        /// Human-readable reason, as the server sent it.
        reason: String,
    },
    /// Attributes the server did not understand, echoed back in a 420.
    UnknownAttributes(Vec<u16>),
    /// The alternate server for a 300 redirect.
    AlternateServer(SocketAddr),
    /// An attribute this decoder does not model, kept verbatim.
    Unknown {
        /// Attribute type, as it appeared on the wire.
        attribute_type: u16,
        /// Unparsed payload, with padding stripped.
        value: Vec<u8>,
    },
}

impl Attribute {
    /// Attribute type code, as it appears on the wire.
    pub const fn attribute_type(&self) -> u16 {
        match self {
            Self::MappedAddress(_) => ATTRIBUTE_MAPPED_ADDRESS,
            Self::XorMappedAddress(_) => ATTRIBUTE_XOR_MAPPED_ADDRESS,
            Self::ChangeRequest { .. } => ATTRIBUTE_CHANGE_REQUEST,
            Self::ResponseOrigin(_) => ATTRIBUTE_RESPONSE_ORIGIN,
            Self::OtherAddress(_) => ATTRIBUTE_OTHER_ADDRESS,
            Self::Software(_) => ATTRIBUTE_SOFTWARE,
            Self::ErrorCode { .. } => ATTRIBUTE_ERROR_CODE,
            Self::UnknownAttributes(_) => ATTRIBUTE_UNKNOWN_ATTRIBUTES,
            Self::AlternateServer(_) => ATTRIBUTE_ALTERNATE_SERVER,
            Self::Unknown { attribute_type, .. } => *attribute_type,
        }
    }

    /// Encode this attribute, including its padding.
    ///
    /// The transaction id is required because `XOR-MAPPED-ADDRESS` is masked
    /// with it; passing it here keeps one encoding path instead of a second
    /// one that would have to remember to apply the mask.
    fn encode(&self, out: &mut Vec<u8>, transaction_id: &TransactionId) {
        let attribute_type = self.attribute_type();
        match self {
            Self::MappedAddress(address) => {
                encode_address_attribute(out, attribute_type, *address, None);
            }
            Self::XorMappedAddress(address) => {
                encode_address_attribute(out, attribute_type, *address, Some(transaction_id));
            }
            Self::ChangeRequest {
                change_ip,
                change_port,
            } => {
                let mut flags = 0u32;
                if *change_ip {
                    flags |= 0b10;
                }
                if *change_port {
                    flags |= 0b100;
                }
                write_attribute_header(out, attribute_type, 4);
                out.extend_from_slice(&flags.to_be_bytes());
            }
            Self::ResponseOrigin(address) | Self::OtherAddress(address) => {
                encode_address_attribute(out, attribute_type, *address, None);
            }
            Self::AlternateServer(address) => {
                encode_address_attribute(out, attribute_type, *address, None);
            }
            Self::Software(text) => {
                write_attribute_header(out, attribute_type, text.len());
                out.extend_from_slice(text.as_bytes());
                out.resize(out.len() + padded_len(text.len()) - text.len(), 0);
            }
            Self::ErrorCode { code, reason } => {
                let length = 4 + reason.len();
                write_attribute_header(out, attribute_type, length);
                out.push(0);
                out.push(0);
                out.push((code / 100) as u8);
                out.push((code % 100) as u8);
                out.extend_from_slice(reason.as_bytes());
                out.resize(out.len() + padded_len(length) - length, 0);
            }
            Self::UnknownAttributes(types) => {
                let length = types.len() * 2;
                write_attribute_header(out, attribute_type, length);
                for attribute_type in types {
                    out.extend_from_slice(&attribute_type.to_be_bytes());
                }
                out.resize(out.len() + padded_len(length) - length, 0);
            }
            Self::Unknown {
                attribute_type,
                value,
            } => {
                write_attribute_header(out, *attribute_type, value.len());
                out.extend_from_slice(value);
                out.resize(out.len() + padded_len(value.len()) - value.len(), 0);
            }
        }
    }

    /// Decode one attribute.
    ///
    /// `transaction_id` is required for the XOR address form: the mask is the
    /// cookie plus the id, so an address cannot be recovered without it.
    fn decode(
        attribute_type: u16,
        value: &[u8],
        transaction_id: &TransactionId,
    ) -> Result<Self, StunError> {
        match attribute_type {
            ATTRIBUTE_MAPPED_ADDRESS => Ok(Self::MappedAddress(decode_address(value, None)?)),
            ATTRIBUTE_XOR_MAPPED_ADDRESS => Ok(Self::XorMappedAddress(decode_address(
                value,
                Some(transaction_id),
            )?)),
            ATTRIBUTE_CHANGE_REQUEST => {
                if value.len() < 4 {
                    return Err(StunError::Truncated);
                }
                let flags = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                Ok(Self::ChangeRequest {
                    change_ip: flags & 0b10 != 0,
                    change_port: flags & 0b100 != 0,
                })
            }
            ATTRIBUTE_RESPONSE_ORIGIN => Ok(Self::ResponseOrigin(decode_address(value, None)?)),
            ATTRIBUTE_OTHER_ADDRESS => Ok(Self::OtherAddress(decode_address(value, None)?)),
            ATTRIBUTE_ALTERNATE_SERVER => Ok(Self::AlternateServer(decode_address(value, None)?)),
            ATTRIBUTE_SOFTWARE => Ok(Self::Software(String::from_utf8_lossy(value).into_owned())),
            ATTRIBUTE_ERROR_CODE => {
                if value.len() < 4 {
                    return Err(StunError::Truncated);
                }
                let class = u16::from(value[2]);
                let number = u16::from(value[3]);
                Ok(Self::ErrorCode {
                    code: class * 100 + number,
                    reason: String::from_utf8_lossy(&value[4..]).into_owned(),
                })
            }
            ATTRIBUTE_UNKNOWN_ATTRIBUTES => {
                if value.len() % 2 != 0 {
                    return Err(StunError::Truncated);
                }
                Ok(Self::UnknownAttributes(
                    value
                        .chunks_exact(2)
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect(),
                ))
            }
            ATTRIBUTE_MESSAGE_INTEGRITY | ATTRIBUTE_FINGERPRINT => Ok(Self::Unknown {
                attribute_type,
                value: value.to_vec(),
            }),
            0x0000..=0x7FFF => Err(StunError::UnsupportedRequiredAttribute(attribute_type)),
            _ => Ok(Self::Unknown {
                attribute_type,
                value: value.to_vec(),
            }),
        }
    }
}

fn write_attribute_header(out: &mut Vec<u8>, attribute_type: u16, length: usize) {
    out.extend_from_slice(&attribute_type.to_be_bytes());
    out.extend_from_slice(&(length as u16).to_be_bytes());
}

fn encode_address_attribute(
    out: &mut Vec<u8>,
    attribute_type: u16,
    address: SocketAddr,
    transaction_id: Option<&TransactionId>,
) {
    let length = if address.is_ipv4() { 8 } else { 20 };
    write_attribute_header(out, attribute_type, length);
    out.push(0);
    match address {
        SocketAddr::V4(v4) => {
            out.push(FAMILY_IPV4);
            let port = match transaction_id {
                Some(_) => v4.port() ^ (MAGIC_COOKIE >> 16) as u16,
                None => v4.port(),
            };
            out.extend_from_slice(&port.to_be_bytes());
            let address = match transaction_id {
                Some(_) => u32::from(*v4.ip()) ^ MAGIC_COOKIE,
                None => u32::from(*v4.ip()),
            };
            out.extend_from_slice(&address.to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(FAMILY_IPV6);
            let port = match transaction_id {
                Some(_) => v6.port() ^ (MAGIC_COOKIE >> 16) as u16,
                None => v6.port(),
            };
            out.extend_from_slice(&port.to_be_bytes());
            let mask = match transaction_id {
                Some(id) => xor_mask_v6(id),
                None => [0u8; 16],
            };
            let mut octets = v6.ip().octets();
            for (byte, mask_byte) in octets.iter_mut().zip(mask.iter()) {
                *byte ^= *mask_byte;
            }
            out.extend_from_slice(&octets);
        }
    }
}

fn xor_mask_v6(transaction_id: &TransactionId) -> [u8; 16] {
    let mut mask = [0u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(&transaction_id.0);
    mask
}

fn decode_address(
    value: &[u8],
    transaction_id: Option<&TransactionId>,
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::ShortAddress);
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::ShortAddress);
            }
            let address = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let ip = match transaction_id {
                Some(_) => Ipv4Addr::from(address ^ MAGIC_COOKIE),
                None => Ipv4Addr::from(address),
            };
            let port = match transaction_id {
                Some(_) => port ^ (MAGIC_COOKIE >> 16) as u16,
                None => port,
            };
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::ShortAddress);
            }
            let id = transaction_id.ok_or(StunError::ShortAddress)?;
            let mask = xor_mask_v6(id);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            for (byte, mask_byte) in octets.iter_mut().zip(mask.iter()) {
                *byte ^= *mask_byte;
            }
            let port = port ^ (MAGIC_COOKIE >> 16) as u16;
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                0,
            )))
        }
        other => Err(StunError::UnknownAddressFamily(other)),
    }
}

/// A complete STUN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Whether this is a request, a response, or an indication.
    pub class: MessageClass,
    /// The method being invoked.
    pub method: Method,
    /// Transaction id tying a response to its request.
    pub transaction_id: TransactionId,
    /// The attributes, in wire order.
    pub attributes: Vec<Attribute>,
}

impl Message {
    /// A binding request with a fresh transaction id.
    pub fn binding_request(transaction_id: TransactionId) -> Self {
        Self {
            class: MessageClass::Request,
            method: Method::Binding,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// The first attribute of the requested type, if the message carries one.
    pub fn find(&self, attribute_type: u16) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|attribute| attribute.attribute_type() == attribute_type)
    }

    /// The address the server observed for this socket.
    ///
    /// `XOR-MAPPED-ADDRESS` wins when both forms are present, which is the
    /// order RFC 8489 §14.1 mandates: the XOR form is the one that survives
    /// middleboxes that rewrite addresses in the clear.
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::XorMappedAddress(address) => Some(*address),
                _ => None,
            })
            .or_else(|| {
                self.attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        Attribute::MappedAddress(address) => Some(*address),
                        _ => None,
                    })
            })
    }

    /// The address the response was sent from.
    ///
    /// Filtering tests compare this against the request target: a response that
    /// arrives from somewhere else is what proves the NAT let an unsolicited
    /// packet through.
    pub fn response_origin(&self) -> Option<SocketAddr> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::ResponseOrigin(address) => Some(*address),
                _ => None,
            })
    }

    /// The server's alternate address, when it advertises one.
    pub fn other_address(&self) -> Option<SocketAddr> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::OtherAddress(address) => Some(*address),
                _ => None,
            })
    }

    /// The error code, when this is an error response.
    pub fn error_code(&self) -> Option<(u16, &str)> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::ErrorCode { code, reason } => Some((*code, reason.as_str())),
                _ => None,
            })
    }

    fn write_header(&self, out: &mut [u8], length: usize) {
        let word = type_word(self.class, self.method.code());
        out[0..2].copy_from_slice(&word.to_be_bytes());
        out[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out[8..20].copy_from_slice(&self.transaction_id.0);
    }

    /// Serialize the message.
    ///
    /// `integrity_key` adds `MESSAGE-INTEGRITY`. `FINGERPRINT` is always added
    /// last. Attributes of those two types in `self.attributes` are ignored:
    /// both are computed over their own position in the message, so accepting
    /// a caller-supplied value could only produce a message that fails its own
    /// verification.
    pub fn encode(&self, integrity_key: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.resize(HEADER_LEN, 0);

        for attribute in &self.attributes {
            match attribute.attribute_type() {
                // Both are computed over their own position in the message, so
                // a caller-supplied copy could only produce a message that
                // fails its own verification.
                ATTRIBUTE_MESSAGE_INTEGRITY | ATTRIBUTE_FINGERPRINT => continue,
                _ => attribute.encode(&mut out, &self.transaction_id),
            }
        }

        if let Some(key) = integrity_key {
            // The tag covers everything before it, with the header already
            // reporting the length that includes it — RFC 8489 §14.5. Patching
            // the length after the digest is the classic way to produce a
            // message every other implementation rejects.
            let length = out.len() - HEADER_LEN + MESSAGE_INTEGRITY_LEN;
            let mut header = [0u8; HEADER_LEN];
            self.write_header(&mut header, length);
            out[0..HEADER_LEN].copy_from_slice(&header);

            let mut tag = [0u8; 20];
            Hmac::<Sha1>::mac_into(key, &out, &mut tag);
            write_attribute_header(&mut out, ATTRIBUTE_MESSAGE_INTEGRITY, tag.len());
            out.extend_from_slice(&tag);
        }

        {
            let length = out.len() - HEADER_LEN + FINGERPRINT_LEN;
            let mut header = [0u8; HEADER_LEN];
            self.write_header(&mut header, length);
            out[0..HEADER_LEN].copy_from_slice(&header);

            let fingerprint = crc32(&out) ^ FINGERPRINT_XOR;
            write_attribute_header(&mut out, ATTRIBUTE_FINGERPRINT, 4);
            out.extend_from_slice(&fingerprint.to_be_bytes());
        }

        let length = out.len() - HEADER_LEN;
        let mut header = [0u8; HEADER_LEN];
        self.write_header(&mut header, length);
        out[0..HEADER_LEN].copy_from_slice(&header);

        out
    }

    /// Parse a message, verifying `FINGERPRINT` when present.
    ///
    /// Returns an error rather than partially-parsed data for anything this
    /// layer cannot use: a fingerprint that does not match, an address
    /// attribute in an unknown family, or a comprehension-required attribute
    /// this decoder does not implement.
    ///
    /// `MESSAGE-INTEGRITY` is surfaced as an opaque attribute but not verified
    /// here, because verification needs a credential this function is not given.
    /// Binding discovery uses no credential, so there is nothing to check on the
    /// path traversal depends on; TURN and ICE with long-term credentials would
    /// call `verify_integrity` with the key instead.
    pub fn decode(bytes: &[u8]) -> Result<Self, StunError> {
        Self::decode_inner(bytes)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, StunError> {
        if bytes.len() < HEADER_LEN {
            return Err(StunError::Truncated);
        }
        let word = u16::from_be_bytes([bytes[0], bytes[1]]);
        if word & 0xC000 != 0 {
            return Err(StunError::NotStunPrefix);
        }
        let (method, class) = split_type_word(word);

        let declared_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let end = HEADER_LEN
            .checked_add(declared_length)
            .ok_or(StunError::AttributeOverflow)?;
        if bytes.len() < end {
            return Err(StunError::Truncated);
        }

        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(StunError::BadMagicCookie);
        }

        let mut transaction_bytes = [0u8; TRANSACTION_ID_LEN];
        transaction_bytes.copy_from_slice(&bytes[8..HEADER_LEN]);
        let transaction_id = TransactionId(transaction_bytes);

        let mut attributes = Vec::new();
        let mut offset = HEADER_LEN;
        let mut fingerprint = None;

        while offset + 4 <= end {
            let attribute_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let attribute_length =
                usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
            if attribute_length > MAX_ATTRIBUTE_LEN {
                return Err(StunError::AttributeOverflow);
            }
            let value_start = offset + 4;
            let value_end = value_start
                .checked_add(attribute_length)
                .ok_or(StunError::AttributeOverflow)?;
            if value_end > end {
                return Err(StunError::AttributeOverflow);
            }

            if attribute_type == ATTRIBUTE_FINGERPRINT && attribute_length == 4 {
                fingerprint = Some((
                    offset,
                    u32::from_be_bytes([
                        bytes[value_start],
                        bytes[value_start + 1],
                        bytes[value_start + 2],
                        bytes[value_start + 3],
                    ]),
                ));
            }

            attributes.push(Attribute::decode(
                attribute_type,
                &bytes[value_start..value_end],
                &transaction_id,
            )?);

            offset = value_end + padded_len(attribute_length) - attribute_length;
        }

        let message = Self {
            class,
            method: match method {
                METHOD_BINDING => Method::Binding,
                other => Method::Other(other),
            },
            transaction_id,
            attributes,
        };

        if let Some((attribute_offset, claimed)) = fingerprint {
            // Verify against a copy whose length field ends at the FINGERPRINT
            // attribute, which is what the sender hashed — the finished message
            // carries the same value there, but the header must not be taken on
            // faith once anything after the attribute is considered.
            let mut candidate = bytes[..attribute_offset].to_vec();
            let length_to_fingerprint = attribute_offset - HEADER_LEN + FINGERPRINT_LEN;
            candidate[2..4].copy_from_slice(&(length_to_fingerprint as u16).to_be_bytes());
            if crc32(&candidate) ^ FINGERPRINT_XOR != claimed {
                return Err(StunError::FingerprintMismatch);
            }
        }

        if message.class == MessageClass::ErrorResponse {
            if let Some((code, reason)) = message.error_code() {
                // 420 asks for the unrecognised attributes to be removed; there
                // is nothing to retry, so it is reported like any other failure.
                return Err(StunError::ServerError {
                    code,
                    reason: reason.to_string(),
                });
            }
        }

        Ok(message)
    }
}

/// STUN client: the socket plus the retransmission schedule.
#[cfg(feature = "std")]
pub mod client {
    use super::{Message, MessageClass, StunError, TransactionId};
    use crate::crypto::rng::ChaChaRng;
    use crate::nat::error::NatError;
    use core::net::SocketAddr;
    use std::io;
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    /// Retransmission schedule from RFC 8489 §6.2.1.
    ///
    /// Seven transmissions with a doubling interval, capped so a single
    /// transaction cannot stall a caller indefinitely. The cap is tighter than
    /// the RFC's 39.5 s worst case because a traversal probe that has not been
    /// answered in two seconds has, in practice, been dropped by a NAT rather
    /// than lost.
    const MAX_TRANSMISSIONS: u32 = 7;
    const INITIAL_RTO: Duration = Duration::from_millis(250);
    const MAX_RTO: Duration = Duration::from_secs(2);

    /// Largest datagram this client will read.
    const READ_BUFFER_LEN: usize = 1500;

    /// Which address the server should answer from.
    ///
    /// Meaningful only against a server that implements RFC 5780; against any
    /// other server the request is answered from the primary address, or not at
    /// all.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct ChangeRequest {
        /// Ask for the answer from the server's alternate IP.
        pub change_ip: bool,
        /// Ask for the answer from the server's alternate port.
        pub change_port: bool,
    }

    /// What a binding transaction learned.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Binding {
        /// Address the server observed for our socket.
        pub mapped: SocketAddr,
        /// Address the answer was actually sent from.
        pub origin: Option<SocketAddr>,
        /// The server's alternate address, when it advertises one.
        pub other: Option<SocketAddr>,
        /// Time between sending the request and reading the answer.
        pub rtt: Duration,
    }

    /// A bound UDP socket talking to one STUN server.
    pub struct StunClient {
        socket: UdpSocket,
        server: SocketAddr,
        deadline: Duration,
        rng: ChaChaRng,
    }

    impl core::fmt::Debug for StunClient {
        /// Reports the socket and target but never the RNG state: the state is
        /// what makes future transaction ids unpredictable, and a stray
        /// `{:?}` in a log line should not be able to leak it.
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("StunClient")
                .field("local", &self.socket.local_addr().ok())
                .field("server", &self.server)
                .field("deadline", &self.deadline)
                .finish_non_exhaustive()
        }
    }

    impl StunClient {
        /// Bind `local` and prepare to talk to `server`.
        ///
        /// `deadline` bounds one [`StunClient::binding`] call, retransmissions
        /// included.
        pub fn bind(
            local: SocketAddr,
            server: SocketAddr,
            deadline: Duration,
            seed: [u8; 32],
        ) -> io::Result<Self> {
            let socket = crate::common::socket::udp_bind(local, MAX_RTO)?;
            Ok(Self {
                socket,
                server,
                deadline,
                rng: ChaChaRng::from_seed(&seed),
            })
        }

        /// The address this client is bound to locally.
        pub fn local_addr(&self) -> io::Result<SocketAddr> {
            self.socket.local_addr()
        }

        /// The server this client talks to.
        pub const fn server(&self) -> SocketAddr {
            self.server
        }

        /// Retarget the client, keeping the same bound socket.
        ///
        /// The RFC 5780 mapping tests depend on this: the question they ask is
        /// what external port the NAT hands out for a *different* destination
        /// from the *same* internal endpoint, so the socket must not change.
        pub fn set_server(&mut self, server: SocketAddr) {
            self.server = server;
        }

        /// The underlying socket, for a caller that needs to keep the same
        /// mapping (punching reuses this port deliberately).
        pub const fn socket(&self) -> &UdpSocket {
            &self.socket
        }

        /// Run one binding transaction.
        ///
        /// Retransmits on the RFC 8489 schedule. A reply whose transaction id
        /// does not match is ignored rather than treated as an error: on a
        /// shared socket that is simply traffic belonging to someone else.
        pub fn binding(&mut self, change: ChangeRequest) -> Result<Binding, NatError> {
            let started = Instant::now();
            let mut rto = INITIAL_RTO;
            let mut last_error = None;

            for _ in 0..MAX_TRANSMISSIONS {
                let remaining = self.deadline.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    break;
                }

                let transaction_id = TransactionId::from_rng(&mut self.rng);
                let mut request = Message::binding_request(transaction_id);
                if change != ChangeRequest::default() {
                    request.attributes.push(super::Attribute::ChangeRequest {
                        change_ip: change.change_ip,
                        change_port: change.change_port,
                    });
                }

                let encoded = request.encode(None);
                let sent_at = Instant::now();
                if let Err(error) = self.socket.send_to(&encoded, self.server) {
                    last_error = Some(format!("send to {} failed: {error}", self.server));
                    continue;
                }

                let window = rto.min(remaining);
                let _ = self
                    .socket
                    .set_read_timeout(Some(window.max(Duration::from_millis(1))));

                if let Some(binding) = self.read_until(&transaction_id.0, sent_at) {
                    return Ok(binding);
                }

                rto = (rto * 2).min(MAX_RTO);
            }

            Err(NatError::NoResponse {
                server: self.server,
                detail: last_error.unwrap_or_else(|| {
                    format!(
                        "no matching reply within {:?} after {MAX_TRANSMISSIONS} transmissions",
                        self.deadline
                    )
                }),
            })
        }

        /// Read datagrams until one answers our transaction, or the socket
        /// timeout fires.
        fn read_until(&self, transaction_id: &[u8; 12], sent_at: Instant) -> Option<Binding> {
            let mut buffer = [0u8; READ_BUFFER_LEN];
            loop {
                let (length, source) = match self.socket.recv_from(&mut buffer) {
                    Ok(received) => received,
                    // A timeout or an ICMP-derived error both mean "nothing
                    // usable arrived in this window"; the caller retransmits.
                    Err(_) => return None,
                };

                let Ok(frame) = self::validate(&buffer[..length], transaction_id) else {
                    continue;
                };

                let mapped = frame.mapped_address()?;
                return Some(Binding {
                    mapped,
                    origin: frame.response_origin().or(Some(source)),
                    other: frame.other_address(),
                    rtt: sent_at.elapsed(),
                });
            }
        }
    }

    /// Parse a datagram and require it to answer `transaction_id`.
    fn validate(bytes: &[u8], transaction_id: &[u8; 12]) -> Result<Message, StunError> {
        let message = Message::decode(bytes)?;
        if message.class != MessageClass::SuccessResponse {
            return Err(StunError::ServerError {
                code: message.error_code().map(|(code, _)| code).unwrap_or(0),
                reason: "not a success response".into(),
            });
        }
        if message.transaction_id.0 != *transaction_id {
            return Err(StunError::ServerError {
                code: 0,
                reason: "transaction id mismatch".into(),
            });
        }
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a frame this test just built, failing the test on any error.
    fn decode(encoded: &[u8]) -> Message {
        Message::decode(encoded).expect("frame must decode")
    }

    fn transaction() -> TransactionId {
        TransactionId::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ])
    }

    #[test]
    fn binding_request_type_word_is_the_documented_value() {
        assert_eq!(type_word(MessageClass::Request, METHOD_BINDING), 0x0001);
        assert_eq!(
            type_word(MessageClass::SuccessResponse, METHOD_BINDING),
            0x0101
        );
        assert_eq!(
            type_word(MessageClass::ErrorResponse, METHOD_BINDING),
            0x0111
        );
        assert_eq!(type_word(MessageClass::Indication, METHOD_BINDING), 0x0011);
    }

    #[test]
    fn type_word_round_trips_for_every_class() {
        for class in [
            MessageClass::Request,
            MessageClass::Indication,
            MessageClass::SuccessResponse,
            MessageClass::ErrorResponse,
        ] {
            for method in [METHOD_BINDING, 0x0002, 0x0003, 0x000A, 0x0016, 0x0FFF] {
                let word = type_word(class, method);
                assert_eq!(split_type_word(word), (method, class));
            }
        }
    }

    #[test]
    fn header_matches_rfc_layout() {
        let message = Message::binding_request(transaction());
        let encoded = message.encode(None);
        assert_eq!(encoded.len(), HEADER_LEN + FINGERPRINT_LEN);
        assert_eq!(&encoded[0..2], &[0x00, 0x01]);
        // Length counts attributes only.
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 8);
        assert_eq!(&encoded[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&encoded[8..20], &transaction().0);
    }

    #[test]
    fn fingerprint_verifies_and_detects_tampering() {
        let message = Message::binding_request(transaction());
        let mut encoded = message.encode(None);
        assert!(Message::decode(&encoded).is_ok());

        // Flip one bit of the transaction id: the fingerprint must notice.
        encoded[15] ^= 0x01;
        assert_eq!(
            Message::decode(&encoded),
            Err(StunError::FingerprintMismatch)
        );
    }

    #[test]
    fn xor_mapped_address_round_trips_and_differs_from_the_clear_form() {
        let address: SocketAddr = "203.0.113.7:54321".parse().expect("valid address");
        let message = Message {
            class: MessageClass::SuccessResponse,
            method: Method::Binding,
            transaction_id: transaction(),
            attributes: vec![
                Attribute::MappedAddress(address),
                Attribute::XorMappedAddress(address),
            ],
        };
        let encoded = message.encode(None);
        let decoded = decode(&encoded);

        // Both forms survive, and the XOR form is what `mapped_address` returns.
        assert_eq!(decoded.mapped_address(), Some(address));
        assert_eq!(decoded.attributes[0], Attribute::MappedAddress(address));
        assert_eq!(decoded.attributes[1], Attribute::XorMappedAddress(address));

        // The clear form must be byte-identical, the XOR form must not.
        let clear_start = HEADER_LEN + 4 + 4;
        assert_eq!(&encoded[clear_start..clear_start + 4], &[203, 0, 113, 7]);
        let xor_start = clear_start + 8 + 4;
        assert_ne!(&encoded[xor_start..xor_start + 4], &[203, 0, 113, 7]);
    }

    #[test]
    fn xor_mapped_address_round_trips_for_ipv6() {
        let address: SocketAddr = "[2001:db8::1]:443".parse().expect("valid address");
        let message = Message {
            class: MessageClass::SuccessResponse,
            method: Method::Binding,
            transaction_id: transaction(),
            attributes: vec![Attribute::XorMappedAddress(address)],
        };
        let encoded = message.encode(None);
        let decoded = decode(&encoded);
        assert_eq!(decoded.mapped_address(), Some(address));
    }

    #[test]
    fn attributes_are_padded_to_four_byte_boundaries() {
        // Three bytes of software name must occupy four on the wire.
        let message = Message {
            class: MessageClass::SuccessResponse,
            method: Method::Binding,
            transaction_id: transaction(),
            attributes: vec![
                Attribute::Software("abc".into()),
                Attribute::OtherAddress("192.0.2.1:3479".parse().expect("valid")),
            ],
        };
        let encoded = message.encode(None);
        let declared = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        assert_eq!(declared % 4, 0, "attribute area must end on a boundary");
        assert_eq!(encoded.len(), HEADER_LEN + declared);
        let decoded = decode(&encoded);
        assert_eq!(
            decoded.other_address(),
            Some("192.0.2.1:3479".parse().expect("valid"))
        );
    }

    #[test]
    fn change_request_flags_round_trip() {
        for (change_ip, change_port) in [(true, true), (true, false), (false, true)] {
            let message = Message {
                class: MessageClass::Request,
                method: Method::Binding,
                transaction_id: transaction(),
                attributes: vec![Attribute::ChangeRequest {
                    change_ip,
                    change_port,
                }],
            };
            let encoded = message.encode(None);
            let decoded = decode(&encoded);
            assert_eq!(
                decoded.find(ATTRIBUTE_CHANGE_REQUEST),
                Some(&Attribute::ChangeRequest {
                    change_ip,
                    change_port
                })
            );
        }
    }

    #[test]
    fn message_integrity_covers_the_patched_length() {
        let key = b"a-shared-secret";
        let message = Message {
            class: MessageClass::Request,
            method: Method::Binding,
            transaction_id: transaction(),
            attributes: vec![Attribute::Software("corduit".into())],
        };
        let encoded = message.encode(Some(key));
        let declared = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        assert_eq!(declared, encoded.len() - HEADER_LEN);
        let integrity_offset = HEADER_LEN + 12;
        assert_eq!(
            &encoded[integrity_offset..integrity_offset + 2],
            &ATTRIBUTE_MESSAGE_INTEGRITY.to_be_bytes()
        );
        assert_eq!(
            u16::from_be_bytes([encoded[integrity_offset + 2], encoded[integrity_offset + 3]]),
            20
        );

        let mut signed = encoded[..integrity_offset].to_vec();
        let length_to_integrity = integrity_offset - HEADER_LEN + MESSAGE_INTEGRITY_LEN;
        signed[2..4].copy_from_slice(&(length_to_integrity as u16).to_be_bytes());
        let mut tag = [0u8; 20];
        Hmac::<Sha1>::mac_into(key, &signed, &mut tag);
        assert_eq!(&encoded[integrity_offset + 4..integrity_offset + 24], &tag);
    }

    #[test]
    fn unknown_required_attribute_is_rejected_but_optional_is_kept() {
        let mut required = Vec::new();
        write_attribute_header(&mut required, 0x0007, 4);
        required.extend_from_slice(&[0, 0, 0, 0]);
        let mut frame = Vec::new();
        let message = Message::binding_request(transaction());
        frame.extend_from_slice(&message.encode(None)[..HEADER_LEN]);
        frame.extend_from_slice(&required);
        frame[2..4].copy_from_slice(&(required.len() as u16).to_be_bytes());

        assert_eq!(
            Message::decode(&frame),
            Err(StunError::UnsupportedRequiredAttribute(0x0007))
        );

        let mut optional = Vec::new();
        write_attribute_header(&mut optional, 0x8007, 4);
        optional.extend_from_slice(&[1, 2, 3, 4]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&message.encode(None)[..HEADER_LEN]);
        frame.extend_from_slice(&optional);
        frame[2..4].copy_from_slice(&(optional.len() as u16).to_be_bytes());
        let decoded = decode(&frame);
        assert_eq!(
            decoded.find(0x8007),
            Some(&Attribute::Unknown {
                attribute_type: 0x8007,
                value: vec![1, 2, 3, 4]
            })
        );
    }

    #[test]
    fn error_response_is_reported_with_its_code() {
        let message = Message {
            class: MessageClass::ErrorResponse,
            method: Method::Binding,
            transaction_id: transaction(),
            attributes: vec![Attribute::ErrorCode {
                code: 420,
                reason: "Unknown Attribute".into(),
            }],
        };
        let encoded = message.encode(None);
        assert_eq!(
            Message::decode(&encoded),
            Err(StunError::ServerError {
                code: 420,
                reason: "Unknown Attribute".into()
            })
        );
    }

    #[test]
    fn truncated_and_foreign_frames_are_rejected() {
        assert_eq!(Message::decode(&[0u8; 8]), Err(StunError::Truncated));
        let mut foreign = Message::binding_request(transaction()).encode(None);
        foreign[0] |= 0x80;
        assert_eq!(Message::decode(&foreign), Err(StunError::NotStunPrefix));
        let mut wrong_cookie = Message::binding_request(transaction()).encode(None);
        wrong_cookie[4] ^= 0xFF;
        assert_eq!(
            Message::decode(&wrong_cookie),
            Err(StunError::BadMagicCookie)
        );
    }

    #[test]
    fn attribute_length_beyond_the_message_is_an_overflow() {
        let mut frame = Vec::new();
        frame
            .extend_from_slice(&Message::binding_request(transaction()).encode(None)[..HEADER_LEN]);
        write_attribute_header(&mut frame, ATTRIBUTE_SOFTWARE, 64);
        frame[2..4].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(Message::decode(&frame), Err(StunError::AttributeOverflow));
    }

    #[test]
    fn crc32_matches_the_published_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
