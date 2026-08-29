//! SOCKS-style address encoding/decoding (`Address`, `AddressType`).
//!
//! The wire codec is `no_std + alloc`: IP types come from `core::net`, byte
//! buffers from `bytes` (itself `no_std`), and parsing is purely slice-based
//! — no OS, no heap beyond the owned `Address` form.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::protocol::error::{ProtocolError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::IPv4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::IPv6),
            _ => Err(ProtocolError::UnsupportedAddressType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Domain(String, u16),
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
}

impl Address {
    #[inline]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::Ipv4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Self::Ipv6(*v6.ip(), v6.port()),
        }
    }

    #[inline]
    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Self::Domain(domain.into(), port)
    }

    #[inline]
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, port) => *port,
            Self::Ipv4(_, port) => *port,
            Self::Ipv6(_, port) => *port,
        }
    }

    #[inline]
    pub fn host(&self) -> String {
        match self {
            Self::Domain(domain, _) => domain.clone(),
            Self::Ipv4(ip, _) => ip.to_string(),
            Self::Ipv6(ip, _) => ip.to_string(),
        }
    }

    #[inline]
    pub fn address_type(&self) -> AddressType {
        match self {
            Self::Ipv4(..) => AddressType::IPv4,
            Self::Ipv6(..) => AddressType::IPv6,
            Self::Domain(..) => AddressType::Domain,
        }
    }

    pub fn write_to(&self, buf: &mut impl BufMut) -> Result<()> {
        match self {
            Self::Ipv4(ip, port) => {
                buf.put_u8(AddressType::IPv4 as u8);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
            Self::Ipv6(ip, port) => {
                buf.put_u8(AddressType::IPv6 as u8);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
            Self::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                if domain_bytes.len() > u8::MAX as usize {
                    return Err(ProtocolError::Protocol(format!(
                        "domain name is {} bytes, exceeding the 255-byte wire limit",
                        domain_bytes.len()
                    )));
                }
                buf.put_u8(AddressType::Domain as u8);
                buf.put_u8(domain_bytes.len() as u8);
                buf.put_slice(domain_bytes);
                buf.put_u16(*port);
            }
        }
        Ok(())
    }

    /// Encode into a plain `Vec<u8>`, returning an error for over-long
    /// domain names instead of truncating the wire length byte.
    pub fn write_to_vec(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Ipv4(ip, port) => {
                buf.push(AddressType::IPv4 as u8);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::Ipv6(ip, port) => {
                buf.push(AddressType::IPv6 as u8);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Self::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                if domain_bytes.len() > u8::MAX as usize {
                    return Err(ProtocolError::Protocol(format!(
                        "domain name is {} bytes, exceeding the 255-byte wire limit",
                        domain_bytes.len()
                    )));
                }
                buf.push(AddressType::Domain as u8);
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(())
    }

    pub fn write_address_to(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Ipv4(ip, _) => {
                buf.push(AddressType::IPv4 as u8);
                buf.extend_from_slice(&ip.octets());
            }
            Self::Ipv6(ip, _) => {
                buf.push(AddressType::IPv6 as u8);
                buf.extend_from_slice(&ip.octets());
            }
            Self::Domain(domain, _) => {
                let domain_bytes = domain.as_bytes();
                if domain_bytes.len() > 255 {
                    return Err(ProtocolError::AddressParse("Domain name too long".into()));
                }
                buf.push(AddressType::Domain as u8);
                buf.push(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
            }
        }
        Ok(())
    }

    /// Encode into a `Bytes` buffer, returning an error for over-long domain
    /// names instead of truncating the wire length byte.
    pub fn to_bytes(&self) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to(&mut buf)?;
        Ok(buf.freeze())
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        match self {
            Self::Ipv4(..) => 7,
            Self::Ipv6(..) => 19,
            Self::Domain(domain, _) => 4 + domain.len(),
        }
    }

    pub fn read_from(buf: &[u8]) -> Result<(Self, usize)> {
        let (addr, consumed) = AddressRef::parse(buf)?;
        Ok((addr.to_owned(), consumed))
    }

    /// Read an address from a byte slice, advancing a `&[u8]` cursor.
    fn parse_from_buf(buf: &mut &[u8]) -> Result<Self> {
        if !buf.has_remaining() {
            return Err(ProtocolError::BufferTooSmall);
        }

        let addr_type = AddressType::try_from(buf.get_u8())?;

        match addr_type {
            AddressType::IPv4 => {
                if buf.remaining() < 6 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let mut ip = [0u8; 4];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Self::Ipv4(Ipv4Addr::from(ip), port))
            }
            AddressType::IPv6 => {
                if buf.remaining() < 18 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let mut ip = [0u8; 16];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Self::Ipv6(Ipv6Addr::from(ip), port))
            }
            AddressType::Domain => {
                if !buf.has_remaining() {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let mut domain = vec![0u8; len];
                buf.copy_to_slice(&mut domain);
                let domain = String::from_utf8(domain)
                    .map_err(|_| ProtocolError::AddressParse("Invalid UTF-8 domain".into()))?;
                let port = buf.get_u16();
                Ok(Self::Domain(domain, port))
            }
        }
    }

    /// Read an address from a `std::io::Read` stream (the engine's socket
    /// path). The read is bounded by the socket's read timeout.
    #[cfg(feature = "std")]
    pub fn read_from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let mut get = |buf: &mut [u8]| -> Result<()> {
            reader
                .read_exact(buf)
                .map_err(|e| ProtocolError::Io(e.to_string()))
        };
        let mut one = [0u8; 1];
        get(&mut one)?;
        let addr_type = AddressType::try_from(one[0])?;

        match addr_type {
            AddressType::IPv4 => {
                let mut ip = [0u8; 4];
                get(&mut ip)?;
                let mut port = [0u8; 2];
                get(&mut port)?;
                Ok(Self::Ipv4(Ipv4Addr::from(ip), u16::from_be_bytes(port)))
            }
            AddressType::IPv6 => {
                let mut ip = [0u8; 16];
                get(&mut ip)?;
                let mut port = [0u8; 2];
                get(&mut port)?;
                Ok(Self::Ipv6(Ipv6Addr::from(ip), u16::from_be_bytes(port)))
            }
            AddressType::Domain => {
                get(&mut one)?;
                let len = one[0] as usize;
                let mut domain = vec![0u8; len];
                get(&mut domain)?;
                let domain = String::from_utf8(domain)
                    .map_err(|_| ProtocolError::AddressParse("Invalid UTF-8 domain".into()))?;
                let mut port = [0u8; 2];
                get(&mut port)?;
                Ok(Self::Domain(domain, u16::from_be_bytes(port)))
            }
        }
    }

    #[inline]
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut buf: &[u8] = data;
        Self::parse_from_buf(&mut buf)
    }

    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ipv4(ip, port) => Some(SocketAddr::V4(SocketAddrV4::new(*ip, *port))),
            Self::Ipv6(ip, port) => Some(SocketAddr::V6(SocketAddrV6::new(*ip, *port, 0, 0))),
            Self::Domain(..) => None,
        }
    }
}

/// Borrowed, allocation-free view of a wire-encoded [`Address`].
///
/// The domain is a validated slice of the input buffer instead of an owned
/// `String`, so hot paths that only need the host or port (routing, logging,
/// connection tracking) never touch the heap. [`AddressRef::to_owned`]
/// converts to the owned form when required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressRef<'a> {
    Domain(&'a str, u16),
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
}

impl<'a> AddressRef<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<(Self, usize)> {
        let mut rest: &[u8] = buf;
        let addr = Self::parse_buf(&mut rest)?;
        Ok((addr, buf.len() - rest.len()))
    }

    fn parse_buf(buf: &mut &'a [u8]) -> Result<Self> {
        if !buf.has_remaining() {
            return Err(ProtocolError::BufferTooSmall);
        }
        let addr_type = AddressType::try_from(buf.get_u8())?;
        match addr_type {
            AddressType::IPv4 => {
                if buf.remaining() < 6 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let mut ip = [0u8; 4];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Self::Ipv4(Ipv4Addr::from(ip), port))
            }
            AddressType::IPv6 => {
                if buf.remaining() < 18 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let mut ip = [0u8; 16];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Self::Ipv6(Ipv6Addr::from(ip), port))
            }
            AddressType::Domain => {
                if !buf.has_remaining() {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(ProtocolError::BufferTooSmall);
                }
                let domain = core::str::from_utf8(&buf[..len])
                    .map_err(|_| ProtocolError::AddressParse("Invalid UTF-8 domain".into()))?;
                buf.advance(len);
                let port = buf.get_u16();
                Ok(Self::Domain(domain, port))
            }
        }
    }

    #[inline]
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, port) => *port,
            Self::Ipv4(_, port) => *port,
            Self::Ipv6(_, port) => *port,
        }
    }

    /// The borrowed domain, if this is a domain address.
    #[inline]
    pub fn domain(&self) -> Option<&'a str> {
        match self {
            Self::Domain(domain, _) => Some(domain),
            Self::Ipv4(..) | Self::Ipv6(..) => None,
        }
    }

    #[inline]
    pub fn address_type(&self) -> AddressType {
        match self {
            Self::Ipv4(..) => AddressType::IPv4,
            Self::Ipv6(..) => AddressType::IPv6,
            Self::Domain(..) => AddressType::Domain,
        }
    }

    pub fn to_owned(&self) -> Address {
        match self {
            Self::Domain(domain, port) => Address::Domain(domain.to_string(), *port),
            Self::Ipv4(ip, port) => Address::Ipv4(*ip, *port),
            Self::Ipv6(ip, port) => Address::Ipv6(*ip, *port),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain, port) => write!(f, "{}:{}", domain, port),
            Self::Ipv4(ip, port) => write!(f, "{}:{}", ip, port),
            Self::Ipv6(ip, port) => write!(f, "[{}]:{}", ip, port),
        }
    }
}

impl From<SocketAddr> for Address {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        Self::from_socket_addr(addr)
    }
}

impl From<SocketAddrV4> for Address {
    #[inline]
    fn from(addr: SocketAddrV4) -> Self {
        Self::Ipv4(*addr.ip(), addr.port())
    }
}

impl From<SocketAddrV6> for Address {
    #[inline]
    fn from(addr: SocketAddrV6) -> Self {
        Self::Ipv6(*addr.ip(), addr.port())
    }
}

impl From<(String, u16)> for Address {
    #[inline]
    fn from((domain, port): (String, u16)) -> Self {
        Self::Domain(domain, port)
    }
}

impl From<(&str, u16)> for Address {
    #[inline]
    fn from((domain, port): (&str, u16)) -> Self {
        Self::Domain(domain.to_string(), port)
    }
}

impl From<(Ipv4Addr, u16)> for Address {
    #[inline]
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        Self::Ipv4(ip, port)
    }
}

impl From<(Ipv6Addr, u16)> for Address {
    #[inline]
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        Self::Ipv6(ip, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_ipv4_roundtrip() {
        let addr = Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1), 8080);
        let bytes = addr.to_bytes().unwrap();
        let (parsed, len) = Address::read_from(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(len, 7);
    }

    #[test]
    fn test_address_ipv6_roundtrip() {
        let addr = Address::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443);
        let bytes = addr.to_bytes().unwrap();
        let (parsed, len) = Address::read_from(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(len, 19);
    }

    #[test]
    fn test_address_domain_roundtrip() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let bytes = addr.to_bytes().unwrap();
        let (parsed, len) = Address::read_from(&bytes).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(len, 4 + "example.com".len());
    }

    #[test]
    fn test_address_display() {
        assert_eq!(
            Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 80).to_string(),
            "127.0.0.1:80"
        );
        assert_eq!(
            Address::Ipv6(Ipv6Addr::LOCALHOST, 443).to_string(),
            "[::1]:443"
        );
        assert_eq!(
            Address::Domain("example.com".to_string(), 8080).to_string(),
            "example.com:8080"
        );
    }

    #[test]
    fn test_address_from_socket_addr() {
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234));
        let addr: Address = v4.into();
        assert!(matches!(addr, Address::Ipv4(_, 1234)));

        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5678, 0, 0));
        let addr: Address = v6.into();
        assert!(matches!(addr, Address::Ipv6(_, 5678)));
    }

    #[test]
    fn test_address_port_and_host() {
        let addr = Address::Domain("test.local".to_string(), 9000);
        assert_eq!(addr.port(), 9000);
        assert_eq!(addr.host(), "test.local");

        let addr = Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 80);
        assert_eq!(addr.port(), 80);
        assert_eq!(addr.host(), "1.2.3.4");
    }

    #[test]
    fn test_address_reader_roundtrip() {
        let addr = Address::Domain("sync.test".to_string(), 12345);
        let bytes = addr.to_bytes().unwrap();
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        let parsed = Address::read_from_reader(&mut cursor).unwrap();
        assert_eq!(addr, parsed);

        // Reader path must also reject truncated wire data.
        let mut cursor = std::io::Cursor::new(vec![AddressType::IPv4 as u8, 1, 2]);
        assert!(Address::read_from_reader(&mut cursor).is_err());
    }

    #[test]
    fn test_address_parse_from_slice_cursor() {
        let addr = Address::Ipv4(Ipv4Addr::new(10, 0, 0, 2), 53);
        let bytes = addr.to_bytes().unwrap();
        let mut buf: &[u8] = &bytes;
        let parsed = Address::parse_from_buf(&mut buf).unwrap();
        assert_eq!(addr, parsed);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_address_ref_borrows_domain() {
        let mut wire = Vec::new();
        wire.push(AddressType::Domain as u8);
        wire.push(11);
        wire.extend_from_slice(b"example.com");
        wire.extend_from_slice(&443u16.to_be_bytes());

        let (parsed, consumed) = AddressRef::parse(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(parsed.port(), 443);
        assert_eq!(parsed.address_type(), AddressType::Domain);

        // The borrowed domain must point into the input buffer, not a copy.
        let domain = parsed.domain().expect("domain address");
        assert_eq!(domain, "example.com");
        // Provenance check: the borrow aliases the wire region, not a heap copy.
        assert_eq!(domain.as_ptr(), wire[2..13].as_ptr());
    }

    #[test]
    fn test_address_ref_owned_conversion_agrees() {
        let owned = Address::Domain("cn.example.com".to_string(), 8080);
        let wire = owned.to_bytes().unwrap();
        let (borrowed, _) = AddressRef::parse(&wire).unwrap();
        assert_eq!(borrowed.to_owned(), owned);

        let ipv4 = Address::Ipv4(Ipv4Addr::new(9, 9, 9, 9), 53);
        let wire = ipv4.to_bytes().unwrap();
        let (borrowed, _) = AddressRef::parse(&wire).unwrap();
        assert_eq!(borrowed.to_owned(), ipv4);
        assert_eq!(borrowed.domain(), None);
    }

    #[test]
    fn test_address_ref_rejects_truncated() {
        assert!(AddressRef::parse(&[AddressType::Domain as u8, 5, b'a']).is_err());
        assert!(
            AddressRef::parse(&[AddressType::Domain as u8, 5, b'a', b'b', b'c', b'd', b'e'])
                .is_err()
        );
        assert!(AddressRef::parse(&[AddressType::IPv4 as u8, 1, 2]).is_err());
        assert!(AddressRef::parse(&[AddressType::IPv4 as u8, 1, 2, 3, 4, 0, 0]).is_ok());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_ipv4_addr() -> impl Strategy<Value = Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    fn arb_ipv6_addr() -> impl Strategy<Value = Ipv6Addr> {
        (
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
        )
            .prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn arb_domain() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{0,62}(\\.[a-z][a-z0-9]{0,62}){0,3}"
            .prop_filter("domain must be <= 255 bytes", |s| s.len() <= 255)
    }

    fn arb_port() -> impl Strategy<Value = u16> {
        1u16..=65535u16
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        prop_oneof![
            (arb_ipv4_addr(), arb_port()).prop_map(|(ip, port)| Address::Ipv4(ip, port)),
            (arb_ipv6_addr(), arb_port()).prop_map(|(ip, port)| Address::Ipv6(ip, port)),
            (arb_domain(), arb_port()).prop_map(|(domain, port)| Address::Domain(domain, port)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_address_serialization_roundtrip(addr in arb_address()) {
            let bytes = addr.to_bytes().unwrap();
            let (parsed, len) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(&addr, &parsed);
            prop_assert_eq!(len, addr.serialized_len());
        }

        #[test]
        fn prop_address_ipv4_roundtrip(ip in arb_ipv4_addr(), port in arb_port()) {
            let addr = Address::Ipv4(ip, port);
            let bytes = addr.to_bytes().unwrap();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr, parsed);
        }

        #[test]
        fn prop_address_ipv6_roundtrip(ip in arb_ipv6_addr(), port in arb_port()) {
            let addr = Address::Ipv6(ip, port);
            let bytes = addr.to_bytes().unwrap();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr, parsed);
        }

        #[test]
        fn prop_address_domain_roundtrip(domain in arb_domain(), port in arb_port()) {
            let addr = Address::Domain(domain, port);
            let bytes = addr.to_bytes().unwrap();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr, parsed);
        }

        #[test]
        fn prop_address_port_preserved(addr in arb_address()) {
            let bytes = addr.to_bytes().unwrap();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr.port(), parsed.port());
        }

        #[test]
        fn prop_address_host_preserved(addr in arb_address()) {
            let bytes = addr.to_bytes().unwrap();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr.host(), parsed.host());
        }

        #[test]
        fn prop_address_type_preserved(addr in arb_address()) {
            let bytes = addr.to_bytes().unwrap();
            let (parsed, _) = Address::read_from(&bytes).unwrap();
            prop_assert_eq!(addr.address_type(), parsed.address_type());
        }

        #[test]
        fn prop_address_serialized_len_correct(addr in arb_address()) {
            let bytes = addr.to_bytes().unwrap();
            prop_assert_eq!(bytes.len(), addr.serialized_len());
        }

        #[test]
        fn prop_address_ref_roundtrip(addr in arb_address()) {
            let bytes = addr.to_bytes().unwrap();
            let (borrowed, consumed) = AddressRef::parse(&bytes).unwrap();
            prop_assert_eq!(consumed, addr.serialized_len());
            prop_assert_eq!(&borrowed.to_owned(), &addr);
            prop_assert_eq!(borrowed.port(), addr.port());
            prop_assert_eq!(borrowed.address_type(), addr.address_type());
            match (&addr, borrowed.domain()) {
                (Address::Domain(d, _), Some(b)) => prop_assert_eq!(b, d),
                (Address::Domain(..), None) => panic!("domain missing from AddressRef"),
                _ => {}
            }
        }

        #[test]
        fn prop_socket_addr_conversion_roundtrip(ip in arb_ipv4_addr(), port in arb_port()) {
            let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            let addr = Address::from(socket_addr);
            let back = addr.to_socket_addr().unwrap();
            prop_assert_eq!(socket_addr, back);
        }
    }
}
