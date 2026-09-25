//! Hole punching: getting two NATed endpoints to accept each other.
//!
//! ## What a punch is, mechanically
//!
//! Both peers send to the other's *predicted* external address at the same time.
//! Nothing about that is magic; what makes it work is that a NAT with
//! address-and-port-dependent filtering creates an inbound allowance as a side
//! effect of an outbound packet. So the two sides are not really "breaking"
//! anything — they are each opening their own door for the other, which is only
//! possible if they do it close enough together that neither allowance expires
//! first.
//!
//! ## Authentication is not optional here
//!
//! A punch is an open window. During it, any packet that arrives from the address
//! being probed and looks plausible would otherwise be taken for the peer — and
//! whoever wins that race owns the session. Two properties therefore have to
//! hold, and both are enforced below:
//!
//! 1. **Every probe is tagged** with a key derived from the session secret, so an
//!    off-path attacker who guesses the 4-tuple still cannot produce a packet
//!    that validates.
//! 2. **The two directions use different keys.** This is the part that is easy
//!    to miss: if both sides tag with the same key, an attacker can reflect a
//!    peer's own probe back at it. The tag is genuine, the source address is one
//!    of the probed targets, and the reflected packet wins the race without the
//!    attacker ever learning the secret. Deriving a separate send key and
//!    receive key per role makes a reflected probe fail validation, because the
//!    side that receives it is checking a key the packet was not made with.
//!
//! ## Which roles, and who decides
//!
//! The two sides must agree on which is [`PunchRole::A`] and which is
//! [`PunchRole::B`], because that decides which key pair each uses. This is
//! signalling-plane work: whoever hands out the session id also names the roles,
//! deterministically, so a retry cannot invert them.
//!
//! ## Probing order
//!
//! Callers build the target list from [`crate::nat::discover::NatProfile`]'s
//! prediction, best guesses first. The racer sends to every target each round
//! rather than walking the list sequentially, because the constraint is time —
//! the peer's inbound allowance for our address expires — and the cost of a
//! wasted datagram is negligible next to a round spent on the wrong port.

use alloc::vec::Vec;
use core::net::SocketAddr;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::crypto::hash::Sha256;
use crate::crypto::mac::Hmac;
use crate::nat::error::NatError;

/// Magic prefix, so a stray datagram on the port is rejected without doing
/// cryptographic work on it.
const PROBE_MAGIC: [u8; 4] = *b"CDPT";

/// Wire version of the probe format.
const PROBE_VERSION: u8 = 1;

/// Bytes covered by the tag: magic, version, kind, session id, sequence.
const PROBE_HEADER_LEN: usize = 18;

/// Tag length. A 128-bit truncation of HMAC-SHA-256 cannot be forged by
/// guessing, and keeping the packet at 34 bytes keeps it well clear of any
/// plausible MTU so it is never fragmented.
const PROBE_TAG_LEN: usize = 16;

/// Total probe length.
const PROBE_LEN: usize = PROBE_HEADER_LEN + PROBE_TAG_LEN;

/// A probe asking the peer to open its side.
const KIND_PROBE: u8 = 1;

/// A confirmation that we received the peer's probe.
const KIND_ACK: u8 = 2;

/// Which of the two ends of a punch this participant is.
///
/// Agreed out of band; see the module documentation for why it must be stable
/// across retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchRole {
    /// The side the signalling plane names first.
    A,
    /// The other side.
    B,
}

impl PunchRole {
    /// Key label this role tags its own packets with.
    const fn send_label(self) -> &'static [u8] {
        match self {
            Self::A => b"corduit/punch/a-to-b",
            Self::B => b"corduit/punch/b-to-a",
        }
    }

    /// Key label this role validates inbound packets against.
    const fn receive_label(self) -> &'static [u8] {
        match self {
            Self::A => b"corduit/punch/b-to-a",
            Self::B => b"corduit/punch/a-to-b",
        }
    }
}

/// Derive a per-direction key from the session secret.
///
/// A single HMAC over a fixed label is enough here, unlike in a
/// password-derived setting: the secret is already a uniform 256-bit value, so
/// there is no work factor to add and all that is needed is domain separation.
fn derive_key(secret: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hmac::<Sha256>::mac_into(secret, label, &mut key);
    key
}

/// Truncated tag over the probe header.
fn tag_of(key: &[u8; 32], header: &[u8]) -> [u8; PROBE_TAG_LEN] {
    let mut full = [0u8; 32];
    Hmac::<Sha256>::mac_into(key, header, &mut full);
    let mut tag = [0u8; PROBE_TAG_LEN];
    tag.copy_from_slice(&full[..PROBE_TAG_LEN]);
    tag
}

/// Build one probe or acknowledgement.
fn encode_probe(key: &[u8; 32], session_id: u64, sequence: u32, kind: u8) -> [u8; PROBE_LEN] {
    let mut packet = [0u8; PROBE_LEN];
    packet[0..4].copy_from_slice(&PROBE_MAGIC);
    packet[4] = PROBE_VERSION;
    packet[5] = kind;
    packet[6..14].copy_from_slice(&session_id.to_be_bytes());
    packet[14..18].copy_from_slice(&sequence.to_be_bytes());
    let tag = tag_of(key, &packet[..PROBE_HEADER_LEN]);
    packet[PROBE_HEADER_LEN..].copy_from_slice(&tag);
    packet
}

/// Compare two tags without an early exit.
///
/// The comparison is over a value an attacker is trying to guess, so a
/// byte-at-a-time exit would leak how much of a guess was right. The `black_box`
/// keeps the optimiser from turning the accumulator back into a branch.
fn tags_match(expected: &[u8; PROBE_TAG_LEN], received: &[u8]) -> bool {
    if received.len() != PROBE_TAG_LEN {
        return false;
    }
    let mut difference = 0u8;
    for (expected_byte, received_byte) in expected.iter().zip(received.iter()) {
        difference |= core::hint::black_box(*expected_byte ^ *received_byte);
    }
    difference == 0
}

/// Validate an inbound datagram, returning its kind when it authenticates.
///
/// The key is derived from the *receiver's* role here rather than passed in, so
/// a caller cannot accidentally check a packet against the key it sends with —
/// the mistake that lets a reflected probe authenticate.
fn validate_probe(secret: &[u8; 32], role: PunchRole, bytes: &[u8], session_id: u64) -> Option<u8> {
    if bytes.len() != PROBE_LEN {
        return None;
    }
    if bytes[0..4] != PROBE_MAGIC || bytes[4] != PROBE_VERSION {
        return None;
    }
    if u64::from_be_bytes(bytes[6..14].try_into().ok()?) != session_id {
        return None;
    }
    let kind = bytes[5];
    // Only the two defined kinds are accepted; anything else is a packet that
    // happens to authenticate but was not produced by this protocol.
    if kind != KIND_PROBE && kind != KIND_ACK {
        return None;
    }
    let key = derive_key(secret, role.receive_label());
    let expected = tag_of(&key, &bytes[..PROBE_HEADER_LEN]);
    tags_match(&expected, &bytes[PROBE_HEADER_LEN..]).then_some(kind)
}

/// Everything needed to run one UDP punch.
#[derive(Debug, Clone)]
pub struct UdpPunchPlan {
    /// Address to bind when the caller does not supply its own socket.
    pub local: SocketAddr,
    /// Addresses to probe, best guess first. Order affects nothing except the
    /// order packets leave in; every target is probed every round.
    pub targets: Vec<SocketAddr>,
    /// Identifies this attempt. Both peers must use the same value.
    pub session_id: u64,
    /// Shared secret. Both peers must use the same value, and it must not be
    /// derivable from the session id.
    pub secret: [u8; 32],
    /// Which end of the punch this participant is.
    pub role: PunchRole,
    /// Total budget for the attempt.
    pub deadline: Duration,
    /// Gap between probe rounds. Also the read timeout inside a round.
    pub probe_interval: Duration,
}

impl UdpPunchPlan {
    /// A plan against a single peer address.
    pub fn new(
        local: SocketAddr,
        peer: SocketAddr,
        session_id: u64,
        secret: [u8; 32],
        role: PunchRole,
        deadline: Duration,
    ) -> Self {
        Self {
            local,
            targets: vec![peer],
            session_id,
            secret,
            role,
            deadline,
            probe_interval: Duration::from_millis(50),
        }
    }

    /// Add predicted ports on an address, after the known-good target.
    ///
    /// The caller orders these; typically the list comes straight from
    /// [`crate::nat::discover::NatProfile::predict_external_ports`], where the
    /// most probable port comes first.
    pub fn with_predicted_ports(mut self, address: core::net::IpAddr, ports: &[u16]) -> Self {
        for port in ports {
            let target = SocketAddr::new(address, *port);
            if !self.targets.contains(&target) {
                self.targets.push(target);
            }
        }
        self
    }

    /// Override the gap between rounds.
    pub fn with_probe_interval(mut self, interval: Duration) -> Self {
        self.probe_interval = interval.max(Duration::from_millis(1));
        self
    }
}

/// A punch that produced a peer.
#[derive(Debug)]
pub struct UdpPunchOutcome {
    /// The socket the peer is reachable on. It has already accepted a datagram
    /// from the peer, so the caller can use it directly.
    pub socket: UdpSocket,
    /// The peer's address, as observed on the winning datagram.
    pub peer: SocketAddr,
    /// Datagrams sent before the peer answered, for diagnostics.
    pub probes_sent: u32,
    /// Time from the first probe to the winning datagram.
    pub elapsed: Duration,
}

/// Bind [`UdpPunchPlan::local`] and race it.
pub fn punch_udp(plan: &UdpPunchPlan) -> Result<UdpPunchOutcome, NatError> {
    if plan.targets.is_empty() {
        return Err(NatError::InvalidPlan {
            detail: "a punch needs at least one target address".into(),
        });
    }
    let socket = crate::common::socket::udp_bind(plan.local, plan.probe_interval)?;
    punch_udp_on(socket, plan)
}

/// Race an already-bound socket.
///
/// Separate from [`punch_udp`] because a real traversal agent binds once and
/// keeps the mapping: the external port discovered by STUN is the one the peer
/// was told to probe, so rebinding would invalidate the whole attempt.
pub fn punch_udp_on(socket: UdpSocket, plan: &UdpPunchPlan) -> Result<UdpPunchOutcome, NatError> {
    if plan.targets.is_empty() {
        return Err(NatError::InvalidPlan {
            detail: "a punch needs at least one target address".into(),
        });
    }

    let send_key = derive_key(&plan.secret, plan.role.send_label());

    let started = Instant::now();
    let mut sequence = 0u32;
    let mut probes_sent = 0u32;
    let mut buffer = [0u8; 2048];

    loop {
        let remaining = plan.deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }

        // One round: every target, immediately. Time is the scarce resource —
        // the peer's inbound allowance for us is already ticking — so a wasted
        // datagram costs far less than a round spent on the wrong port.
        for target in &plan.targets {
            let packet = encode_probe(&send_key, plan.session_id, sequence, KIND_PROBE);
            if socket.send_to(&packet, target).is_ok() {
                probes_sent = probes_sent.saturating_add(1);
            }
        }
        sequence = sequence.wrapping_add(1);

        let round_end = Instant::now() + plan.probe_interval.min(remaining);
        while let Some(time_left) = round_end.checked_duration_since(Instant::now()) {
            socket.set_read_timeout(Some(time_left.max(Duration::from_millis(1))))?;
            let (length, source) = match socket.recv_from(&mut buffer) {
                Ok(received) => received,
                // A timeout ends the read phase; the next round probes again.
                Err(_) => break,
            };
            if validate_probe(&plan.secret, plan.role, &buffer[..length], plan.session_id).is_none()
            {
                continue;
            }
            // The peer is real: only the session secret could produce that tag,
            // and only with the key for *its* direction. Confirm receipt so the
            // session survives a case where our probe was dropped but theirs
            // arrived — the two directions open independently.
            let acknowledgement = encode_probe(&send_key, plan.session_id, sequence, KIND_ACK);
            let _ = socket.send_to(&acknowledgement, source);
            socket.set_read_timeout(None)?;
            return Ok(UdpPunchOutcome {
                socket,
                peer: source,
                probes_sent,
                elapsed: started.elapsed(),
            });
        }
    }

    Err(NatError::NoPath {
        attempts: probes_sent,
        detail: format!(
            "no authenticated reply from {} target(s) within {:?}",
            plan.targets.len(),
            plan.deadline
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::mpsc;
    use std::thread;

    const SECRET: [u8; 32] = [0x5A; 32];

    #[test]
    fn a_probe_validates_only_with_the_receiving_roles_key() {
        let a_send = derive_key(&SECRET, PunchRole::A.send_label());

        let packet = encode_probe(&a_send, 42, 7, KIND_PROBE);
        assert_eq!(
            validate_probe(&SECRET, PunchRole::B, &packet, 42),
            Some(KIND_PROBE)
        );
        // A's own probe must not validate for A: that is exactly the
        // reflected-packet case the direction split exists for.
        assert_eq!(validate_probe(&SECRET, PunchRole::A, &packet, 42), None);
    }

    #[test]
    fn a_foreign_secret_is_rejected() {
        let mut other = SECRET;
        other[0] ^= 0x01;
        let key = derive_key(&other, PunchRole::A.send_label());
        let packet = encode_probe(&key, 42, 0, KIND_PROBE);
        assert_eq!(validate_probe(&SECRET, PunchRole::B, &packet, 42), None);
    }

    #[test]
    fn a_different_session_is_rejected() {
        let key = derive_key(&SECRET, PunchRole::A.send_label());
        let packet = encode_probe(&key, 42, 0, KIND_PROBE);
        assert_eq!(validate_probe(&SECRET, PunchRole::B, &packet, 43), None);
    }

    #[test]
    fn a_tampered_payload_is_rejected() {
        let key = derive_key(&SECRET, PunchRole::A.send_label());
        let mut packet = encode_probe(&key, 42, 0, KIND_PROBE);
        packet[16] ^= 0x01; // one bit of the sequence
        assert_eq!(validate_probe(&SECRET, PunchRole::B, &packet, 42), None);
    }

    #[test]
    fn an_unknown_kind_is_rejected_even_when_it_authenticates() {
        let key = derive_key(&SECRET, PunchRole::A.send_label());
        let packet = encode_probe(&key, 42, 0, 0x7F);
        assert_eq!(validate_probe(&SECRET, PunchRole::B, &packet, 42), None);
    }

    #[test]
    fn short_and_foreign_datagrams_are_rejected_without_panicking() {
        assert_eq!(validate_probe(&SECRET, PunchRole::B, &[], 42), None);
        assert_eq!(
            validate_probe(&SECRET, PunchRole::B, &[0u8; PROBE_LEN], 42),
            None
        );
        assert_eq!(
            validate_probe(&SECRET, PunchRole::B, &[0u8; PROBE_LEN + 8], 42),
            None
        );
    }

    #[test]
    fn probe_layout_matches_its_documented_length() {
        let key = derive_key(&SECRET, PunchRole::A.send_label());
        let packet = encode_probe(&key, 1, 2, KIND_PROBE);
        assert_eq!(packet.len(), 34);
        assert_eq!(&packet[0..4], b"CDPT");
        assert_eq!(packet[4], PROBE_VERSION);
        assert_eq!(packet[5], KIND_PROBE);
    }

    #[test]
    fn tags_match_accepts_only_the_exact_tag() {
        let expected = [0xABu8; PROBE_TAG_LEN];
        assert!(tags_match(&expected, &expected));
        let mut wrong = expected;
        wrong[PROBE_TAG_LEN - 1] ^= 0x01;
        assert!(!tags_match(&expected, &wrong));
        assert!(!tags_match(&expected, &expected[..8]));
    }

    /// Two sockets on the loopback, each probing the other. There is no NAT in
    /// the middle, so this does not prove traversal works — it proves the two
    /// halves of the protocol agree, which is the part that is ours.
    #[test]
    fn mirrored_probes_on_loopback_connect_each_other() {
        let left = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind left");
        let right = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind right");
        let left_addr = left.local_addr().expect("left addr");
        let right_addr = right.local_addr().expect("right addr");

        let deadline = Duration::from_secs(5);
        let (left_tx, left_rx) = mpsc::channel();
        let (right_tx, right_rx) = mpsc::channel();

        let left_plan = UdpPunchPlan::new(
            left_addr,
            right_addr,
            0xC0FFEE,
            SECRET,
            PunchRole::A,
            deadline,
        );
        let right_plan = UdpPunchPlan::new(
            right_addr,
            left_addr,
            0xC0FFEE,
            SECRET,
            PunchRole::B,
            deadline,
        );

        thread::spawn(move || {
            let _ = left_tx.send(punch_udp_on(left, &left_plan).map(|outcome| outcome.peer));
        });
        thread::spawn(move || {
            let _ = right_tx.send(punch_udp_on(right, &right_plan).map(|outcome| outcome.peer));
        });

        let left_peer = left_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("left punch returned")
            .expect("left punch succeeded");
        let right_peer = right_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("right punch returned")
            .expect("right punch succeeded");

        assert_eq!(left_peer, right_addr);
        assert_eq!(right_peer, left_addr);
    }

    #[test]
    fn a_punch_with_no_targets_is_rejected_before_binding_anything() {
        let plan = UdpPunchPlan {
            targets: Vec::new(),
            ..UdpPunchPlan::new(
                (Ipv4Addr::LOCALHOST, 0).into(),
                (Ipv4Addr::LOCALHOST, 1).into(),
                1,
                SECRET,
                PunchRole::A,
                Duration::from_millis(10),
            )
        };
        assert!(matches!(
            punch_udp(&plan),
            Err(NatError::InvalidPlan { .. })
        ));
    }

    #[test]
    fn a_punch_against_silence_gives_up_within_its_budget() {
        // A port nothing is listening on; the loopback will answer an ICMP
        // unreachable, which the racer has to treat as "keep trying", not
        // "abort".
        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let silent_addr = silent.local_addr().expect("addr");
        drop(silent);

        let plan = UdpPunchPlan::new(
            (Ipv4Addr::LOCALHOST, 0).into(),
            silent_addr,
            7,
            SECRET,
            PunchRole::A,
            Duration::from_millis(250),
        )
        .with_probe_interval(Duration::from_millis(20));

        let started = Instant::now();
        let result = punch_udp(&plan);
        assert!(matches!(result, Err(NatError::NoPath { .. })));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "a bounded punch must not overrun its budget by much"
        );
    }

    #[test]
    fn predicted_ports_extend_the_target_list_without_duplicating() {
        let peer: SocketAddr = (Ipv4Addr::new(203, 0, 113, 9), 40000).into();
        let plan = UdpPunchPlan::new(
            (Ipv4Addr::LOCALHOST, 0).into(),
            peer,
            1,
            SECRET,
            PunchRole::A,
            Duration::from_secs(1),
        )
        .with_predicted_ports(Ipv4Addr::new(203, 0, 113, 9).into(), &[40001, 40002, 40000]);

        assert_eq!(plan.targets.len(), 3);
        assert_eq!(plan.targets[0], peer);
        assert_eq!(
            plan.targets
                .iter()
                .filter(|target| **target == peer)
                .count(),
            1,
            "the known-good target must appear exactly once"
        );
    }
}
