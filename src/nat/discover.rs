//! Measuring what a local NAT actually does, and using that measurement.
//!
//! Everything in [`crate::nat::punch`] depends on this module being right: how
//! many ports to probe, whether a direct path is even plausible, and how long to
//! keep trying all follow from the profile computed here.
//!
//! ## The measurement
//!
//! [RFC 5780] defines two independent tests, each a small set of STUN binding
//! requests whose answers are compared:
//!
//! * **Mapping** — does a different destination get the same external port?
//!   Answered by comparing the port the server sees when we talk to its primary
//!   address, its alternate address, and its alternate address and port.
//! * **Filtering** — does an inbound packet from a destination we have not
//!   written to get through? Answered by asking the server to reply from its
//!   alternate address and/or port and seeing whether anything arrives.
//!
//! ## The honesty problem, and how it is handled
//!
//! Neither test is observable against a server that does not implement RFC 5780,
//! and most public STUN servers do not. The tests rely on the server advertising
//! an alternate address (`OTHER-ADDRESS`) and honouring `CHANGE-REQUEST`.
//!
//! There is no way to distinguish "the NAT filtered the packet" from "the server
//! ignored the request". A profile that guessed between those two would be worse
//! than no profile, because the punch layer would then size its probe budget on
//! a fiction. So this module reports [`NatMapping::Undetermined`] and
//! [`NatFiltering::Undetermined`] together with the reason, and the punch layer
//! treats "undetermined" as "probe as though it were the hard case" — which is
//! always safe, only slower.
//!
//! [RFC 5780]: https://www.rfc-editor.org/rfc/rfc5780

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::SocketAddr;
use std::time::Duration;

use crate::nat::error::NatError;
use crate::nat::stun::client::{ChangeRequest, StunClient};

/// Low end of the port range a NAT allocates from, used to keep a predicted
/// port inside the range the kernel would actually have chosen.
const EPHEMERAL_LOW: u16 = 1024;

/// High end of the ephemeral range.
const EPHEMERAL_HIGH: u16 = 65_535;

/// How a NAT assigns an external port to an internal endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMapping {
    /// The same external port is reused for every destination — "cone".
    ///
    /// The easy case: one discovery is enough, and any peer that has learned
    /// this port can reach it once filtering allows.
    EndpointIndependent,
    /// The external port depends on the destination address but not its port.
    AddressDependent,
    /// The external port changes for every destination, port included.
    ///
    /// Symmetric NAT. A direct path to a peer behind another such NAT is not
    /// guaranteed and has to be sought probabilistically.
    AddressAndPortDependent,
    /// Not observable against the server that was used.
    Undetermined,
}

/// How a NAT decides whether an inbound packet may enter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatFiltering {
    /// Any inbound packet for an existing mapping is allowed.
    EndpointIndependent,
    /// Only packets from an address the inside has already written to.
    AddressDependent,
    /// Only packets from an address *and port* the inside has already written to.
    ///
    /// This is why hole punching is symmetric in time: both peers must send at
    /// roughly the same moment, because each send is what opens the other's
    /// filter.
    AddressAndPortDependent,
    /// Not observable against the server that was used.
    Undetermined,
}

impl NatFiltering {
    /// Whether an inbound packet from an arbitrary address is admitted.
    ///
    /// `false` for [`NatFiltering::Undetermined`]: unknown filtering is treated
    /// as the restrictive case, because that assumption only costs probes while
    /// the opposite assumption costs a failed session.
    pub const fn admits_unsolicited(self) -> bool {
        matches!(self, Self::EndpointIndependent)
    }
}

/// What a traversal attempt should expect, derived from a measured profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalOutlook {
    /// Cone mapping: a single probe pair should connect.
    Direct,
    /// Mapping is per-destination, so a direct path is a probability and port
    /// prediction has to carry it.
    Probabilistic,
    /// No observable behaviour supports a direct path.
    RelayOnly,
    /// The profile is incomplete. A direct path may still work, so the punch
    /// layer should try with the widest budget it can afford.
    Unknown,
}

/// A measured NAT profile.
#[derive(Debug, Clone)]
pub struct NatProfile {
    /// Address the client was bound to locally.
    pub local: SocketAddr,
    /// Address the server observed for the primary destination.
    pub mapped: SocketAddr,
    /// The server's alternate address, when it advertised one.
    pub other: Option<SocketAddr>,
    /// How the NAT maps endpoints.
    pub mapping: NatMapping,
    /// How the NAT filters inbound packets.
    pub filtering: NatFiltering,
    /// External addresses observed for distinct destinations, in test order.
    ///
    /// This is the raw evidence the stride inference reads. Keeping it rather
    /// than only the conclusion means an operator can see *why* a prediction
    /// was made.
    pub samples: Vec<(SocketAddr, SocketAddr)>,
    /// Human-readable reasons for anything left undetermined.
    pub notes: Vec<String>,
}

impl NatProfile {
    /// What to expect when trying to reach a peer.
    pub fn outlook(&self) -> TraversalOutlook {
        match (self.mapping, self.filtering) {
            (NatMapping::Undetermined, _) => TraversalOutlook::Unknown,
            (NatMapping::EndpointIndependent, NatFiltering::Undetermined) => {
                TraversalOutlook::Unknown
            }
            (NatMapping::EndpointIndependent, _) => TraversalOutlook::Direct,
            (NatMapping::AddressDependent, _) => TraversalOutlook::Probabilistic,
            // Two peers that both map per destination cannot learn each other's
            // next port by observation. A path is sometimes still possible by
            // stride prediction, so it is not written off — but it is not
            // promised either.
            (NatMapping::AddressAndPortDependent, _) => TraversalOutlook::Probabilistic,
        }
    }

    /// External ports observed for destinations other than the primary one.
    fn distinct_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .samples
            .iter()
            .map(|(_, mapped)| mapped.port())
            .filter(|port| *port >= EPHEMERAL_LOW)
            .collect();
        ports.dedup();
        ports
    }

    /// The step between successive external ports, when the samples show one.
    ///
    /// Returning `None` means the samples are consistent with a random
    /// allocator, in which case no stride will be assumed: a wrong stride
    /// concentrates every probe on ports the NAT will never hand out.
    pub fn port_stride(&self) -> Option<u16> {
        let ports = self.distinct_ports();
        if ports.len() < 2 {
            return None;
        }
        let mut stride: Option<u16> = None;
        for pair in ports.windows(2) {
            let delta = pair[1].saturating_sub(pair[0]);
            match stride {
                None => stride = Some(delta),
                Some(previous) if previous == delta => {}
                // Two different steps: the allocator is not following a fixed
                // stride, and pretending otherwise would be worse than
                // admitting we do not know.
                Some(_) => return None,
            }
        }
        stride.filter(|delta| *delta > 0)
    }

    /// Ports worth probing on the peer's address, best guesses first.
    ///
    /// The order is the whole point. When the samples reveal a stride, following
    /// it reproduces exactly what the NAT did for every previous destination, so
    /// those probes go first. What remains of the window is then sampled in an
    /// order that spreads across it, because for an allocator that picks ports
    /// pseudo-randomly only coverage helps and clustering every probe in the
    /// first few ports wastes the budget.
    pub fn predict_external_ports(&self, window: u16, limit: usize) -> Vec<u16> {
        if window == 0 || limit == 0 {
            return Vec::new();
        }

        let stride = self.port_stride().unwrap_or(1);
        let base = self
            .distinct_ports()
            .last()
            .copied()
            .unwrap_or_else(|| self.mapped.port());

        let mut candidates = Vec::with_capacity(limit);
        let mut push = |port: u16| {
            if candidates.len() < limit && port >= EPHEMERAL_LOW && !candidates.contains(&port) {
                candidates.push(port);
            }
        };

        // Phase 1: the observed allocator.
        let sequential = usize::from(window) / 2;
        for step in 1..=sequential {
            push(advance_port(base, stride, step));
        }

        // Phase 2: even coverage of the remaining window. Stepping by a value
        // coprime with the window length visits every offset before repeating,
        // which is what makes the coverage useful rather than lopsided.
        let sequential = usize::from(window) / 2;
        let spread = usize::from(window) - sequential;
        if spread > 1 {
            let step = pick_coprime(spread);
            let mut visited = 0usize;
            let mut offset = 0usize;
            while visited < spread {
                push(advance_port(base, stride, sequential + 1 + offset));
                offset = (offset + step) % spread;
                visited += 1;
            }
        }

        candidates
    }
}

/// Add `steps * stride` to `port`, wrapping inside the ephemeral range.
///
/// Wrapping is deliberate: an allocator that has run to the top of the range
/// starts again at the bottom, and a prediction that stopped at 65535 would miss
/// every port it handed out next.
fn advance_port(base: u16, stride: u16, steps: usize) -> u16 {
    let span = u32::from(EPHEMERAL_HIGH - EPHEMERAL_LOW) + 1;
    let offset =
        (u32::from(base.saturating_sub(EPHEMERAL_LOW)) + u32::from(stride) * steps as u32) % span;
    (u32::from(EPHEMERAL_LOW) + offset) as u16
}

/// A step size that shares no factor with `span`, so repeated addition visits
/// every offset in the window exactly once.
fn pick_coprime(span: usize) -> usize {
    if span <= 2 {
        return 1;
    }
    // Any prime above the window's own factors works; the window is small and
    // bounded, so a short search is cheaper than a table.
    for candidate in 2..span {
        if gcd(candidate, span) == 1 {
            return candidate;
        }
    }
    1
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

/// How to reach the STUN server used for measurement.
#[derive(Debug, Clone)]
pub struct DiscoverConfig {
    /// Server to measure against. It must implement RFC 5780 for the filtering
    /// and mapping tests to produce answers rather than `Undetermined`.
    pub server: SocketAddr,
    /// Local address to bind; port 0 lets the OS choose.
    pub local: SocketAddr,
    /// Budget for each individual STUN transaction.
    pub timeout: Duration,
    /// Seed for the transaction-id CSPRNG.
    pub seed: [u8; 32],
}

/// Measure the local NAT.
///
/// Runs the full RFC 5780 test plan and returns everything that was observable.
/// A server without RFC 5780 support is not an error: the profile comes back
/// with `Undetermined` behaviours and a note explaining what was missing, which
/// is the accurate answer.
pub fn discover(config: &DiscoverConfig) -> Result<NatProfile, NatError> {
    let mut client = StunClient::bind(config.local, config.server, config.timeout, config.seed)?;
    let local = client.local_addr()?;

    // Test I: the baseline mapping for this socket.
    let baseline = client.binding(ChangeRequest::default())?;
    let mut profile = NatProfile {
        local,
        mapped: baseline.mapped,
        other: baseline.other,
        mapping: NatMapping::Undetermined,
        filtering: NatFiltering::Undetermined,
        samples: vec![(config.server, baseline.mapped)],
        notes: Vec::new(),
    };

    let Some(other) = baseline.other else {
        profile.notes.push(
            "the server did not advertise OTHER-ADDRESS, so RFC 5780 mapping and filtering \
             tests are not observable against it; use a server that implements RFC 5780 for a \
             complete profile"
                .to_string(),
        );
        return Ok(profile);
    };

    // --- filtering ---------------------------------------------------------
    //
    // Both tests ask the server to answer from somewhere our socket has not
    // written to. A response therefore proves the NAT admitted an unsolicited
    // packet; silence proves it did not. The order matters: the weaker
    // requirement is tested first so a failure can be attributed.
    if client
        .binding(ChangeRequest {
            change_ip: true,
            change_port: true,
        })
        .is_ok()
    {
        profile.filtering = NatFiltering::EndpointIndependent;
    } else if client
        .binding(ChangeRequest {
            change_ip: false,
            change_port: true,
        })
        .is_ok()
    {
        // The port change was admitted but not the address change.
        profile.filtering = NatFiltering::AddressDependent;
    } else if client.binding(ChangeRequest::default()).is_ok() {
        profile.filtering = NatFiltering::AddressAndPortDependent;
    } else {
        profile.notes.push(
            "the server stopped answering entirely during the filtering tests, so filtering \
             stays undetermined"
                .to_string(),
        );
    }

    // --- mapping -----------------------------------------------------------
    //
    // Same socket, different destinations. The external *port* is what decides
    // this: a NAT that spreads mappings across a pool of public addresses would
    // otherwise look address-dependent when it is not.
    let primary_port = baseline.mapped.port();
    let other_same_port = SocketAddr::new(other.ip(), config.server.port());
    client.set_server(other_same_port);
    let mut second_port = None;
    match client.binding(ChangeRequest::default()) {
        Ok(binding) => {
            profile.samples.push((other_same_port, binding.mapped));
            second_port = Some(binding.mapped.port());
        }
        Err(error) => profile.notes.push(format!(
            "the alternate address {other_same_port} did not answer ({error}), so mapping is \
             only partially measured"
        )),
    }

    if let Some(second_port) = second_port {
        client.set_server(other);
        match client.binding(ChangeRequest::default()) {
            Ok(binding) => {
                profile.samples.push((other, binding.mapped));
                let third_port = binding.mapped.port();
                profile.mapping = if second_port == primary_port {
                    NatMapping::EndpointIndependent
                } else if third_port == second_port {
                    NatMapping::AddressDependent
                } else {
                    NatMapping::AddressAndPortDependent
                };
            }
            Err(error) => profile.notes.push(format!(
                "the alternate address and port {other} did not answer ({error}), so mapping \
                 stays undetermined"
            )),
        }
    }

    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with(samples: &[(u16, u16)]) -> NatProfile {
        NatProfile {
            local: "192.0.2.10:40000".parse().expect("valid"),
            mapped: format!("203.0.113.5:{}", samples[0].1)
                .parse()
                .expect("valid"),
            other: None,
            mapping: NatMapping::AddressAndPortDependent,
            filtering: NatFiltering::AddressAndPortDependent,
            samples: samples
                .iter()
                .map(|(server_port, mapped_port)| {
                    (
                        format!("198.51.100.1:{server_port}")
                            .parse()
                            .expect("valid"),
                        format!("203.0.113.5:{mapped_port}").parse().expect("valid"),
                    )
                })
                .collect(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_constant_step_is_detected_as_the_stride() {
        let profile = profile_with(&[(3478, 40000), (3479, 40002), (3480, 40004)]);
        assert_eq!(profile.port_stride(), Some(2));
    }

    #[test]
    fn an_inconsistent_step_is_reported_as_no_stride() {
        let profile = profile_with(&[(3478, 40000), (3479, 40002), (3480, 40007)]);
        assert_eq!(profile.port_stride(), None);
    }

    #[test]
    fn a_single_sample_cannot_establish_a_stride() {
        let profile = profile_with(&[(3478, 40000)]);
        assert_eq!(profile.port_stride(), None);
    }

    #[test]
    fn predictions_follow_the_observed_stride_first() {
        let profile = profile_with(&[(3478, 40000), (3479, 40002)]);
        let predicted = profile.predict_external_ports(8, 4);
        // The NAT moved by two per destination, so the first several guesses
        // have to as well: 40004, 40006, 40008, 40010.
        assert_eq!(&predicted[..4], &[40004, 40006, 40008, 40010]);
    }

    #[test]
    fn predictions_never_repeat_and_stay_in_range() {
        let profile = profile_with(&[(3478, 40000), (3479, 40001)]);
        let predicted = profile.predict_external_ports(64, 64);
        let mut sorted = predicted.clone();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), before, "a port must not be probed twice");
        assert!(predicted.iter().all(|port| *port >= EPHEMERAL_LOW));
    }

    #[test]
    fn prediction_wraps_at_the_top_of_the_range() {
        let profile = profile_with(&[(3478, 65534), (3479, 65535)]);
        let predicted = profile.predict_external_ports(4, 3);
        // Past the top the allocator restarts at the bottom of the ephemeral
        // range, so a prediction that stopped dead would miss every port.
        assert!(
            predicted.iter().any(|port| *port < EPHEMERAL_LOW + 8),
            "expected a wrapped-around port, got {predicted:?}"
        );
    }

    #[test]
    fn the_spread_phase_covers_the_window_before_repeating() {
        let profile = profile_with(&[(3478, 40000)]);
        let predicted = profile.predict_external_ports(32, 32);
        assert_eq!(predicted.len(), 32);
        let mut sorted = predicted.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 32);
    }

    #[test]
    fn an_empty_window_predicts_nothing() {
        let profile = profile_with(&[(3478, 40000)]);
        assert!(profile.predict_external_ports(0, 16).is_empty());
        assert!(profile.predict_external_ports(16, 0).is_empty());
    }

    #[test]
    fn outlook_treats_unknown_filtering_as_unresolved_not_as_permissive() {
        let mut profile = profile_with(&[(3478, 40000)]);
        profile.mapping = NatMapping::EndpointIndependent;
        profile.filtering = NatFiltering::Undetermined;
        // A permissive answer here would size the probe budget for an easy
        // network that has not been demonstrated to exist.
        assert_eq!(profile.outlook(), TraversalOutlook::Unknown);
        assert!(!profile.filtering.admits_unsolicited());
    }

    #[test]
    fn outlook_maps_the_four_behaviours_to_the_expected_expectations() {
        let mut profile = profile_with(&[(3478, 40000)]);
        profile.mapping = NatMapping::Undetermined;
        assert_eq!(profile.outlook(), TraversalOutlook::Unknown);
        profile.mapping = NatMapping::EndpointIndependent;
        profile.filtering = NatFiltering::AddressAndPortDependent;
        assert_eq!(profile.outlook(), TraversalOutlook::Direct);
        profile.mapping = NatMapping::AddressDependent;
        assert_eq!(profile.outlook(), TraversalOutlook::Probabilistic);
        profile.mapping = NatMapping::AddressAndPortDependent;
        assert_eq!(profile.outlook(), TraversalOutlook::Probabilistic);
    }

    #[test]
    fn advance_port_wraps_inside_the_ephemeral_range() {
        assert_eq!(advance_port(40000, 2, 1), 40002);
        // One past the top comes back to the bottom, not to zero.
        assert_eq!(advance_port(EPHEMERAL_HIGH, 1, 1), EPHEMERAL_LOW);
        assert_eq!(advance_port(EPHEMERAL_HIGH, 1, 2), EPHEMERAL_LOW + 1);
    }

    #[test]
    fn coprime_search_returns_something_that_visits_every_offset() {
        for span in 2..64usize {
            let step = pick_coprime(span);
            assert_eq!(
                gcd(step, span),
                1,
                "step {step} shares a factor with {span}"
            );
        }
    }
}
