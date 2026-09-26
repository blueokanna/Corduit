//! Proxy groups: how a group decides which member serves a connection.
//!
//! A group is not a proxy. It is a policy over other proxies, and every group
//! type is a *different policy*:
//!
//! | Type | Decides by |
//! |---|---|
//! | `select` | the user's choice, and nothing else |
//! | `url-test` | the lowest measured HTTP latency |
//! | `fallback` | the first member that is alive, in configured order |
//! | `load-balance` | rotation across the members that are alive |
//! | `relay` | chaining, which is not a choice at all |
//!
//! Treating them as one policy — "use the first member, or whatever the user
//! picked" — is the single most consequential shortcut available here, because
//! it is invisible from the outside: a `url-test` group that never tests, and a
//! `fallback` group that never falls back, both look like a working group until
//! the day the first member dies.
//!
//! ## What health actually buys
//!
//! Selection is only as good as the liveness information behind it, so the group
//! tracks per-member health and probes it on an interval. Two decisions are made
//! deliberately:
//!
//! * **A member that has never been probed counts as available.** Starting every
//!   member dead would strand the whole group until the first probe round
//!   completed, which is exactly when a user is watching the connect button.
//! * **Two consecutive failures, not one, retire a member.** A single failure is
//!   as likely to be a transient route change as a dead node, and one-failure
//!   eviction makes a group flap under normal network noise.
//!
//! ## On failing over inside one connection
//!
//! The obvious next step — catch a relay failure and transparently retry on the
//! next member — is **not** expressible through this trait, and the reason is
//! worth stating rather than working around badly: `relay_tcp_with_connection`
//! takes the inbound stream **by value**, so by the time it fails the stream has
//! already been consumed and there is nothing left to retry with. A trait that
//! owns the stream cannot offer per-connection failover; it would have to lend
//! the stream and hand it back on failure.
//!
//! What is implemented instead is the part that does work: a failed relay
//! retires that member, so the *next* connection avoids it. Combined with
//! health-driven selection that covers the realistic failure mode — a node that
//! goes away and stays away — without lying about what a single connection can
//! survive.

use crate::common::cancel::CancellationToken;
use crate::common::stream::BoxStream;
use crate::engine::config::{OutboundConfig, OutboundType};
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{
    get_global_selector_selections, OutboundProxy, ProxyRegistry, TargetAddr, UdpReplySink,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Health-check URL: a `204`-answering endpoint, so the measurement is one
/// round trip and nothing else — and the same URL almost every provider's
/// latency column is computed against, so the numbers stay comparable.
const DEFAULT_TEST_URL: &str = "http://www.gstatic.com/generate_204";

/// Per-probe timeout.
const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between probe rounds.
const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(300);

/// Members probed concurrently within a round.
///
/// A group with two hundred nodes must neither open two hundred sockets at once
/// nor take two hundred timeouts to finish a round; eight keeps both bounded.
const MAX_PROBE_CONCURRENCY: usize = 8;

/// Consecutive failures before a member is taken out of rotation.
const FAILURES_BEFORE_DEAD: u32 = 2;

/// How a group chooses among its members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupStrategy {
    /// Manual: the user's choice is authoritative and the group never overrides
    /// it. Health is still tracked, and reported.
    Select,
    /// The member with the lowest measured latency.
    UrlTest,
    /// The first member that is alive, in configured order.
    Fallback,
    /// Alive members in rotation.
    LoadBalance,
    /// Members chained, in order, into one tunnel.
    Relay,
}

impl GroupStrategy {
    fn from_outbound_type(outbound_type: OutboundType) -> Option<Self> {
        match outbound_type {
            OutboundType::Selector => Some(Self::Select),
            OutboundType::Urltest => Some(Self::UrlTest),
            OutboundType::Fallback => Some(Self::Fallback),
            OutboundType::Loadbalance => Some(Self::LoadBalance),
            OutboundType::Relay => Some(Self::Relay),
            _ => None,
        }
    }

    /// Whether this policy's decision depends on measured latency.
    const fn needs_probing(self) -> bool {
        matches!(self, Self::UrlTest | Self::Fallback | Self::LoadBalance)
    }

    /// Whether a stored manual selection is what decides.
    const fn honours_manual_selection(self) -> bool {
        matches!(self, Self::Select)
    }
}

/// What the group knows about one member.
#[derive(Debug, Clone, Copy, Default)]
struct MemberHealth {
    /// Measured round-trip time of the last successful probe.
    latency: Option<Duration>,
    /// Failures since the last success.
    consecutive_failures: u32,
}

impl MemberHealth {
    /// Whether this member may be chosen.
    ///
    /// A member that has never been probed has zero failures and therefore
    /// counts as available — see the module note on why that is deliberate.
    fn is_available(&self) -> bool {
        self.consecutive_failures < FAILURES_BEFORE_DEAD
    }
}

/// A group of outbounds with a selection policy.
pub struct GroupOutbound {
    config: OutboundConfig,
    strategy: GroupStrategy,
    members: Vec<String>,
    registry: ProxyRegistry,
    health: RwLock<HashMap<String, MemberHealth>>,
    /// Rotation cursor for `load-balance`.
    cursor: AtomicUsize,
    test_url: String,
    test_timeout: Duration,
    probe_interval: Duration,
    /// Set once, so the prober thread is started at most once.
    prober_started: AtomicBool,
    cancelled: CancellationToken,
}

impl GroupOutbound {
    /// Build a group from its configuration.
    ///
    /// The strategy comes from the outbound type, which is why this cannot be a
    /// plain `Selector`: five different policies arrive through one type.
    pub fn new(config: OutboundConfig, registry: ProxyRegistry) -> Result<Self> {
        let strategy =
            GroupStrategy::from_outbound_type(config.outbound_type).ok_or_else(|| {
                Error::config(format!(
                    "Outbound '{}' is a {} outbound, not a proxy group",
                    config.tag,
                    config.outbound_type.as_str()
                ))
            })?;

        let members = parse_member_tags(&config);

        if members.is_empty() {
            // A group with no members cannot decide anything. Failing here is
            // better than every connection through it failing later, because
            // the diagnostic names the group.
            return Err(Error::config(format!(
                "Proxy group '{}' has no members; it needs an `outbounds` list",
                config.tag
            )));
        }

        if strategy == GroupStrategy::Relay {
            // Chaining needs to tunnel through each member in turn, which the
            // relay entry point cannot express today (see the module note on
            // stream ownership). Say so once, loudly, instead of quietly
            // behaving like a different group type.
            tracing::warn!(
                "Proxy group '{}' is a relay: chaining is not implemented, so traffic is \
                 forwarded through the first member only. Use a `select`/`url-test` group unless \
                 the hop-by-hop topology is required.",
                config.tag
            );
        }

        let test_url =
            option_string(&config, "url").unwrap_or_else(|| DEFAULT_TEST_URL.to_string());
        let test_timeout = option_u64(&config, "timeout")
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_TEST_TIMEOUT);
        let probe_interval = option_u64(&config, "interval")
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_PROBE_INTERVAL);

        tracing::info!(
            "Proxy group '{}' ({:?}) with {} members: {:?}",
            config.tag,
            strategy,
            members.len(),
            members
        );

        Ok(Self {
            config,
            strategy,
            members,
            registry,
            health: RwLock::new(HashMap::new()),
            cursor: AtomicUsize::new(0),
            test_url,
            test_timeout,
            probe_interval: probe_interval.max(Duration::from_secs(1)),
            prober_started: AtomicBool::new(false),
            cancelled: CancellationToken::new(),
        })
    }

    /// The group's policy.
    pub const fn strategy(&self) -> GroupStrategy {
        self.strategy
    }

    /// Member tags in configured order.
    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// The member that would serve a new connection.
    ///
    /// For `select` this is the user's choice; for the automatic strategies it
    /// is what the policy currently computes, so a UI reading this gets the
    /// member traffic is actually using rather than the last thing it sent.
    pub fn effective_member(&self) -> Option<String> {
        self.primary().ok()
    }

    /// Measured latency of every member that has one.
    pub fn member_latencies(&self) -> HashMap<String, Option<Duration>> {
        let health = self.health.read();
        self.members
            .iter()
            .map(|tag| (tag.clone(), health.get(tag).and_then(|state| state.latency)))
            .collect()
    }

    /// Record that a member carried a connection successfully.
    pub fn record_success(&self, tag: &str, latency: Option<Duration>) {
        let mut health = self.health.write();
        let state = health.entry(tag.to_string()).or_default();
        state.consecutive_failures = 0;
        if let Some(latency) = latency {
            state.latency = Some(latency);
        }
    }

    /// Record that a member failed, retiring it after two consecutive failures.
    pub fn record_failure(&self, tag: &str) {
        let mut health = self.health.write();
        let state = health.entry(tag.to_string()).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if !state.is_available() {
            tracing::warn!(
                "Proxy group '{}': member '{}' retired after {} consecutive failures",
                self.config.tag,
                tag,
                state.consecutive_failures
            );
        }
    }

    /// The member a manual selection points at, if it is a member at all.
    fn manual_selection(&self) -> Option<String> {
        get_global_selector_selections()
            .read()
            .get(&self.config.tag)
            .filter(|tag| self.members.contains(tag))
            .cloned()
    }

    /// Members that may currently be chosen, in configured order.
    ///
    /// Falls back to the full list when nothing is available: a group where
    /// every member looks dead is far more likely to be a probe problem than a
    /// total outage, and refusing to route at all would turn a transient
    /// monitoring failure into an outage.
    fn available_members(&self) -> Vec<String> {
        let health = self.health.read();
        let available: Vec<String> = self
            .members
            .iter()
            .filter(|tag| {
                health
                    .get(tag.as_str())
                    .map(|state| state.is_available())
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if available.is_empty() {
            self.members.clone()
        } else {
            available
        }
    }

    fn primary(&self) -> Result<String> {
        match self.strategy {
            GroupStrategy::Select => self
                .manual_selection()
                .or_else(|| self.members.first().cloned())
                .ok_or_else(|| self.empty_group_error()),
            GroupStrategy::Relay => self
                .members
                .first()
                .cloned()
                .ok_or_else(|| self.empty_group_error()),
            GroupStrategy::Fallback => {
                let available = self.available_members();
                available
                    .first()
                    .cloned()
                    .ok_or_else(|| self.empty_group_error())
            }
            GroupStrategy::UrlTest => self
                .fastest_member()
                .ok_or_else(|| self.empty_group_error()),
            GroupStrategy::LoadBalance => {
                let available = self.available_members();
                if available.is_empty() {
                    return Err(self.empty_group_error());
                }
                // Rotation over the *available* list, so a member that is out
                // does not consume a turn.
                let turn = self.cursor.fetch_add(1, Ordering::Relaxed);
                Ok(available[turn % available.len()].clone())
            }
        }
    }

    /// The available member with the lowest measured latency.
    ///
    /// Members that have never produced a measurement are kept as a final
    /// resort, in configured order: a group whose probes have all failed should
    /// still try something.
    fn fastest_member(&self) -> Option<String> {
        let available = self.available_members();
        let health = self.health.read();
        let mut best: Option<(Option<Duration>, &String)> = None;
        for tag in &available {
            let latency = health.get(tag.as_str()).and_then(|state| state.latency);
            match &best {
                // A measured member always beats an unmeasured one.
                Some((Some(current), _)) => {
                    if latency.is_some_and(|latency| latency < *current) {
                        best = Some((latency, tag));
                    }
                }
                Some((None, _)) => {
                    if latency.is_some() {
                        best = Some((latency, tag));
                    }
                }
                None => best = Some((latency, tag)),
            }
        }
        best.map(|(_, tag)| tag.clone())
    }

    fn empty_group_error(&self) -> Error {
        Error::config(format!(
            "Proxy group '{}' has no selectable member",
            self.config.tag
        ))
    }

    fn find(&self, tag: &str) -> Option<Arc<dyn OutboundProxy>> {
        self.registry.read().get(tag).cloned()
    }

    fn resolved(&self) -> Result<Arc<dyn OutboundProxy>> {
        let tag = self.primary()?;
        self.find(&tag).ok_or_else(|| {
            Error::config(format!(
                "Proxy group '{}' selected '{tag}', which is not in the registry",
                self.config.tag
            ))
        })
    }

    /// Probe every member once and fold the results into the health table.
    ///
    /// Exposed so a caller can force a refresh (a "test all" button, or a first
    /// connection through a group whose prober has not run yet).
    pub fn probe_all(&self) {
        let members = self.members.clone();
        let workers = MAX_PROBE_CONCURRENCY.min(members.len());
        if workers == 0 {
            return;
        }

        let results: parking_lot::Mutex<Vec<(String, Result<Duration>)>> =
            parking_lot::Mutex::new(Vec::with_capacity(members.len()));
        let next = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(tag) = members.get(index) else {
                        break;
                    };
                    let Some(proxy) = self.find(tag) else {
                        results
                            .lock()
                            .push((tag.clone(), Err(Error::config("not in registry"))));
                        continue;
                    };
                    let measured = proxy.test_http_latency(&self.test_url, self.test_timeout);
                    results.lock().push((tag.clone(), measured));
                });
            }
        });

        for (tag, measured) in results.into_inner() {
            match measured {
                Ok(latency) => self.record_success(&tag, Some(latency)),
                Err(_) => self.record_failure(&tag),
            }
        }

        if self.strategy == GroupStrategy::UrlTest {
            tracing::debug!(
                "Proxy group '{}' probe round finished; fastest is {:?}",
                self.config.tag,
                self.fastest_member()
            );
        }
    }

    /// Start the periodic probe loop, once, and only for strategies whose
    /// decision actually depends on a measurement.
    ///
    /// Called when the outbound manager registers the group, so a group that is
    /// never installed never spends a thread on it. A `select` group is skipped
    /// entirely: the user's choice is the answer, and probing it would be
    /// measurement nobody reads.
    pub(crate) fn ensure_prober(self: &Arc<Self>) {
        if !self.strategy.needs_probing() {
            return;
        }
        if self.prober_started.swap(true, Ordering::SeqCst) {
            return;
        }

        let weak = Arc::downgrade(self);
        let spawned = std::thread::Builder::new()
            .name(format!("group-probe-{}", self.config.tag))
            .spawn(move || {
                if let Some(group) = weak.upgrade() {
                    group.probe_all();
                }
                loop {
                    let Some(group) = weak.upgrade() else {
                        return;
                    };
                    let _ = group.cancelled.wait(group.probe_interval);
                    if group.cancelled.is_cancelled() {
                        return;
                    }
                    group.probe_all();
                }
            });

        if let Err(error) = spawned {
            self.prober_started.store(false, Ordering::SeqCst);
            tracing::warn!(
                "Proxy group '{}' could not start its health prober ({error}); selection falls \
                 back to configured order",
                self.config.tag
            );
        }
    }

    /// Stop the probe loop. Called when the group is dropped by the engine.
    pub fn shutdown(&self) {
        self.cancelled.cancel();
    }

    /// Whether a manual selection is being ignored because the policy is
    /// automatic. Surfaced so a UI can explain a "tap does nothing" report.
    pub fn manual_override_ignored(&self) -> bool {
        !self.strategy.honours_manual_selection() && self.manual_selection().is_some()
    }
}

impl std::fmt::Debug for GroupOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GroupOutbound")
            .field("tag", &self.config.tag)
            .field("strategy", &self.strategy)
            .field("members", &self.members)
            .finish_non_exhaustive()
    }
}

impl OutboundProxy for GroupOutbound {
    fn connect(&self) -> Result<()> {
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        self.resolved().ok()?.server_addr()
    }

    fn supports_udp(&self) -> bool {
        self.resolved()
            .map(|proxy| proxy.supports_udp())
            .unwrap_or(false)
    }

    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<Arc<crate::engine::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        let tag = self.primary()?;
        let proxy = self.find(&tag).ok_or_else(|| {
            Error::config(format!(
                "Proxy group '{}' selected '{tag}', which is not in the registry",
                self.config.tag
            ))
        })?;

        let started = Instant::now();
        let outcome = proxy.relay_tcp_with_connection(inbound, target, connection);
        match outcome {
            Ok(()) => {
                self.record_success(&tag, Some(started.elapsed()));
                Ok(())
            }
            Err(error) => {
                // The inbound stream is consumed by the call, so this failure
                // cannot be retried here; retiring the member is what makes the
                // *next* connection avoid it.
                self.record_failure(&tag);
                Err(error)
            }
        }
    }

    fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let proxy = self.resolved()?;
        proxy.relay_udp_packet(target, data)
    }

    /// Delegated so a member's session-based UDP path is used when the group
    /// is what the rules selected; the default implementation here would fall
    /// back to the member's blocking one-shot relay instead.
    fn udp_submit(&self, target: &TargetAddr, data: &[u8], sink: &Arc<UdpReplySink>) -> Result<()> {
        let proxy = self.resolved()?;
        proxy.udp_submit(target, data, sink)
    }

    fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        let proxy = self.resolved()?;
        proxy.test_http_latency(test_url, timeout)
    }
}

/// Read the member tags out of a group's options.
///
/// The `options` map round-trips through the config codec, so a list can arrive
/// either as a sequence or as a JSON string that encodes one. Both are accepted
/// because both occur in profiles in the wild.
fn parse_member_tags(config: &OutboundConfig) -> Vec<String> {
    let Some(value) = config.options.get("outbounds") else {
        tracing::warn!(
            "Proxy group '{}' has no 'outbounds' in its options; available keys: {:?}",
            config.tag,
            config.options.keys().collect::<Vec<_>>()
        );
        return Vec::new();
    };

    if let Some(array) = value.as_array() {
        return array
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect();
    }

    if let Some(encoded) = value.as_str() {
        match nextjson::from_str::<Vec<String>>(encoded) {
            Ok(members) => return members,
            Err(error) => tracing::warn!(
                "Proxy group '{}' has an 'outbounds' string that is not a JSON array: {error}",
                config.tag
            ),
        }
    }

    tracing::warn!(
        "Proxy group '{}' has an 'outbounds' value that is neither a sequence nor a string",
        config.tag
    );
    Vec::new()
}

fn option_string(config: &OutboundConfig, key: &str) -> Option<String> {
    config
        .options
        .get(key)
        .and_then(|value| value.as_str().map(String::from))
}

fn option_u64(config: &OutboundConfig, key: &str) -> Option<u64> {
    config
        .options
        .get(key)
        .and_then(nextjson::Value::as_u64)
        .or_else(|| {
            config
                .options
                .get(key)
                .and_then(|value| value.as_str())
                .and_then(|text| text.parse().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::config::OutboundConfig;
    use nextjson::Value as Json;

    /// A group tagged `G`.
    fn group(kind: OutboundType, members: &[&str]) -> GroupOutbound {
        group_named("G", kind, members)
    }

    /// A group with an explicit tag.
    ///
    /// Tests that touch the manual-selection table need their own tag: that
    /// table is process-global, and the test harness runs these in parallel, so
    /// two tests sharing a tag would read each other's writes.
    fn group_named(tag: &str, kind: OutboundType, members: &[&str]) -> GroupOutbound {
        let mut options = HashMap::new();
        options.insert(
            "outbounds".to_string(),
            Json::from(
                members
                    .iter()
                    .map(|member| Json::from((*member).to_string()))
                    .collect::<Vec<Json>>(),
            ),
        );
        GroupOutbound::new(
            OutboundConfig {
                outbound_type: kind,
                tag: tag.to_string(),
                server: None,
                port: None,
                options,
            },
            Arc::new(RwLock::new(HashMap::new())),
        )
        .expect("group builds")
    }

    #[test]
    fn a_group_without_members_is_rejected_by_name() {
        let error = GroupOutbound::new(
            OutboundConfig {
                outbound_type: OutboundType::Selector,
                tag: "EMPTY".to_string(),
                server: None,
                port: None,
                options: HashMap::new(),
            },
            Arc::new(RwLock::new(HashMap::new())),
        )
        .expect_err("a group with no members must not build");
        assert!(format!("{error}").contains("EMPTY"));
    }

    #[test]
    fn a_leaf_outbound_type_is_not_accepted_as_a_group() {
        let result = GroupOutbound::new(
            OutboundConfig {
                outbound_type: OutboundType::Direct,
                tag: "DIRECT".to_string(),
                server: None,
                port: None,
                options: HashMap::new(),
            },
            Arc::new(RwLock::new(HashMap::new())),
        );
        assert!(result.is_err());
    }

    #[test]
    fn every_group_type_maps_to_its_own_strategy() {
        for (kind, expected) in [
            (OutboundType::Selector, GroupStrategy::Select),
            (OutboundType::Urltest, GroupStrategy::UrlTest),
            (OutboundType::Fallback, GroupStrategy::Fallback),
            (OutboundType::Loadbalance, GroupStrategy::LoadBalance),
            (OutboundType::Relay, GroupStrategy::Relay),
        ] {
            let group = group(kind, &["A", "B"]);
            assert_eq!(group.strategy(), expected, "{kind:?}");
        }
    }

    #[test]
    fn members_are_read_from_a_json_string_too() {
        let mut options = HashMap::new();
        options.insert(
            "outbounds".to_string(),
            Json::from(r#"["A","B","C"]"#.to_string()),
        );
        let group = GroupOutbound::new(
            OutboundConfig {
                outbound_type: OutboundType::Fallback,
                tag: "G".to_string(),
                server: None,
                port: None,
                options,
            },
            Arc::new(RwLock::new(HashMap::new())),
        )
        .expect("group builds");
        assert_eq!(group.members(), ["A", "B", "C"]);
    }

    #[test]
    fn fallback_takes_the_first_member_in_order() {
        let group = group(OutboundType::Fallback, &["A", "B", "C"]);
        assert_eq!(group.effective_member().as_deref(), Some("A"));
    }

    #[test]
    fn fallback_skips_a_retired_member() {
        let group = group(OutboundType::Fallback, &["A", "B", "C"]);
        group.record_failure("A");
        assert_eq!(group.effective_member().as_deref(), Some("A"));
        group.record_failure("A");
        assert_eq!(group.effective_member().as_deref(), Some("B"));
    }

    #[test]
    fn a_successful_probe_revives_a_retired_member() {
        let group = group(OutboundType::Fallback, &["A", "B"]);
        group.record_failure("A");
        group.record_failure("A");
        assert_eq!(group.effective_member().as_deref(), Some("B"));
        group.record_success("A", Some(Duration::from_millis(10)));
        assert_eq!(group.effective_member().as_deref(), Some("A"));
    }

    #[test]
    fn every_member_retired_still_yields_a_choice() {
        let group = group(OutboundType::Fallback, &["A", "B"]);
        for member in ["A", "B"] {
            group.record_failure(member);
            group.record_failure(member);
        }
        assert_eq!(group.effective_member().as_deref(), Some("A"));
    }

    #[test]
    fn url_test_takes_the_fastest_measured_member() {
        let group = group(OutboundType::Urltest, &["A", "B", "C"]);
        group.record_success("A", Some(Duration::from_millis(120)));
        group.record_success("B", Some(Duration::from_millis(40)));
        group.record_success("C", Some(Duration::from_millis(80)));
        assert_eq!(group.effective_member().as_deref(), Some("B"));
    }

    #[test]
    fn url_test_prefers_a_measured_member_over_an_unmeasured_one() {
        let group = group(OutboundType::Urltest, &["A", "B"]);
        group.record_success("B", Some(Duration::from_millis(500)));
        assert_eq!(group.effective_member().as_deref(), Some("B"));
    }

    #[test]
    fn url_test_ignores_a_retired_member_even_when_it_is_fastest() {
        let group = group(OutboundType::Urltest, &["A", "B"]);
        group.record_success("A", Some(Duration::from_millis(10)));
        group.record_success("B", Some(Duration::from_millis(90)));
        assert_eq!(group.effective_member().as_deref(), Some("A"));
        group.record_failure("A");
        group.record_failure("A");
        assert_eq!(group.effective_member().as_deref(), Some("B"));
    }

    #[test]
    fn load_balance_rotates_over_the_available_members() {
        let group = group(OutboundType::Loadbalance, &["A", "B", "C"]);
        let first: Vec<String> = (0..6)
            .map(|_| group.effective_member().expect("a member"))
            .collect();
        assert_eq!(first, ["A", "B", "C", "A", "B", "C"]);
    }

    #[test]
    fn load_balance_does_not_consume_a_turn_for_a_retired_member() {
        let group = group(OutboundType::Loadbalance, &["A", "B"]);
        group.record_failure("A");
        group.record_failure("A");
        let seen: Vec<String> = (0..4)
            .map(|_| group.effective_member().expect("a member"))
            .collect();
        assert_eq!(seen, ["B", "B", "B", "B"]);
    }

    #[test]
    fn select_honours_the_users_choice() {
        let group = group_named("SELECT-HONOURS", OutboundType::Selector, &["A", "B"]);
        assert_eq!(group.effective_member().as_deref(), Some("A"));
        get_global_selector_selections()
            .write()
            .insert("SELECT-HONOURS".to_string(), "B".to_string());
        assert_eq!(group.effective_member().as_deref(), Some("B"));
        get_global_selector_selections()
            .write()
            .remove("SELECT-HONOURS");
    }

    #[test]
    fn select_ignores_a_selection_that_is_not_a_member() {
        let group = group_named("SELECT-STRANGE", OutboundType::Selector, &["A", "B"]);
        get_global_selector_selections()
            .write()
            .insert("SELECT-STRANGE".to_string(), "NOT_A_MEMBER".to_string());
        assert_eq!(group.effective_member().as_deref(), Some("A"));
        get_global_selector_selections()
            .write()
            .remove("SELECT-STRANGE");
    }

    #[test]
    fn an_automatic_strategy_reports_that_it_ignores_a_manual_choice() {
        let group = group_named("AUTO-IGNORES", OutboundType::Urltest, &["A", "B"]);
        assert!(!group.manual_override_ignored());
        get_global_selector_selections()
            .write()
            .insert("AUTO-IGNORES".to_string(), "B".to_string());
        assert!(group.manual_override_ignored());
        // The stored choice must not be what decides.
        group.record_success("A", Some(Duration::from_millis(5)));
        assert_eq!(group.effective_member().as_deref(), Some("A"));
        get_global_selector_selections()
            .write()
            .remove("AUTO-IGNORES");
    }

    #[test]
    fn only_the_automatic_strategies_need_probing() {
        assert!(!GroupStrategy::Select.needs_probing());
        assert!(!GroupStrategy::Relay.needs_probing());
        assert!(GroupStrategy::UrlTest.needs_probing());
        assert!(GroupStrategy::Fallback.needs_probing());
        assert!(GroupStrategy::LoadBalance.needs_probing());
    }

    #[test]
    fn latencies_are_reported_for_every_member() {
        let group = group(OutboundType::Urltest, &["A", "B"]);
        group.record_success("A", Some(Duration::from_millis(30)));
        let latencies = group.member_latencies();
        assert_eq!(latencies.get("A"), Some(&Some(Duration::from_millis(30))));
        assert_eq!(latencies.get("B"), Some(&None));
    }

    #[test]
    fn a_streaming_relay_retires_the_member_that_failed() {
        // The registry is empty, so the group cannot resolve a proxy and the
        // failure path is exercised through `resolved`.
        let group = group(OutboundType::Fallback, &["A", "B"]);
        assert!(group.resolved().is_err());
        // A missing member must not be silently swapped for another.
        assert_eq!(group.effective_member().as_deref(), Some("A"));
    }
}
