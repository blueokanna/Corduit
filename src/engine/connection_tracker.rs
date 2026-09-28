//! Real-time connection tracking for Corduit
//! Tracks active connections with traffic statistics

use crate::common::cancel::CancellationToken;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Unique connection ID generator
static CONNECTION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a unique connection ID
pub fn generate_connection_id() -> String {
    let id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("conn-{}", id)
}

/// Represents an active connection
#[derive(Debug)]
pub struct TrackedConnection {
    pub id: String,
    pub inbound_tag: String,
    pub outbound_tag: String,
    pub host: String,
    /// The address behind [`host`](Self::host), as far as anyone has looked
    /// it up.
    ///
    /// Written by whoever resolves the name, which is deliberately never the
    /// code path of the connection itself: the value feeds the connection
    /// list, and a list field is not worth a lookup in front of a relay.
    destination_ip: parking_lot::RwLock<Option<String>>,
    pub destination_port: u16,
    pub protocol: String,
    pub network: String,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    pub start_time: Instant,
    pub start_timestamp: u64,
    pub rule: String,
    pub rule_payload: String,
    pub process_name: Option<String>,
    cancel: CancellationToken,
}

impl TrackedConnection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inbound_tag: String,
        outbound_tag: String,
        host: String,
        destination_port: u16,
        protocol: String,
        network: String,
        rule: String,
        rule_payload: String,
    ) -> Self {
        let start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id: generate_connection_id(),
            inbound_tag,
            outbound_tag,
            host,
            destination_ip: parking_lot::RwLock::new(None),
            destination_port,
            protocol,
            network,
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            start_time: Instant::now(),
            start_timestamp: start,
            rule,
            rule_payload,
            process_name: None,
            cancel: CancellationToken::new(),
        }
    }

    /// Create a new tracked connection with destination IP address
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ip(
        inbound_tag: String,
        outbound_tag: String,
        host: String,
        destination_ip: Option<String>,
        destination_port: u16,
        protocol: String,
        network: String,
        rule: String,
        rule_payload: String,
    ) -> Self {
        let start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id: generate_connection_id(),
            inbound_tag,
            outbound_tag,
            host,
            destination_ip: parking_lot::RwLock::new(destination_ip),
            destination_port,
            protocol,
            network,
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            start_time: Instant::now(),
            start_timestamp: start,
            rule,
            rule_payload,
            process_name: None,
            cancel: CancellationToken::new(),
        }
    }

    /// The token that must be handed to every relay serving this connection.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// The address the connection list shows, once it is known.
    pub fn destination_ip(&self) -> Option<String> {
        self.destination_ip.read().clone()
    }

    /// Record the resolved address.
    ///
    /// Called after the connection is already running —
    /// [`fill_destination_ip_in_background`] is the intended caller — so the
    /// relay never waits for a lookup that exists for the connection list's
    /// sake.
    pub fn set_destination_ip(&self, address: Option<String>) {
        *self.destination_ip.write() = address;
    }

    pub fn add_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn get_upload(&self) -> u64 {
        self.upload_bytes.load(Ordering::Relaxed)
    }

    pub fn get_download(&self) -> u64 {
        self.download_bytes.load(Ordering::Relaxed)
    }

    pub fn duration_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

/// Global connection tracker
pub struct ConnectionTracker {
    connections: DashMap<String, Arc<TrackedConnection>>,
    total_connections: AtomicU64,
    total_upload: AtomicU64,
    total_download: AtomicU64,
    // Real-time traffic counters (reset periodically for speed calculation)
    realtime_upload: AtomicU64,
    realtime_download: AtomicU64,
    last_speed_update: std::sync::RwLock<Instant>,
    upload_speed: AtomicU64,
    download_speed: AtomicU64,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            total_connections: AtomicU64::new(0),
            total_upload: AtomicU64::new(0),
            total_download: AtomicU64::new(0),
            realtime_upload: AtomicU64::new(0),
            realtime_download: AtomicU64::new(0),
            last_speed_update: std::sync::RwLock::new(Instant::now()),
            upload_speed: AtomicU64::new(0),
            download_speed: AtomicU64::new(0),
        }
    }

    /// Add global upload bytes (called from relay functions)
    pub fn add_global_upload(&self, bytes: u64) {
        self.total_upload.fetch_add(bytes, Ordering::Relaxed);
        self.realtime_upload.fetch_add(bytes, Ordering::Relaxed);
        self.maybe_update_speed();
    }

    /// Add global download bytes (called from relay functions)
    pub fn add_global_download(&self, bytes: u64) {
        self.total_download.fetch_add(bytes, Ordering::Relaxed);
        self.realtime_download.fetch_add(bytes, Ordering::Relaxed);
        self.maybe_update_speed();
    }

    /// Update speed calculation if enough time has passed
    fn maybe_update_speed(&self) {
        if let Ok(mut last_update) = self.last_speed_update.try_write() {
            let elapsed = last_update.elapsed();
            // Update speed every 500ms for more responsive display
            if elapsed >= std::time::Duration::from_millis(500) {
                let secs = elapsed.as_secs_f64();
                if secs > 0.0 {
                    let upload = self.realtime_upload.swap(0, Ordering::Relaxed);
                    let download = self.realtime_download.swap(0, Ordering::Relaxed);
                    self.upload_speed
                        .store((upload as f64 / secs) as u64, Ordering::Relaxed);
                    self.download_speed
                        .store((download as f64 / secs) as u64, Ordering::Relaxed);
                }
                *last_update = Instant::now();
            }
        }
    }

    /// Force update speed calculation (called periodically from FFI)
    pub fn update_speed(&self) {
        if let Ok(mut last_update) = self.last_speed_update.write() {
            let elapsed = last_update.elapsed();
            let secs = elapsed.as_secs_f64();
            if secs > 0.0 {
                let upload = self.realtime_upload.swap(0, Ordering::Relaxed);
                let download = self.realtime_download.swap(0, Ordering::Relaxed);
                self.upload_speed
                    .store((upload as f64 / secs) as u64, Ordering::Relaxed);
                self.download_speed
                    .store((download as f64 / secs) as u64, Ordering::Relaxed);
            }
            *last_update = Instant::now();
        }
    }

    /// Get current upload speed in bytes/sec
    pub fn upload_speed(&self) -> u64 {
        self.upload_speed.load(Ordering::Relaxed)
    }

    /// Get current download speed in bytes/sec
    pub fn download_speed(&self) -> u64 {
        self.download_speed.load(Ordering::Relaxed)
    }

    /// Start tracking a new connection
    pub fn track(&self, conn: TrackedConnection) -> Arc<TrackedConnection> {
        let id = conn.id.clone();
        let conn_arc = Arc::new(conn);
        self.connections.insert(id, Arc::clone(&conn_arc));
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        conn_arc
    }

    /// Remove a connection from tracking
    pub fn untrack(&self, id: &str) {
        // Just remove the connection from tracking
        // Traffic is already counted in add_global_upload/download during relay
        self.connections.remove(id);
    }

    /// Get a connection by ID
    pub fn get(&self, id: &str) -> Option<Arc<TrackedConnection>> {
        self.connections.get(id).map(|c| Arc::clone(&c))
    }

    /// Get all active connections
    pub fn get_all(&self) -> Vec<Arc<TrackedConnection>> {
        self.connections
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect()
    }

    /// Get active connection count
    pub fn active_count(&self) -> usize {
        self.connections.len()
    }

    /// Get total connection count (including closed)
    pub fn total_count(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Get total upload bytes
    pub fn total_upload(&self) -> u64 {
        // Global traffic is already tracked via add_global_upload
        self.total_upload.load(Ordering::Relaxed)
    }

    /// Get total download bytes
    pub fn total_download(&self) -> u64 {
        // Global traffic is already tracked via add_global_download
        self.total_download.load(Ordering::Relaxed)
    }

    /// Close a connection by ID
    ///
    /// Cancels the connection's token first: removing the entry only hides it
    /// from the list, while the token is what actually tears the relay down
    /// and frees its sockets.
    pub fn close_connection(&self, id: &str) -> bool {
        let Some((_, conn)) = self.connections.remove(id) else {
            return false;
        };
        conn.cancellation_token().cancel();
        true
    }

    /// Close all connections
    pub fn close_all(&self) {
        let ids: Vec<String> = self.connections.iter().map(|e| e.key().clone()).collect();
        for id in ids {
            self.close_connection(&id);
        }
    }

    /// Reset all statistics (called when service restarts)
    pub fn reset(&self) {
        // Clear all connections, tearing down whatever still runs
        self.close_all();
        self.connections.clear();

        // Reset all counters
        self.total_connections.store(0, Ordering::Relaxed);
        self.total_upload.store(0, Ordering::Relaxed);
        self.total_download.store(0, Ordering::Relaxed);
        self.realtime_upload.store(0, Ordering::Relaxed);
        self.realtime_download.store(0, Ordering::Relaxed);
        self.upload_speed.store(0, Ordering::Relaxed);
        self.download_speed.store(0, Ordering::Relaxed);

        // Reset speed update time
        if let Ok(mut last_update) = self.last_speed_update.write() {
            *last_update = Instant::now();
        }
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Fill in a connection's display address without anyone waiting for it.
///
/// The lookup runs on a thread of its own, so the relay behind it starts
/// immediately. That ordering is the whole point: on a profile whose
/// resolver is a remote DoH endpoint, a cold name costs a network round
/// trip (up to the engine resolver's full budget), and paying it **before**
/// the tunnel opens puts a DNS latency in front of every HTTPS connection a
/// browser makes — the browser's `CONNECT` needs no lookup to be useful, so
/// the lookup must not hold it back. The answer is dropped when the
/// connection ends first, which costs nothing.
/// Cap on concurrent display lookups.
///
/// The lookup is cosmetic (it fills the connection list's address column), so
/// a burst of domain connections sheds these instead of spawning one OS
/// thread per connection.
const MAX_DISPLAY_LOOKUPS: usize = 32;

/// Display lookups currently in flight.
static DISPLAY_LOOKUPS_IN_FLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub fn fill_destination_ip_in_background(
    connection: Arc<TrackedConnection>,
    host: String,
    port: u16,
) {
    struct InFlightGuard;

    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            DISPLAY_LOOKUPS_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
        }
    }

    if DISPLAY_LOOKUPS_IN_FLIGHT.fetch_add(1, Ordering::AcqRel) >= MAX_DISPLAY_LOOKUPS {
        DISPLAY_LOOKUPS_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
        return;
    }
    let guard = InFlightGuard;
    let _ = std::thread::Builder::new()
        .name("corduit-display-ip".into())
        .spawn(move || {
            let _guard = guard;
            if let Some(address) = resolve_for_display(&host, port) {
                connection.set_destination_ip(Some(address));
            }
        });
}

/// The address that stands for `host:port` in the connection list.
///
/// The engine's resolver answers first for the same reason the dial path
/// prefers it — a profile may make a name resolvable only through its own
/// `nameserver-policy` — with the system resolver as the documented
/// fallback, exactly as on the dial path.
fn resolve_for_display(host: &str, port: u16) -> Option<String> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    if let Some(Ok(addresses)) = crate::dns::engine_resolver::resolve(host, port) {
        if let Some(address) = addresses.first() {
            return Some(address.ip().to_string());
        }
    }
    crate::common::socket::resolve_host(host, port, std::time::Duration::from_secs(3))
        .ok()
        .and_then(|addresses| addresses.into_iter().next())
        .map(|address| address.ip().to_string())
}

/// Connection handle that auto-untracks when dropped
pub struct ConnectionHandle {
    tracker: Arc<ConnectionTracker>,
    connection: Arc<TrackedConnection>,
}

impl ConnectionHandle {
    pub fn new(tracker: Arc<ConnectionTracker>, connection: Arc<TrackedConnection>) -> Self {
        Self {
            tracker,
            connection,
        }
    }

    pub fn id(&self) -> &str {
        &self.connection.id
    }

    pub fn add_upload(&self, bytes: u64) {
        self.connection.add_upload(bytes);
    }

    pub fn add_download(&self, bytes: u64) {
        self.connection.add_download(bytes);
    }

    pub fn connection(&self) -> &TrackedConnection {
        &self.connection
    }
}

impl Drop for ConnectionHandle {
    fn drop(&mut self) {
        self.tracker.untrack(&self.connection.id);
    }
}

// Global tracker instance
static GLOBAL_TRACKER: once_cell::sync::Lazy<Arc<ConnectionTracker>> =
    once_cell::sync::Lazy::new(|| Arc::new(ConnectionTracker::new()));

/// Get the global connection tracker
pub fn global_tracker() -> Arc<ConnectionTracker> {
    Arc::clone(&GLOBAL_TRACKER)
}

/// The token a relay should watch for the given tracked connection.
///
/// An untracked relay still needs a token, and a fresh one is never
/// cancelled: same behaviour as before tracking existed.
pub fn cancellation_for(connection: Option<&Arc<TrackedConnection>>) -> CancellationToken {
    connection
        .map(|conn| conn.cancellation_token())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_display_address_is_writable_after_tracking() {
        let tracker = ConnectionTracker::new();
        let conn = TrackedConnection::new_with_ip(
            "mixed".to_string(),
            "proxy".to_string(),
            "example.com".to_string(),
            None,
            443,
            "HTTPS".to_string(),
            "tcp".to_string(),
            "MATCH".to_string(),
            "MATCH".to_string(),
        );
        let tracked = tracker.track(conn);
        assert_eq!(tracked.destination_ip(), None);

        tracked.set_destination_ip(Some("203.0.113.10".to_string()));
        assert_eq!(tracked.destination_ip().as_deref(), Some("203.0.113.10"));
    }

    #[test]
    fn the_background_fill_lands_without_anyone_waiting() {
        let tracker = ConnectionTracker::new();
        let conn = TrackedConnection::new_with_ip(
            "mixed".to_string(),
            "proxy".to_string(),
            "203.0.113.7".to_string(),
            None,
            443,
            "HTTPS".to_string(),
            "tcp".to_string(),
            "MATCH".to_string(),
            "MATCH".to_string(),
        );
        let tracked = tracker.track(conn);
        fill_destination_ip_in_background(Arc::clone(&tracked), "203.0.113.7".to_string(), 443);

        // A literal needs no lookup, so this settles almost immediately; the
        // loop only bounds the thread hand-off.
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        while tracked.destination_ip().is_none() && Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(tracked.destination_ip().as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn test_connection_tracking() {
        let tracker = ConnectionTracker::new();

        let conn = TrackedConnection::new(
            "mixed".to_string(),
            "proxy".to_string(),
            "example.com".to_string(),
            443,
            "HTTPS".to_string(),
            "tcp".to_string(),
            "DOMAIN-SUFFIX".to_string(),
            "example.com".to_string(),
        );

        let id = conn.id.clone();
        let tracked = tracker.track(conn);

        assert_eq!(tracker.active_count(), 1);

        tracked.add_upload(1024);
        tracked.add_download(2048);

        assert_eq!(tracked.get_upload(), 1024);
        assert_eq!(tracked.get_download(), 2048);

        // Simulate global traffic tracking (as done in relay functions)
        tracker.add_global_upload(1024);
        tracker.add_global_download(2048);

        tracker.untrack(&id);
        assert_eq!(tracker.active_count(), 0);
        // Global traffic is tracked separately
        assert_eq!(tracker.total_upload(), 1024);
        assert_eq!(tracker.total_download(), 2048);
    }
}
