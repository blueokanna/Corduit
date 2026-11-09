//! Count successful UDP submissions at leaf outbounds. Group members use the
//! same factory, so selectors and load balancing cannot misclassify an exit.
//! TCP accounting stays in the copy loop; replies are counted by UdpReplySink.
use super::{OutboundProxy, TargetAddr, UdpReplySink};
use crate::common::stream::BoxStream;
use crate::engine::connection_tracker::{TrackedConnection, global_tracker};
use crate::engine::error::Result;
use std::sync::Arc;
use std::time::Duration;

pub(super) struct MeteredOutbound {
    inner: Arc<dyn OutboundProxy>,
    direct: bool,
}

impl MeteredOutbound {
    pub(super) fn new(inner: Arc<dyn OutboundProxy>, direct: bool) -> Self {
        Self { inner, direct }
    }

    fn uploaded(&self, size: usize) {
        let tracker = global_tracker();
        if self.direct {
            tracker.add_direct_upload(size as u64);
        } else {
            tracker.add_global_upload(size as u64);
        }
    }
}

impl OutboundProxy for MeteredOutbound {
    fn connect(&self) -> Result<()> {
        self.inner.connect()
    }
    fn disconnect(&self) -> Result<()> {
        self.inner.disconnect()
    }
    fn tag(&self) -> &str {
        self.inner.tag()
    }
    fn server_addr(&self) -> Option<(String, u16)> {
        self.inner.server_addr()
    }
    fn supports_udp(&self) -> bool {
        self.inner.supports_udp()
    }
    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.inner.relay_tcp(inbound, target)
    }
    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<Arc<TrackedConnection>>,
    ) -> Result<()> {
        self.inner
            .relay_tcp_with_connection(inbound, target, connection)
    }
    fn udp_submit(&self, target: &TargetAddr, data: &[u8], sink: &Arc<UdpReplySink>) -> Result<()> {
        self.inner.udp_submit(target, data, sink)?;
        self.uploaded(data.len());
        Ok(())
    }
    fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let reply = self.inner.relay_udp_packet(target, data)?;
        self.uploaded(data.len());
        let tracker = global_tracker();
        if self.direct {
            tracker.add_direct_download(reply.len() as u64);
        } else {
            tracker.add_global_download(reply.len() as u64);
        }
        Ok(reply)
    }
    fn test_http_latency(&self, url: &str, timeout: Duration) -> Result<Duration> {
        self.inner.test_http_latency(url, timeout)
    }
}
