//! Nonblocking TUN egress with bounds on both packet bytes and queue metadata.
//!
//! A full device queue drops packets, as a network interface may. TCP retains
//! unacknowledged data and retransmits; blocking here could prevent its ACKs
//! from being processed. A disconnected writer remains a terminal error.

use bytes::BytesMut;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

pub const MAX_QUEUED_BYTES: usize = 1024 * 1024;
pub const MAX_QUEUED_PACKETS: usize = 512;
// Matches the largest packet representable by the platform TUN adapters.
pub const MAX_PACKET_BYTES: usize = u16::MAX as usize;

#[derive(Default)]
struct Budget {
    bytes: AtomicUsize,
    dropped: AtomicU64,
    closed: AtomicBool,
}

/// A queued packet owns exactly its payload, never a larger shared read buffer.
/// Its reservation lasts until the writer finishes with it, including I/O.
pub struct QueuedPacket {
    bytes: Box<[u8]>,
    budget: Arc<Budget>,
}
impl Deref for QueuedPacket {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for QueuedPacket {
    fn drop(&mut self) {
        let length = self.bytes.len();
        drop(std::mem::take(&mut self.bytes));
        self.budget.bytes.fetch_sub(length, Ordering::AcqRel);
    }
}

/// A best-effort packet sink. `Ok(())` means the writer is alive, not delivery.
/// Legacy caller-owned channels remain supported by the stack constructors;
/// platform TUN devices always use the bounded channel below.
#[derive(Clone)]
pub struct PacketSender(Sender);
#[derive(Clone)]
enum Sender {
    Bounded(mpsc::SyncSender<QueuedPacket>, Arc<Budget>),
    Legacy(mpsc::Sender<BytesMut>),
}
impl From<mpsc::Sender<BytesMut>> for PacketSender {
    fn from(sender: mpsc::Sender<BytesMut>) -> Self {
        Self(Sender::Legacy(sender))
    }
}
impl PacketSender {
    pub fn send(&self, packet: BytesMut) -> Result<(), mpsc::SendError<BytesMut>> {
        let (sender, budget) = match &self.0 {
            Sender::Bounded(sender, budget) => (sender, budget),
            Sender::Legacy(sender) => return sender.send(packet),
        };
        if budget.closed.load(Ordering::Acquire) {
            return Err(mpsc::SendError(packet));
        }
        let length = packet.len();
        if length > MAX_PACKET_BYTES {
            budget.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        if budget
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(length)
                    .filter(|&total| total <= MAX_QUEUED_BYTES)
            })
            .is_err()
        {
            budget.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let queued = QueuedPacket {
            bytes: packet.as_ref().into(),
            budget: Arc::clone(budget),
        };
        match sender.try_send(queued) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => {
                budget.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => Err(mpsc::SendError(packet)),
        }
    }

    /// Includes packets currently held by the writer, not only waiting packets.
    pub fn retained_bytes(&self) -> Option<usize> {
        match &self.0 {
            Sender::Bounded(_, budget) => Some(budget.bytes.load(Ordering::Acquire)),
            Sender::Legacy(_) => None,
        }
    }
    pub fn dropped_packets(&self) -> u64 {
        match &self.0 {
            Sender::Bounded(_, budget) => budget.dropped.load(Ordering::Relaxed),
            Sender::Legacy(_) => 0,
        }
    }
}

pub struct PacketReceiver {
    receiver: mpsc::Receiver<QueuedPacket>,
    budget: Arc<Budget>,
}
impl PacketReceiver {
    pub fn recv(&self) -> Result<QueuedPacket, mpsc::RecvError> {
        self.receiver.recv()
    }

    pub fn try_recv(&self) -> Result<QueuedPacket, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<QueuedPacket, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}
impl Drop for PacketReceiver {
    fn drop(&mut self) {
        self.budget.closed.store(true, Ordering::Release);
    }
}

pub fn channel(packets: usize) -> (PacketSender, PacketReceiver) {
    let budget = Arc::new(Budget::default());
    let (sender, receiver) = mpsc::sync_channel(packets.clamp(1, MAX_QUEUED_PACKETS));
    (
        PacketSender(Sender::Bounded(sender, Arc::clone(&budget))),
        PacketReceiver { receiver, budget },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_writer_cannot_retain_more_than_the_byte_budget() {
        let (sender, receiver) = channel(MAX_QUEUED_PACKETS);
        for _ in 0..1000 {
            sender.send(BytesMut::from(&[42; 16384][..])).unwrap();
        }
        assert_eq!(sender.retained_bytes(), Some(MAX_QUEUED_BYTES));
        assert_eq!(sender.dropped_packets(), 936);
        let packet = receiver.recv_timeout(Duration::ZERO).unwrap();
        assert_eq!(packet.len(), 16384);
        assert_eq!(sender.retained_bytes(), Some(MAX_QUEUED_BYTES));
        drop(packet);
        assert_eq!(sender.retained_bytes(), Some(MAX_QUEUED_BYTES - 16384));
        sender.send(BytesMut::from(&[7; 16384][..])).unwrap();
        assert_eq!(sender.retained_bytes(), Some(MAX_QUEUED_BYTES));
        drop(receiver);
        assert_eq!(sender.retained_bytes(), Some(0));
        assert!(sender.send(BytesMut::from(&b"closed"[..])).is_err());
    }

    #[test]
    fn packet_count_and_small_slices_do_not_retain_large_backing_buffers() {
        let (sender, receiver) = channel(2);
        let mut backing = BytesMut::with_capacity(8 * 1024 * 1024);
        backing.extend_from_slice(b"abc");
        sender.send(backing.split_to(3)).unwrap();
        sender.send(BytesMut::new()).unwrap();
        sender.send(BytesMut::new()).unwrap();
        assert_eq!(sender.dropped_packets(), 1);
        assert_eq!(sender.retained_bytes(), Some(3));
        let packet = receiver.recv_timeout(Duration::ZERO).unwrap();
        assert_eq!(&*packet, b"abc");
        assert_eq!(packet.bytes.len(), 3);
        drop(backing);
        drop(packet);
        assert_eq!(sender.retained_bytes(), Some(0));
    }

    #[test]
    fn oversized_packets_are_dropped_before_device_length_conversion() {
        let (sender, receiver) = channel(1);
        sender
            .send(BytesMut::from(&vec![1; MAX_PACKET_BYTES + 1][..]))
            .unwrap();
        assert_eq!(sender.retained_bytes(), Some(0));
        assert_eq!(sender.dropped_packets(), 1);
        assert!(matches!(
            receiver.recv_timeout(Duration::ZERO),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
    }

    #[test]
    fn concurrent_producers_share_one_budget_and_stop_without_blocking() {
        let (sender, receiver) = channel(MAX_QUEUED_PACKETS);
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let sender = sender.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        sender.send(BytesMut::from(&[1; 8192][..])).unwrap();
                        assert!(sender.retained_bytes().unwrap() <= MAX_QUEUED_BYTES);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(sender.retained_bytes(), Some(MAX_QUEUED_BYTES));
        drop(receiver);
        assert_eq!(sender.retained_bytes(), Some(0));
    }
}
