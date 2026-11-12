//! Bounded, cumulative-ACK TCP sender for the local TUN peer.
//!
//! Keep bytes until acknowledged: a successful write to the TUN device does
//! not mean the application's socket accepted the segment. No window scaling
//! is negotiated by this stack, so the peer window is the raw 16-bit value.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

const INITIAL_RTO: Duration = Duration::from_millis(300);
const MAX_RTO: Duration = Duration::from_secs(8);

pub(super) struct Segment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub fin: bool,
}

pub(super) struct SendQueue {
    bytes: VecDeque<u8>,
    capacity: usize,
    base: u32,
    next: u32,
    window: u32,
    window_seq: Option<u32>,
    window_ack: u32,
    deadline: Option<Instant>,
    rto: Duration,
    eof: bool,
    fin_seq: Option<u32>,
    fin_acked: bool,
}

fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

impl SendQueue {
    pub fn new(sequence: u32, capacity: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            capacity,
            base: sequence,
            next: sequence,
            window: 0,
            window_seq: None,
            window_ack: sequence,
            deadline: None,
            rto: INITIAL_RTO,
            eof: false,
            fin_seq: None,
            fin_acked: false,
        }
    }

    pub fn next_sequence(&self) -> u32 {
        self.next
    }
    pub fn fin_sent(&self) -> bool {
        self.fin_seq.is_some()
    }
    #[cfg(test)]
    pub fn fin_acked(&self) -> bool {
        self.fin_acked
    }
    pub fn outstanding(&self) -> bool {
        self.base != self.next
    }
    pub fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.bytes.len())
    }
    pub fn can_read(&self) -> bool {
        !self.eof && self.remaining() > 0 && self.bytes.len() < self.window.max(1) as usize
    }
    pub fn finish(&mut self) {
        self.eof = true;
    }
    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    pub fn enqueue(&mut self, data: &[u8]) -> bool {
        if self.eof || data.len() > self.remaining() {
            return false;
        }
        self.bytes.extend(data);
        true
    }

    pub fn acknowledge(&mut self, seq: u32, ack: u32, window: u16, now: Instant) {
        if before(ack, self.base) || before(self.next, ack) {
            return;
        }
        if self
            .window_seq
            .is_none_or(|old| before(old, seq) || (old == seq && !before(ack, self.window_ack)))
        {
            self.window = window as u32;
            self.window_seq = Some(seq);
            self.window_ack = ack;
        }
        let acknowledged = ack.wrapping_sub(self.base) as usize;
        if acknowledged > 0 {
            self.bytes.drain(..acknowledged.min(self.bytes.len()));
            self.base = ack;
            self.fin_acked = self.fin_seq.is_some_and(|fin| ack == fin.wrapping_add(1));
            self.rto = INITIAL_RTO;
            self.deadline = self.outstanding().then_some(now + self.rto);
        }
    }

    pub fn next_segment(&mut self, now: Instant, mss: usize) -> Option<Segment> {
        let mss = mss.max(1);
        let in_flight = self.next.wrapping_sub(self.base) as usize;
        if self.deadline.is_some_and(|deadline| now >= deadline) && in_flight > 0 {
            let fin = self.fin_seq == Some(self.base);
            let count = if fin {
                0
            } else {
                in_flight
                    .min(self.bytes.len())
                    .min(mss)
                    .min(self.window.max(1) as usize)
            };
            self.rto = (self.rto * 2).min(MAX_RTO);
            self.deadline = Some(now + self.rto);
            return Some(Segment {
                seq: self.base,
                data: self.bytes.iter().take(count).copied().collect(),
                fin,
            });
        }
        if self.fin_seq.is_some() {
            return None;
        }
        let available = (self.window as usize).saturating_sub(in_flight);
        let unsent = self.bytes.len().saturating_sub(in_flight);
        if unsent > 0 {
            let allowance = if self.window == 0 && in_flight == 0 {
                1
            } else {
                available
            };
            let count = unsent.min(mss).min(allowance);
            if count == 0 {
                return None;
            }
            let segment = Segment {
                seq: self.next,
                data: self
                    .bytes
                    .iter()
                    .skip(in_flight)
                    .take(count)
                    .copied()
                    .collect(),
                fin: false,
            };
            self.next = self.next.wrapping_add(count as u32);
            if self.deadline.is_none() {
                self.deadline = Some(now + self.rto);
            }
            return Some(segment);
        }
        if self.eof && self.bytes.is_empty() && available > 0 && !self.fin_acked {
            self.fin_seq = Some(self.next);
            let segment = Segment {
                seq: self.next,
                data: Vec::new(),
                fin: true,
            };
            self.next = self.next.wrapping_add(1);
            self.deadline = Some(now + self.rto);
            return Some(segment);
        }
        if self.eof
            && self.window == 0
            && self.bytes.is_empty()
            && self.deadline.is_none_or(|deadline| now >= deadline)
        {
            self.deadline = Some(now + self.rto);
            self.rto = (self.rto * 2).min(MAX_RTO);
            return Some(Segment {
                seq: self.next.wrapping_sub(1),
                data: Vec::new(),
                fin: false,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_segments_and_partial_acks_preserve_exact_bytes() {
        let now = Instant::now();
        let mut queue = SendQueue::new(u32::MAX - 3, 16);
        queue.acknowledge(10, u32::MAX - 3, 5, now);
        assert!(queue.enqueue(b"abcdefgh"));
        let first = queue.next_segment(now, 3).unwrap();
        assert_eq!(first.data, b"abc");
        assert_eq!(queue.next_segment(now, 3).unwrap().data, b"de");
        assert!(queue.next_segment(now, 3).is_none());
        assert_eq!(
            queue.next_segment(now + INITIAL_RTO, 3).unwrap().data,
            b"abc"
        );
        queue.acknowledge(10, u32::MAX - 1, 5, now + INITIAL_RTO);
        assert_eq!(
            queue.next_segment(now + INITIAL_RTO, 3).unwrap().data,
            b"fg"
        );
        queue.acknowledge(10, 1, 5, now + INITIAL_RTO);
        assert_eq!(queue.next_segment(now + INITIAL_RTO, 3).unwrap().data, b"h");
        queue.acknowledge(10, 4, 5, now);
        assert_eq!(queue.remaining(), 16);
        assert!(!queue.outstanding());
    }

    #[test]
    fn closed_window_probes_recover_after_a_lost_window_update() {
        let now = Instant::now();
        let mut queue = SendQueue::new(100, 8);
        queue.acknowledge(10, 100, 0, now);
        assert!(queue.enqueue(b"payload"));
        let probe = queue.next_segment(now, 1400).unwrap();
        assert_eq!((probe.seq, probe.data.as_slice()), (100, &b"p"[..]));
        assert!(queue.next_segment(now, 1400).is_none());
        let retry = queue.next_segment(now + INITIAL_RTO, 1400).unwrap();
        assert_eq!((retry.seq, retry.data), (100, b"p".to_vec()));
        queue.acknowledge(10, 101, 8, now);
        assert_eq!(queue.next_segment(now, 1400).unwrap().data, b"ayload");
        assert!(!queue.enqueue(b"overflow"));
    }

    #[test]
    fn fin_waits_for_payload_ack_and_is_retransmitted() {
        let now = Instant::now();
        let mut queue = SendQueue::new(100, 8);
        queue.acknowledge(10, 100, 8, now);
        assert!(queue.enqueue(b"data"));
        queue.finish();
        assert!(!queue.next_segment(now, 1400).unwrap().fin);
        assert!(queue.next_segment(now, 1400).is_none());
        queue.acknowledge(10, 104, 8, now);
        let fin = queue.next_segment(now, 1400).unwrap();
        assert!(fin.fin);
        assert_eq!(fin.seq, 104);
        assert!(queue.next_segment(now + INITIAL_RTO, 1400).unwrap().fin);
        queue.acknowledge(10, 105, 8, now);
        assert!(queue.fin_acked());
        assert!(queue.next_segment(now + MAX_RTO, 1400).is_none());
    }

    #[test]
    fn future_acks_and_stale_window_updates_are_ignored() {
        let now = Instant::now();
        let mut queue = SendQueue::new(100, 8);
        queue.acknowledge(20, 100, 4, now);
        assert!(queue.enqueue(b"abcdefgh"));
        queue.acknowledge(21, 108, 65535, now);
        queue.acknowledge(19, 100, 65535, now);
        assert_eq!(queue.next_segment(now, 1400).unwrap().data, b"abcd");
        assert!(queue.next_segment(now, 1400).is_none());
    }
}
