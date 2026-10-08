//! Pure per-session state machine.
//!
//! OS resource ownership belongs to `transport`; this module only describes protocol state,
//! echo assembly and absolute timers. In particular, `Closing` means the scheduler is waiting
//! for the transport to report `GenerationDrained` before a reconnect may be scheduled.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Connecting,
    Active,
    Closing,
    ReconnectWait,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Verified,
    Partial,
    PeerClosed,
    Corrupted,
}

#[derive(Debug)]
pub struct Session {
    pub index: u32,
    pub state: SessionState,
    pub echoes: u64,
    /// Bytes already received for the attempt currently in flight.
    pub received: u32,
    /// Absolute operation deadline (connect or active I/O), if one is armed.
    pub deadline: Option<u64>,
    /// Absolute time for the next interval-spaced send.
    pub send_at: Option<u64>,
    /// Absolute time for a reconnect attempt after the old generation drained.
    pub reconnect_at: Option<u64>,
}

impl Session {
    pub fn new(index: u32) -> Self {
        Self {
            index,
            state: SessionState::Idle,
            echoes: 0,
            received: 0,
            deadline: None,
            send_at: None,
            reconnect_at: None,
        }
    }

    pub fn begin_connect(&mut self, now: u64, timeout_ms: u64) -> bool {
        if self.state != SessionState::Idle {
            return false;
        }
        self.state = SessionState::Connecting;
        self.received = 0;
        self.send_at = None;
        self.reconnect_at = None;
        self.deadline = Some(now.saturating_add(timeout_ms));
        true
    }

    pub fn connected(&mut self) -> bool {
        if self.state != SessionState::Connecting {
            return false;
        }
        self.state = SessionState::Active;
        self.deadline = None;
        true
    }

    pub fn begin_closing(&mut self) -> bool {
        if matches!(
            self.state,
            SessionState::Closing | SessionState::Completed | SessionState::Failed
        ) {
            return false;
        }
        self.state = SessionState::Closing;
        self.deadline = None;
        self.send_at = None;
        self.reconnect_at = None;
        self.received = 0;
        true
    }

    pub fn fail_permanently(&mut self) {
        self.state = SessionState::Failed;
        self.deadline = None;
        self.send_at = None;
        self.reconnect_at = None;
        self.received = 0;
    }

    pub fn complete(&mut self) {
        self.state = SessionState::Completed;
        self.deadline = None;
        self.send_at = None;
        self.reconnect_at = None;
        self.received = 0;
    }

    pub fn schedule_reconnect(&mut self, now: u64, delay_seconds: u32) -> bool {
        if self.state != SessionState::Closing {
            return false;
        }
        self.state = SessionState::ReconnectWait;
        self.deadline = None;
        self.reconnect_at = Some(
            now.saturating_add(u64::from(delay_seconds).saturating_mul(1_000)),
        );
        true
    }

    pub fn reconnect_due(&mut self, now: u64, timeout_ms: u64) -> bool {
        if self.state != SessionState::ReconnectWait {
            return false;
        }
        match self.reconnect_at {
            Some(at) if now >= at => {
                self.state = SessionState::Idle;
                self.reconnect_at = None;
                self.begin_connect(now, timeout_ms)
            }
            _ => false,
        }
    }

    /// Bytes of the current attempt still expected. The scheduler posts the remainder after a
    /// partial receive, so the accumulator is per attempt rather than per echo unit.
    pub fn receive_remaining(&self, attempt_bytes: u32) -> Option<u32> {
        attempt_bytes.checked_sub(self.received).filter(|remaining| *remaining != 0)
    }

    /// Validates received bytes against the attempt's expected payload. One attempt carries
    /// `units` copies of `pattern`, so the expected byte at any offset is the pattern byte at
    /// that offset modulo the pattern length. That keeps the comparison allocation-free while
    /// still requiring the exact bytes at the exact offsets.
    pub fn on_received(
        &mut self,
        chunk: &[u8],
        pattern: &[u8],
        units: u32,
        now: u64,
        timeout_ms: u64,
        allow_partial: bool,
    ) -> ReceiveOutcome {
        if self.state != SessionState::Active {
            return ReceiveOutcome::Corrupted;
        }
        if chunk.is_empty() {
            return if allow_partial {
                ReceiveOutcome::PeerClosed
            } else {
                ReceiveOutcome::Corrupted
            };
        }
        if pattern.is_empty() || units == 0 {
            return ReceiveOutcome::Corrupted;
        }
        let Some(total) = (pattern.len() as u64).checked_mul(u64::from(units)) else {
            return ReceiveOutcome::Corrupted;
        };
        let start = self.received as usize;
        let Some(end) = start.checked_add(chunk.len()) else {
            return ReceiveOutcome::Corrupted;
        };
        if end as u64 > total {
            return ReceiveOutcome::Corrupted;
        }
        if chunk
            .iter()
            .enumerate()
            .any(|(offset, byte)| *byte != pattern[(start + offset) % pattern.len()])
        {
            return ReceiveOutcome::Corrupted;
        }

        self.received = end as u32;
        if end as u64 == total {
            self.echoes = self.echoes.saturating_add(u64::from(units));
            self.received = 0;
            self.deadline = None;
            ReceiveOutcome::Verified
        } else if allow_partial {
            self.deadline = Some(now.saturating_add(timeout_ms));
            ReceiveOutcome::Partial
        } else {
            // Datagram boundaries are semantic boundaries. A short UDP datagram must not be
            // concatenated with the next datagram to manufacture one successful echo.
            ReceiveOutcome::Corrupted
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.state, SessionState::Completed | SessionState::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"abcdef";

    #[test]
    fn reconnect_wait_starts_only_after_closing() {
        let mut session = Session::new(0);
        assert!(session.begin_connect(0, 5_000));
        assert!(session.connected());
        assert!(session.begin_closing());
        assert!(session.schedule_reconnect(100, 2));
        assert_eq!(session.state, SessionState::ReconnectWait);
        assert!(!session.reconnect_due(2_099, 5_000));
        assert!(session.reconnect_due(2_100, 5_000));
        assert_eq!(session.state, SessionState::Connecting);
    }

    #[test]
    fn partial_echo_is_byte_exact() {
        let mut session = Session::new(1);
        session.begin_connect(0, 5_000);
        session.connected();
        assert_eq!(
            session.on_received(b"abc", PAYLOAD, 1, 1, 5_000, true),
            ReceiveOutcome::Partial
        );
        assert_eq!(session.receive_remaining(PAYLOAD.len() as u32), Some(3));
        assert_eq!(
            session.on_received(b"def", PAYLOAD, 1, 2, 5_000, true),
            ReceiveOutcome::Verified
        );
        assert_eq!(session.echoes, 1);
    }

    #[test]
    fn zero_length_is_peer_close() {
        let mut session = Session::new(2);
        session.begin_connect(0, 5_000);
        session.connected();
        assert_eq!(
            session.on_received(&[], PAYLOAD, 1, 0, 5_000, true),
            ReceiveOutcome::PeerClosed
        );
    }
}

// A session owns its socket, its request queue and the batch scheduler that drives its progress.
pub mod scheduler;
pub mod transport;

