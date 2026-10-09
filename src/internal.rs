//! Worker, session state machine, scheduler and timers.
//!
//! This is the reference's cec_engine_internal.cpp: business state and timers only. Native object
//! lifetime belongs to `engine::transport`, which is why a generation is closed in two phases here.

pub mod session {
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
        /// `units` copies of `pattern`, so the bytes at any offset are the pattern's bytes at that
        /// offset modulo the pattern length. The comparison walks whole slices of the pattern and
        /// compares them with slice equality, which is a memcmp: comparing byte by byte with a
        /// modulo each would dominate the run for the 32 KiB attempts that /k 8 /z 4096 posts.
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
            let pattern_length = pattern.len();
            let mut offset = start;
            let mut rest = chunk;
            while !rest.is_empty() {
                let within = offset % pattern_length;
                let take = (pattern_length - within).min(rest.len());
                if rest[..take] != pattern[within..within + take] {
                    return ReceiveOutcome::Corrupted;
                }
                offset += take;
                rest = &rest[take..];
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

pub mod scheduler {
    //! Per-worker scheduler.
    //!
    //! The scheduler owns business state only. Native generation lifetime is owned by the
    //! transport and reconnect is deliberately split in two phases: failure -> `Close`, then
    //! `GenerationDrained` -> reconnect timer. This prevents a new socket from being created
    //! while the old generation can still produce completions.

    use crate::metrics::Statistics;
    use crate::session::{ReceiveOutcome, Session, SessionState};
    use crate::worker::timer::TimerHeap;
    use crate::types::{Options, Protocol};

    const GENERATION_DRAIN_GRACE_MS: u64 = 5_000;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Step {
        Connect(u32),
        Send { index: u32, bytes: u32 },
        Receive { index: u32, bytes: u32 },
        Close(u32),
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Flow {
        /// Echo units requested from this session, including already verified units.
        requested: u64,
        /// Echo units carried by the attempt currently posted; zero when no attempt is posted.
        batch_units: u32,
        /// The posted attempt's send has completed.
        send_done: bool,
        /// Exactly one receive may be outstanding per session.
        receive_posted: bool,
        /// The posted attempt's receive has been fully verified.
        receive_done: bool,
        /// The first attempt of this transport generation is immediate. `/i` spaces only later
        /// cycles, matching the baseline behaviour.
        started: bool,
    }

    impl Flow {
        /// Starts a fresh transport generation without rewinding the lifetime business counter.
        /// `Session::echoes` is cumulative across reconnects, so requested must restart at the
        /// same verified baseline rather than at zero.
        fn at_verified(verified: u64) -> Self {
            Self {
                requested: verified,
                ..Self::default()
            }
        }
    }

    pub struct Scheduler {
        sessions: Vec<Session>,
        heap: TimerHeap,
        statistics: Statistics,
        payload_bytes: u32,
        limit: u64,
        timeout_milliseconds: u64,
        interval_milliseconds: u32,
        reconnect_seconds: Option<u32>,
        protocol: Protocol,
        /// Echo units one attempt may carry: `/k` for TCP and a single unit for UDP, exactly as the
        /// reference sizes one send/receive pair.
        batch_capacity: u32,
        flows: Vec<Flow>,
    }

    impl Scheduler {
        pub fn new(session_count: u32, payload_bytes: u32, options: &Options) -> Self {
            let count = session_count as usize;
            Self {
                sessions: (0..session_count).map(Session::new).collect(),
                heap: TimerHeap::new(count),
                statistics: Statistics::default(),
                payload_bytes,
                limit: options.echo_count,
                timeout_milliseconds: u64::from(options.timeout_seconds).saturating_mul(1_000),
                interval_milliseconds: options.interval_milliseconds,
                reconnect_seconds: options.reconnect_seconds,
                protocol: options.protocol,
                batch_capacity: if options.protocol == Protocol::Tcp {
                    options.pipeline_depth.max(1)
                } else {
                    1
                },
                flows: vec![Flow::default(); count],
            }
        }

        pub fn statistics(&self) -> Statistics {
            self.statistics
        }

        pub fn sessions(&self) -> &[Session] {
            &self.sessions
        }

        pub fn session(&self, index: u32) -> Option<&Session> {
            self.sessions.get(index as usize)
        }

        pub fn all_finished(&self) -> bool {
            self.sessions.iter().all(Session::is_finished)
        }

        pub fn mark_fatal(&mut self) {
            self.statistics.fatal = true;
        }

        pub fn record_latency(&mut self, micros: u32) {
            self.statistics.record_latency(micros);
        }

        pub fn set_elapsed_milliseconds(&mut self, milliseconds: u64) {
            self.statistics.elapsed_milliseconds = milliseconds;
        }

        pub fn start(&mut self, now: u64) -> Vec<Step> {
            let mut steps = Vec::with_capacity(self.sessions.len());
            for index in 0..self.sessions.len() as u32 {
                if self.sessions[index as usize].begin_connect(now, self.timeout_milliseconds) {
                    self.arm(index);
                    steps.push(Step::Connect(index));
                }
            }
            steps
        }

        pub fn wait_milliseconds(&self, now: u64, maximum: u32) -> u32 {
            let Some(deadline) = self.heap.next_deadline() else {
                return maximum;
            };
            if deadline <= now {
                return 0;
            }
            let delta = deadline - now;
            delta.min(u64::from(maximum)) as u32
        }

        fn inflight_echoes(&self, slot: usize) -> Option<u64> {
            self.flows
                .get(slot)?
                .requested
                .checked_sub(self.sessions.get(slot)?.echoes)
        }

        fn arm(&mut self, index: u32) {
            let Some(session) = self.sessions.get(index as usize) else {
                return;
            };
            let earliest = [session.deadline, session.send_at, session.reconnect_at]
                .into_iter()
                .flatten()
                .min();
            match earliest {
                Some(at) => {
                    if !self.heap.insert_or_update(at, index) {
                        self.statistics.fatal = true;
                    }
                }
                None => {
                    self.heap.remove(index);
                }
            }
        }

        /// Bytes one attempt carrying `units` echo units occupies in registered memory.
        fn attempt_bytes(&self, units: u32) -> Option<u32> {
            units.checked_mul(self.payload_bytes)
        }

        /// Bytes of the attempt currently posted for `index`, zero when none is posted. The worker
        /// uses it to validate a send completion against the exact native request length.
        pub fn batch_bytes(&self, index: u32) -> u32 {
            self.flows
                .get(index as usize)
                .and_then(|flow| self.attempt_bytes(flow.batch_units))
                .unwrap_or(0)
        }

        fn can_request_more(&self, slot: usize) -> bool {
            // Exactly one attempt at a time per session. The reference begins the next attempt only
            // after the previous one's send and receive have both completed, which is what keeps the
            // request queue at one outstanding receive plus one outstanding send per session.
            if self.flows[slot].batch_units != 0 {
                return false;
            }
            self.limit == 0 || self.flows[slot].requested < self.limit
        }

        /// Echo units the next attempt may carry: the batch capacity, trimmed to the remaining finite
        /// quota so the final attempt of a run may be shorter than `/k`.
        fn granted_units(&self, slot: usize) -> u32 {
            let capacity = u64::from(self.batch_capacity);
            let granted = if self.limit == 0 {
                capacity
            } else {
                capacity.min(self.limit.saturating_sub(self.flows[slot].requested))
            };
            granted.min(u64::from(u32::MAX)) as u32
        }

        fn post_one_send(&mut self, index: u32, steps: &mut Vec<Step>) -> bool {
            let slot = index as usize;
            if !self.can_request_more(slot) {
                return false;
            }
            let granted = self.granted_units(slot);
            if granted == 0 {
                return false;
            }
            let Some(bytes) = self.attempt_bytes(granted) else {
                self.statistics.fatal = true;
                return false;
            };
            let Some(requested) = self.flows[slot].requested.checked_add(u64::from(granted)) else {
                self.statistics.fatal = true;
                return false;
            };
            let flow = &mut self.flows[slot];
            flow.requested = requested;
            flow.batch_units = granted;
            flow.send_done = false;
            flow.receive_done = false;
            flow.started = true;
            self.statistics.attempted = self.statistics.attempted.saturating_add(u64::from(granted));
            steps.push(Step::Send { index, bytes });
            true
        }

        fn ensure_receive(&mut self, index: u32, steps: &mut Vec<Step>) {
            let slot = index as usize;
            let flow = self.flows[slot];
            // A receive is posted once per attempt, and only for the bytes still missing after a
            // partial completion. Nothing is posted while no attempt is in flight.
            if flow.batch_units == 0 || flow.receive_posted || flow.receive_done {
                return;
            }
            let Some(expected) = self.attempt_bytes(flow.batch_units) else {
                self.statistics.fatal = true;
                return;
            };
            let Some(bytes) = self.sessions[slot].receive_remaining(expected) else {
                self.statistics.fatal = true;
                return;
            };
            self.flows[slot].receive_posted = true;
            steps.push(Step::Receive { index, bytes });
        }

        fn refresh_active_timers(&mut self, index: u32, now: u64) {
            let slot = index as usize;
            if self.sessions[slot].state != SessionState::Active {
                self.arm(index);
                return;
            }
            let busy = self.flows[slot].batch_units != 0;
            self.sessions[slot].deadline = busy.then_some(now.saturating_add(self.timeout_milliseconds));
            self.arm(index);
        }

        /// Fills an active session. With `/i == 0` it fills the business pipeline immediately.
        /// With `/i != 0`, the first send is immediate and later cycles are paced by `send_at`.
        fn top_up(&mut self, index: u32, now: u64) -> Vec<Step> {
            let slot = index as usize;
            let mut steps = Vec::new();
            if slot >= self.sessions.len() || self.sessions[slot].state != SessionState::Active {
                return steps;
            }

            let Some(inflight) = self.inflight_echoes(slot) else {
                self.statistics.fatal = true;
                return steps;
            };
            if inflight > u64::from(self.batch_capacity) {
                self.statistics.fatal = true;
                debug_assert!(false, "attempt batch exceeded its capacity");
                return steps;
            }

            if self.interval_milliseconds == 0 {
                while self.can_request_more(slot) {
                    if !self.post_one_send(index, &mut steps) {
                        break;
                    }
                }
            } else if self.can_request_more(slot) && self.sessions[slot].send_at.is_none() {
                // Preserve the baseline pacing contract: the first cycle starts immediately;
                // `/i` delays only subsequent cycles.
                if !self.flows[slot].started {
                    self.post_one_send(index, &mut steps);
                }
                if self.can_request_more(slot) {
                    self.sessions[slot].send_at = Some(
                        now.saturating_add(u64::from(self.interval_milliseconds)),
                    );
                }
            }

            self.ensure_receive(index, &mut steps);
            self.refresh_active_timers(index, now);

            let inflight = match self.inflight_echoes(slot) {
                Some(inflight) => inflight,
                None => {
                    self.statistics.fatal = true;
                    return steps;
                }
            };
            let busy = self.flows[slot].batch_units != 0;
            if self.limit != 0
                && self.sessions[slot].echoes >= self.limit
                && inflight == 0
                && !busy
            {
                self.sessions[slot].complete();
                self.heap.remove(index);
                steps.push(Step::Close(index));
            }
            steps
        }

        pub fn on_connected(&mut self, index: u32, now: u64) -> Vec<Step> {
            let slot = index as usize;
            if slot >= self.sessions.len() || !self.sessions[slot].connected() {
                return Vec::new();
            }
            self.statistics.connections = self.statistics.connections.saturating_add(1);
            self.flows[slot] = Flow::at_verified(self.sessions[slot].echoes);
            self.top_up(index, now)
        }

        pub fn on_sent(&mut self, index: u32, now: u64) -> Vec<Step> {
            let slot = index as usize;
            if slot >= self.flows.len() || self.sessions[slot].state != SessionState::Active {
                return Vec::new();
            }
            if self.flows[slot].batch_units == 0 || self.flows[slot].send_done {
                self.statistics.fatal = true;
                return Vec::new();
            }
            self.flows[slot].send_done = true;
            self.finish_attempt(index, now)
        }

        /// Retires the posted attempt once both of its native operations have completed and starts
        /// the next one. Nothing else may be posted for the session before that, because its request
        /// queue holds exactly one outstanding receive and one outstanding send.
        fn finish_attempt(&mut self, index: u32, now: u64) -> Vec<Step> {
            let slot = index as usize;
            let flow = self.flows[slot];
            if flow.batch_units == 0 || !flow.send_done || !flow.receive_done || flow.receive_posted {
                return Vec::new();
            }
            self.flows[slot].batch_units = 0;
            self.flows[slot].send_done = false;
            self.flows[slot].receive_done = false;
            // `/i` spaces attempts, never the operations inside one attempt. A finished quota still
            // falls through to top_up so the session can close instead of parking on a timer.
            if self.interval_milliseconds != 0 && self.can_request_more(slot) {
                self.sessions[slot].send_at =
                    Some(now.saturating_add(u64::from(self.interval_milliseconds)));
                self.arm(index);
                return Vec::new();
            }
            self.top_up(index, now)
        }

        pub fn on_sent_bytes(&mut self, bytes: u64) {
            self.statistics.sent_bytes = self.statistics.sent_bytes.saturating_add(bytes);
        }

        /// Reverses one scheduler reservation whose native post was never accepted. `top_up` may
        /// precompute several steps for one session; dispatch calls this for the failed step and
        /// every later step for that same session before classifying the generation as failed.
        pub fn rollback_unposted_step(&mut self, step: Step) {
            match step {
                Step::Send { index, .. } => {
                    let slot = index as usize;
                    let Some(flow) = self.flows.get_mut(slot) else {
                        self.statistics.fatal = true;
                        return;
                    };
                    let units = u64::from(flow.batch_units);
                    if units == 0 {
                        self.statistics.fatal = true;
                        return;
                    }
                    let Some(requested) = flow.requested.checked_sub(units) else {
                        self.statistics.fatal = true;
                        return;
                    };
                    if requested < self.sessions[slot].echoes {
                        self.statistics.fatal = true;
                        return;
                    }
                    flow.requested = requested;
                    flow.batch_units = 0;
                    flow.send_done = false;
                    flow.receive_done = false;
                }
                Step::Receive { index, .. } => {
                    let slot = index as usize;
                    let Some(flow) = self.flows.get_mut(slot) else {
                        self.statistics.fatal = true;
                        return;
                    };
                    if !flow.receive_posted {
                        self.statistics.fatal = true;
                        return;
                    }
                    flow.receive_posted = false;
                }
                Step::Connect(_) | Step::Close(_) => {}
            }
        }

        pub fn on_received(
            &mut self,
            index: u32,
            chunk: &[u8],
            payload: &[u8],
            now: u64,
        ) -> Vec<Step> {
            let slot = index as usize;
            if slot >= self.sessions.len() || self.sessions[slot].state != SessionState::Active {
                return Vec::new();
            }
            if !self.flows[slot].receive_posted {
                self.statistics.fatal = true;
                return Vec::new();
            }
            // The OS request ended when its completion was dequeued. A partial echo therefore
            // gets a brand-new receive request in top_up().
            self.flows[slot].receive_posted = false;
            self.statistics.received_bytes = self
                .statistics
                .received_bytes
                .saturating_add(chunk.len() as u64);

            let units = self.flows[slot].batch_units;
            if units == 0 {
                self.statistics.fatal = true;
                return Vec::new();
            }
            // TCP is a byte stream and may complete with a strict prefix. UDP is
            // message-oriented, so Session rejects a short datagram instead of concatenating it
            // with the next datagram.
            let outcome = self.sessions[slot].on_received(
                chunk,
                payload,
                units,
                now,
                self.timeout_milliseconds,
                self.protocol == Protocol::Tcp,
            );

            match outcome {
                ReceiveOutcome::Partial => {
                    crate::worker::trace::event_args("RECV_PARTIAL", format_args!("session={index}"));
                    self.top_up(index, now)
                }
                ReceiveOutcome::Verified => {
                    crate::worker::trace::event_args("RECV_COMPLETE", format_args!("session={index}"));
                    let Some(bytes) = self.attempt_bytes(units) else {
                        self.statistics.fatal = true;
                        return Vec::new();
                    };
                    // Echoes and validated bytes are counted per attempt, so a batch of `units`
                    // echoes advances the identity by exactly that many units.
                    self.statistics.echoes = self.statistics.echoes.saturating_add(u64::from(units));
                    self.statistics.bytes = self.statistics.bytes.saturating_add(u64::from(bytes));
                    self.flows[slot].receive_done = true;
                    self.finish_attempt(index, now)
                }
                ReceiveOutcome::PeerClosed => self.on_transport_failure(index, now),
                ReceiveOutcome::Corrupted => self.on_corrupted_receive(index),
            }
        }

        /// Terminates a session after a protocol/data-integrity failure. This is also used for
        /// an oversized UDP echo reported by RIO as WSAEMSGSIZE: reconnecting cannot turn an
        /// invalid echo into a valid one, so it is an EchoFailure rather than a network retry.
        pub fn on_corrupted_receive(&mut self, index: u32) -> Vec<Step> {
            let slot = index as usize;
            if slot >= self.sessions.len() || self.sessions[slot].is_finished() {
                return Vec::new();
            }
            crate::worker::trace::event_args("RECV_CORRUPT", format_args!("session={index}"));
            // Integrity is judged per attempt: a corrupted batch is as many corrupted echoes as the
            // batch carried, which is how the reference counts it.
            let units = u64::from(self.flows[slot].batch_units.max(1));
            self.statistics.corrupted = self.statistics.corrupted.saturating_add(units);
            let lost = match self.inflight_echoes(slot) {
                Some(inflight) => inflight.max(1),
                None => {
                    self.statistics.fatal = true;
                    1
                }
            };
            self.statistics.lost = self.statistics.lost.saturating_add(lost);
            self.flows[slot] = Flow::default();
            self.sessions[slot].fail_permanently();
            self.heap.remove(index);
            vec![Step::Close(index)]
        }

        /// Starts generation retirement after a connection-scoped failure. This is idempotent:
        /// cancellation completions from a generation already closing do not count as new losses.
        pub fn on_transport_failure(&mut self, index: u32, now: u64) -> Vec<Step> {
            let slot = index as usize;
            if slot >= self.sessions.len() {
                return Vec::new();
            }
            if matches!(
                self.sessions[slot].state,
                SessionState::Closing
                    | SessionState::ReconnectWait
                    | SessionState::Completed
                    | SessionState::Failed
            ) {
                return Vec::new();
            }

            let lost = match self.inflight_echoes(slot) {
                Some(inflight) => inflight,
                None => {
                    self.statistics.fatal = true;
                    0
                }
            };
            self.statistics.lost = self.statistics.lost.saturating_add(lost);
            self.flows[slot] = Flow::at_verified(self.sessions[slot].echoes);
            self.heap.remove(index);
            if self.sessions[slot].begin_closing() {
                // Cancellation completion is normally prompt, but never let a broken provider
                // strand the worker in Closing forever. Expiry is fatal; transport shutdown then
                // performs its bounded safe-drain/leak fallback rather than freeing live memory.
                self.sessions[slot].deadline =
                    Some(now.saturating_add(GENERATION_DRAIN_GRACE_MS));
                self.arm(index);
                vec![Step::Close(index)]
            } else {
                Vec::new()
            }
        }

        /// Called only after the transport proved all completions from the old generation were
        /// dequeued and its OVERLAPPED/RQ/socket can no longer be referenced by Windows.
        pub fn on_generation_drained(&mut self, index: u32, now: u64) -> Vec<Step> {
            let slot = index as usize;
            if slot >= self.sessions.len() || self.sessions[slot].state != SessionState::Closing {
                return Vec::new();
            }
            match self.reconnect_seconds {
                Some(delay) => {
                    if self.sessions[slot].schedule_reconnect(now, delay) {
                        self.statistics.reconnects = self.statistics.reconnects.saturating_add(1);
                        self.arm(index);
                    }
                }
                None => {
                    self.statistics.network_failures =
                        self.statistics.network_failures.saturating_add(1);
                    self.sessions[slot].fail_permanently();
                    self.heap.remove(index);
                }
            }
            Vec::new()
        }

        fn interval_send_due(&mut self, index: u32, now: u64) -> Vec<Step> {
            let slot = index as usize;
            let mut steps = Vec::new();
            if self.sessions[slot].state != SessionState::Active {
                return steps;
            }
            self.sessions[slot].send_at = None;
            self.post_one_send(index, &mut steps);
            self.ensure_receive(index, &mut steps);

            if self.interval_milliseconds != 0
                && self.can_request_more(slot)
                && self.sessions[slot].send_at.is_none()
            {
                self.sessions[slot].send_at = Some(
                    now.saturating_add(u64::from(self.interval_milliseconds)),
                );
            }
            self.refresh_active_timers(index, now);
            steps
        }

        pub fn poll(&mut self, now: u64, expired: &mut Vec<u32>) -> Vec<Step> {
            expired.clear();
            let count = self.heap.pop_expired(now, expired);
            let mut steps = Vec::new();

            for position in 0..count {
                let index = expired[position];
                let slot = index as usize;
                if slot >= self.sessions.len() {
                    self.statistics.fatal = true;
                    continue;
                }

                match self.sessions[slot].state {
                    SessionState::ReconnectWait => {
                        if self.sessions[slot].reconnect_due(now, self.timeout_milliseconds) {
                            self.arm(index);
                            steps.push(Step::Connect(index));
                        } else {
                            self.arm(index);
                        }
                    }
                    SessionState::Active => {
                        // An already-expired native I/O deadline wins over a send timer when
                        // both timestamps are equal; never post fresh work onto a timed-out
                        // generation just because its pacing timer fired at the same instant.
                        if self.sessions[slot].deadline.is_some_and(|at| now >= at) {
                            steps.extend(self.on_transport_failure(index, now));
                        } else if self.sessions[slot].send_at.is_some_and(|at| now >= at) {
                            steps.extend(self.interval_send_due(index, now));
                        } else {
                            self.arm(index);
                        }
                    }
                    SessionState::Connecting => {
                        if self.sessions[slot].deadline.is_some_and(|at| now >= at) {
                            steps.extend(self.on_transport_failure(index, now));
                        } else {
                            self.arm(index);
                        }
                    }
                    SessionState::Closing => {
                        if self.sessions[slot].deadline.is_some_and(|at| now >= at) {
                            crate::worker::trace::event_args(
                                "GENERATION_DRAIN_TIMEOUT",
                                format_args!("session={index}"),
                            );
                            self.statistics.fatal = true;
                            self.heap.remove(index);
                        } else {
                            self.arm(index);
                        }
                    }
                    _ => self.arm(index),
                }
            }
            steps
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::types::{Options, Protocol};

        fn scheduler(depth: u32, interval: u32, reconnect: Option<u32>) -> Scheduler {
            let mut options = Options::default();
            options.protocol = Protocol::Tcp;
            options.pipeline_depth = depth;
            options.interval_milliseconds = interval;
            options.reconnect_seconds = reconnect;
            options.echo_count = 10;
            Scheduler::new(1, 6, &options)
        }

        #[test]
        fn one_attempt_carries_the_batch_and_one_send_receive_pair() {
            // /k 4 with a 6-byte payload is a single 24-byte send plus one 24-byte receive whose
            // expected bytes are four copies of the pattern.
            let mut scheduler = scheduler(4, 0, None);
            assert_eq!(scheduler.start(0), vec![Step::Connect(0)]);
            let steps = scheduler.on_connected(0, 1);
            assert_eq!(steps, vec![Step::Send { index: 0, bytes: 24 }, Step::Receive { index: 0, bytes: 24 }]);
            assert_eq!(scheduler.inflight_echoes(0), Some(4));
            assert_eq!(scheduler.statistics.attempted, 4);

            let verified = scheduler.on_received(0, b"abcdefabcdefabcdefabcdef", b"abcdef", 2);
            assert!(verified.is_empty());
            assert_eq!(scheduler.statistics.echoes, 4);
            assert_eq!(scheduler.statistics.bytes, 24);

            // The attempt retires only once its send has completed too.
            let next = scheduler.on_sent(0, 3);
            assert_eq!(next, vec![Step::Send { index: 0, bytes: 24 }, Step::Receive { index: 0, bytes: 24 }]);
        }

        #[test]
        fn final_attempt_is_trimmed_to_the_remaining_quota() {
            // /k 4 with a quota of 6 grants 4 then 2, so the last attempt is shorter than /k.
            let mut options = Options::default();
            options.protocol = Protocol::Tcp;
            options.pipeline_depth = 4;
            options.echo_count = 6;
            let mut scheduler = Scheduler::new(1, 6, &options);
            scheduler.start(0);
            let first = scheduler.on_connected(0, 1);
            assert_eq!(first, vec![Step::Send { index: 0, bytes: 24 }, Step::Receive { index: 0, bytes: 24 }]);
            scheduler.on_sent(0, 2);
            let second = scheduler.on_received(0, b"abcdefabcdefabcdefabcdef", b"abcdef", 3);
            assert_eq!(second, vec![Step::Send { index: 0, bytes: 12 }, Step::Receive { index: 0, bytes: 12 }]);
            assert_eq!(scheduler.statistics.attempted, 6);
        }

        #[test]
        fn partial_receive_reposts_only_the_remaining_bytes() {
            let mut scheduler = scheduler(1, 0, None);
            scheduler.start(0);
            scheduler.on_connected(0, 0);
            let steps = scheduler.on_received(0, b"abc", b"abcdef", 10);
            assert!(steps.iter().any(|s| matches!(s, Step::Receive { index: 0, bytes: 3 })));
        }

        #[test]
        fn udp_short_datagram_is_not_reassembled_as_tcp_stream_data() {
            let mut options = Options::default();
            options.protocol = Protocol::Udp;
            options.pipeline_depth = 1;
            options.echo_count = 1;
            let mut scheduler = Scheduler::new(1, 6, &options);
            scheduler.start(0);
            scheduler.on_connected(0, 0);
            let steps = scheduler.on_received(0, b"abc", b"abcdef", 10);
            assert_eq!(scheduler.statistics.corrupted, 1);
            assert_eq!(scheduler.sessions[0].state, SessionState::Failed);
            assert_eq!(steps, vec![Step::Close(0)]);
        }

        #[test]
        fn corrupted_receive_is_terminal_even_when_reconnect_is_enabled() {
            let mut scheduler = scheduler(2, 0, Some(1));
            scheduler.start(0);
            scheduler.on_connected(0, 0);
            let close = scheduler.on_corrupted_receive(0);
            assert_eq!(close, vec![Step::Close(0)]);
            assert_eq!(scheduler.sessions[0].state, SessionState::Failed);
            // Integrity is counted per attempt: this attempt carried two echo units.
            assert_eq!(scheduler.statistics.corrupted, 2);
            assert!(scheduler.statistics.lost >= 1);
            assert_eq!(scheduler.statistics.reconnects, 0);
        }

        #[test]
        fn reconnect_wait_begins_only_after_generation_drained() {
            let mut scheduler = scheduler(1, 0, Some(2));
            scheduler.start(0);
            scheduler.on_connected(0, 0);
            let close = scheduler.on_transport_failure(0, 100);
            assert_eq!(close, vec![Step::Close(0)]);
            assert_eq!(scheduler.sessions[0].state, SessionState::Closing);
            assert!(scheduler.sessions[0].reconnect_at.is_none());

            scheduler.on_generation_drained(0, 200);
            assert_eq!(scheduler.sessions[0].state, SessionState::ReconnectWait);
            assert_eq!(scheduler.sessions[0].reconnect_at, Some(2_200));

            let mut expired = Vec::new();
            assert!(scheduler.poll(2_199, &mut expired).is_empty());
            assert_eq!(scheduler.poll(2_200, &mut expired), vec![Step::Connect(0)]);
        }

        #[test]
        fn reconnect_preserves_verified_counter_baseline() {
            let mut scheduler = scheduler(1, 0, Some(0));
            scheduler.start(0);
            scheduler.on_connected(0, 0);
            scheduler.on_sent(0, 1);
            let _ = scheduler.on_received(0, b"abcdef", b"abcdef", 2);
            assert_eq!(scheduler.sessions[0].echoes, 1);

            assert_eq!(scheduler.on_transport_failure(0, 3), vec![Step::Close(0)]);
            scheduler.on_generation_drained(0, 4);
            let mut expired = Vec::new();
            assert_eq!(scheduler.poll(4, &mut expired), vec![Step::Connect(0)]);
            let steps = scheduler.on_connected(0, 5);
            assert!(!scheduler.statistics.fatal);
            assert!(steps.iter().any(|step| matches!(step, Step::Send { .. })));
            assert_eq!(scheduler.inflight_echoes(0), Some(1));
        }

        #[test]
        fn receive_may_complete_before_send_without_posting_a_second_attempt() {
            let mut scheduler = scheduler(1, 0, None);
            scheduler.start(0);
            let initial = scheduler.on_connected(0, 0);
            assert_eq!(initial.iter().filter(|step| matches!(step, Step::Send { .. })).count(), 1);

            // RIO completion ordering between send and receive is not a business ordering
            // guarantee. Verify the echo first while the original send is still native-in-flight.
            let after_receive = scheduler.on_received(0, b"abcdef", b"abcdef", 1);
            assert!(!after_receive.iter().any(|step| matches!(step, Step::Send { .. })));
            assert_eq!(scheduler.flows[0].batch_units, 1);

            // Once that native send completion retires, the next attempt may be posted.
            let after_send = scheduler.on_sent(0, 2);
            assert!(after_send.iter().any(|step| matches!(step, Step::Send { .. })));
            assert_eq!(scheduler.flows[0].batch_units, 1);
            assert_eq!(scheduler.inflight_echoes(0), Some(1));
        }

        #[test]
        fn interval_pacing_spaces_attempts_and_keeps_the_first_immediate() {
            let mut scheduler = scheduler(4, 25, None);
            scheduler.start(100);
            let first = scheduler.on_connected(0, 100);
            assert_eq!(first.iter().filter(|step| matches!(step, Step::Send { .. })).count(), 1);
            assert!(first.iter().any(|step| matches!(step, Step::Receive { index: 0, bytes: 24 })));
            // The first attempt is immediate; the pause applies to the attempts after it.
            assert_eq!(scheduler.sessions[0].send_at, None);

            scheduler.on_sent(0, 101);
            let paced = scheduler.on_received(0, b"abcdefabcdefabcdefabcdef", b"abcdef", 101);
            assert!(paced.is_empty());
            assert_eq!(scheduler.sessions[0].send_at, Some(126));

            let mut expired = Vec::new();
            assert!(scheduler.poll(125, &mut expired).is_empty());
            let second = scheduler.poll(126, &mut expired);
            assert_eq!(second.iter().filter(|step| matches!(step, Step::Send { .. })).count(), 1);
        }

        #[test]
        fn closing_generation_has_a_finite_drain_deadline() {
            let mut scheduler = scheduler(1, 0, Some(1));
            scheduler.start(0);
            scheduler.on_connected(0, 0);
            assert_eq!(scheduler.on_transport_failure(0, 100), vec![Step::Close(0)]);
            assert_eq!(scheduler.sessions[0].state, SessionState::Closing);
            let deadline = scheduler.sessions[0].deadline.expect("closing deadline");

            let mut expired = Vec::new();
            assert!(scheduler.poll(deadline.saturating_sub(1), &mut expired).is_empty());
            assert!(!scheduler.statistics.fatal);
            assert!(scheduler.poll(deadline, &mut expired).is_empty());
            assert!(scheduler.statistics.fatal);
        }
    }
}
}

pub mod worker {
    //! Worker loop for the completion-driven client.
    //!
    //! The transport owns native generations and resource lifetime. The scheduler owns business
    //! state. The worker is the only bridge between them: it never interprets a stale completion,
    //! never posts an extra receive behind the scheduler's back, and always asks the transport to
    //! quiesce before the worker thread returns.

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use crate::native::completion::{Operation, WSAEMSGSIZE, is_connection_level};
    use crate::session::scheduler::{Scheduler, Step};
    use crate::types::Options;

    /// One completion after native ownership accounting has already been retired by the transport.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Completion {
        pub index: u32,
        pub generation: u32,
        /// TX pipeline slot for a send completion. Other operations use NO_SEND_SLOT.
        pub slot: u32,
        pub operation: Operation,
        pub status: i32,
        pub bytes: u32,
    }

    /// Narrow interface driven by the worker. Production uses `RioTransport`; tests use a recorder.
    pub trait Transport {
        fn connect(&mut self, index: u32) -> Result<(), String>;
        fn send(&mut self, index: u32, bytes: u32) -> Result<(), String>;
        fn receive(&mut self, index: u32, bytes: u32) -> Result<(), String>;
        fn close(&mut self, index: u32);

        /// Applies protocol-specific work after a successful connect completion.
        fn connected(&mut self, _index: u32, _generation: u32) -> Result<(), String> {
            Ok(())
        }

        /// Re-checks whether a completion that was collected into the current batch still belongs
        /// to a live generation. This matters when an earlier completion in the same batch starts
        /// Closing: later completions are still needed for native accounting but must not steer the
        /// business state machine.
        fn completion_is_live(&self, _index: u32, _generation: u32) -> bool {
            true
        }

        /// Bytes written by a completed receive. The lifetime ends before the next receive post.
        fn received(&self, _index: u32, _generation: u32, _length: u32) -> &[u8] {
            &[]
        }

        fn drain(&mut self, _budget: u32) -> Result<Vec<Completion>, String> {
            Ok(Vec::new())
        }

        fn wait_and_drain(
            &mut self,
            _wait_milliseconds: u32,
            budget: u32,
        ) -> Result<Vec<Completion>, String> {
            self.drain(budget)
        }

        /// Takes back the batch the previous `wait_and_drain` handed out so the transport can
        /// reuse its buffer. Without this the buffer is freed every loop iteration, which the
        /// datagram path pays once per round trip.
        fn recycle(&mut self, _completions: Vec<Completion>) {}

        /// Quiesces native I/O and releases resources in a safe order.
        fn shutdown(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    pub trait Clock {
        fn now_milliseconds(&mut self) -> u64;
        fn wait(&mut self, milliseconds: u32);
    }

    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    /// Process-wide stop token. A console control handler can set it without locks or allocation.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct StopFlag;

    impl StopFlag {
        pub fn clear_global() {
            STOP_REQUESTED.store(false, Ordering::Release);
        }

        pub fn request_global() {
            STOP_REQUESTED.store(true, Ordering::Release);
        }

        pub fn request(&self) {
            Self::request_global();
        }

        pub fn is_requested(&self) -> bool {
            STOP_REQUESTED.load(Ordering::Acquire)
        }
    }

    pub const DRAIN_BATCHES: u32 = 64;

    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct RunOutcome {
        pub controlled_stop: bool,
        pub batches: u64,
        pub steps: u64,
        pub failures: u64,
    }

    pub struct Worker {
        scheduler: Scheduler,
        payload_bytes: u32,
        payload: std::sync::Arc<[u8]>,
        report_seconds: u32,
        quiet: bool,
        next_report: u64,
        run_seconds: u32,
        run_deadline: Option<u64>,
        started_at: Instant,
        /// One timestamp per business echo in post order. TCP echo ordering makes this exact for
        /// TCP; for UDP it is a best-effort FIFO sample because identical datagrams carry no ID.
        /// When the attempt each session has in flight was posted. One attempt at a time means
        /// one sample slot, so the latency path never allocates.
        attempt_started: Vec<Option<Instant>>,
    }

    impl Worker {
        pub fn new(options: &Options, session_count: u32, payload_bytes: u32, _now: u64) -> Self {
            Self {
                scheduler: Scheduler::new(session_count, payload_bytes, options),
                payload_bytes,
                payload: std::sync::Arc::from(vec![0u8; payload_bytes as usize].into_boxed_slice()),
                report_seconds: options.report_seconds,
                quiet: options.quiet,
                next_report: 0,
                run_seconds: options.run_seconds,
                run_deadline: None,
                started_at: Instant::now(),
                attempt_started: (0..session_count).map(|_| None).collect(),
            }
        }

        pub fn set_payload(&mut self, payload: std::sync::Arc<[u8]>) {
            self.payload_bytes = payload.len() as u32;
            self.payload = payload;
        }

        pub fn payload(&self) -> &[u8] {
            &self.payload
        }

        pub fn scheduler(&self) -> &Scheduler {
            &self.scheduler
        }

        pub fn scheduler_mut(&mut self) -> &mut Scheduler {
            &mut self.scheduler
        }

        fn clear_latency_queue(&mut self, index: u32) {
            if let Some(started) = self.attempt_started.get_mut(index as usize) {
                *started = None;
            }
        }

        fn record_verified_latency(&mut self, index: u32) {
            // Exactly one attempt is in flight per session, so the sample is the time that attempt
            // took: no queue is needed, and the hot path performs one store and one load.
            let Some(started) = self.attempt_started.get_mut(index as usize) else {
                return;
            };
            let Some(sent) = started.take() else {
                return;
            };
            let micros = Instant::now()
                .duration_since(sent)
                .as_micros()
                .min(u128::from(u32::MAX)) as u32;
            self.scheduler.record_latency(micros);
        }

        fn fail_session<T: Transport>(
            &mut self,
            index: u32,
            now: u64,
            transport: &mut T,
            outcome: &mut RunOutcome,
        ) {
            self.clear_latency_queue(index);
            let steps = self.scheduler.on_transport_failure(index, now);
            self.dispatch(&steps, transport, outcome, now);
        }

        fn handle_completion<T: Transport>(
            &mut self,
            completion: Completion,
            now: u64,
            transport: &mut T,
            outcome: &mut RunOutcome,
        ) {
            crate::worker::trace::event_args(
                "COMPLETION",
                format_args!(
                    "session={} generation={} op={:?} slot={} status={} bytes={}",
                    completion.index,
                    completion.generation,
                    completion.operation,
                    completion.slot,
                    completion.status,
                    completion.bytes
                ),
            );

            if completion.operation == Operation::GenerationDrained {
                let steps = self.scheduler.on_generation_drained(completion.index, now);
                self.dispatch(&steps, transport, outcome, now);
                return;
            }

            // The transport may have collected several completions before the worker sees them.
            // A previous completion in this same Vec can already have moved the generation to
            // Closing, so re-check liveness immediately before touching scheduler state.
            if !transport.completion_is_live(completion.index, completion.generation) {
                crate::worker::trace::event_args(
                    "COMPLETION_IGNORED_AFTER_CLOSE",
                    format_args!(
                        "session={} generation={} op={:?}",
                        completion.index, completion.generation, completion.operation
                    ),
                );
                return;
            }

            if completion.status != 0 {
                outcome.failures = outcome.failures.saturating_add(1);
                if completion.operation == Operation::Receive && completion.status == WSAEMSGSIZE {
                    // A connected UDP receive that does not fit the expected echo buffer is a
                    // protocol/data-integrity failure, not a reason to reconnect indefinitely.
                    self.clear_latency_queue(completion.index);
                    let steps = self.scheduler.on_corrupted_receive(completion.index);
                    self.dispatch(&steps, transport, outcome, now);
                } else if is_connection_level(completion.status) {
                    crate::worker::trace::event_args(
                        "CONNECTION_FAILURE",
                        format_args!(
                            "session={} generation={} status={}",
                            completion.index, completion.generation, completion.status
                        ),
                    );
                    self.fail_session(completion.index, now, transport, outcome);
                } else {
                    // An unknown native completion status is not safely attributable to an
                    // ordinary peer/network failure. Reconnecting would hide provider/state
                    // corruption and could loop forever, so make the run fatal. Transport
                    // shutdown still performs the bounded cancellation/drain protocol.
                    crate::worker::trace::event_args(
                        "NATIVE_OPERATION_FATAL",
                        format_args!(
                            "session={} generation={} op={:?} status={}",
                            completion.index,
                            completion.generation,
                            completion.operation,
                            completion.status
                        ),
                    );
                    self.scheduler.mark_fatal();
                }
                return;
            }

            let steps = match completion.operation {
                Operation::Connect => {
                    if let Err(reason) = transport.connected(completion.index, completion.generation) {
                        crate::worker::trace::event("CONNECT_FINALIZE_FAILED", &reason);
                        outcome.failures = outcome.failures.saturating_add(1);
                        self.fail_session(completion.index, now, transport, outcome);
                        return;
                    }
                    self.scheduler.on_connected(completion.index, now)
                }
                Operation::Send => {
                    // The transport re-posts the remainder of a partial native send, so a send
                    // completion always covers the whole attempt it was posted for.
                    let expected = self.scheduler.batch_bytes(completion.index);
                    if completion.bytes != expected {
                        crate::worker::trace::event_args(
                            "SHORT_SEND",
                            format_args!(
                                "session={} generation={} bytes={} expected={}",
                                completion.index,
                                completion.generation,
                                completion.bytes,
                                expected
                            ),
                        );
                        outcome.failures = outcome.failures.saturating_add(1);
                        self.fail_session(completion.index, now, transport, outcome);
                        return;
                    }
                    self.scheduler.on_sent_bytes(u64::from(completion.bytes));
                    self.scheduler.on_sent(completion.index, now)
                },
                Operation::Receive => {
                    let before = self
                        .scheduler
                        .session(completion.index)
                        .map(|session| session.echoes)
                        .unwrap_or(0);
                    let chunk = transport.received(
                        completion.index,
                        completion.generation,
                        completion.bytes,
                    );
                    let steps = self.scheduler.on_received(
                        completion.index,
                        chunk,
                        &self.payload,
                        now,
                    );
                    let after = self
                        .scheduler
                        .session(completion.index)
                        .map(|session| session.echoes)
                        .unwrap_or(before);
                    if after > before {
                        self.record_verified_latency(completion.index);
                    }
                    steps
                }
                Operation::GenerationDrained => unreachable!(),
            };
            self.dispatch(&steps, transport, outcome, now);
        }

        /// Runs until all sessions finish, a controlled stop/run deadline fires, or a fatal
        /// transport error makes progress impossible. Native shutdown is always attempted before
        /// returning, even for a controlled stop.
        pub fn run<C: Clock, T: Transport>(
            &mut self,
            clock: &mut C,
            transport: &mut T,
            stop: &StopFlag,
        ) -> RunOutcome {
            let mut outcome = RunOutcome::default();
            let started = clock.now_milliseconds();
            self.started_at = Instant::now();
            self.run_deadline = if self.run_seconds == 0 {
                None
            } else {
                Some(started.saturating_add(u64::from(self.run_seconds).saturating_mul(1_000)))
            };
            self.next_report = if self.report_seconds == 0 {
                0
            } else {
                started.saturating_add(u64::from(self.report_seconds).saturating_mul(1_000))
            };

            let steps = self.scheduler.start(started);
            self.dispatch(&steps, transport, &mut outcome, started);
            let mut expired = Vec::new();

            loop {
                if stop.is_requested() {
                    outcome.controlled_stop = true;
                    break;
                }
                let now = clock.now_milliseconds();
                if self.run_deadline.is_some_and(|deadline| now >= deadline) {
                    outcome.controlled_stop = true;
                    break;
                }
                if self.scheduler.all_finished() || self.scheduler.statistics().fatal {
                    break;
                }

                let wait = self.scheduler.wait_milliseconds(now, 1_000);
                if wait == 0 {
                    let poll_now = clock.now_milliseconds();
                    let steps = self.scheduler.poll(poll_now, &mut expired);
                    self.dispatch(&steps, transport, &mut outcome, poll_now);
                    continue;
                }

                // Test clocks advance here. The production clock intentionally does nothing;
                // RioTransport::wait_and_drain performs the blocking GQCS wait.
                clock.wait(wait);
                let now = clock.now_milliseconds();
                let completions = match transport.wait_and_drain(wait, DRAIN_BATCHES) {
                    Ok(completions) => completions,
                    Err(reason) => {
                        crate::worker::trace::event("WAIT_DRAIN_FAILED", &reason);
                        self.scheduler.mark_fatal();
                        outcome.failures = outcome.failures.saturating_add(1);
                        break;
                    }
                };

                for position in 0..completions.len() {
                    let completion = completions[position];
                    self.handle_completion(completion, now, transport, &mut outcome);
                    if self.scheduler.statistics().fatal {
                        break;
                    }
                }
                transport.recycle(completions);

                if self.report_seconds != 0 && !self.quiet {
                    let reported_at = clock.now_milliseconds();
                    if reported_at >= self.next_report {
                        // The periodic report uses the terminal line's schema, so the live counters are
                        // read from the scheduler at the moment of the report.
                        let sessions = self.scheduler.sessions().len() as u32;
                        let active = self.scheduler.sessions().iter().filter(|s| !s.is_finished()).count() as u32;
                        println!("{}", self.scheduler.statistics().line("final", sessions, active));
                        self.next_report = reported_at
                            .saturating_add(u64::from(self.report_seconds).saturating_mul(1_000));
                    }
                }

                let poll_now = clock.now_milliseconds();
                let steps = self.scheduler.poll(poll_now, &mut expired);
                self.dispatch(&steps, transport, &mut outcome, poll_now);
                outcome.batches = outcome.batches.saturating_add(1);
            }

            // Only an internal failure means no further progress is possible anywhere, and only then
            // may this worker end the run for its peers. Waking them because *this* worker's session
            // lost its connection would truncate their accounting: a peer that is still closing its
            // own generation never reaches the drain event that counts its network failure.
            let terminal = self.scheduler.statistics();
            if !outcome.controlled_stop && terminal.fatal {
                StopFlag::request_global();
            }

            if let Err(reason) = transport.shutdown() {
                crate::worker::trace::event("TRANSPORT_SHUTDOWN_FAILED", &reason);
                self.scheduler.mark_fatal();
                StopFlag::request_global();
                outcome.failures = outcome.failures.saturating_add(1);
            }
            self.scheduler
                .set_elapsed_milliseconds(self.started_at.elapsed().as_millis() as u64);
            outcome
        }

        fn dispatch<T: Transport>(
            &mut self,
            steps: &[Step],
            transport: &mut T,
            outcome: &mut RunOutcome,
            now: u64,
        ) {
            // A top_up() can emit several operations for one session. If one post fails, its
            // generation immediately enters Closing; the remaining precomputed steps for that
            // same session must be skipped rather than producing a cascade of expected errors.
            let mut failed_session: Option<u32> = None;
            for (position, step) in steps.iter().enumerate() {
                let step_index = match *step {
                    Step::Connect(index) | Step::Close(index) => index,
                    Step::Send { index, .. } | Step::Receive { index, .. } => index,
                };
                if failed_session == Some(step_index) {
                    crate::worker::trace::event_args("STEP_SKIPPED_AFTER_FAILURE", format_args!("{step:?}"));
                    continue;
                }

                let result = match *step {
                    Step::Connect(index) => transport.connect(index),
                    Step::Send { index, bytes } => transport.send(index, bytes),
                    Step::Receive { index, bytes } => transport.receive(index, bytes),
                    Step::Close(index) => {
                        transport.close(index);
                        self.clear_latency_queue(index);
                        Ok(())
                    }
                };

                match result {
                    Ok(()) => {
                        outcome.steps = outcome.steps.saturating_add(1);
                        crate::worker::trace::event_args("STEP_OK", format_args!("{step:?}"));
                        if let Step::Send { index, .. } = *step {
                            if let Some(started) = self.attempt_started.get_mut(index as usize) {
                                *started = Some(Instant::now());
                            }
                        }
                    }
                    Err(reason) => {
                        crate::worker::trace::event_args("STEP_FAILED", format_args!("{step:?} reason={reason}"));
                        outcome.failures = outcome.failures.saturating_add(1);

                        // The scheduler reserved every step in this precomputed batch before
                        // dispatch began. The failed native post and later steps for this same
                        // session were never accepted, so remove those reservations *before*
                        // loss accounting moves the live generation into Closing. Earlier
                        // successful posts remain counted and will be retired by completion.
                        for pending in &steps[position..] {
                            let pending_index = match *pending {
                                Step::Connect(index) | Step::Close(index) => index,
                                Step::Send { index, .. } | Step::Receive { index, .. } => index,
                            };
                            if pending_index == step_index {
                                self.scheduler.rollback_unposted_step(*pending);
                            }
                        }

                        failed_session = Some(step_index);
                        self.fail_session(step_index, now, transport, outcome);
                    }
                }
            }
        }

    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::native::completion::NO_SEND_SLOT;

        #[derive(Default)]
        struct TestClock {
            now: u64,
        }

        impl Clock for TestClock {
            fn now_milliseconds(&mut self) -> u64 {
                self.now
            }

            fn wait(&mut self, milliseconds: u32) {
                self.now = self.now.saturating_add(u64::from(milliseconds));
            }
        }

        #[derive(Default)]
        struct Recorder {
            connects: Vec<u32>,
            sends: Vec<u32>,
            receives: Vec<(u32, u32)>,
            closes: Vec<u32>,
            completions: VecDeque<Completion>,
            live: bool,
        }

        impl Transport for Recorder {
            fn connect(&mut self, index: u32) -> Result<(), String> {
                self.connects.push(index);
                self.live = true;
                self.completions.push_back(Completion {
                    index,
                    generation: 1,
                    slot: NO_SEND_SLOT,
                    operation: Operation::Connect,
                    status: 0,
                    bytes: 0,
                });
                Ok(())
            }

            fn send(&mut self, index: u32, bytes: u32) -> Result<(), String> {
                self.sends.push(index);
                self.completions.push_back(Completion {
                    index,
                    generation: 1,
                    slot: 0,
                    operation: Operation::Send,
                    status: 0,
                    bytes,
                });
                Ok(())
            }

            fn receive(&mut self, index: u32, bytes: u32) -> Result<(), String> {
                self.receives.push((index, bytes));
                Ok(())
            }

            fn close(&mut self, index: u32) {
                self.closes.push(index);
                self.live = false;
            }

            fn completion_is_live(&self, _index: u32, _generation: u32) -> bool {
                self.live
            }

            fn wait_and_drain(
                &mut self,
                _wait_milliseconds: u32,
                _budget: u32,
            ) -> Result<Vec<Completion>, String> {
                Ok(self.completions.drain(..).collect())
            }
        }

        #[test]
        fn receive_step_carries_requested_length() {
            let mut options = Options::default();
            options.echo_count = 1;
            options.pipeline_depth = 1;
            let mut worker = Worker::new(&options, 1, 6, 0);
            worker.set_payload(std::sync::Arc::from(&b"abcdef"[..]));
            let mut recorder = Recorder::default();
            let mut clock = TestClock::default();
            StopFlag::clear_global();
            let stop = StopFlag;
            // This recorder does not synthesize a receive completion, so /w bounds the test.
            worker.run_seconds = 1;
            let _ = worker.run(&mut clock, &mut recorder, &stop);
            assert!(recorder.receives.iter().any(|entry| *entry == (0, 6)));
        }
    }

    // The worker owns the IOCP loop, the RIONotify lifecycle, the timer wheel and the trace helpers.

pub mod timer {
    //! Worker-private index minimum heap over deadlines.
    //!
    //! Only the owning thread touches it, so no synchronisation is needed. The heap keeps a
    //! position map so a session's deadline can be updated or removed in place, and its
    //! capacity is fixed for the whole run: it is never allowed to grow.

    /// One scheduled deadline.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct TimerNode {
        pub deadline: u64,
        pub connection_index: u32,
    }

    #[derive(Debug)]
    pub struct TimerHeap {
        capacity: usize,
        size: usize,
        nodes: Vec<TimerNode>,
        /// Index of a session inside `nodes`, or -1 when the session has no deadline.
        positions: Vec<i32>,
    }

    impl TimerHeap {
        pub fn new(capacity: usize) -> Self {
            Self {
                capacity,
                size: 0,
                nodes: vec![TimerNode::default(); capacity],
                positions: vec![-1; capacity],
            }
        }

        pub fn capacity(&self) -> usize {
            self.capacity
        }

        pub fn len(&self) -> usize {
            self.size
        }

        pub fn is_empty(&self) -> bool {
            self.size == 0
        }

        pub fn contains(&self, connection_index: u32) -> bool {
            (connection_index as usize) < self.capacity
                && self.positions[connection_index as usize] >= 0
        }

        /// Deadline of the nearest entry, or None when the heap is empty.
        pub fn next_deadline(&self) -> Option<u64> {
            if self.size == 0 {
                None
            } else {
                Some(self.nodes[0].deadline)
            }
        }

        fn less(&self, a: usize, b: usize) -> bool {
            let left = self.nodes[a];
            let right = self.nodes[b];
            (left.deadline, left.connection_index) < (right.deadline, right.connection_index)
        }

        fn swap(&mut self, a: usize, b: usize) {
            self.nodes.swap(a, b);
            let left = self.nodes[a].connection_index as usize;
            let right = self.nodes[b].connection_index as usize;
            self.positions[left] = a as i32;
            self.positions[right] = b as i32;
        }

        fn sift_up(&mut self, mut index: usize) {
            while index > 0 {
                let parent = (index - 1) / 2;
                if !self.less(index, parent) {
                    break;
                }
                self.swap(index, parent);
                index = parent;
            }
        }

        fn sift_down(&mut self, mut index: usize) {
            loop {
                let left = index * 2 + 1;
                if left >= self.size {
                    break;
                }
                let right = left + 1;
                let smallest = if right < self.size && self.less(right, left) {
                    right
                } else {
                    left
                };
                if !self.less(smallest, index) {
                    break;
                }
                self.swap(index, smallest);
                index = smallest;
            }
        }

        /// Schedules or reschedules a session. Returns false when the session has no slot and
        /// the heap is already full: the caller must treat that as a hard failure instead of
        /// silently dropping a deadline.
        pub fn insert_or_update(&mut self, deadline: u64, connection_index: u32) -> bool {
            let slot = connection_index as usize;
            if slot >= self.capacity {
                return false;
            }
            let existing = self.positions[slot];
            if existing >= 0 {
                let position = existing as usize;
                let previous = self.nodes[position].deadline;
                self.nodes[position].deadline = deadline;
                if deadline < previous {
                    self.sift_up(position);
                } else if deadline > previous {
                    self.sift_down(position);
                }
                return true;
            }
            if self.size == self.capacity {
                return false;
            }
            let position = self.size;
            self.size += 1;
            self.nodes[position] = TimerNode {
                deadline,
                connection_index,
            };
            self.positions[slot] = position as i32;
            self.sift_up(position);
            true
        }

        /// Drops a session's deadline. Removing an unscheduled session is not an error.
        pub fn remove(&mut self, connection_index: u32) -> bool {
            let slot = connection_index as usize;
            if slot >= self.capacity {
                return false;
            }
            let position = self.positions[slot];
            if position < 0 {
                return false;
            }
            let position = position as usize;
            let last = self.size - 1;
            self.positions[slot] = -1;
            if position != last {
                self.nodes.swap(position, last);
                self.positions[self.nodes[position].connection_index as usize] = position as i32;
                let moved_deadline = self.nodes[position].deadline;
                self.size = last;
                // Repair in whichever direction the moved entry can violate the invariant.
                let parent = if position > 0 {
                    Some((position - 1) / 2)
                } else {
                    None
                };
                if let Some(parent) = parent {
                    if self.less(position, parent) {
                        self.sift_up(position);
                        return true;
                    }
                }
                let _ = moved_deadline;
                self.sift_down(position);
            } else {
                self.size = last;
            }
            true
        }

        /// Wakes up only the sessions whose deadline has passed. Each removed session is
        /// reported so the caller can drive its timeout path.
        pub fn pop_expired(&mut self, now: u64, out: &mut Vec<u32>) -> usize {
            let mut count = 0;
            while self.size > 0 && self.nodes[0].deadline <= now {
                let node = self.nodes[0];
                self.remove(node.connection_index);
                out.push(node.connection_index);
                count += 1;
            }
            count
        }

        /// Milliseconds to wait for the nearest deadline, clamped so a caller can pass its own
        /// idle bound (for example a run deadline or an infinite wait).
        pub fn timeout_milliseconds(&self, now: u64, maximum: u32) -> u32 {
            match self.next_deadline() {
                None => maximum,
                Some(deadline) if deadline <= now => 0,
                Some(deadline) => {
                    let delta = deadline - now;
                    let capped = delta.min(u64::from(maximum));
                    capped as u32
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn orders_by_deadline_then_index() {
            let mut heap = TimerHeap::new(8);
            assert!(heap.insert_or_update(30, 2));
            assert!(heap.insert_or_update(10, 1));
            assert!(heap.insert_or_update(20, 0));
            assert_eq!(heap.next_deadline(), Some(10));
            let mut expired = Vec::new();
            assert_eq!(heap.pop_expired(25, &mut expired), 2);
            assert_eq!(expired, vec![1, 0]);
            assert_eq!(heap.next_deadline(), Some(30));
            assert_eq!(heap.len(), 1);
        }

        #[test]
        fn update_moves_the_entry_in_both_directions() {
            let mut heap = TimerHeap::new(4);
            assert!(heap.insert_or_update(100, 0));
            assert!(heap.insert_or_update(200, 1));
            assert!(heap.insert_or_update(5, 0));
            assert_eq!(heap.next_deadline(), Some(5));
            assert_eq!(heap.len(), 2);
            assert!(heap.insert_or_update(500, 0));
            assert_eq!(heap.next_deadline(), Some(200));
            assert!(heap.contains(0));
        }

        #[test]
        fn remove_reports_missing_entries_and_repairs_the_heap() {
            let mut heap = TimerHeap::new(4);
            assert!(!heap.remove(0));
            assert!(heap.insert_or_update(10, 0));
            assert!(heap.insert_or_update(20, 1));
            assert!(heap.insert_or_update(30, 2));
            assert!(heap.remove(0));
            assert!(!heap.contains(0));
            assert_eq!(heap.next_deadline(), Some(20));
            assert_eq!(heap.len(), 2);
            assert!(heap.remove(2));
            assert_eq!(heap.next_deadline(), Some(20));
        }

        #[test]
        fn capacity_is_fixed_and_indices_are_bounds_checked() {
            let mut heap = TimerHeap::new(2);
            assert!(heap.insert_or_update(1, 0));
            assert!(heap.insert_or_update(2, 1));
            // Full: a third distinct session is refused instead of growing the heap.
            assert!(!heap.insert_or_update(3, 2));
            // Out-of-range indices are refused even when a slot is free.
            assert!(!heap.insert_or_update(3, 99));
            assert_eq!(heap.len(), 2);
        }

        #[test]
        fn timeout_is_clamped() {
            let mut heap = TimerHeap::new(2);
            assert_eq!(heap.timeout_milliseconds(1_000, 250), 250);
            assert!(heap.insert_or_update(1_500, 0));
            assert_eq!(heap.timeout_milliseconds(1_000, 250), 250);
            assert!(heap.insert_or_update(1_100, 0));
            assert_eq!(heap.timeout_milliseconds(1_000, 250), 100);
            assert_eq!(heap.timeout_milliseconds(2_000, 250), 0);
        }
    }
}

pub mod trace {
    //! Stage tracing for the completion-driven engine.
    //!
    //! Off by default: set CEC_TRACE=1 and every stage transition prints one line. The flag is
    //! cached once and formatted trace details use `format_args!`, so disabled tracing performs
    //! no heap allocation on the completion path.

    use std::fmt;
    use std::sync::OnceLock;

    static ENABLED: OnceLock<bool> = OnceLock::new();

    /// Whether tracing is requested for this process.
    pub fn enabled() -> bool {
        *ENABLED.get_or_init(|| std::env::var_os("CEC_TRACE").is_some())
    }

    /// Records a stage with an already-borrowed string detail.
    pub fn event(stage: &str, detail: &str) {
        if enabled() {
            if detail.is_empty() {
                eprintln!("{stage}");
            } else {
                eprintln!("{stage} {detail}");
            }
        }
    }

    /// Allocation-free formatted tracing. `format_args!` only renders when tracing is enabled.
    pub fn event_args(stage: &str, detail: fmt::Arguments<'_>) {
        if enabled() {
            eprintln!("{stage} {detail}");
        }
    }
}
}
