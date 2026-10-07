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
    Send(u32),
    Receive { index: u32, bytes: u32 },
    Close(u32),
}

#[derive(Clone, Copy, Debug, Default)]
struct Flow {
    /// Echo units requested from this session, including already verified units.
    requested: u64,
    /// RIO send requests posted but not yet completed.
    sends_in_flight: u32,
    /// Exactly one receive may be outstanding per session.
    receive_posted: bool,
    /// The first send of this transport generation is immediate. `/i` spaces only later
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
            sends_in_flight: 0,
            receive_posted: false,
            started: false,
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
    depth: u32,
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
            depth: options.pipeline_depth.max(1),
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

    fn can_request_more(&self, slot: usize) -> bool {
        let Some(inflight) = self.inflight_echoes(slot) else {
            return false;
        };
        // Two independent bounds must hold. `inflight` is the business pipeline, while
        // `sends_in_flight` is the native RQ reservation. Receive completions are allowed to
        // race ahead of send completions, so business progress alone must never overfill the
        // request queue.
        if inflight >= u64::from(self.depth) || self.flows[slot].sends_in_flight >= self.depth {
            return false;
        }
        self.limit == 0 || self.flows[slot].requested < self.limit
    }

    fn post_one_send(&mut self, index: u32, steps: &mut Vec<Step>) -> bool {
        let slot = index as usize;
        if !self.can_request_more(slot) {
            return false;
        }
        let flow = &mut self.flows[slot];
        let Some(requested) = flow.requested.checked_add(1) else {
            self.statistics.fatal = true;
            return false;
        };
        let Some(sends) = flow.sends_in_flight.checked_add(1) else {
            self.statistics.fatal = true;
            return false;
        };
        flow.requested = requested;
        flow.sends_in_flight = sends;
        flow.started = true;
        self.statistics.attempted = self.statistics.attempted.saturating_add(1);
        steps.push(Step::Send(index));
        true
    }

    fn ensure_receive(&mut self, index: u32, steps: &mut Vec<Step>) {
        let slot = index as usize;
        let Some(inflight) = self.inflight_echoes(slot) else {
            self.statistics.fatal = true;
            return;
        };
        if inflight == 0 || self.flows[slot].receive_posted {
            return;
        }
        let Some(bytes) = self.sessions[slot].receive_remaining(self.payload_bytes) else {
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
        let flow = self.flows[slot];
        let busy = flow.sends_in_flight != 0 || flow.receive_posted;
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
        if inflight > u64::from(self.depth) {
            self.statistics.fatal = true;
            debug_assert!(false, "pipeline depth exceeded");
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
        let flow = self.flows[slot];
        let busy = flow.sends_in_flight != 0 || flow.receive_posted;
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
        if self.flows[slot].sends_in_flight == 0 {
            self.statistics.fatal = true;
            return Vec::new();
        }
        self.flows[slot].sends_in_flight -= 1;
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
            Step::Send(index) => {
                let slot = index as usize;
                let Some(flow) = self.flows.get_mut(slot) else {
                    self.statistics.fatal = true;
                    return;
                };
                let Some(sends) = flow.sends_in_flight.checked_sub(1) else {
                    self.statistics.fatal = true;
                    return;
                };
                let Some(requested) = flow.requested.checked_sub(1) else {
                    self.statistics.fatal = true;
                    return;
                };
                if requested < self.sessions[slot].echoes {
                    self.statistics.fatal = true;
                    return;
                }
                flow.sends_in_flight = sends;
                flow.requested = requested;
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

        // TCP is a byte stream and may complete with a strict prefix. UDP is
        // message-oriented, so Session rejects a short datagram instead of concatenating it
        // with the next datagram.
        let outcome = self.sessions[slot].on_received(
            chunk,
            payload,
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
                self.statistics.echoes = self.statistics.echoes.saturating_add(1);
                self.top_up(index, now)
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
        self.statistics.corrupted = self.statistics.corrupted.saturating_add(1);
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
    fn business_pipeline_is_bounded_by_requested_minus_verified() {
        let mut scheduler = scheduler(4, 0, None);
        assert_eq!(scheduler.start(0), vec![Step::Connect(0)]);
        let steps = scheduler.on_connected(0, 1);
        assert_eq!(steps.iter().filter(|s| matches!(s, Step::Send(0))).count(), 4);
        assert_eq!(scheduler.inflight_echoes(0), Some(4));
        assert!(steps.iter().any(|s| matches!(s, Step::Receive { index: 0, bytes: 6 })));
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
        assert_eq!(scheduler.statistics.corrupted, 1);
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
        assert!(steps.iter().any(|step| matches!(step, Step::Send(0))));
        assert_eq!(scheduler.inflight_echoes(0), Some(1));
    }

    #[test]
    fn receive_may_complete_before_send_without_exceeding_native_send_depth() {
        let mut scheduler = scheduler(1, 0, None);
        scheduler.start(0);
        let initial = scheduler.on_connected(0, 0);
        assert_eq!(initial.iter().filter(|step| matches!(step, Step::Send(0))).count(), 1);

        // RIO completion ordering between send and receive is not a business ordering
        // guarantee. Verify the echo first while the original send is still native-in-flight.
        let after_receive = scheduler.on_received(0, b"abcdef", b"abcdef", 1);
        assert!(!after_receive.iter().any(|step| matches!(step, Step::Send(0))));
        assert_eq!(scheduler.flows[0].sends_in_flight, 1);

        // Once that native send completion retires, the next business send may be posted.
        let after_send = scheduler.on_sent(0, 2);
        assert!(after_send.iter().any(|step| matches!(step, Step::Send(0))));
        assert_eq!(scheduler.flows[0].sends_in_flight, 1);
        assert_eq!(scheduler.inflight_echoes(0), Some(1));
    }

    #[test]
    fn interval_pacing_sends_first_cycle_immediately() {
        let mut scheduler = scheduler(4, 25, None);
        scheduler.start(100);
        let first = scheduler.on_connected(0, 100);
        assert_eq!(first.iter().filter(|step| matches!(step, Step::Send(0))).count(), 1);
        assert!(first.iter().any(|step| matches!(step, Step::Receive { index: 0, bytes: 6 })));
        assert_eq!(scheduler.sessions[0].send_at, Some(125));

        let mut expired = Vec::new();
        assert!(scheduler.poll(124, &mut expired).is_empty());
        let second = scheduler.poll(125, &mut expired);
        assert_eq!(second.iter().filter(|step| matches!(step, Step::Send(0))).count(), 1);
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

