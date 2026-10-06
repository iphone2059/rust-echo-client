//! Worker loop for the completion-driven client.
//!
//! The transport owns native generations and resource lifetime. The scheduler owns business
//! state. The worker is the only bridge between them: it never interprets a stale completion,
//! never posts an extra receive behind the scheduler's back, and always asks the transport to
//! quiesce before the worker thread returns.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::native::completion::{Operation, WSAEMSGSIZE, is_connection_level};
use crate::scheduler::{Scheduler, Step};
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
    sent_at: Vec<VecDeque<Instant>>,
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
            sent_at: (0..session_count).map(|_| VecDeque::new()).collect(),
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
        if let Some(queue) = self.sent_at.get_mut(index as usize) {
            queue.clear();
        }
    }

    fn record_verified_latency(&mut self, index: u32) {
        let Some(queue) = self.sent_at.get_mut(index as usize) else {
            return;
        };
        let Some(sent) = queue.pop_front() else {
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
                if completion.bytes != self.payload_bytes {
                    crate::worker::trace::event_args(
                        "SHORT_SEND",
                        format_args!(
                            "session={} generation={} bytes={} expected={}",
                            completion.index,
                            completion.generation,
                            completion.bytes,
                            self.payload_bytes
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

            for completion in completions {
                self.handle_completion(completion, now, transport, &mut outcome);
                if self.scheduler.statistics().fatal {
                    break;
                }
            }

            if self.report_seconds != 0 && !self.quiet {
                let reported_at = clock.now_milliseconds();
                if reported_at >= self.next_report {
                    println!("{}", self.scheduler.statistics().line("final"));
                    self.next_report = reported_at
                        .saturating_add(u64::from(self.report_seconds).saturating_mul(1_000));
                }
            }

            let poll_now = clock.now_milliseconds();
            let steps = self.scheduler.poll(poll_now, &mut expired);
            self.dispatch(&steps, transport, &mut outcome, poll_now);
            outcome.batches = outcome.batches.saturating_add(1);
        }

        let terminal = self.scheduler.statistics();
        if !outcome.controlled_stop
            && (terminal.fatal
                || terminal.network_failures != 0
                || terminal.corrupted != 0)
        {
            // Wake peer workers before this worker enters its bounded native shutdown. This
            // prevents an unlimited peer from continuing for the entire shutdown grace.
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
                Step::Connect(index) | Step::Send(index) | Step::Close(index) => index,
                Step::Receive { index, .. } => index,
            };
            if failed_session == Some(step_index) {
                crate::worker::trace::event_args("STEP_SKIPPED_AFTER_FAILURE", format_args!("{step:?}"));
                continue;
            }

            let result = match *step {
                Step::Connect(index) => transport.connect(index),
                Step::Send(index) => transport.send(index, self.payload_bytes),
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
                    if let Step::Send(index) = *step {
                        if let Some(queue) = self.sent_at.get_mut(index as usize) {
                            queue.push_back(Instant::now());
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
                            Step::Connect(index) | Step::Send(index) | Step::Close(index) => index,
                            Step::Receive { index, .. } => index,
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
pub mod timer;
pub mod trace;


