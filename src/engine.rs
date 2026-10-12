//! Top-level orchestration: worker resolution, session partitioning, worker startup and join,
//! statistics aggregation, terminal accounting, console registration and result classification.

use crate::engine::transport::RioTransport;
use crate::metrics::Statistics;
use crate::native::clock::RioClock;
use crate::native::{RioFunctions, Winsock, load_connect_ex, registered_socket};
use crate::payload::{build, validate_payload};
use crate::types::{ExitCode, Options, Protocol, available_processors, resolved_worker_count};
use crate::worker::{Progress, StopFlag, WakePort, Worker};
use windows::Win32::ws2::SOCKADDR_IN;

#[derive(Clone, Copy, Debug, Default)]
struct NotificationCounters {
    arms: u64,
    deliveries: u64,
    timeouts: u64,
}

fn write_diagnostics(protocol: Protocol, snapshots: &[NotificationCounters]) {
    use std::io::Write;
    let Some(path) = std::env::var_os("CEC_DIAG_FILE").filter(|path| !path.is_empty()) else {
        return;
    };
    let Ok(mut file) = std::fs::File::create(path) else {
        return;
    };
    let protocol = if protocol == Protocol::Tcp {
        "tcp"
    } else {
        "udp"
    };
    for (worker, snapshot) in snapshots.iter().enumerate() {
        if writeln!(file, "role=client protocol={protocol} worker={worker} notify_arms={} notify_deliveries={} notify_gap={} timeout_wakeups_while_outstanding={}",
            snapshot.arms, snapshot.deliveries, snapshot.arms.saturating_sub(snapshot.deliveries), snapshot.timeouts).is_err() {
            return;
        }
    }
}

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
}

unsafe extern "system" fn console_ctrl_handler(control: u32) -> i32 {
    // CTRL_C_EVENT, CTRL_BREAK_EVENT and CTRL_CLOSE_EVENT.
    if matches!(control, 0 | 1 | 2) {
        StopFlag::request_global();
        1
    } else {
        0
    }
}

struct ConsoleHandler;

#[link(name = "Winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
    fn timeEndPeriod(period: u32) -> u32;
}

struct TimerResolution;

impl TimerResolution {
    fn start() -> Result<Self, u32> {
        let status = unsafe { timeBeginPeriod(1) };
        if status == 0 { Ok(Self) } else { Err(status) }
    }
}

impl Drop for TimerResolution {
    fn drop(&mut self) {
        unsafe {
            let _ = timeEndPeriod(1);
        }
    }
}

impl ConsoleHandler {
    fn install() -> Result<Self, crate::native::NativeError> {
        let ok = unsafe { SetConsoleCtrlHandler(Some(console_ctrl_handler), 1) };
        if ok == 0 {
            return Err(crate::native::NativeError {
                stage: "SetConsoleCtrlHandler",
                code: unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32,
                origin: crate::types::FailureDomain::Win32,
            });
        }
        Ok(Self)
    }
}

impl Drop for ConsoleHandler {
    fn drop(&mut self) {
        unsafe {
            let _ = SetConsoleCtrlHandler(Some(console_ctrl_handler), 0);
        }
    }
}

fn partition(session_count: u32, worker_count: u32) -> Vec<u32> {
    // The reference resolves /threads (or the automatic count) and then takes the smaller of that and
    // the session count, so the shard the capacity rules compute is the one actually used.
    let workers = resolved_worker_count(worker_count, available_processors())
        .min(session_count)
        .max(1);
    let base = session_count / workers;
    let extra = session_count % workers;
    (0..workers)
        .map(|index| base + u32::from(index < extra))
        .filter(|count| *count > 0)
        .collect()
}

fn worker_memory_share(total: u64, worker_sessions: u32, total_sessions: u32) -> u64 {
    if total_sessions == 0 {
        return 0;
    }
    (total / u64::from(total_sessions)).saturating_mul(u64::from(worker_sessions))
}

#[allow(clippy::too_many_arguments)]
fn run_worker(
    options: Options,
    payload: std::sync::Arc<[u8]>,
    sessions: u32,
    memory_share: u64,
    target: SOCKADDR_IN,
    stop: StopFlag,
    progress: Option<Progress>,
    wake: WakePort,
    rio: RioFunctions,
    connect_ex: windows::Win32::mswsock::LPFN_CONNECTEX,
) -> Result<
    (
        Statistics,
        bool,
        NotificationCounters,
        transport::DrainedOwner,
    ),
    String,
> {
    let result = (|| -> Result<(Statistics, bool, NotificationCounters, transport::DrainedOwner), String> {
        let _winsock = Winsock::start()
            .map_err(|error| format!("{} failed: native_error={}", error.stage, error.code))?;
        let payload_bytes = u32::try_from(payload.len())
            .map_err(|_| "payload is too large for the worker".to_string())?;
        let mut worker_options = options.clone();
        worker_options.run_seconds = 0;
        let mut worker = Worker::new(&worker_options, sessions, payload_bytes, 0);
        worker.set_payload(std::sync::Arc::clone(&payload));
        if let Some(progress) = progress {
            worker.set_progress(
                progress,
                u64::from(options.report_seconds)
                    .saturating_mul(1_000)
                    .min(50),
            );
        }
        let mut clock = RioClock::new()
            .map_err(|error| format!("{} failed: native_error={}", error.stage, error.code))?;
        let mut transport = RioTransport::new(
            &options,
            sessions,
            payload,
            memory_share,
            target,
            rio,
            connect_ex,
        )?;
        transport.set_wake(wake)?;
        let outcome = worker.run(&mut clock, &mut transport, &stop);
        let statistics = worker.scheduler().statistics();
        // Only an internal failure means no further progress is possible anywhere, and only then
        // may one worker end the run for its peers. A session that lost its connection or its
        // payload is terminal for that session alone: the reference keeps the other sessions
        // running until their own work or the run deadline finishes, which is also what makes
        // every failed session count exactly once toward network_errors.
        if !outcome.controlled_stop && statistics.fatal {
            StopFlag::request_fatal_global();
        }
        Ok((
            statistics,
            outcome.controlled_stop,
            transport.notification_counters(),
            transport.into_drained_owner(),
        ))
    })();
    if result.is_err() {
        // Setup errors happen before Worker::run can observe the shared flag. Propagate the
        // stop to already-running peer workers so the join loop cannot deadlock on /n 0.
        StopFlag::request_fatal_global();
    }
    result
}

pub fn run(options: &Options) -> ExitCode {
    if options.protocol == Protocol::None {
        return ExitCode::Usage;
    }
    StopFlag::clear_global();
    let _console_handler = match ConsoleHandler::install() {
        Ok(handler) => handler,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::Internal;
        }
    };
    // The reference starts Winsock and loads the RIO extensions before it resolves the target, so
    // the run owns the Winsock lifetime here as well and every worker joins it by refcount.
    let _winsock = match Winsock::start() {
        Ok(winsock) => winsock,
        Err(error) => {
            eprintln!("{} failed: native_error={}", error.stage, error.code);
            return ExitCode::Network;
        }
    };
    let extensions = (|| {
        let probe = registered_socket(Protocol::Tcp)?;
        Ok::<_, crate::native::NativeError>((
            RioFunctions::load(probe.raw())?,
            load_connect_ex(probe.raw())?,
        ))
    })();
    let (rio, connect_ex) = match extensions {
        Ok(extensions) => extensions,
        Err(error) => {
            eprintln!("{} failed: native_error={}", error.stage, error.code);
            return ExitCode::Network;
        }
    };
    // The target is resolved before anything else is built, exactly like the reference: the test
    // 256.256.256.256 reports GetAddrInfoW's status and exits as a network failure even though the
    // payload of that command line is otherwise valid.
    let target = match crate::native::endpoint::resolve_ipv4(&options.host, options.remote_port) {
        Ok(target) => target,
        Err(code) => {
            eprintln!("GetAddrInfoW(IPv4) failed: native_error={code}");
            return ExitCode::Network;
        }
    };

    let payload = match build(options) {
        Ok(payload) => payload,
        Err(error) => {
            eprintln!("Invalid payload: {}", error.0);
            return ExitCode::Usage;
        }
    };
    if let Err(error) = validate_payload(options, &payload) {
        eprintln!("Invalid payload: {}", error.0);
        return ExitCode::Usage;
    }
    let _timer_resolution = if options.interval_milliseconds != 0 {
        match TimerResolution::start() {
            Ok(resolution) => Some(resolution),
            Err(error) => {
                eprintln!("timeBeginPeriod(client pacing) failed: native_error={error}");
                return ExitCode::Internal;
            }
        }
    } else {
        None
    };
    // Capacity is an argument property, not a run-time one: the parser has already validated the
    // completion-queue and registered-memory budgets against the largest shard, and the transport
    // re-checks its own arena size as a last line of defence. No usage diagnostic may be produced
    // from here, because the reference reports both failures during argument parsing.

    let stop = StopFlag;

    let payload: std::sync::Arc<[u8]> = std::sync::Arc::from(payload.into_boxed_slice());
    let counts = partition(options.session_count, options.worker_count);
    let mut handles = Vec::with_capacity(counts.len());
    let mut progress = if options.report_seconds == 0 {
        Vec::new()
    } else {
        Vec::with_capacity(counts.len())
    };
    let mut wake_ports = Vec::with_capacity(counts.len());
    let mut worker_spawn_error = false;
    for (worker_index, sessions) in counts.into_iter().enumerate() {
        let options = options.clone();
        let worker_payload = std::sync::Arc::clone(&payload);
        let snapshot = (options.report_seconds != 0)
            .then(|| std::sync::Arc::new(std::sync::Mutex::new((Statistics::default(), 0))));
        let worker_progress = snapshot.as_ref().map(std::sync::Arc::clone);
        let wake = std::sync::Arc::new(std::sync::Mutex::new(0));
        let worker_wake = std::sync::Arc::clone(&wake);
        let memory_share =
            worker_memory_share(options.memory_bytes, sessions, options.session_count);
        let handle = std::thread::Builder::new()
            .name(format!("cec-worker-{worker_index}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_worker(
                        options,
                        worker_payload,
                        sessions,
                        memory_share,
                        target,
                        stop,
                        worker_progress,
                        worker_wake,
                        rio,
                        connect_ex,
                    )
                }));
                match result {
                    Ok(result) => result,
                    Err(payload) => {
                        // A panic must wake unlimited peer workers before this JoinHandle is
                        // eventually observed by the main thread. Resume the original panic so
                        // the join result still records an abnormal worker termination.
                        StopFlag::request_fatal_global();
                        std::panic::resume_unwind(payload);
                    }
                }
            });
        match handle {
            Ok(handle) => {
                handles.push(handle);
                if let Some(snapshot) = snapshot {
                    progress.push(snapshot);
                }
                wake_ports.push(wake);
            }
            Err(error) => {
                eprintln!("failed to create worker thread {worker_index}: {error}");
                worker_spawn_error = true;
                StopFlag::request_fatal_global();
                break;
            }
        }
    }

    let started = std::time::Instant::now();
    let mut next_report = u64::from(options.report_seconds).saturating_mul(1_000);
    let mut monitor_failure = false;
    let mut stop_posts_sent = false;
    loop {
        let elapsed = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        if options.run_seconds != 0
            && elapsed >= u64::from(options.run_seconds).saturating_mul(1_000)
        {
            StopFlag::request_global();
        }
        if stop.is_requested() && !stop_posts_sent {
            for wake in &wake_ports {
                match wake.lock() {
                    Ok(handle) if *handle != 0 => {
                        // Hold the snapshot lock through the post: transport teardown clears this
                        // handle under the same lock before closing the port.
                        let posted = unsafe {
                            windows::Win32::ioapiset::PostQueuedCompletionStatus(
                                *handle as *mut core::ffi::c_void,
                                0,
                                1,
                                None,
                            )
                        };
                        if !posted.as_bool() {
                            monitor_failure = true;
                            StopFlag::request_fatal_global();
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        monitor_failure = true;
                        StopFlag::request_fatal_global();
                    }
                }
            }
            stop_posts_sent = true;
        }
        if options.report_seconds != 0 && elapsed >= next_report {
            let mut report = Statistics::default();
            let mut active = 0u32;
            for snapshot in &progress {
                match snapshot.lock() {
                    Ok(snapshot) => {
                        report.merge(&snapshot.0);
                        active = active.saturating_add(snapshot.1);
                    }
                    Err(_) => {
                        monitor_failure = true;
                        StopFlag::request_fatal_global();
                    }
                }
            }
            report.elapsed_milliseconds = elapsed;
            println!("{}", report.line("report", options.session_count, active));
            next_report =
                elapsed.saturating_add(u64::from(options.report_seconds).saturating_mul(1_000));
        }
        if handles.iter().all(std::thread::JoinHandle::is_finished) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut statistics = Statistics::default();
    let mut controlled_stop = stop.is_requested() && !stop.is_fatal();
    let mut snapshots = Vec::with_capacity(handles.len());
    let mut worker_panic = false;
    // A worker that returns Err never reached a clean stop, so the run must not be classified from the
    // statistics it left behind: those are partial and a controlled stop would otherwise look clean.
    let mut worker_failure = false;
    let mut joined_owners = Vec::with_capacity(handles.len());

    // Always join every worker. Returning on the first failed handle would detach the rest
    // while they may still own sockets, RIO queues and registered memory. `run_worker`
    // already raises the global stop flag on failure, so peers will quiesce and can be joined
    // cleanly here.
    for handle in handles {
        match handle.join() {
            Ok(Ok((worker_statistics, controlled, snapshot, owner))) => {
                statistics.merge(&worker_statistics);
                controlled_stop |= controlled;
                snapshots.push(snapshot);
                joined_owners.push(owner);
            }
            Ok(Err(reason)) => {
                eprintln!("RIO worker failed: {reason}");
                worker_failure = true;
                StopFlag::request_fatal_global();
            }
            Err(_) => {
                eprintln!("worker thread ended abnormally");
                worker_panic = true;
                StopFlag::request_fatal_global();
            }
        }
    }

    // Join every owner before any provider release precondition or native teardown.
    for owner in &joined_owners {
        owner.require_release();
    }
    for owner in joined_owners {
        owner.release();
    }

    // A finite quota the run never claimed is a loss, exactly like the reference: those attempts
    // were asked for and never completed, so the shared classification reports an echo failure even
    // when the terminal cause was a worker or network failure. An unlimited run or a controlled stop
    // claims nothing extra.
    let fatal =
        statistics.fatal || worker_panic || worker_spawn_error || worker_failure || monitor_failure;
    controlled_stop &= !fatal;
    let unclaimed =
        statistics.unclaimed(options.echo_count, options.session_count, controlled_stop);
    if unclaimed != 0 {
        statistics.lost = statistics.lost.saturating_add(unclaimed);
        // The reference reports an echo that was asked for and never claimed as both lost and
        // attempted, so attempted stays the size of the run the command line described.
        statistics.attempted = statistics.attempted.saturating_add(unclaimed);
    }
    // A controlled stop cancels the attempts that were claimed and never finished; they are neither
    // echoes nor losses, which is what the reference reports as cancelled.
    if controlled_stop {
        let unfinished = statistics.attempted.saturating_sub(
            statistics
                .echoes
                .saturating_add(statistics.corrupted)
                .saturating_add(statistics.lost),
        );
        statistics.cancelled = unfinished;
    } else if fatal {
        let unfinished = statistics.attempted.saturating_sub(
            statistics
                .echoes
                .saturating_add(statistics.corrupted)
                .saturating_add(statistics.lost)
                .saturating_add(statistics.cancelled),
        );
        statistics.lost = statistics.lost.saturating_add(unfinished);
    }

    // The reference prints the terminal line by default: /q suppresses it and /stats forces it,
    // so /q /stats is exactly one line and neither switch is silent. Every worker has joined here,
    // so no session is live when the line is printed.
    if options.stats || !options.quiet {
        statistics.elapsed_milliseconds =
            started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        println!("{}", statistics.line("final", options.session_count, 0));
    }
    write_diagnostics(options.protocol, &snapshots);
    if fatal {
        ExitCode::Internal
    } else {
        statistics.exit_code(controlled_stop)
    }
}

#[cfg(test)]
mod tests {
    use super::{partition, worker_memory_share};

    #[test]
    fn worker_count_resolution_follows_the_reference() {
        use crate::types::resolved_worker_count;
        // An explicit /threads wins; the automatic count is the processor count clamped to [1, 64].
        assert_eq!(resolved_worker_count(3, 8), 3);
        assert_eq!(resolved_worker_count(0, 8), 8);
        assert_eq!(resolved_worker_count(0, 0), 1);
        assert_eq!(resolved_worker_count(0, 200), 64);
    }

    #[test]
    fn sessions_are_partitioned_evenly() {
        // Only explicit worker counts are asserted here: the automatic count depends on the machine, and
        // the rule for it is pinned separately by worker_count_resolution.
        assert_eq!(partition(10, 3), vec![4, 3, 3]);
        assert_eq!(partition(9, 3), vec![3, 3, 3]);
        assert_eq!(partition(2, 8), vec![1, 1]);
        assert_eq!(partition(10, 1), vec![10]);
    }

    #[test]
    fn memory_budget_is_proportional_to_owned_sessions() {
        assert_eq!(worker_memory_share(1_000, 4, 10), 400);
        assert_eq!(worker_memory_share(1_000, 3, 10), 300);
        assert_eq!(worker_memory_share(1_000, 0, 10), 0);
    }
}

/// RIO transport with explicit generation retirement, the reference's cec_engine.cpp session
/// machinery: sockets, request queues, registered arenas and the drain protocol.
pub mod transport {
    //! RIO transport with explicit generation retirement.
    //!
    //! The important ownership rule is simple: closing a socket starts cancellation, it does
    //! not end the lifetime of pending I/O. A generation therefore keeps its request queue,
    //! ConnectEx OVERLAPPED and registered buffers alive until every completion has actually
    //! been dequeued. Only then is `GenerationDrained` reported to the scheduler.

    use core::ffi::c_void;
    use core::ptr;
    use std::time::{Duration, Instant};

    use windows::Win32::ioapiset::{CreateIoCompletionPort, GetQueuedCompletionStatus};
    use windows::Win32::minwinbase::OVERLAPPED;
    use windows::Win32::mswsock::LPFN_CONNECTEX;
    use windows::Win32::mswsockdef::RIORESULT;
    use windows::Win32::winsock2::SOCKET;
    use windows::Win32::ws2::SOCKADDR_IN;

    use crate::native::arena::Arena;
    use crate::native::completion::{
        MAXIMUM_SESSION_INDEX, NO_SEND_SLOT, Operation, RequestContext, decode_context,
        encode_context, next_generation,
    };
    use crate::native::endpoint::{begin_connect, bind_local, connect_udp, update_connect_context};
    use crate::native::overlapped::PendingOverlapped;
    use crate::native::rio::{CompletionPort, CompletionQueue, RequestQueue};
    use crate::native::{
        NativeError, RioFunctions, SocketOwner, configure_socket, registered_socket,
    };
    use crate::types::{Options, Protocol};
    use crate::worker::{Completion, Transport};

    pub const MAX_RECEIVE: u32 = 1;
    pub const MAX_SEND: u32 = 1;
    pub const COMPLETION_BATCH_SIZE: usize = 256;
    const WAIT_TIMEOUT: i32 = 258;
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

    fn stage(error: NativeError) -> NativeError {
        crate::worker::trace::event_args(
            "TRANSPORT_ERROR",
            format_args!("{} code={}", error.stage, error.code),
        );
        error
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum GenerationState {
        Empty,
        Connecting,
        Active,
        Closing,
    }

    struct SessionTransport {
        generation: u32,
        state: GenerationState,
        /// An earlier completion in this collected batch failed the attempt. The worker still
        /// consumes that completion before changing state, but later sends must not resume it.
        failure_pending: bool,
        close_deadline: Option<Instant>,
        connect_outstanding: bool,
        send_outstanding: u32,
        receive_outstanding: u32,
        /// Native TX slot and byte range of the send currently outstanding. A partial completion
        /// re-posts the remainder of the same slot, so one attempt stays one outstanding RIOSend.
        send_slot: u32,
        send_posted_bytes: u32,
        send_offset: u32,
        /// Exact length of the one posted RIOReceive; zero when no receive is outstanding.
        receive_posted_bytes: u32,
        socket: Option<SocketOwner>,
        request_queue: Option<RequestQueue>,
        overlapped: PendingOverlapped,
        target: SOCKADDR_IN,
        tx_in_use: bool,
    }

    impl SessionTransport {
        fn new(target: SOCKADDR_IN) -> Self {
            Self {
                generation: 0,
                state: GenerationState::Empty,
                failure_pending: false,
                close_deadline: None,
                connect_outstanding: false,
                send_outstanding: 0,
                receive_outstanding: 0,
                send_slot: 0,
                send_posted_bytes: 0,
                send_offset: 0,
                receive_posted_bytes: 0,
                socket: None,
                request_queue: None,
                overlapped: PendingOverlapped::new(),
                target,
                tx_in_use: false,
            }
        }

        fn socket(&self) -> Result<SOCKET, NativeError> {
            self.socket
                .as_ref()
                .map(SocketOwner::raw)
                .ok_or_else(|| NativeError::invariant("session has no socket"))
        }

        fn queue(&self) -> Result<&RequestQueue, NativeError> {
            self.request_queue
                .as_ref()
                .ok_or_else(|| NativeError::invariant("session has no request queue"))
        }

        fn generation_drained(&self) -> bool {
            !self.connect_outstanding && self.send_outstanding == 0 && self.receive_outstanding == 0
        }

        fn allocate_send_slot(&mut self) -> Option<u32> {
            if self.tx_in_use {
                return None;
            }
            self.tx_in_use = true;
            Some(0)
        }

        fn release_send_slot(&mut self, slot: u32) -> Result<(), NativeError> {
            if slot != 0 {
                return Err(NativeError::invariant(
                    "send completion has an out-of-range slot",
                ));
            }
            if !self.tx_in_use {
                return Err(NativeError::invariant(
                    "send completion references a free slot",
                ));
            }
            self.tx_in_use = false;
            Ok(())
        }

        fn reset_generation_storage(&mut self) -> Result<(), NativeError> {
            if !self.generation_drained() {
                return Err(NativeError::invariant(
                    "generation released before all completions drained",
                ));
            }
            if self.tx_in_use {
                return Err(NativeError::invariant(
                    "generation drained while a send slot is still busy",
                ));
            }
            if self.receive_posted_bytes != 0 {
                return Err(NativeError::invariant(
                    "generation drained with a stale receive length",
                ));
            }
            if self.send_posted_bytes != 0 || self.send_offset != 0 {
                return Err(NativeError::invariant(
                    "generation drained with a stale send range",
                ));
            }
            if self.overlapped.is_armed() {
                return Err(NativeError::invariant(
                    "generation drained while ConnectEx OVERLAPPED is armed",
                ));
            }
            self.request_queue = None;
            self.socket = None;
            self.overlapped
                .reset_after_drain()
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
            self.state = GenerationState::Empty;
            self.close_deadline = None;
            self.failure_pending = false;
            Ok(())
        }
    }

    pub struct RioTransport {
        // After the mandatory release guard: CQ -> registered arena -> host session storage ->
        // IOCP -> notification OVERLAPPED. Native counts are zero before any of these drop.
        queue: Option<CompletionQueue>,
        arena: Option<Arena>,
        sessions: Vec<SessionTransport>,
        port: Option<CompletionPort>,
        notification_overlapped: Option<Box<OVERLAPPED>>,
        rio: RioFunctions,
        connect_ex: LPFN_CONNECTEX,
        results: Vec<RIORESULT>,
        protocol: Protocol,
        pending: Vec<Completion>,
        last_failure: Option<crate::types::Failure>,
        no_delay: bool,
        send_buffer_bytes: u32,
        receive_buffer_bytes: u32,
        local_port: u16,
        /// Registered bytes one attempt occupies: the payload repeated `batch_capacity` times.
        batch_bytes: u32,
        shutdown_started: bool,
        shutdown_deadline: Option<Instant>,
        completed_buffer: Vec<Completion>,
        drain_arbitration: Option<Instant>,
        sent_bytes: u64,
        rio_outstanding: u32,
        notify_arms: u64,
        notify_deliveries: u64,
        timeout_wakeups_while_outstanding: u64,
        wake: Option<crate::worker::WakePort>,
    }

    impl RioTransport {
        pub fn new(
            options: &Options,
            session_count: u32,
            payload: std::sync::Arc<[u8]>,
            memory_bytes: u64,
            target: SOCKADDR_IN,
            rio: RioFunctions,
            connect_ex: LPFN_CONNECTEX,
        ) -> Result<Self, NativeError> {
            if session_count == 0 || payload.is_empty() {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "transport requires at least one session and one payload byte",
                    code: 87,
                });
            }
            let payload_bytes = u32::try_from(payload.len()).map_err(|_| NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "payload is too large for a RIO_BUF",
                code: 87,
            })?;
            // One attempt is one send plus one receive, whatever /k is: /k is the number of echo
            // units an attempt carries, not the number of concurrent operations. UDP never batches.
            let batch_capacity = if options.protocol == Protocol::Tcp {
                options.pipeline_depth.max(1)
            } else {
                1
            };
            let batch_bytes = u32::try_from(
                u64::from(payload_bytes)
                    .checked_mul(u64::from(batch_capacity))
                    .ok_or_else(|| NativeError {
                        origin: crate::types::FailureDomain::Invariant,
                        stage: "attempt batch size overflow",
                        code: 87,
                    })?,
            )
            .map_err(|_| NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "attempt batch exceeds a RIO buffer",
                code: 87,
            })?;
            if u64::from(session_count) > u64::from(MAXIMUM_SESSION_INDEX) + 1 {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "session count exceeds request-context capacity",
                    code: 87,
                });
            }
            if options.cq_capacity == 0 {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "completion queue capacity must be non-zero",
                    code: 87,
                });
            }

            // RQ reservations are charged against the shared CQ. One receive plus one send per
            // session makes the sum exact, not an estimate.
            let per_session = u64::from(MAX_RECEIVE)
                .checked_add(u64::from(MAX_SEND))
                .ok_or_else(|| NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "request queue reservation overflow",
                    code: 87,
                })?;
            let required_cq = u64::from(session_count)
                .checked_mul(per_session)
                .ok_or_else(|| NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "completion queue reservation overflow",
                    code: 87,
                })?;
            if required_cq > u64::from(options.cq_capacity) {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "completion queue capacity",
                    code: 13,
                });
            }

            // One registered window per session in each direction, each the size of a full attempt.
            let receive_bytes = u64::from(session_count)
                .checked_mul(u64::from(batch_bytes))
                .ok_or_else(|| NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "receive arena size overflow",
                    code: 87,
                })?;
            let send_bytes = u64::from(session_count)
                .checked_mul(u64::from(batch_bytes))
                .ok_or_else(|| NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "send arena size overflow",
                    code: 87,
                })?;
            let required_memory =
                receive_bytes
                    .checked_add(send_bytes)
                    .ok_or_else(|| NativeError {
                        origin: crate::types::FailureDomain::Invariant,
                        stage: "registered memory size overflow",
                        code: 87,
                    })?;
            if required_memory > memory_bytes {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Allocation,
                    stage: "RIO registered memory budget",
                    code: 8,
                });
            }
            if required_memory > u64::from(u32::MAX) {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "worker registered arena exceeds DWORD capacity",
                    code: 87,
                });
            }

            // Local declaration order is chosen for the constructor-error path too: Rust drops
            // locals in reverse order, giving CQ -> IOCP -> notification OVERLAPPED if anything
            // after queue creation fails. The steady-state shutdown uses the same ordering.
            let mut notification_overlapped = Box::new(OVERLAPPED::default());
            let port = CompletionPort::create().map_err(stage)?;
            let queue = CompletionQueue::create(
                &rio,
                &port,
                options.cq_capacity,
                crate::native::rio::RIO_COMPLETION_KEY as *mut c_void,
                &mut *notification_overlapped as *mut OVERLAPPED as *mut c_void,
            )
            .map_err(stage)?;

            // Both directions share one virtual-memory owner. TX registrations remain isolated
            // from each other and RX, as required while RIOSend is outstanding. Each TX window
            // holds a full batch; a finite quota's tail uses a shorter view of the same bytes.
            let arena =
                Arena::create_worker(&rio, session_count, batch_bytes, &payload).map_err(stage)?;
            // The target was resolved once for the whole run, so every worker connects to the
            // same address the reference resolved in cec_run_client.
            let sessions = (0..session_count)
                .map(|_| SessionTransport::new(target))
                .collect();

            Ok(Self {
                sessions,
                queue: Some(queue),
                port: Some(port),
                notification_overlapped: Some(notification_overlapped),
                arena: Some(arena),
                rio,
                connect_ex,
                results: vec![RIORESULT::default(); COMPLETION_BATCH_SIZE],
                protocol: options.protocol,
                pending: Vec::with_capacity(session_count as usize),
                last_failure: None,
                no_delay: options.protocol == Protocol::Tcp,
                send_buffer_bytes: options.socket_buffer_bytes,
                receive_buffer_bytes: options.socket_buffer_bytes,
                local_port: options.local_port,
                batch_bytes,
                shutdown_started: false,
                shutdown_deadline: None,
                completed_buffer: Vec::with_capacity((session_count as usize).saturating_mul(4)),
                drain_arbitration: None,
                sent_bytes: 0,
                rio_outstanding: 0,
                notify_arms: 0,
                notify_deliveries: 0,
                timeout_wakeups_while_outstanding: 0,
                wake: None,
            })
        }

        fn queue(&self) -> Result<&CompletionQueue, NativeError> {
            self.queue
                .as_ref()
                .ok_or_else(|| NativeError::invariant("transport completion queue is closed"))
        }

        pub(super) fn notification_counters(&self) -> super::NotificationCounters {
            super::NotificationCounters {
                arms: self.notify_arms,
                deliveries: self.notify_deliveries,
                timeouts: self.timeout_wakeups_while_outstanding,
            }
        }

        pub(super) fn set_wake(
            &mut self,
            wake: crate::worker::WakePort,
        ) -> Result<(), NativeError> {
            let handle = self.port()?.raw() as usize;
            *wake
                .lock()
                .map_err(|_| NativeError::invariant("worker wake mutex poisoned"))? = handle;
            self.wake = Some(wake);
            Ok(())
        }

        fn clear_wake_port(&mut self) {
            if let Some(wake) = self.wake.take() {
                match wake.lock() {
                    Ok(mut handle) => *handle = 0,
                    Err(poisoned) => *poisoned.into_inner() = 0,
                };
            }
        }

        fn arm_queue(&mut self) -> Result<(), NativeError> {
            if self.rio_outstanding == 0 || self.queue()?.is_armed() {
                return Ok(());
            }
            if let Some(overlapped) = self.notification_overlapped.as_mut() {
                **overlapped = OVERLAPPED::default();
            }
            let rio = &self.rio;
            let queue = self
                .queue
                .as_mut()
                .ok_or_else(|| NativeError::invariant("transport completion queue is closed"))?;
            queue
                .arm(rio)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
            self.notify_arms = self.notify_arms.saturating_add(1);
            Ok(())
        }

        fn port(&self) -> Result<&CompletionPort, NativeError> {
            self.port
                .as_ref()
                .ok_or_else(|| NativeError::invariant("transport completion port is closed"))
        }

        fn generation_of(&self, index: u32) -> Result<u32, NativeError> {
            self.sessions
                .get(index as usize)
                .map(|slot| slot.generation)
                .ok_or_else(|| NativeError::invariant("session index out of range"))
        }

        fn prepare(&mut self, index: u32) -> Result<(), NativeError> {
            if self.shutdown_started {
                return Err(NativeError::invariant("transport is shutting down"));
            }
            let slot_index = index as usize;
            let current_generation = self
                .sessions
                .get(slot_index)
                .ok_or_else(|| NativeError::invariant("session index out of range"))?
                .generation;
            if self.sessions[slot_index].state != GenerationState::Empty {
                return Err(NativeError::invariant(
                    "previous connection generation has not drained",
                ));
            }
            let generation = next_generation(current_generation);

            let socket = registered_socket(self.protocol).map_err(stage)?;
            let associated = unsafe {
                CreateIoCompletionPort(
                    socket.raw() as *mut c_void,
                    Some(self.port()?.raw()),
                    encode_context(index, generation, NO_SEND_SLOT, Operation::Connect) as usize,
                    0,
                )
            };
            if associated.is_null() {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Win32,
                    stage: "CreateIoCompletionPort(socket)",
                    code: unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32,
                });
            }

            configure_socket(
                socket.raw(),
                self.no_delay,
                self.send_buffer_bytes,
                self.receive_buffer_bytes,
            )
            .map_err(stage)?;
            bind_local(socket.raw(), self.local_port).map_err(stage)?;
            let slot = &mut self.sessions[slot_index];
            slot.generation = generation;
            slot.state = GenerationState::Connecting;
            slot.failure_pending = false;
            slot.connect_outstanding = false;
            slot.send_outstanding = 0;
            slot.receive_outstanding = 0;
            slot.receive_posted_bytes = 0;
            slot.tx_in_use = false;
            slot.request_queue = None;
            slot.socket = Some(socket);
            slot.overlapped
                .reset_after_drain()
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));

            crate::worker::trace::event_args(
                "GENERATION_BEGIN",
                format_args!("session={index} generation={generation}"),
            );
            Ok(())
        }

        fn tx_global_slot(&self, index: u32, slot: u32) -> Result<u32, NativeError> {
            if slot != 0 || index as usize >= self.sessions.len() {
                return Err(NativeError::invariant("TX slot index exceeds arena"));
            }
            Ok(index)
        }

        fn finish_generation(&mut self, index: u32) -> Result<Completion, NativeError> {
            let slot = self
                .sessions
                .get_mut(index as usize)
                .ok_or_else(|| NativeError::invariant("session index out of range"))?;
            let generation = slot.generation;
            slot.reset_generation_storage()?;
            crate::worker::trace::event_args(
                "GENERATION_DRAINED",
                format_args!("session={index} generation={generation}"),
            );
            Ok(Completion {
                index,
                generation,
                slot: NO_SEND_SLOT,
                operation: Operation::GenerationDrained,
                status: 0,
                bytes: 0,
            })
        }

        fn begin_close(&mut self, index: u32) -> Result<(), NativeError> {
            let slot_index = index as usize;
            let Some(slot) = self.sessions.get_mut(slot_index) else {
                return Err(NativeError::invariant("session index out of range"));
            };
            if slot.state == GenerationState::Closing {
                return Ok(());
            }
            if slot.state == GenerationState::Empty {
                // A connect/setup post can fail before a native generation exists. The scheduler
                // has already moved to Closing and still needs the same retirement handshake to
                // decide between permanent failure and reconnect. Emit the internal drain event
                // immediately because there is no native resource left to wait for.
                if !self.shutdown_started {
                    self.pending.push(Completion {
                        index,
                        generation: slot.generation,
                        slot: NO_SEND_SLOT,
                        operation: Operation::GenerationDrained,
                        status: 0,
                        bytes: 0,
                    });
                }
                return Ok(());
            }

            crate::worker::trace::event_args(
                "CLOSE_BEGIN",
                format_args!("session={index} generation={}", slot.generation),
            );
            slot.state = GenerationState::Closing;
            slot.close_deadline = Some(Instant::now() + SHUTDOWN_TIMEOUT);
            // closesocket releases the RQ and starts cancellation. Keep the RQ value,
            // OVERLAPPED and registered buffers alive until their completions are dequeued.
            drop(slot.socket.take());
            let drained = slot.generation_drained();

            if drained {
                let completion = self.finish_generation(index)?;
                self.pending.push(completion);
            } else if let Err(error) = self.arm_queue() {
                return Err(error);
            }
            Ok(())
        }

        /// Retires exactly one native completion into the caller-owned batch. Cancellation
        /// completions for a generation already in Closing are consumed internally; only the
        /// final GenerationDrained event is exposed to the scheduler. The caller owns the Vec so
        /// this hot path performs no per-completion heap allocation.
        fn retire_into(
            &mut self,
            context: RequestContext,
            mut status: i32,
            bytes: u32,
            completions: &mut Vec<Completion>,
        ) -> Result<(), NativeError> {
            let slot_index = context.index as usize;
            let Some(session) = self.sessions.get_mut(slot_index) else {
                return Err(NativeError::invariant(
                    "completion has an out-of-range session index",
                ));
            };
            if context.generation != session.generation {
                crate::worker::trace::event_args(
                    "STALE_COMPLETION",
                    format_args!(
                        "session={} generation={} live={}",
                        context.index, context.generation, session.generation
                    ),
                );
                return Err(NativeError::invariant("completion from retired generation"));
            }

            let closing = session.state == GenerationState::Closing;
            let suppress_send = closing || session.failure_pending;
            // A send that had to be re-posted reports the whole attempt, not its last segment:
            // the worker checks the completion against the batch it posted.
            let mut reported_bytes = bytes;
            match context.operation {
                Operation::Connect => {
                    if !session.connect_outstanding {
                        return Err(NativeError::invariant(
                            "duplicate/unexpected ConnectEx completion",
                        ));
                    }
                    if !session.overlapped.is_armed() || bytes != 0 {
                        crate::native::fail_fast("ConnectEx completion metadata", 13);
                    }
                    session.connect_outstanding = false;
                    session
                        .overlapped
                        .complete()
                        .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
                }
                Operation::Send => {
                    if session.send_outstanding != 1 || context.slot != session.send_slot {
                        return Err(NativeError::invariant(
                            "send completion arrived with no send outstanding",
                        ));
                    }
                    let remaining = session
                        .send_posted_bytes
                        .checked_sub(session.send_offset)
                        .ok_or_else(|| NativeError::invariant("send offset exceeds its request"))?;
                    if bytes > remaining {
                        crate::native::fail_fast("client send completion exceeds posted range", 13);
                    }
                    self.rio_outstanding = self
                        .rio_outstanding
                        .checked_sub(1)
                        .ok_or_else(|| NativeError::invariant("RIO send completion underflow"))?;
                    session.send_outstanding -= 1;
                    if status == 0 && !suppress_send && bytes == 0 {
                        status = crate::native::completion::WSAECONNRESET;
                    }
                    if status == 0 && !suppress_send {
                        self.sent_bytes = self.sent_bytes.saturating_add(u64::from(bytes));
                    }
                    // A native send may complete with a strict prefix. The reference re-posts the
                    // remainder of the same attempt, so the scheduler sees exactly one send
                    // completion per attempt and the request queue never exceeds one send.
                    let remainder = if status == 0 && !suppress_send && bytes != 0 {
                        let offset = session.send_offset.saturating_add(bytes);
                        (offset < session.send_posted_bytes).then_some((
                            session.send_slot,
                            offset,
                            session.send_posted_bytes - offset,
                        ))
                    } else {
                        None
                    };
                    if let Some((send_slot, offset, remaining)) = remainder {
                        let global_slot = self.tx_global_slot(context.index, send_slot)?;
                        let buffer = self
                            .arena
                            .as_ref()
                            .ok_or_else(|| NativeError::invariant("send arena is unavailable"))?
                            .send_view_from(global_slot, offset, remaining)
                            .unwrap_or_else(|error| {
                                crate::native::fail_fast(error.stage, error.code)
                            });
                        let reposted = self.sessions[slot_index].queue()?.send(
                            &self.rio,
                            &buffer,
                            encode_context(
                                context.index,
                                context.generation,
                                send_slot,
                                Operation::Send,
                            ),
                        );
                        match reposted {
                            Ok(()) => {
                                let slot = &mut self.sessions[slot_index];
                                slot.send_outstanding += 1;
                                self.rio_outstanding += 1;
                                slot.send_offset = offset;
                                self.arm_queue()?;
                                return Ok(());
                            }
                            Err(error) => {
                                status = error.code;
                            }
                        }
                    }
                    let session = &mut self.sessions[slot_index];
                    reported_bytes = session.send_offset.saturating_add(bytes);
                    session.send_offset = 0;
                    session.send_posted_bytes = 0;
                    session.release_send_slot(context.slot)?;
                }
                Operation::Receive => {
                    if session.receive_outstanding != 1 || session.receive_posted_bytes == 0 {
                        return Err(NativeError::invariant(
                            "receive completion arrived without exactly one receive outstanding",
                        ));
                    }
                    if bytes > session.receive_posted_bytes {
                        return Err(NativeError::invariant(
                            "receive completion exceeds posted range",
                        ));
                    }
                    self.rio_outstanding =
                        self.rio_outstanding.checked_sub(1).ok_or_else(|| {
                            NativeError::invariant("RIO receive completion underflow")
                        })?;
                    if !closing
                        && self.protocol == Protocol::Tcp
                        && bytes != session.receive_posted_bytes
                    {
                        session.failure_pending = true;
                    }
                    session.receive_outstanding = 0;
                    session.receive_posted_bytes = 0;
                }
                Operation::GenerationDrained => {
                    return Err(NativeError::invariant(
                        "GenerationDrained cannot come from an OS request",
                    ));
                }
            }

            if !closing {
                // Match the reference's per-result failure order even though native ownership is
                // retired in batches: later completions still drain, but cannot count or repost a
                // send after the first failed operation. Keep liveness until the worker sees it.
                if status != 0 {
                    self.sessions[slot_index].failure_pending = true;
                }
                completions.push(Completion {
                    index: context.index,
                    generation: context.generation,
                    slot: context.slot,
                    operation: context.operation,
                    status,
                    bytes: reported_bytes,
                });
            }

            if self.sessions[slot_index].state == GenerationState::Closing
                && self.sessions[slot_index].generation_drained()
            {
                completions.push(self.finish_generation(context.index)?);
            }
            Ok(())
        }

        fn drain_rio_into(
            &mut self,
            budget: u32,
            completions: &mut Vec<Completion>,
        ) -> Result<(), NativeError> {
            self.drain_rio_bounded_into(budget, None, completions)
        }

        fn drain_rio_bounded_into(
            &mut self,
            budget: u32,
            mut records: Option<u32>,
            completions: &mut Vec<Completion>,
        ) -> Result<(), NativeError> {
            for _ in 0..budget {
                let capacity = records.map_or(self.results.len(), |remaining| {
                    (remaining as usize).min(self.results.len())
                });
                if capacity == 0 {
                    break;
                }
                let count = {
                    let rio = &self.rio;
                    let results = &mut self.results;
                    let queue = self.queue.as_mut().ok_or_else(|| {
                        NativeError::invariant("transport completion queue is closed")
                    })?;
                    queue
                        .dequeue(rio, &mut results[..capacity])
                        .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code))
                };
                if count == 0 {
                    break;
                }
                if let Some(remaining) = &mut records {
                    *remaining -= count;
                }
                // Do not clear the RIONotify armed state merely because CQ entries were
                // dequeued. The one-shot notification is retired only when its IOCP packet is
                // actually consumed by GetQueuedCompletionStatus (RIO_COMPLETION_KEY). An
                // unrelated ConnectEx packet may be observed first while the RIO notification
                // is still queued.
                for position in 0..count as usize {
                    let item = self.results[position];
                    let context = decode_context(item.RequestContext).ok_or_else(|| {
                        NativeError::invariant("completion has an invalid request context")
                    })?;
                    if !matches!(context.operation, Operation::Send | Operation::Receive) {
                        return Err(NativeError::invariant("RIO completion operation"));
                    }
                    self.retire_into(context, item.Status, item.BytesTransferred, completions)?;
                }
            }
            Ok(())
        }

        fn wait_iocp_once_into(
            &mut self,
            wait_ms: u32,
            completions: &mut Vec<Completion>,
        ) -> Result<Option<bool>, NativeError> {
            let mut bytes = 0u32;
            let mut key = 0u64;
            let mut overlapped: *mut OVERLAPPED = ptr::null_mut();
            let signaled = unsafe {
                GetQueuedCompletionStatus(
                    self.port()?.raw(),
                    &mut bytes,
                    &mut key,
                    &mut overlapped,
                    wait_ms,
                )
            };

            let error = if signaled.as_bool() {
                0
            } else {
                (unsafe { windows::Win32::errhandlingapi::GetLastError() }) as i32
            };
            if error == 0 && key == 1 && overlapped.is_null() {
                return Ok(Some(false));
            }
            if key as usize == crate::native::rio::RIO_COMPLETION_KEY {
                let expected = self
                    .notification_overlapped
                    .as_mut()
                    .map(|value| &mut **value as *mut OVERLAPPED)
                    .ok_or_else(|| {
                        NativeError::invariant("RIO notification OVERLAPPED is unavailable")
                    })?;
                if error != 0 {
                    crate::native::fail_fast(
                        "GetQueuedCompletionStatus(client notification)",
                        error,
                    );
                }
                if overlapped != expected {
                    crate::native::fail_fast("invalid RIO notification packet identity", 13);
                }
                self.queue
                    .as_mut()
                    .ok_or_else(|| NativeError::invariant("transport completion queue is closed"))?
                    .on_delivery()
                    .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
                self.notify_deliveries = self.notify_deliveries.saturating_add(1);
                return Ok(Some(true));
            }
            if !overlapped.is_null() {
                let context = decode_context(key).ok_or_else(|| {
                    NativeError::invariant("failed IOCP completion has an invalid completion key")
                })?;
                if context.operation != Operation::Connect {
                    return Err(NativeError::invariant(
                        "non-ConnectEx operation arrived through IOCP",
                    ));
                }
                let slot = self
                    .sessions
                    .get_mut(context.index as usize)
                    .ok_or_else(|| {
                        NativeError::invariant("ConnectEx packet has an invalid session index")
                    })?;
                if context.generation != slot.generation
                    || overlapped != slot.overlapped.as_mut_ptr()
                {
                    return Err(NativeError::invariant(
                        "invalid ConnectEx completion identity",
                    ));
                }
                self.retire_into(context, error, bytes, completions)?;
                return Ok(Some(false));
            }
            if error == WAIT_TIMEOUT && key == 0 {
                if self.rio_outstanding != 0 && !self.queue()?.is_armed() {
                    self.timeout_wakeups_while_outstanding =
                        self.timeout_wakeups_while_outstanding.saturating_add(1);
                }
                Ok(None)
            } else {
                Err(NativeError {
                    origin: crate::types::FailureDomain::Win32,
                    stage: "GetQueuedCompletionStatus(client)",
                    code: if error == 0 { 13 } else { error },
                })
            }
        }

        fn lifecycle_snapshot(&self) -> crate::types::Lifecycle {
            let total_outstanding = self.sessions.iter().fold(0u32, |count, session| {
                count
                    .saturating_add(u32::from(session.connect_outstanding))
                    .saturating_add(session.send_outstanding)
                    .saturating_add(session.receive_outstanding)
            });
            let releasable = total_outstanding == 0
                && self.rio_outstanding == 0
                && self.sessions.iter().all(|session| {
                    !session.overlapped.is_armed()
                        && !session.tx_in_use
                        && session.send_posted_bytes == 0
                        && session.receive_posted_bytes == 0
                });
            crate::types::Lifecycle {
                phase: if self.shutdown_started {
                    if releasable {
                        crate::types::LifecyclePhase::Stopped
                    } else {
                        crate::types::LifecyclePhase::Draining
                    }
                } else {
                    crate::types::LifecyclePhase::Running
                },
                total_outstanding,
                rio_outstanding: self.rio_outstanding,
                notification_armed: self.queue.as_ref().is_some_and(CompletionQueue::is_armed),
                releasable,
            }
        }

        fn require_release(&self) {
            if !self.lifecycle_snapshot().releasable {
                crate::native::fail_fast("client worker release precondition", 996);
            }
        }

        fn release_resources(&mut self) {
            self.require_release();
            self.clear_wake_port();
            // The notification OVERLAPPED and IOCP outlive the CQ, registered arena, and host
            // session storage. Every provider-held request was already retired by the guard.
            drop(self.queue.take());
            drop(self.arena.take());
            drop(core::mem::take(&mut self.sessions));
            drop(core::mem::take(&mut self.results));
            drop(core::mem::take(&mut self.pending));
            drop(core::mem::take(&mut self.completed_buffer));
            drop(self.port.take());
            drop(self.notification_overlapped.take());
        }

        pub fn shutdown_with_timeout(&mut self, timeout: Duration) -> Result<(), NativeError> {
            if self.queue.is_none() {
                return Ok(());
            }
            if !self.shutdown_started {
                self.shutdown_started = true;
                // This caller cap starts at the first global stop. Older generations keep their
                // own first-close limits, but their drained deadlines cannot shorten other slots.
                self.shutdown_deadline = Some(Instant::now() + timeout);
                self.pending.clear();
                for index in 0..self.sessions.len() as u32 {
                    if let Err(error) = self.begin_close(index) {
                        crate::native::fail_fast(error.stage, error.code);
                    }
                }
            }

            loop {
                if self
                    .sessions
                    .iter()
                    .all(|session| session.state == GenerationState::Empty)
                {
                    self.pending.clear();
                    self.clear_wake_port();
                    crate::worker::trace::event("SHUTDOWN", "all generations drained");
                    return Ok(());
                }
                match self.wait_and_drain(50, 64) {
                    Ok(completions) => self.recycle(completions),
                    Err(error) => crate::native::fail_fast(error.stage, error.code),
                }
            }
        }
    }

    impl Drop for RioTransport {
        fn drop(&mut self) {
            if std::thread::panicking() {
                crate::native::fail_fast("client worker panic with native resources", 13);
            }
            let _ = self.shutdown_with_timeout(SHUTDOWN_TIMEOUT);
            self.release_resources();
        }
    }

    /// Only a successfully quiesced transport crosses the JoinHandle boundary. The registered
    /// arena and notification OVERLAPPED retain their heap addresses until coordinator release.
    pub(super) struct DrainedOwner {
        transport: RioTransport,
    }
    // SAFETY: its private constructor follows successful shutdown. Heap addresses remain stable
    // across the ownership move; the resources have no native thread affinity and no other thread
    // retains a reference. The coordinator performs every Join before collective release checks.
    unsafe impl Send for DrainedOwner {}
    impl DrainedOwner {
        pub(super) fn require_release(&self) {
            self.transport.require_release();
        }
        pub(super) fn release(mut self) {
            self.transport.release_resources();
        }
    }
    impl RioTransport {
        pub(super) fn into_drained_owner(self) -> DrainedOwner {
            DrainedOwner { transport: self }
        }
    }

    impl RioTransport {
        fn try_close(&mut self, index: u32) -> Result<(), NativeError> {
            self.begin_close(index)
        }

        fn sent_bytes(&self) -> Option<u64> {
            Some(self.sent_bytes)
        }

        fn connect(&mut self, index: u32) -> Result<(), NativeError> {
            self.connect_at(index, &mut || {})
        }

        fn connect_at<F: FnMut()>(
            &mut self,
            index: u32,
            before_post: &mut F,
        ) -> Result<(), NativeError> {
            self.prepare(index)?;
            let slot_index = index as usize;
            let generation = self.generation_of(index)?;

            if self.protocol == Protocol::Udp {
                let (socket, target) = {
                    let slot = &self.sessions[slot_index];
                    (slot.socket()?, slot.target)
                };
                before_post();
                connect_udp(socket, &target).map_err(stage)?;
                // Keep the transport in Connecting until the synthetic completion is consumed
                // by the worker and `connected()` performs the same state transition as TCP.
                self.pending.push(Completion {
                    index,
                    generation,
                    slot: NO_SEND_SLOT,
                    operation: Operation::Connect,
                    status: 0,
                    bytes: 0,
                });
                crate::worker::trace::event_args(
                    "CONNECT_POST",
                    format_args!("session={index} generation={generation} udp=1"),
                );
                return Ok(());
            }

            let result = {
                let connect_ex = self.connect_ex;
                let slot = &mut self.sessions[slot_index];
                slot.overlapped
                    .arm()
                    .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
                let socket = slot.socket()?;
                let target = slot.target;
                let overlapped = slot.overlapped.as_mut_ptr();
                before_post();
                begin_connect(connect_ex, socket, &target, overlapped)
            };
            match result {
                Ok(_) => {
                    self.sessions[slot_index].connect_outstanding = true;
                    crate::worker::trace::event_args(
                        "CONNECT_POST",
                        format_args!("session={index} generation={generation}"),
                    );
                    Ok(())
                }
                Err(error) => {
                    self.sessions[slot_index]
                        .overlapped
                        .post_failed()
                        .map_err(stage)?;
                    Err(stage(error))
                }
            }
        }

        fn connected(&mut self, index: u32, generation: u32) -> Result<(), NativeError> {
            let protocol = self.protocol;
            let queue_raw = self.queue()?.raw();
            let rio = self.rio;
            let slot = self
                .sessions
                .get_mut(index as usize)
                .ok_or_else(|| NativeError::invariant("session index out of range"))?;
            if slot.generation != generation || slot.state != GenerationState::Connecting {
                return Err(NativeError::invariant(
                    "connect completion does not belong to the live generation",
                ));
            }
            if protocol == Protocol::Tcp && (slot.connect_outstanding || slot.overlapped.is_armed())
            {
                return Err(NativeError::invariant(
                    "ConnectEx completion was not retired before connected()",
                ));
            }
            if protocol == Protocol::Tcp {
                update_connect_context(slot.socket()?).map_err(stage)?;
            }
            slot.request_queue = Some(
                RequestQueue::create(
                    &rio,
                    slot.socket()?,
                    MAX_RECEIVE,
                    1,
                    MAX_SEND,
                    1,
                    queue_raw,
                    queue_raw,
                    encode_context(index, generation, NO_SEND_SLOT, Operation::Connect),
                )
                .map_err(stage)?,
            );
            slot.state = GenerationState::Active;
            crate::worker::trace::event_args(
                "CONNECT_COMPLETE",
                format_args!("session={index} generation={generation}"),
            );
            Ok(())
        }

        fn send(&mut self, index: u32, bytes: u32) -> Result<(), NativeError> {
            if self.shutdown_started {
                return Err(NativeError::invariant("transport is shutting down"));
            }
            let slot_index = index as usize;
            let generation = self.generation_of(index)?;
            if self.sessions[slot_index].state != GenerationState::Active {
                return Err(NativeError::invariant(
                    "send attempted outside an active generation",
                ));
            }
            if bytes == 0 || bytes > self.batch_bytes {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "invalid send length",
                    code: 87,
                });
            }
            if self.sessions[slot_index].send_outstanding >= MAX_SEND {
                return Err(NativeError::invariant("RIO send depth exceeded"));
            }

            let send_slot = self.sessions[slot_index]
                .allocate_send_slot()
                .ok_or_else(|| {
                    NativeError::invariant("no free TX slot despite available send depth")
                })?;
            let global_slot = self.tx_global_slot(index, send_slot)?;
            let buffer = self
                .arena
                .as_ref()
                .ok_or_else(|| NativeError::invariant("send arena is unavailable"))?
                .send_view(global_slot, bytes)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
            let context = encode_context(index, generation, send_slot, Operation::Send);
            let posted = self.sessions[slot_index]
                .queue()?
                .send(&self.rio, &buffer, context)
                .map_err(stage);
            if let Err(error) = posted {
                self.sessions[slot_index].release_send_slot(send_slot)?;
                return Err(error);
            }
            self.sessions[slot_index].send_outstanding += 1;
            self.rio_outstanding += 1;
            self.sessions[slot_index].send_slot = send_slot;
            self.sessions[slot_index].send_posted_bytes = bytes;
            self.sessions[slot_index].send_offset = 0;
            self.arm_queue()?;
            crate::worker::trace::event_args(
                "SEND_POST",
                format_args!(
                    "session={index} generation={generation} slot={send_slot} bytes={bytes}"
                ),
            );
            Ok(())
        }

        fn receive(&mut self, index: u32, bytes: u32) -> Result<(), NativeError> {
            if self.shutdown_started {
                return Err(NativeError::invariant("transport is shutting down"));
            }
            let slot_index = index as usize;
            let generation = self.generation_of(index)?;
            if self.sessions[slot_index].state != GenerationState::Active {
                return Err(NativeError::invariant(
                    "receive attempted outside an active generation",
                ));
            }
            if self.sessions[slot_index].receive_outstanding != 0 {
                return Err(NativeError::invariant(
                    "second RIOReceive posted for the same session",
                ));
            }
            if bytes == 0 || bytes > self.batch_bytes {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "invalid receive length",
                    code: 87,
                });
            }

            let buffer = self
                .arena
                .as_ref()
                .ok_or_else(|| NativeError::invariant("receive arena is unavailable"))?
                .receive_view(index, bytes)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
            self.sessions[slot_index]
                .queue()?
                .receive(
                    &self.rio,
                    &buffer,
                    encode_context(index, generation, NO_SEND_SLOT, Operation::Receive),
                    if self.protocol == Protocol::Tcp {
                        windows::Win32::mswsockdef::RIO_MSG_WAITALL as u32
                    } else {
                        0
                    },
                )
                .map_err(stage)?;
            self.sessions[slot_index].receive_outstanding = 1;
            self.rio_outstanding += 1;
            self.sessions[slot_index].receive_posted_bytes = bytes;
            self.arm_queue()?;
            crate::worker::trace::event_args(
                "RECV_POST",
                format_args!("session={index} generation={generation} bytes={bytes}"),
            );
            Ok(())
        }

        fn close(&mut self, index: u32) {
            if let Err(error) = self.begin_close(index) {
                crate::native::fail_fast(error.stage, error.code);
            }
        }

        fn completion_is_live(&self, index: u32, generation: u32) -> bool {
            self.sessions.get(index as usize).is_some_and(|slot| {
                slot.generation == generation
                    && matches!(
                        slot.state,
                        GenerationState::Connecting | GenerationState::Active
                    )
            })
        }

        fn received(&self, index: u32, generation: u32, length: u32) -> &[u8] {
            if !self.completion_is_live(index, generation) {
                return &[];
            }
            if length > self.batch_bytes {
                return &[];
            }
            self.arena
                .as_ref()
                .map(|arena| arena.read_receive(index, length))
                .unwrap_or(&[])
        }

        fn drain(&mut self, budget: u32) -> Result<Vec<Completion>, NativeError> {
            let mut completions = core::mem::take(&mut self.completed_buffer);
            completions.extend(self.pending.drain(..));
            self.drain_rio_into(budget, &mut completions)?;
            // RIONotify is one-shot. If native work remains after a drain, re-arm even when the
            // scheduler did not post a replacement operation (for example, only a receive is
            // still outstanding after several send completions).
            if self.rio_outstanding != 0 {
                self.arm_queue()?;
            }
            Ok(completions)
        }

        fn wait_and_drain(
            &mut self,
            wait_milliseconds: u32,
            budget: u32,
        ) -> Result<Vec<Completion>, NativeError> {
            let mut completions = core::mem::take(&mut self.completed_buffer);
            completions.extend(self.pending.drain(..));
            let grace_wait = self
                .sessions
                .iter()
                .filter_map(|session| session.close_deadline)
                .chain(self.shutdown_deadline)
                .map(|deadline| {
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(u128::from(u32::MAX)) as u32
                })
                .min()
                .unwrap_or(wait_milliseconds);
            let wait = if completions.is_empty() {
                wait_milliseconds.min(grace_wait)
            } else {
                0
            };
            if self.wait_iocp_once_into(wait, &mut completions)? == Some(true) {
                self.drain_rio_into(budget, &mut completions)?;
            }
            let arbitration = Instant::now();
            self.drain_arbitration = Some(arbitration);
            let due = self
                .shutdown_deadline
                .is_some_and(|deadline| arbitration >= deadline)
                || self.sessions.iter().any(|session| {
                    session
                        .close_deadline
                        .is_some_and(|deadline| arbitration >= deadline)
                });
            // The grace can expire during the blocking wait. Give queued ConnectEx, control,
            // and notification packets a bounded zero-wait pass before checking ownership.
            if due {
                for _ in 0..self.sessions.len().saturating_add(2) {
                    if self.wait_iocp_once_into(0, &mut completions)? == Some(true) {
                        self.drain_rio_into(budget, &mut completions)?;
                    }
                }
            }
            if self.rio_outstanding != 0 {
                self.arm_queue()?;
            }
            // RIONotify delivery can lag behind already-queued RIO results. At the release
            // deadline inspect the CQ itself, without retiring the notification's armed state.
            // At most two native RIO operations per session can be held by the provider; allow
            // one nonempty dequeue per operation even when the provider returns short batches.
            if due {
                let records = (self.sessions.len() as u32).saturating_mul(2);
                self.drain_rio_bounded_into(records, Some(records), &mut completions)?;
            }
            for session in &self.sessions {
                if session
                    .close_deadline
                    .is_some_and(|deadline| arbitration >= deadline)
                    && !session.generation_drained()
                {
                    crate::native::fail_fast("client generation drain", 1460);
                }
            }
            if self
                .shutdown_deadline
                .is_some_and(|deadline| arbitration >= deadline)
                && self
                    .sessions
                    .iter()
                    .any(|session| !session.generation_drained())
            {
                crate::native::fail_fast("client shutdown drain", 1460);
            }
            Ok(completions)
        }

        fn poll_deadline_packet(
            &mut self,
            budget: u32,
        ) -> Result<Option<Vec<Completion>>, NativeError> {
            let mut completions = core::mem::take(&mut self.completed_buffer);
            completions.extend(self.pending.drain(..));
            let packet = self.wait_iocp_once_into(0, &mut completions)?;
            if packet == Some(true) {
                self.drain_rio_into(budget, &mut completions)?;
            }
            if self.rio_outstanding != 0 {
                self.arm_queue()?;
            }
            if packet.is_none() && completions.is_empty() {
                self.completed_buffer = completions;
                Ok(None)
            } else {
                Ok(Some(completions))
            }
        }

        fn drain_before_deadlines(&mut self) -> Result<Vec<Completion>, NativeError> {
            let mut completions = core::mem::take(&mut self.completed_buffer);
            completions.extend(self.pending.drain(..));
            let records = (self.sessions.len() as u32).saturating_mul(2);
            self.drain_rio_bounded_into(records, Some(records), &mut completions)?;
            if self.rio_outstanding != 0 {
                self.arm_queue()?;
            }
            Ok(completions)
        }

        fn recycle(&mut self, mut completions: Vec<Completion>) {
            // Keep the capacity the batch grew to: the next wait_and_drain reuses this buffer
            // instead of allocating and growing a new one on every round trip.
            completions.clear();
            // Handling this batch can synchronously retire a generation and enqueue its drain
            // event. Preserve those new control completions when returning the reusable buffer.
            self.completed_buffer = completions;
        }

        fn shutdown(&mut self) -> Result<(), NativeError> {
            self.shutdown_with_timeout(SHUTDOWN_TIMEOUT)
        }
    }

    impl RioTransport {
        fn report_failure(&mut self, error: NativeError) -> String {
            self.last_failure = Some(crate::types::Failure {
                classification: crate::types::FailureClass::Network,
                domain: error.origin,
                stage: error.stage,
                code: error.code,
            });
            eprintln!("{} failed: native_error={}", error.stage, error.code);
            String::new()
        }
    }

    impl Transport for RioTransport {
        fn failure(&self) -> Option<crate::types::Failure> {
            self.last_failure
        }
        fn lifecycle(&self) -> Option<crate::types::Lifecycle> {
            Some(self.lifecycle_snapshot())
        }
        fn generation_outstanding(&self, index: u32) -> bool {
            self.sessions
                .get(index as usize)
                .is_some_and(|session| !session.generation_drained())
        }
        fn check_generation_drain(&self, index: u32) {
            // The pure QPC timer can expire slightly before its native close timestamp. Only
            // the saved Instant arbitration has proved a due CQ received its bounded pass.
            if self.sessions.get(index as usize).is_some_and(|session| {
                self.drain_arbitration.is_some_and(|arbitration| {
                    session
                        .close_deadline
                        .is_some_and(|deadline| arbitration >= deadline)
                }) && !session.generation_drained()
            }) {
                crate::native::fail_fast("client generation drain", 1460);
            }
        }
        fn connect(&mut self, index: u32) -> Result<(), String> {
            RioTransport::connect(self, index).map_err(|error| self.report_failure(error))
        }
        fn connect_at(&mut self, index: u32, before_post: &mut dyn FnMut()) -> Result<(), String> {
            RioTransport::connect_at(self, index, &mut || before_post())
                .map_err(|error| self.report_failure(error))
        }
        fn connect_at_static<F: FnMut()>(
            &mut self,
            index: u32,
            before_post: &mut F,
        ) -> Result<(), String> {
            RioTransport::connect_at(self, index, before_post)
                .map_err(|error| self.report_failure(error))
        }
        fn connected(&mut self, index: u32, generation: u32) -> Result<(), String> {
            RioTransport::connected(self, index, generation)
                .map_err(|error| self.report_failure(error))
        }
        fn send(&mut self, index: u32, bytes: u32) -> Result<(), String> {
            RioTransport::send(self, index, bytes).map_err(|error| self.report_failure(error))
        }
        fn receive(&mut self, index: u32, bytes: u32) -> Result<(), String> {
            RioTransport::receive(self, index, bytes).map_err(|error| self.report_failure(error))
        }
        fn close(&mut self, index: u32) {
            RioTransport::close(self, index);
        }
        fn try_close(&mut self, index: u32) -> Result<(), String> {
            RioTransport::try_close(self, index)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
            Ok(())
        }
        fn sent_bytes(&self) -> Option<u64> {
            RioTransport::sent_bytes(self)
        }
        fn completion_is_live(&self, index: u32, generation: u32) -> bool {
            RioTransport::completion_is_live(self, index, generation)
        }
        fn received(&self, index: u32, generation: u32, length: u32) -> &[u8] {
            RioTransport::received(self, index, generation, length)
        }
        fn drain(&mut self, budget: u32) -> Result<Vec<Completion>, String> {
            Ok(RioTransport::drain(self, budget)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code)))
        }
        fn wait_and_drain(&mut self, wait: u32, budget: u32) -> Result<Vec<Completion>, String> {
            Ok(RioTransport::wait_and_drain(self, wait, budget)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code)))
        }
        fn poll_deadline_packet(&mut self, budget: u32) -> Result<Option<Vec<Completion>>, String> {
            Ok(RioTransport::poll_deadline_packet(self, budget)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code)))
        }
        fn drain_before_deadlines(&mut self) -> Result<Vec<Completion>, String> {
            Ok(RioTransport::drain_before_deadlines(self)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code)))
        }
        fn recycle(&mut self, completions: Vec<Completion>) {
            RioTransport::recycle(self, completions);
        }
        fn shutdown(&mut self) -> Result<(), String> {
            RioTransport::shutdown(self)
                .unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code));
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use std::cell::RefCell;
        use windows::Win32::mswsock::{RIO_EXTENSION_FUNCTION_TABLE, RIO_NOTIFICATION_COMPLETION};
        use windows::Win32::mswsockdef::{RIO_BUF, RIO_BUFFERID, RIO_CQ, RIO_RQ};

        #[derive(Default)]
        struct SendProbe {
            ranges: Vec<(usize, u32, u32)>,
            fail_post: Option<usize>,
        }

        thread_local! {
            static SEND_PROBE: RefCell<SendProbe> = RefCell::new(SendProbe::default());
        }

        unsafe extern "system" fn fake_send(
            _queue: RIO_RQ,
            buffer: *mut RIO_BUF,
            _count: u32,
            _flags: u32,
            _context: *const c_void,
        ) -> windows::core::BOOL {
            let buffer = unsafe { &*buffer };
            let fail = SEND_PROBE.with(|probe| {
                let mut probe = probe.borrow_mut();
                probe
                    .ranges
                    .push((buffer.BufferId as usize, buffer.Offset, buffer.Length));
                probe.fail_post == Some(probe.ranges.len())
            });
            if fail {
                unsafe { windows::Win32::winsock2::WSASetLastError(10_054) };
            }
            windows::core::BOOL(i32::from(!fail))
        }

        unsafe extern "system" fn fake_register(base: *mut i8, _length: u32) -> RIO_BUFFERID {
            base.cast()
        }

        unsafe extern "system" fn fake_deregister(_buffer: RIO_BUFFERID) {}

        unsafe extern "system" fn fake_create_cq(
            _size: u32,
            _notification: *mut RIO_NOTIFICATION_COMPLETION,
        ) -> RIO_CQ {
            core::ptr::NonNull::dangling().as_ptr()
        }

        unsafe extern "system" fn fake_close_cq(_queue: RIO_CQ) {}

        unsafe extern "system" fn fake_notify(_queue: RIO_CQ) -> i32 {
            0
        }

        unsafe extern "system" fn fake_create_rq(
            _socket: SOCKET,
            _receives: u32,
            _receive_buffers: u32,
            _sends: u32,
            _send_buffers: u32,
            _receive_cq: RIO_CQ,
            _send_cq: RIO_CQ,
            _context: *const c_void,
        ) -> RIO_RQ {
            core::ptr::NonNull::dangling().as_ptr()
        }

        /// Inject only the provider boundary: exercise the production arena views, send posting,
        /// completion retirement, continuation and slot ownership with deterministic native results.
        fn send_transport(fail_post: Option<usize>) -> RioTransport {
            SEND_PROBE.with(|probe| {
                *probe.borrow_mut() = SendProbe {
                    fail_post,
                    ..SendProbe::default()
                }
            });
            let table = RIO_EXTENSION_FUNCTION_TABLE {
                RIOSend: Some(fake_send),
                RIORegisterBuffer: Some(fake_register),
                RIODeregisterBuffer: Some(fake_deregister),
                RIOCreateCompletionQueue: Some(fake_create_cq),
                RIOCloseCompletionQueue: Some(fake_close_cq),
                RIOCreateRequestQueue: Some(fake_create_rq),
                RIONotify: Some(fake_notify),
                ..RIO_EXTENSION_FUNCTION_TABLE::default()
            };
            let rio = RioFunctions::from_test_table(table);
            let options = Options {
                protocol: Protocol::Tcp,
                ..Options::default()
            };
            let target = SOCKADDR_IN::default();
            let mut transport = RioTransport::new(
                &options,
                1,
                std::sync::Arc::from(&b"abcdef"[..]),
                4096,
                target,
                rio,
                None,
            )
            .unwrap();
            let queue = RequestQueue::create(
                &rio,
                0,
                1,
                1,
                1,
                1,
                transport.queue().unwrap().raw(),
                transport.queue().unwrap().raw(),
                ptr::null_mut(),
            )
            .unwrap();
            transport.sessions[0].request_queue = Some(queue);
            transport.sessions[0].state = GenerationState::Active;
            transport.sessions[0].generation = 1;
            transport
        }

        fn send_context() -> RequestContext {
            RequestContext {
                index: 0,
                generation: 1,
                slot: 0,
                operation: Operation::Send,
            }
        }

        const FAIL_FAST_PROBE: &str = "CEC_NATIVE_FAIL_FAST_PROBE";

        fn is_fail_fast_probe(test_name: &str) -> bool {
            std::env::var(FAIL_FAST_PROBE).is_ok_and(|value| value == test_name)
        }

        /// Ownership faults terminate the process, so keep the existing fault fixtures isolated
        /// from the test runner. A hung child is a failure, with no unbounded process wait.
        fn assert_fail_fast(test_name: &str, stage: &str) {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
                .env(FAIL_FAST_PROBE, test_name)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    panic!("native fail-fast child exceeded its deadline: {test_name}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(crate::types::ExitCode::Internal as i32)
            );
            assert!(String::from_utf8_lossy(&output.stderr).contains(stage));
        }

        #[test]
        fn native_partial_send_preserves_registration_and_reports_whole_attempt() {
            let mut transport = send_transport(None);
            transport.send(0, 6).unwrap();
            let mut completions = Vec::new();
            transport
                .retire_into(send_context(), 0, 2, &mut completions)
                .unwrap();
            assert!(completions.is_empty());
            assert_eq!(transport.rio_outstanding, 1);
            assert_eq!(transport.sessions[0].send_outstanding, 1);
            assert!(transport.sessions[0].tx_in_use);
            assert_eq!(transport.sent_bytes, 2);
            transport
                .retire_into(send_context(), 0, 4, &mut completions)
                .unwrap();
            assert_eq!(completions.len(), 1);
            assert_eq!(completions[0].bytes, 6);
            assert_eq!(completions[0].status, 0);
            assert_eq!(transport.sent_bytes, 6);
            assert_eq!(transport.rio_outstanding, 0);
            assert!(!transport.sessions[0].tx_in_use);
            SEND_PROBE.with(|probe| {
                let probe = probe.borrow();
                assert_eq!(probe.ranges.len(), 2);
                assert_eq!(probe.ranges[0].0, probe.ranges[1].0);
                assert_eq!((probe.ranges[0].1, probe.ranges[0].2), (0, 6));
                assert_eq!((probe.ranges[1].1, probe.ranges[1].2), (2, 4));
            });
            transport.shutdown().unwrap();
        }

        #[test]
        fn native_partial_send_failure_retires_slot_and_counts_only_successful_prefix() {
            for synchronous_failure in [false, true] {
                let mut transport = send_transport(synchronous_failure.then_some(2));
                transport.send(0, 6).unwrap();
                let mut completions = Vec::new();
                transport
                    .retire_into(send_context(), 0, 2, &mut completions)
                    .unwrap();
                if !synchronous_failure {
                    assert!(completions.is_empty());
                    transport
                        .retire_into(send_context(), 10_054, 0, &mut completions)
                        .unwrap();
                }
                assert_eq!(completions.len(), 1);
                assert_eq!(completions[0].status, 10_054);
                assert_eq!(transport.sent_bytes, 2);
                assert_eq!(transport.rio_outstanding, 0);
                assert_eq!(transport.sessions[0].send_outstanding, 0);
                assert!(!transport.sessions[0].tx_in_use);
                assert!(transport.sessions[0].failure_pending);
                transport.shutdown().unwrap();
            }
        }

        #[test]
        fn native_synchronous_send_failure_rolls_back_unaccepted_slot() {
            let mut transport = send_transport(Some(1));
            assert!(transport.send(0, 6).is_err());
            assert_eq!(transport.rio_outstanding, 0);
            assert_eq!(transport.sessions[0].send_outstanding, 0);
            assert!(!transport.sessions[0].tx_in_use);
            assert_eq!(transport.sent_bytes, 0);
            transport.shutdown().unwrap();
        }

        #[test]
        fn native_invalid_successful_send_lengths_fail_without_counting_bytes() {
            let test_name = "engine::transport::tests::native_invalid_successful_send_lengths_fail_without_counting_bytes";
            if is_fail_fast_probe(test_name) {
                let mut transport = send_transport(None);
                transport.send(0, 6).unwrap();
                let _ = transport.retire_into(send_context(), 0, 7, &mut Vec::new());
                panic!("oversized native completion crossed its ownership guard");
            }
            // A zero-byte send is a connection failure. An oversized provider completion is
            // ownership corruption and must terminate before retiring or counting its bytes.
            for bytes in [0] {
                let mut transport = send_transport(None);
                transport.send(0, 6).unwrap();
                let mut completions = Vec::new();
                transport
                    .retire_into(send_context(), 0, bytes, &mut completions)
                    .unwrap();
                assert_eq!(completions.len(), 1);
                assert_eq!(completions[0].status, 10_054);
                assert_eq!(transport.sent_bytes, 0);
                assert_eq!(transport.rio_outstanding, 0);
                assert!(!transport.sessions[0].tx_in_use);
                transport.shutdown().unwrap();
            }
            assert_fail_fast(test_name, "client send completion exceeds posted range");
        }

        #[test]
        fn tx_slot_cannot_be_reused_before_completion() {
            let test_name = "engine::transport::tests::tx_slot_cannot_be_reused_before_completion";
            let target: SOCKADDR_IN = unsafe { core::mem::zeroed() };
            let mut session = SessionTransport::new(target);
            let slot = session.allocate_send_slot().expect("slot");
            assert_eq!(slot, 0);
            assert!(session.allocate_send_slot().is_none());
            if is_fail_fast_probe(test_name) {
                let _ = session.release_send_slot(1);
                panic!("out-of-range release crossed its ownership guard");
            }
            assert_fail_fast(test_name, "send completion has an out-of-range slot");
            assert!(session.allocate_send_slot().is_none());
            session.release_send_slot(slot).expect("release");
            assert_eq!(session.allocate_send_slot(), Some(0));
            assert!(session.allocate_send_slot().is_none());
        }

        #[test]
        fn tx_slot_double_release_is_rejected() {
            let test_name = "engine::transport::tests::tx_slot_double_release_is_rejected";
            let target: SOCKADDR_IN = unsafe { core::mem::zeroed() };
            let mut session = SessionTransport::new(target);
            let slot = session.allocate_send_slot().expect("slot");
            session.release_send_slot(slot).expect("release");
            if is_fail_fast_probe(test_name) {
                let _ = session.release_send_slot(slot);
                panic!("double release crossed its ownership guard");
            }
            assert_fail_fast(test_name, "send completion references a free slot");
        }
    }
}
