//! Top-level orchestration: worker resolution, session partitioning, worker startup and join,
//! statistics aggregation, terminal accounting, console registration and result classification.


use crate::native::clock::RioClock;
use crate::native::Winsock;
use crate::metrics::Statistics;
use crate::payload::{build, validate_payload};
use crate::session::transport::RioTransport;
use crate::types::{ExitCode, Options, Protocol};
use crate::worker::{StopFlag, Worker};

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
}

unsafe extern "system" fn console_ctrl_handler(control: u32) -> i32 {
    // CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT.
    if matches!(control, 0 | 1 | 2 | 5 | 6) {
        StopFlag::request_global();
        1
    } else {
        0
    }
}

struct ConsoleHandler;

impl ConsoleHandler {
    fn install() -> Result<Self, String> {
        let ok = unsafe { SetConsoleCtrlHandler(Some(console_ctrl_handler), 1) };
        if ok == 0 {
            return Err("SetConsoleCtrlHandler failed".to_string());
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
    let workers = if worker_count == 0 {
        session_count.min(32)
    } else {
        worker_count.min(session_count)
    }
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
    let share = u128::from(total)
        .saturating_mul(u128::from(worker_sessions))
        / u128::from(total_sessions);
    share.min(u128::from(u64::MAX)) as u64
}

fn run_worker(
    options: Options,
    payload: std::sync::Arc<[u8]>,
    sessions: u32,
    memory_share: u64,
    stop: StopFlag,
) -> Result<(Statistics, bool), String> {
    let result = (|| -> Result<(Statistics, bool), String> {
        let _winsock = Winsock::start()
            .map_err(|error| format!("{} failed ({})", error.stage, error.code))?;
        let payload_bytes = u32::try_from(payload.len())
            .map_err(|_| "payload is too large for the worker".to_string())?;
        let mut worker = Worker::new(&options, sessions, payload_bytes, 0);
        worker.set_payload(std::sync::Arc::clone(&payload));
        let mut transport = RioTransport::new(&options, sessions, payload, memory_share)?;
        let mut clock = RioClock::new();
        let outcome = worker.run(&mut clock, &mut transport, &stop);
        let statistics = worker.scheduler().statistics();
        // A terminal worker failure must wake peers too. Otherwise an unlimited run can
        // leave healthy workers running forever while one worker has already become terminal.
        if !outcome.controlled_stop
            && (statistics.fatal
                || statistics.network_failures != 0
                || statistics.corrupted != 0)
        {
            StopFlag::request_global();
        }
        Ok((statistics, outcome.controlled_stop))
    })();
    if result.is_err() {
        // Setup errors happen before Worker::run can observe the shared flag. Propagate the
        // stop to already-running peer workers so the join loop cannot deadlock on /n 0.
        StopFlag::request_global();
    }
    result
}

pub fn run(options: &Options) -> ExitCode {
    if options.protocol == Protocol::None {
        return ExitCode::Usage;
    }

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
    // Capacity is an argument property, not a run-time one: the request queues reserve their
    // outstanding operations against the completion queue, and the registered arena holds one
    // receive window per pipeline slot plus the shared send region. Both budgets are checked
    // here so an impossible configuration fails as a usage error before any RIO object exists,
    // which is the same contract the C++ client follows.
    let slots_per_session = u64::from(options.pipeline_depth) + 1;
    let required_operations = match u64::from(options.session_count).checked_mul(slots_per_session) {
        Some(value) => value,
        None => {
            eprintln!("Invalid arguments: completion queue budget overflows");
            return ExitCode::Usage;
        }
    };
    if required_operations > u64::from(options.cq_capacity) {
        eprintln!(
            "Invalid arguments: completion queue holds {} entries but {} sessions reserve {}",
            options.cq_capacity, options.session_count, required_operations
        );
        return ExitCode::Usage;
    }
    let required_memory = match required_operations.checked_mul(payload.len() as u64) {
        Some(value) => value,
        None => {
            eprintln!("Invalid arguments: registered memory budget overflows");
            return ExitCode::Usage;
        }
    };
    if required_memory > options.memory_bytes {
        eprintln!(
            "Invalid arguments: registered memory needs {required_memory} bytes but /memory is {}",
            options.memory_bytes
        );
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
    let stop = StopFlag;

    let payload: std::sync::Arc<[u8]> = std::sync::Arc::from(payload.into_boxed_slice());
    let counts = partition(options.session_count, options.worker_count);
    let mut handles = Vec::with_capacity(counts.len());
    let mut worker_spawn_error = false;
    for (worker_index, sessions) in counts.into_iter().enumerate() {
        let options = options.clone();
        let worker_payload = std::sync::Arc::clone(&payload);
        let memory_share = worker_memory_share(
            options.memory_bytes,
            sessions,
            options.session_count,
        );
        let handle = std::thread::Builder::new()
            .name(format!("cec-worker-{worker_index}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_worker(options, worker_payload, sessions, memory_share, stop)
                }));
                match result {
                    Ok(result) => result,
                    Err(payload) => {
                        // A panic must wake unlimited peer workers before this JoinHandle is
                        // eventually observed by the main thread. Resume the original panic so
                        // the join result still records an abnormal worker termination.
                        StopFlag::request_global();
                        std::panic::resume_unwind(payload);
                    }
                }
            });
        match handle {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                eprintln!("failed to create worker thread {worker_index}: {error}");
                worker_spawn_error = true;
                StopFlag::request_global();
                break;
            }
        }
    }

    let mut statistics = Statistics::default();
    let mut all_controlled = true;
    let mut worker_panic = false;

    // Always join every worker. Returning on the first failed handle would detach the rest
    // while they may still own sockets, RIO queues and registered memory. `run_worker`
    // already raises the global stop flag on failure, so peers will quiesce and can be joined
    // cleanly here.
    for handle in handles {
        match handle.join() {
            Ok(Ok((worker_statistics, controlled))) => {
                statistics.merge(&worker_statistics);
                all_controlled &= controlled;
            }
            Ok(Err(reason)) => {
                eprintln!("RIO worker failed: {reason}");
                StopFlag::request_global();
            }
            Err(_) => {
                eprintln!("worker thread ended abnormally");
                worker_panic = true;
                StopFlag::request_global();
            }
        }
    }

    // A finite quota the run never claimed is a loss, exactly like the reference: those attempts
    // were asked for and never completed, so the shared classification reports an echo failure even
    // when the terminal cause was a worker or network failure. An unlimited run or a controlled stop
    // claims nothing extra.
    let unclaimed = statistics.unclaimed(options.echo_count, all_controlled);
    if unclaimed != 0 {
        statistics.lost = statistics.lost.saturating_add(unclaimed);
    }

    if options.stats {
        println!("{}", statistics.line("final"));
    }
    if worker_panic || worker_spawn_error {
        ExitCode::Internal
    } else {
        statistics.exit_code(all_controlled)
    }
}

#[cfg(test)]
mod tests {
    use super::{partition, worker_memory_share};

    #[test]
    fn sessions_are_partitioned_evenly() {
        assert_eq!(partition(1, 0), vec![1]);
        assert_eq!(partition(10, 0), vec![1; 10]);
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