//! Shared client vocabulary: protocol, exit codes, payload mode and options.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    None,
    Tcp,
    Udp,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    Usage = 1,
    Network = 2,
    EchoFailure = 3,
    Internal = 4,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pattern {
    /// "echo from <host>" (the baseline default payload).
    DefaultText,
    LiteralText,
    BinaryCounter,
    PrintableCounter,
}

#[derive(Clone, Debug)]
pub struct ArgumentError(pub String);

pub const DEFAULT_REMOTE_PORT: u16 = 7;
pub const DEFAULT_ECHO_COUNT: u64 = 5;
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 5;
pub const DEFAULT_CQ_CAPACITY: u32 = 4_096;
pub const DEFAULT_MEMORY_BYTES: u64 = 1_073_741_824;
pub const MAXIMUM_TCP_BATCH_BYTES: u64 = 67_108_864;
pub const MAXIMUM_UDP_PAYLOAD_BYTES: u64 = 65_507;
pub const MAXIMUM_SESSIONS: u32 = 1_048_576;

#[derive(Clone, Debug)]
pub struct Options {
    pub protocol: Protocol,
    pub host: String,
    pub pattern: Pattern,
    pub literal_pattern: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub echo_count: u64,
    pub timeout_seconds: u32,
    pub interval_milliseconds: u32,
    pub pattern_bytes: u32,
    pub pipeline_depth: u32,
    pub session_count: u32,
    pub worker_count: u32,
    pub run_seconds: u32,
    /// None disables reconnects; Some(delay) reschedules a failed session after the old
    /// transport generation has completely drained.
    pub reconnect_seconds: Option<u32>,
    pub report_seconds: u32,
    pub socket_buffer_bytes: u32,
    pub cq_capacity: u32,
    pub memory_bytes: u64,
    pub quiet: bool,
    pub stats: bool,
    pub help: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            protocol: Protocol::None,
            host: String::new(),
            pattern: Pattern::DefaultText,
            literal_pattern: String::new(),
            remote_port: DEFAULT_REMOTE_PORT,
            local_port: 0,
            echo_count: DEFAULT_ECHO_COUNT,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            interval_milliseconds: 0,
            pattern_bytes: 0,
            pipeline_depth: 1,
            session_count: 1,
            worker_count: 0,
            run_seconds: 0,
            reconnect_seconds: None,
            report_seconds: 0,
            socket_buffer_bytes: 0,
            cq_capacity: DEFAULT_CQ_CAPACITY,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            quiet: false,
            stats: false,
            help: false,
        }
    }
}

/// Automatic worker count is the active processor count, clamped to this cap, mirroring the
/// reference's CEC_MAX_WORKERS.
pub const AUTOMATIC_WORKER_CAP: u32 = 64;

/// Resolves /threads, or the automatic count when it is absent, exactly like the reference: the
/// processor count is clamped to [1, 64] and the caller then takes the smaller of that and the
/// session count. The processor count is passed in so the rule is testable without the machine.
pub fn resolved_worker_count(worker_count: u32, processors: u32) -> u32 {
    if worker_count != 0 {
        return worker_count;
    }
    processors.clamp(1, AUTOMATIC_WORKER_CAP)
}

/// Active processors across all processor groups, matching the Windows reference.
pub fn available_processors() -> u32 {
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn GetActiveProcessorCount(group_number: u16) -> u32;
    }
    unsafe { GetActiveProcessorCount(u16::MAX) }
}

/// Failure metadata shared by pure engines and their runtimes. Native ownership faults are fatal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureClass {
    Network,
    Invariant,
    DrainTimeout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureDomain {
    Win32,
    Winsock,
    Allocation,
    Invariant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub classification: FailureClass,
    pub domain: FailureDomain,
    pub stage: &'static str,
    pub code: i32,
}

impl Failure {
    pub const fn invariant(stage: &'static str) -> Self {
        Self {
            classification: FailureClass::Invariant,
            domain: FailureDomain::Invariant,
            stage,
            code: 13,
        }
    }
    pub const fn timeout(stage: &'static str) -> Self {
        Self {
            classification: FailureClass::DrainTimeout,
            domain: FailureDomain::Win32,
            stage,
            code: 1460,
        }
    }
}

/// Pure clock conversions: timer decisions depend only on the supplied counter frequency.
pub(crate) fn milliseconds_to_ticks(milliseconds: u64, frequency: u64) -> u64 {
    if let Some(scaled) = milliseconds.checked_mul(frequency) {
        scaled.div_ceil(1_000)
    } else {
        (u128::from(milliseconds) * u128::from(frequency))
            .div_ceil(1_000)
            .min(u128::from(u64::MAX)) as u64
    }
}
pub(crate) fn ticks_to_wait_milliseconds(ticks: u64, frequency: u64) -> u64 {
    if let Some(scaled) = ticks.checked_mul(1_000) {
        scaled.div_ceil(frequency)
    } else {
        (u128::from(ticks) * 1_000)
            .div_ceil(u128::from(frequency))
            .min(u128::from(u64::MAX)) as u64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecyclePhase {
    Running,
    Draining,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lifecycle {
    pub phase: LifecyclePhase,
    pub total_outstanding: u32,
    pub rio_outstanding: u32,
    pub notification_armed: bool,
    pub releasable: bool,
}
