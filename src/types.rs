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
pub struct ArgumentError(pub &'static str);

/// The reference keeps command-line text in fixed UTF-16 arrays. No parser or worker copy
/// allocates, and the trailing zero is always present for the native resolver.
#[derive(Clone)]
pub struct OptionText<const CAPACITY: usize> {
    units: [u16; CAPACITY],
    length: usize,
}

impl<const CAPACITY: usize> Default for OptionText<CAPACITY> {
    fn default() -> Self {
        Self {
            units: [0; CAPACITY],
            length: 0,
        }
    }
}

impl<const CAPACITY: usize> OptionText<CAPACITY> {
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn as_units(&self) -> &[u16] {
        &self.units[..self.length]
    }
    pub(crate) fn as_ptr(&self) -> *const u16 {
        self.units.as_ptr()
    }

    pub(crate) fn copy_units(&mut self, units: impl Iterator<Item = u16>) -> bool {
        self.length = 0;
        for unit in units {
            if self.length + 1 >= CAPACITY {
                return false;
            }
            self.units[self.length] = unit;
            self.length += 1;
        }
        self.units[self.length] = 0;
        self.length != 0
    }

    pub(crate) fn utf8_bytes(&self) -> Option<usize> {
        char::decode_utf16(self.as_units().iter().copied()).try_fold(0usize, |length, value| {
            Some(length + value.ok()?.len_utf8())
        })
    }

    pub(crate) fn append_utf8(&self, output: &mut Vec<u8>) -> bool {
        for value in char::decode_utf16(self.as_units().iter().copied()) {
            let Ok(character) = value else {
                return false;
            };
            let mut bytes = [0u8; 4];
            output.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
        }
        true
    }
}

impl<const CAPACITY: usize> core::fmt::Debug for OptionText<CAPACITY> {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.debug_struct("OptionText")
            .field("units", &self.as_units())
            .finish()
    }
}

impl<const CAPACITY: usize> PartialEq<&str> for OptionText<CAPACITY> {
    fn eq(&self, text: &&str) -> bool {
        self.as_units().iter().copied().eq(text.encode_utf16())
    }
}

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
    pub host: OptionText<256>,
    pub pattern: Pattern,
    pub literal_pattern: OptionText<32_768>,
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
            host: OptionText::default(),
            pattern: Pattern::DefaultText,
            literal_pattern: OptionText::default(),
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
    pub const fn allocation(stage: &'static str) -> Self {
        Self {
            classification: FailureClass::Network,
            domain: FailureDomain::Allocation,
            stage,
            code: 8,
        }
    }
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

/// Fixed production storage: reserve before initializing so allocation failures stay reportable.
/// These helpers contain no native dependency and are usable by pure engines.
pub(crate) fn try_vec_with_capacity<T>(
    capacity: usize,
    stage: &'static str,
) -> Result<Vec<T>, Failure> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| Failure::allocation(stage))?;
    Ok(values)
}

pub(crate) fn try_vec_with<T>(
    count: usize,
    stage: &'static str,
    mut value: impl FnMut(usize) -> T,
) -> Result<Vec<T>, Failure> {
    let mut values = try_vec_with_capacity(count, stage)?;
    for index in 0..count {
        values.push(value(index));
    }
    Ok(values)
}

pub(crate) fn try_arc<T>(value: T, stage: &'static str) -> Result<std::sync::Arc<T>, Failure> {
    std::sync::Arc::try_new(value).map_err(|_| Failure::allocation(stage))
}

pub(crate) fn try_box<T>(value: T, stage: &'static str) -> Result<Box<T>, Failure> {
    Box::try_new(value).map_err(|_| Failure::allocation(stage))
}

#[cfg(test)]
mod allocation_tests {
    use super::*;
    #[test]
    fn reserved_storage_has_positive_and_overflow_controls() {
        let values = try_vec_with(3, "allocation probe", |index| index as u16).unwrap();
        assert_eq!(values.as_slice(), &[0, 1, 2]);
        assert_eq!(
            try_vec_with_capacity::<u16>(usize::MAX, "allocation probe").unwrap_err(),
            Failure::allocation("allocation probe")
        );
        let value = try_box(7u32, "allocation probe").unwrap();
        assert_eq!(*value, 7);
        let value = try_arc(9u32, "allocation probe").unwrap();
        assert_eq!(*value, 9);
    }
}
