//! The client binary's contract: the command line (switches, ranges, diagnostic tokens, usage
//! text) and the accounting helpers, in one place, mirroring the reference's single contract file.
//!
//! Reference implementation: echo-binary-contract-v1 (the C++ client).

/// Identifier of the frozen binary contract this file implements.
pub const CONTRACT_VERSION: &str = "echo-binary-contract-v1";

/// Diagnostic tokens that must follow "Invalid arguments: " on stderr.
pub mod token {
    pub const PROTOCOL_OPTION: &str = "protocol-option";
    pub const INVALID_NUMBER: &str = "invalid-number";
    pub const OUT_OF_RANGE: &str = "out-of-range";
    pub const UNKNOWN_SWITCH: &str = "unknown-switch";
    pub const UNEXPECTED_VALUE: &str = "unexpected-value";
    pub const MISSING_VALUE: &str = "missing-value";
    pub const CONFLICTING_PAYLOAD: &str = "conflicting-payload";
    pub const LOCAL_PORT_CONFLICT: &str = "local-port-conflict";
    pub const QUOTA_OVERFLOW: &str = "quota-overflow";
    pub const PAYLOAD_SIZE: &str = "payload-size";
    pub const MEMORY_CAPACITY: &str = "memory-capacity";
    pub const CQ_CAPACITY: &str = "cq-capacity";
    pub const MISSING_TARGET: &str = "missing-target";
    pub const MISSING_PROTOCOL: &str = "missing-protocol";
    pub const UNEXPECTED_TARGET: &str = "unexpected-target";
    pub const INVALID_UTF16: &str = "invalid-utf16";
}

/// Usage text, one entry per line; printed on stdout for a valid /h command line.
pub const USAGE: &[&str] = &[
    "Usage: rust-echo-client target /p tcp|udp [/r port] [/l port] [/n count] [/t seconds] [/i ms]",
    "       [/d text | /z bytes | /zt bytes] [/k depth] [/c sessions]",
    "       [/threads workers] [/w seconds] [/rc [seconds]] [/report seconds]",
    "       [/b bytes] [/cq capacity] [/memory bytes] [/q] [/stats] [/h]",
    "/n count: attempts per session; 0 means unlimited.",
    "/k depth: TCP requests in flight per session; UDP rejects /k.",
    "/threads 0: automatic workers, min(sessions, active processors, 64).",
    "/rc [seconds]: reconnect after failure; bare /rc means 1 second.",
    "/w 0: no run limit. /report 0: no periodic reports.",
    "/q suppresses the default final; /stats forces final; /h shows help.",
];

/// The usage text as the process prints it.
pub const HELP_TEXT: &str = concat!(
    "Usage: rust-echo-client target /p tcp|udp [/r port] [/l port] [/n count] [/t seconds] [/i ms]\n",
    "       [/d text | /z bytes | /zt bytes] [/k depth] [/c sessions]\n",
    "       [/threads workers] [/w seconds] [/rc [seconds]] [/report seconds]\n",
    "       [/b bytes] [/cq capacity] [/memory bytes] [/q] [/stats] [/h]\n",
    "/n count: attempts per session; 0 means unlimited.\n",
    "/k depth: TCP requests in flight per session; UDP rejects /k.\n",
    "/threads 0: automatic workers, min(sessions, active processors, 64).\n",
    "/rc [seconds]: reconnect after failure; bare /rc means 1 second.\n",
    "/w 0: no run limit. /report 0: no periodic reports.\n",
    "/q suppresses the default final; /stats forces final; /h shows help.\n",
);

pub fn help_text() -> &'static str {
    HELP_TEXT
}

use crate::types::{
    ArgumentError, MAXIMUM_SESSIONS, MAXIMUM_UDP_PAYLOAD_BYTES, Options, Pattern, Protocol,
};

pub fn checked_product(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)
}

pub fn unclaimed_echoes(limit: u64, claimed: u64, controlled_stop: bool) -> u64 {
    if controlled_stop || limit == 0 || claimed >= limit {
        0
    } else {
        limit - claimed
    }
}

pub fn classify_result(
    echoed: u64,
    corrupted: u64,
    lost: u64,
    _network_failures: u64,
    fatal: bool,
    controlled_stop: bool,
) -> crate::types::ExitCode {
    use crate::types::ExitCode;
    if fatal {
        return ExitCode::Internal;
    }
    if corrupted != 0 || lost != 0 {
        return ExitCode::EchoFailure;
    }
    if controlled_stop {
        return ExitCode::Success;
    }
    if echoed == 0 {
        ExitCode::Network
    } else {
        ExitCode::Success
    }
}

#[derive(Clone, Copy)]
enum ArgumentSource<'a> {
    Utf8(&'a str),
    Os(&'a std::ffi::OsStr),
    Wide(&'a [u16]),
}

#[derive(Clone, Copy)]
struct Argument<'a> {
    source: ArgumentSource<'a>,
    begin: usize,
    end: usize,
}

enum Units<'a> {
    Utf8(std::str::EncodeUtf16<'a>),
    Os(std::os::windows::ffi::EncodeWide<'a>),
    Wide(std::iter::Copied<std::slice::Iter<'a, u16>>),
}

impl Iterator for Units<'_> {
    type Item = u16;
    fn next(&mut self) -> Option<u16> {
        match self {
            Self::Utf8(value) => value.next(),
            Self::Os(value) => value.next(),
            Self::Wide(value) => value.next(),
        }
    }
}

impl<'a> Argument<'a> {
    fn new(source: ArgumentSource<'a>) -> Self {
        let mut value = Self {
            source,
            begin: 0,
            end: usize::MAX,
        };
        // CRT argv ends at the first NUL; keep the public adapters on that same contract.
        value.end = value.units().take_while(|unit| *unit != 0).count();
        value
    }
    fn units(self) -> impl Iterator<Item = u16> + 'a {
        use std::os::windows::ffi::OsStrExt;
        let units = match self.source {
            ArgumentSource::Utf8(value) => Units::Utf8(value.encode_utf16()),
            ArgumentSource::Os(value) => Units::Os(value.encode_wide()),
            ArgumentSource::Wide(value) => Units::Wide(value.iter().copied()),
        };
        units.skip(self.begin).take(self.end - self.begin)
    }
    fn len(self) -> usize {
        self.end - self.begin
    }
    fn is_empty(self) -> bool {
        self.len() == 0
    }
    fn from(self, begin: usize) -> Self {
        Self {
            begin: self.begin + begin,
            ..self
        }
    }
    fn to(self, end: usize) -> Self {
        Self {
            end: self.begin + end,
            ..self
        }
    }
    fn equal(self, text: &str) -> bool {
        self.units()
            .map(|unit| {
                if (65..=90).contains(&unit) {
                    unit + 32
                } else {
                    unit
                }
            })
            .eq(text.encode_utf16())
    }
    fn valid_utf16(self) -> bool {
        char::decode_utf16(self.units()).all(|value| value.is_ok())
    }
}

trait Arguments {
    fn len(&self) -> usize;
    fn argument(&self, index: usize) -> Argument<'_>;
}
impl Arguments for [String] {
    fn len(&self) -> usize {
        <[String]>::len(self)
    }
    fn argument(&self, index: usize) -> Argument<'_> {
        Argument::new(ArgumentSource::Utf8(&self[index]))
    }
}
impl Arguments for [std::ffi::OsString] {
    fn len(&self) -> usize {
        <[std::ffi::OsString]>::len(self)
    }
    fn argument(&self, index: usize) -> Argument<'_> {
        Argument::new(ArgumentSource::Os(&self[index]))
    }
}
impl Arguments for crate::native::NativeArguments {
    fn len(&self) -> usize {
        self.len()
    }
    fn argument(&self, index: usize) -> Argument<'_> {
        Argument::new(ArgumentSource::Wide(self.argument(index)))
    }
}

fn switch_offset(token: Argument<'_>) -> Option<usize> {
    let mut units = token.units();
    let first = units.next()?;
    let second = units.next()?;
    if first != u16::from(b'/') && first != u16::from(b'-') {
        return None;
    }
    let (offset, letter) =
        if token.len() > 2 && first == u16::from(b'-') && second == u16::from(b'-') {
            (2, units.next()?)
        } else {
            (1, second)
        };
    if (65..=90).contains(&letter) || (97..=122).contains(&letter) {
        Some(offset)
    } else {
        None
    }
}

fn numeric(value: Argument<'_>) -> Result<u64, ArgumentError> {
    if value.is_empty() {
        return Err(ArgumentError(token::INVALID_NUMBER));
    }
    value.units().try_fold(0u64, |number, unit| {
        let digit = unit
            .checked_sub(u16::from(b'0'))
            .filter(|digit| *digit <= 9)
            .ok_or(ArgumentError(token::INVALID_NUMBER))?;
        number
            .checked_mul(10)
            .and_then(|number| number.checked_add(u64::from(digit)))
            .ok_or(ArgumentError(token::INVALID_NUMBER))
    })
}

/// Strict parser: exactly one positional target host, mutually exclusive payload
/// switches, and cross rules (fixed local port requires one session and forbids
/// reconnects on TCP). /h never masks a malformed command line.
pub fn parse(arguments: &[String]) -> Result<Options, ArgumentError> {
    parse_impl(arguments)
}

/// Preserve the reference's token-consumption order even when Windows supplies unpaired UTF-16
/// surrogates. Invalid numeric/protocol values receive their normal value diagnostics; invalid
/// literal text is diagnosed after the same mandatory/cross-field rules as the reference.
pub fn parse_os(arguments: &[std::ffi::OsString]) -> Result<Options, ArgumentError> {
    parse_impl(arguments)
}

pub fn parse_native(arguments: &crate::native::NativeArguments) -> Result<Options, ArgumentError> {
    parse_impl(arguments)
}

fn parse_impl(arguments: &(impl Arguments + ?Sized)) -> Result<Options, ArgumentError> {
    if arguments.len() == 0 {
        return Err(ArgumentError("invalid parser arguments"));
    }
    let mut options = Options::default();
    let mut literal = false;
    let mut binary = false;
    let mut printable = false;
    let mut saw_pipeline = false;
    // A second positional is reported after the cross-field rules, exactly as the reference does,
    // so the worker split still wins when both are wrong.
    let mut saw_extra_target = false;
    let mut index = 1;
    while index < arguments.len() {
        let token = arguments.argument(index);
        if !token.valid_utf16() {
            return Err(ArgumentError(token::INVALID_UTF16));
        }
        index += 1;
        let Some(offset) = switch_offset(token) else {
            if !options.host.is_empty() {
                saw_extra_target = true;
                continue;
            }
            if token.is_empty() {
                return Err(ArgumentError(token::OUT_OF_RANGE));
            }
            if token.len() >= 256 {
                return Err(ArgumentError(token::OUT_OF_RANGE));
            }
            if !options.host.copy_units(token.units()) {
                return Err(ArgumentError(token::OUT_OF_RANGE));
            }
            continue;
        };
        let rest = token.from(offset);
        let separator = rest.units().position(|unit| unit == u16::from(b'='));
        let name_view = separator.map_or(rest, |position| rest.to(position));
        let inline = separator.map(|position| rest.from(position + 1));
        let name = [
            "q", "quiet", "stats", "h", "help", "p", "d", "r", "l", "n", "t", "i", "b", "k", "z",
            "zt", "w", "rc", "report", "c", "threads", "cq", "memory",
        ]
        .into_iter()
        .find(|name| name_view.equal(name))
        .ok_or(ArgumentError(token::UNKNOWN_SWITCH))?;
        if matches!(name, "q" | "quiet" | "stats" | "h" | "help") {
            if inline.is_some() {
                // A flag never takes a value, and an empty one is still a value.
                return Err(ArgumentError(token::UNEXPECTED_VALUE));
            }
            match name {
                "q" | "quiet" => options.quiet = true,
                "stats" => options.stats = true,
                _ => options.help = true,
            }
            continue;
        }
        if name == "rc" && inline.is_none() {
            let next_is_value =
                index < arguments.len() && switch_offset(arguments.argument(index)).is_none();
            if !next_is_value {
                options.reconnect_seconds = Some(1);
                continue;
            }
        }
        if !matches!(
            name,
            "p" | "d"
                | "r"
                | "l"
                | "n"
                | "t"
                | "i"
                | "b"
                | "k"
                | "z"
                | "zt"
                | "w"
                | "rc"
                | "report"
                | "c"
                | "threads"
                | "cq"
                | "memory"
        ) {
            return Err(ArgumentError(token::UNKNOWN_SWITCH));
        }
        let value = match inline {
            Some(value) if !value.is_empty() => value,
            Some(_) => return Err(ArgumentError(token::MISSING_VALUE)),
            None => {
                if index >= arguments.len()
                    || arguments.argument(index).is_empty()
                    || switch_offset(arguments.argument(index)).is_some()
                {
                    return Err(ArgumentError(token::MISSING_VALUE));
                }
                let value = arguments.argument(index);
                index += 1;
                value
            }
        };
        if name == "p" {
            // The reference matches the protocol keyword itself and reports the parse failure as
            // an out-of-range value, not as a protocol-specific message.
            options.protocol = if value.equal("tcp") {
                Protocol::Tcp
            } else if value.equal("udp") {
                Protocol::Udp
            } else {
                return Err(ArgumentError(token::OUT_OF_RANGE));
            };
            continue;
        }
        if name == "d" || name == "z" || name == "zt" {
            let number = if name == "d" { 0 } else { numeric(value)? };
            if name != "d" {
                if number == 0 || number > crate::types::MAXIMUM_TCP_BATCH_BYTES {
                    return Err(ArgumentError(token::OUT_OF_RANGE));
                }
            }
            match name {
                "d" => {
                    if value.len() >= 32_768 {
                        return Err(ArgumentError(token::OUT_OF_RANGE));
                    }
                    literal = true;
                    options.pattern = Pattern::LiteralText;
                    if !options.literal_pattern.copy_units(value.units()) {
                        return Err(ArgumentError(token::OUT_OF_RANGE));
                    }
                }
                "z" => {
                    binary = true;
                    options.pattern = Pattern::BinaryCounter;
                    options.pattern_bytes = number as u32;
                }
                _ => {
                    printable = true;
                    options.pattern = Pattern::PrintableCounter;
                    options.pattern_bytes = number as u32;
                }
            }
            continue;
        }
        let number = numeric(value)?;
        let range = match name {
            // /n allows 0, which means "unlimited echoes".
            "n" => 0..=u64::MAX,
            "r" => 1..=65_535,
            "l" => 0..=65_535,
            "t" => 1..=u64::from(u32::MAX),
            "i" | "report" | "w" => 0..=u64::from(u32::MAX),
            "rc" => 0..=u64::from(u32::MAX),
            "b" => 0..=2_147_483_647,
            "k" => 1..=65_536,
            "c" => 1..=u64::from(MAXIMUM_SESSIONS),
            "threads" => 0..=64,
            "cq" => 64..=1_048_576,
            _ => 1_048_576..=u64::MAX,
        };
        if !range.contains(&number) {
            return Err(ArgumentError(token::OUT_OF_RANGE));
        }
        match name {
            "r" => options.remote_port = number as u16,
            "l" => options.local_port = number as u16,
            "n" => options.echo_count = number,
            "t" => options.timeout_seconds = number as u32,
            "i" => options.interval_milliseconds = number as u32,
            "b" => options.socket_buffer_bytes = number as u32,
            "k" => {
                saw_pipeline = true;
                options.pipeline_depth = number as u32;
            }
            "w" => options.run_seconds = number as u32,
            "rc" => options.reconnect_seconds = Some(number as u32),
            "report" => options.report_seconds = number as u32,
            "c" => options.session_count = number as u32,
            "threads" => options.worker_count = number as u32,
            "cq" => options.cq_capacity = number as u32,
            _ => options.memory_bytes = number,
        }
    }
    // The worker split is validated before the mandatory arguments, which is why
    // `/c 1 /threads 2` reports out-of-range and not missing-target.
    if options.worker_count > options.session_count {
        return Err(ArgumentError(token::OUT_OF_RANGE));
    }
    // /h suppresses only the two mandatory-argument checks. Every other rule, including the
    // capacity budgets, still applies exactly as it does without /h.
    // The baseline reports the missing target first and the missing protocol second, so a bare
    // invocation and a host-only invocation produce different diagnostics.
    if !options.help && options.host.is_empty() {
        return Err(ArgumentError(token::MISSING_TARGET));
    }
    if saw_extra_target {
        return Err(ArgumentError(token::UNEXPECTED_TARGET));
    }
    if !options.help && options.protocol == Protocol::None {
        return Err(ArgumentError(token::MISSING_PROTOCOL));
    }
    // The target is not required to be a literal: the reference resolves it with GetAddrInfoW
    // after parsing, so a name is accepted here and an unresolvable one is a network failure
    // rather than a usage error.
    let payload_switches = [literal, binary, printable]
        .iter()
        .filter(|flag| **flag)
        .count();
    if payload_switches > 1 {
        return Err(ArgumentError(token::CONFLICTING_PAYLOAD));
    }
    if options.protocol == Protocol::Udp && saw_pipeline {
        return Err(ArgumentError(token::PROTOCOL_OPTION));
    }
    if options.local_port != 0
        && (options.session_count != 1
            || (options.protocol == Protocol::Tcp && options.reconnect_seconds.is_some()))
    {
        return Err(ArgumentError(token::LOCAL_PORT_CONFLICT));
    }
    // The run the command line describes may not exceed the quota the engine can represent.
    if options.session_count != 0
        && options.echo_count > u64::MAX / u64::from(options.session_count)
    {
        return Err(ArgumentError(token::QUOTA_OVERFLOW));
    }
    // The effective payload length is known before any session exists: the counter payloads carry
    // their own /z or /zt length, while the literal and default texts are measured in UTF-8 bytes
    // exactly as the reference measures them through WideCharToMultiByte.
    let pattern_bytes = match options.pattern {
        Pattern::BinaryCounter | Pattern::PrintableCounter => u64::from(options.pattern_bytes),
        Pattern::LiteralText => options
            .literal_pattern
            .utf8_bytes()
            .ok_or(ArgumentError(token::INVALID_UTF16))? as u64,
        Pattern::DefaultText => {
            if options.host.is_empty() {
                0
            } else {
                (crate::payload::DEFAULT_TEXT_PREFIX.len()
                    + options
                        .host
                        .utf8_bytes()
                        .ok_or(ArgumentError(token::INVALID_UTF16))?) as u64
            }
        }
    };
    if options.protocol == Protocol::Udp && pattern_bytes > MAXIMUM_UDP_PAYLOAD_BYTES {
        return Err(ArgumentError(token::PAYLOAD_SIZE));
    }
    // Nothing else can be validated without a protocol, which is how /h alone succeeds.
    if options.protocol == Protocol::None {
        return Ok(options);
    }
    // Capacity rules, validated here in the parser exactly like the reference: each worker owns its own
    // CQ and its own registered arena, so the largest shard decides both budgets, and both failures are
    // reported before any Winsock call is made.
    let workers = crate::types::resolved_worker_count(
        options.worker_count,
        crate::types::available_processors(),
    )
    .min(options.session_count)
    .max(1);
    let shard = u64::from(options.session_count).div_ceil(u64::from(workers));
    if pattern_bytes != 0 {
        let Some(batch) = pattern_bytes
            .checked_mul(u64::from(options.pipeline_depth))
            .filter(|bytes| *bytes <= crate::types::MAXIMUM_TCP_BATCH_BYTES)
        else {
            return Err(ArgumentError(token::PAYLOAD_SIZE));
        };
        let storage = batch
            .checked_mul(u64::from(options.session_count))
            .and_then(|one_direction| one_direction.checked_mul(2));
        let per_worker = batch
            .checked_mul(2)
            .and_then(|per_session| per_session.checked_mul(shard));
        match (storage, per_worker) {
            (Some(storage), Some(per_worker))
                if storage <= options.memory_bytes && per_worker <= u64::from(u32::MAX) => {}
            _ => return Err(ArgumentError(token::MEMORY_CAPACITY)),
        }
    }
    // One attempt is one receive plus one send whatever /k is, so the largest shard reserves exactly
    // two operations per session against the completion queue.
    match shard.checked_mul(2) {
        Some(reserved) if reserved <= u64::from(options.cq_capacity) => {}
        _ => return Err(ArgumentError(token::CQ_CAPACITY)),
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        std::iter::once("rust-echo-client".to_string())
            .chain(values.iter().map(|value| value.to_string()))
            .collect()
    }

    #[test]
    fn capacity_rules_match_the_reference() {
        // Measured against the reference: it rejects the first (storage) and accepts the other two.
        let args = |extra: &[&str]| {
            let mut list: Vec<String> = ["client", "127.0.0.1", "/p", "tcp", "/r", "9"]
                .iter()
                .map(|value| value.to_string())
                .collect();
            list.extend(extra.iter().map(|value| value.to_string()));
            list
        };
        assert!(
            parse(&args(&[
                "/c", "1", "/k", "2", "/z", "300000", "/memory", "1048576"
            ]))
            .is_err()
        );
        assert!(
            parse(&args(&[
                "/c", "1", "/k", "2", "/z", "300000", "/memory", "2097152"
            ]))
            .is_ok()
        );
        assert!(
            parse(&args(&[
                "/c", "64", "/threads", "2", "/k", "1", "/cq", "64"
            ]))
            .is_ok()
        );
        assert!(parse(&args(&["/c", "1", "/k", "64", "/cq", "64", "/z", "1"])).is_ok());
    }

    #[test]
    fn defaults_match_the_baseline() {
        let options = parse(&args(&["127.0.0.1", "/p", "tcp"])).expect("valid");
        assert_eq!(options.host, "127.0.0.1");
        assert_eq!(options.remote_port, 7);
        assert_eq!(options.echo_count, 5);
        assert_eq!(options.timeout_seconds, 5);
        assert_eq!(options.pipeline_depth, 1);
        assert_eq!(options.session_count, 1);
        assert_eq!(options.reconnect_seconds, None);
        assert_eq!(options.cq_capacity, 4_096);
    }

    #[test]
    fn switch_forms_and_case_are_accepted() {
        let options =
            parse(&args(&["127.0.0.1", "--p=UDP", "-R", "7000", "/n", "0"])).expect("valid");
        assert_eq!(options.protocol, Protocol::Udp);
        assert_eq!(options.remote_port, 7000);
        assert_eq!(options.echo_count, 0);
        let reconnect = parse(&args(&["127.0.0.1", "/p", "udp", "/rc"])).expect("valid");
        assert_eq!(reconnect.reconnect_seconds, Some(1));
    }

    fn error_token(arguments: &[&str]) -> &'static str {
        parse(&args(arguments))
            .expect_err("expected a rejected command line")
            .0
    }

    #[test]
    fn zero_run_duration_and_worker_count_are_valid() {
        let parsed = parse(&args(&[
            "localhost",
            "/p",
            "tcp",
            "/w",
            "0",
            "/threads",
            "0",
        ]))
        .expect("zero disables the deadline and selects automatic workers");
        assert_eq!(parsed.run_seconds, 0);
        assert_eq!(parsed.worker_count, 0);
    }

    #[test]
    fn decimal_numbers_reject_signs_and_counter_limits_apply_without_a_protocol() {
        assert_eq!(error_token(&["/h", "/n", "+1"]), token::INVALID_NUMBER);
        assert_eq!(
            error_token(&["/h", "/n", "18446744073709551616"]),
            token::INVALID_NUMBER
        );
        assert_eq!(error_token(&["/h", "/z", "67108865"]), token::OUT_OF_RANGE);
        assert_eq!(error_token(&["/h", "/zt", "67108865"]), token::OUT_OF_RANGE);
    }

    #[test]
    fn text_capacity_is_measured_in_utf16_units() {
        let mut values = args(&["/h"]);
        values.push("界".repeat(255));
        assert!(parse(&values).is_ok());
        values[2] = "界".repeat(256);
        assert_eq!(parse(&values).unwrap_err().0, token::OUT_OF_RANGE);
        values[2] = "😀".repeat(128);
        assert_eq!(parse(&values).unwrap_err().0, token::OUT_OF_RANGE);
        let mut values = args(&["/h", "/d"]);
        values.push("界".repeat(32_767));
        assert!(parse(&values).is_ok());
        values[3].push('界');
        assert_eq!(parse(&values).unwrap_err().0, token::OUT_OF_RANGE);
        assert_eq!(error_token(&[""]), token::OUT_OF_RANGE);
    }

    #[test]
    fn cross_field_diagnostic_precedence_matches_the_reference() {
        assert_eq!(
            error_token(&["/p", "udp", "/k", "1"]),
            token::MISSING_TARGET
        );
        assert_eq!(
            error_token(&["/h", "/p", "udp", "/k", "1", "/threads", "2"]),
            token::OUT_OF_RANGE
        );
        assert_eq!(
            error_token(&["/h", "/p", "udp", "/k", "1", "/d", "x", "/z", "1"]),
            token::CONFLICTING_PAYLOAD
        );
        assert!(parse(&args(&["localhost", "/p", "udp", "/k", "1", "/p", "tcp"])).is_ok());
    }

    /// Every case below is a measured reference diagnostic, so the tokens are the contract rather
    /// than a paraphrase of it.
    #[test]
    fn diagnostics_use_the_reference_tokens() {
        assert_eq!(error_token(&[]), token::MISSING_TARGET);
        assert_eq!(error_token(&["127.0.0.1"]), token::MISSING_PROTOCOL);
        assert_eq!(error_token(&["/p", "tcp"]), token::MISSING_TARGET);
        assert_eq!(
            error_token(&["127.0.0.1", "127.0.0.2", "/p", "tcp"]),
            token::UNEXPECTED_TARGET
        );
        assert_eq!(
            error_token(&["/c", "1", "/threads", "2", "/p", "tcp"]),
            token::OUT_OF_RANGE
        );
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "tcp", "/d", "x", "/z", "8"]),
            token::CONFLICTING_PAYLOAD
        );
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "udp", "/k", "1"]),
            token::PROTOCOL_OPTION
        );
        // The switch was supplied even though its value is the default, which is what the
        // reference keys on.
        assert_eq!(
            error_token(&["127.0.0.1", "/k", "1", "/p", "udp"]),
            token::PROTOCOL_OPTION
        );
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "tcp", "/l", "7000", "/c", "2"]),
            token::LOCAL_PORT_CONFLICT
        );
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "tcp", "/l", "7000", "/rc", "1"]),
            token::LOCAL_PORT_CONFLICT
        );
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "udp", "/z", "65508"]),
            token::PAYLOAD_SIZE
        );
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "tcp", "/k", "65536", "/z", "65536"]),
            token::PAYLOAD_SIZE
        );
        assert_eq!(
            error_token(&[
                "127.0.0.1",
                "/p",
                "tcp",
                "/n",
                "18446744073709551615",
                "/c",
                "1048576"
            ]),
            token::QUOTA_OVERFLOW
        );
        assert_eq!(
            error_token(&[
                "127.0.0.1",
                "/p",
                "tcp",
                "/c",
                "200",
                "/threads",
                "4",
                "/cq",
                "64"
            ]),
            token::CQ_CAPACITY
        );
        assert_eq!(
            error_token(&[
                "127.0.0.1",
                "/p",
                "tcp",
                "/k",
                "2",
                "/z",
                "300000",
                "/memory",
                "1048576"
            ]),
            token::MEMORY_CAPACITY
        );
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "sctp"]),
            token::OUT_OF_RANGE
        );
        assert_eq!(error_token(&["/q=1"]), token::UNEXPECTED_VALUE);
        assert_eq!(error_token(&["/r="]), token::MISSING_VALUE);
        assert_eq!(error_token(&["/r"]), token::MISSING_VALUE);
        assert_eq!(error_token(&["/b=x"]), token::INVALID_NUMBER);
        assert_eq!(error_token(&["/zzz"]), token::UNKNOWN_SWITCH);
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "tcp", "/k", "0"]),
            token::OUT_OF_RANGE
        );
        assert_eq!(
            error_token(&["127.0.0.1", "/p", "tcp", "/cq", "63"]),
            token::OUT_OF_RANGE
        );
        // /h suppresses only the mandatory arguments; the budgets still apply.
        assert_eq!(
            error_token(&["/h", "/p", "tcp", "/c", "200", "/threads", "4", "/cq", "64"]),
            token::CQ_CAPACITY
        );
        assert_eq!(
            error_token(&["/h", "/d", "x", "/z", "8"]),
            token::CONFLICTING_PAYLOAD
        );
        assert!(parse(&args(&["/h", "/p", "tcp", "/n", "1", "/d", "x"])).is_ok());
    }

    #[test]
    fn strict_errors_are_reported() {
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/n"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "sctp"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/q=1"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "second-host"])).is_err());
        assert!(parse(&args(&["/p", "tcp"])).is_err());
        // A name is a legal target: resolution, not parsing, decides whether it works.
        assert!(parse(&args(&["localhost", "/p", "tcp"])).is_ok());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/d", "x", "/z", "16"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/l", "7001", "/c", "2"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/l", "7001", "/rc", "1"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "udp", "/z", "70000"])).is_err());
    }

    #[test]
    fn storage_budget_and_classification() {
        // The capacity rules are exercised through the parser instead: see
        // capacity_rules_match_the_reference.
        assert_eq!(unclaimed_echoes(5, 3, false), 2);
        assert_eq!(unclaimed_echoes(5, 3, true), 0);
        assert_eq!(
            classify_result(5, 0, 0, 0, false, false),
            crate::types::ExitCode::Success
        );
        assert_eq!(
            classify_result(0, 0, 0, 0, false, false),
            crate::types::ExitCode::Network
        );
        assert_eq!(
            classify_result(1, 0, 1, 0, false, false),
            crate::types::ExitCode::EchoFailure
        );
        assert_eq!(
            classify_result(5, 0, 0, 1, false, false),
            crate::types::ExitCode::Success
        );
    }
}
