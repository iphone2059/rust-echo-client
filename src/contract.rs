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
}

/// Usage text, one entry per line; printed on stdout for a valid /h command line.
pub const USAGE: &[&str] = &[
    "Usage: rust-echo-client <IPv4-address> /p tcp|udp [/r port] [/l port] [/n count]",
    "       [/t seconds] [/i ms] [/d text | /z bytes | /zt bytes] [/k tcp-depth]",
    "       [/c sessions] [/threads workers] [/w seconds] [/rc [seconds]]",
    "       [/report seconds] [/b bytes] [/cq capacity] [/memory bytes] [/q] [/stats]",
    "Data I/O is always RIO; CQ notification is always IOCP. No fallback backend exists.",
    "Each worker requires CQ >= sessions*(1+/k) and registered memory >= sessions*(1+/k)*payload.",
];

/// The usage text as the process prints it.
pub fn help_text() -> String {
    USAGE.join("\n")
}

use crate::types::{
    ArgumentError, Options, Pattern, Protocol, MAXIMUM_SESSIONS, MAXIMUM_UDP_PAYLOAD_BYTES,
};

pub fn checked_product(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)
}

/// Registered-memory budget for the rewritten RIO layout. Every session owns one payload-
/// sized RX slice and `/k` independent TX registrations, each one payload wide.
pub fn checked_registered_storage_bytes(
    sessions: u64,
    pipeline_depth: u64,
    payload_bytes: u64,
    memory_limit: u64,
) -> Option<u64> {
    if sessions == 0 || pipeline_depth == 0 || payload_bytes == 0 {
        return None;
    }
    let slots_per_session = pipeline_depth.checked_add(1)?;
    let slots = sessions.checked_mul(slots_per_session)?;
    slots
        .checked_mul(payload_bytes)
        .filter(|bytes| *bytes <= memory_limit)
}

pub fn unclaimed_echoes(limit: u64, claimed: u64, controlled_stop: bool) -> u64 {
    if controlled_stop || limit == 0 || claimed >= limit { 0 } else { limit - claimed }
}

pub fn classify_result(
    echoed: u64,
    corrupted: u64,
    lost: u64,
    network_failures: u64,
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
    if network_failures != 0 {
        return ExitCode::Network;
    }
    if controlled_stop {
        return ExitCode::Success;
    }
    if echoed == 0 { ExitCode::Network } else { ExitCode::Success }
}

fn switch_offset(token: &str) -> Option<usize> {
    let bytes = token.as_bytes();
    if bytes.len() < 2 || (bytes[0] != b'/' && bytes[0] != b'-') {
        return None;
    }
    let offset = if bytes.len() > 2 && bytes[0] == b'-' && bytes[1] == b'-' { 2 } else { 1 };
    let first = bytes[offset].to_ascii_lowercase();
    if first.is_ascii_lowercase() { Some(offset) } else { None }
}

fn numeric(value: &str) -> Result<u64, ArgumentError> {
    value
        .parse::<u64>()
        .map_err(|_| ArgumentError(token::INVALID_NUMBER.to_string()))
}

/// Strict parser: exactly one positional target host, mutually exclusive payload
/// switches, and cross rules (fixed local port requires one session and forbids
/// reconnects on TCP). /h never masks a malformed command line.
pub fn parse(arguments: &[String]) -> Result<Options, ArgumentError> {
    if arguments.is_empty() {
        return Err(ArgumentError("invalid parser arguments".to_string()));
    }
    let mut options = Options::default();
    let mut literal = false;
    let mut binary = false;
    let mut printable = false;
    let mut index = 1;
    while index < arguments.len() {
        let token = arguments[index].clone();
        index += 1;
        let Some(offset) = switch_offset(&token) else {
            if !options.host.is_empty() || token.is_empty() {
                return Err(ArgumentError(
                    "client requires exactly one valid target host".to_string(),
                ));
            }
            if token.len() >= 256 {
                return Err(ArgumentError("target host is too long".to_string()));
            }
            options.host = token;
            continue;
        };
        let rest = &token[offset..];
        let (name, inline) = match rest.split_once('=') {
            Some((_name, value)) if value.is_empty() => {
                return Err(ArgumentError("switch requires a non-empty inline value".to_string()));
            }
            Some((name, value)) => (name.to_ascii_lowercase(), Some(value.to_string())),
            None => (rest.to_ascii_lowercase(), None),
        };
        if matches!(name.as_str(), "q" | "quiet" | "stats" | "h" | "help") {
            if inline.is_some() {
                return Err(ArgumentError("flag switch does not accept a value".to_string()));
            }
            match name.as_str() {
                "q" | "quiet" => options.quiet = true,
                "stats" => options.stats = true,
                _ => options.help = true,
            }
            continue;
        }
        if name == "rc" && inline.is_none() {
            let next_is_value = index < arguments.len() && switch_offset(&arguments[index]).is_none();
            if !next_is_value {
                options.reconnect_seconds = Some(1);
                continue;
            }
        }
        if !matches!(
            name.as_str(),
            "p" | "d" | "r" | "l" | "n" | "t" | "i" | "b" | "k" | "z" | "zt" | "w" | "rc"
                | "report" | "c" | "threads" | "cq" | "memory"
        ) {
            return Err(ArgumentError(token::UNKNOWN_SWITCH.to_string()));
        }
        let value = match inline {
            Some(value) => value,
            None => {
                if index >= arguments.len()
                    || arguments[index].is_empty()
                    || switch_offset(&arguments[index]).is_some()
                {
                    return Err(ArgumentError("switch requires a non-empty value".to_string()));
                }
                let value = arguments[index].clone();
                index += 1;
                value
            }
        };
        if name == "p" {
            options.protocol = match value.to_ascii_lowercase().as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => return Err(ArgumentError("/p requires tcp or udp".to_string())),
            };
            continue;
        }
        if name == "d" || name == "z" || name == "zt" {
            let number = if name == "d" { 0 } else { numeric(&value)? };
            if name != "d" {
                if number == 0 || number > MAXIMUM_UDP_PAYLOAD_BYTES.max(u64::from(u32::MAX)) {
                    return Err(ArgumentError(token::OUT_OF_RANGE.to_string()));
                }
            }
            match name.as_str() {
                "d" => {
                    literal = true;
                    options.pattern = Pattern::LiteralText;
                    options.literal_pattern = value;
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
        let number = numeric(&value)?;
        let range = match name.as_str() {
            // /n allows 0, which means "unlimited echoes".
            "n" => 0..=u64::MAX,
            "r" => 1..=65_535,
            "l" => 0..=65_535,
            "t" | "w" => 1..=u64::from(u32::MAX),
            "i" | "report" => 0..=u64::from(u32::MAX),
            "rc" => 0..=u64::from(u32::MAX),
            "b" => 0..=2_147_483_647,
            "k" => 1..=65_536,
            "c" => 1..=u64::from(MAXIMUM_SESSIONS),
            "threads" => 1..=64,
            "cq" => 64..=1_048_576,
            _ => 1_048_576..=u64::MAX,
        };
        if !range.contains(&number) {
            return Err(ArgumentError(token::OUT_OF_RANGE.to_string()));
        }
        match name.as_str() {
            "r" => options.remote_port = number as u16,
            "l" => options.local_port = number as u16,
            "n" => options.echo_count = number,
            "t" => options.timeout_seconds = number as u32,
            "i" => options.interval_milliseconds = number as u32,
            "b" => options.socket_buffer_bytes = number as u32,
            "k" => {
                // /k is the TCP pipeline depth. The datagram path has no equivalent, and the
                // baseline clients reject the switch outright for UDP, so accepting it here
                // would silently diverge.
                if options.protocol == Protocol::Udp {
                    return Err(ArgumentError(token::PROTOCOL_OPTION.to_string()));
                }
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
    // The datagram path has no /k; a /k that appeared before /p udp is rejected here, before the
    // help short-circuit, so the diagnostic does not depend on the order of the switches.
    if options.protocol == Protocol::Udp && options.pipeline_depth != 1 {
        return Err(ArgumentError(token::PROTOCOL_OPTION.to_string()));
    }
    if options.help {
        return Ok(options);
    }
    // The baseline reports the missing target first and the missing protocol second, so a bare
    // invocation and a host-only invocation produce different diagnostics.
    if options.host.is_empty() {
        return Err(ArgumentError("missing-target".to_string()));
    }
    if options.protocol == Protocol::None {
        return Err(ArgumentError("missing-protocol".to_string()));
    }
    if options.host.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(ArgumentError(
            "target must be an IPv4 address literal".to_string(),
        ));
    }
    let payload_switches = [literal, binary, printable].iter().filter(|flag| **flag).count();
    if payload_switches > 1 {
        return Err(ArgumentError(
            "/d, /z and /zt are mutually exclusive".to_string(),
        ));
    }
    if options.local_port != 0 && options.session_count != 1 {
        return Err(ArgumentError("a fixed local port requires /c 1".to_string()));
    }
    if options.local_port != 0 && options.protocol == Protocol::Tcp && options.reconnect_seconds.is_some() {
        return Err(ArgumentError(
            "TCP fixed local port does not allow /rc".to_string(),
        ));
    }
    if options.protocol == Protocol::Udp && u64::from(options.pattern_bytes) > MAXIMUM_UDP_PAYLOAD_BYTES
    {
        return Err(ArgumentError("UDP payload exceeds 65507 bytes".to_string()));
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
        let options = parse(&args(&["127.0.0.1", "--p=UDP", "-R", "7000", "/n", "0"]))
            .expect("valid");
        assert_eq!(options.protocol, Protocol::Udp);
        assert_eq!(options.remote_port, 7000);
        assert_eq!(options.echo_count, 0);
        let reconnect = parse(&args(&["127.0.0.1", "/p", "udp", "/rc"])).expect("valid");
        assert_eq!(reconnect.reconnect_seconds, Some(1));
    }

    #[test]
    fn strict_errors_are_reported() {
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/n"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "sctp"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/q=1"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "second-host"])).is_err());
        assert!(parse(&args(&["/p", "tcp"])).is_err());
        assert!(parse(&args(&["localhost", "/p", "tcp"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/d", "x", "/z", "16"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/l", "7001", "/c", "2"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "tcp", "/l", "7001", "/rc", "1"])).is_err());
        assert!(parse(&args(&["127.0.0.1", "/p", "udp", "/z", "70000"])).is_err());
    }

    #[test]
    fn storage_budget_and_classification() {
        assert_eq!(checked_registered_storage_bytes(8, 2, 4_096, u64::MAX), Some(98_304));
        assert_eq!(checked_registered_storage_bytes(8, 2, 4_096, 1_000), None);
        assert_eq!(checked_registered_storage_bytes(0, 1, 16, u64::MAX), None);
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
            crate::types::ExitCode::Network
        );
    }
}