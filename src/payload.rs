//! Echo payload construction and byte-exact verification, plus the run statistics the
//! exit code is derived from.

use crate::types::{
    ArgumentError, MAXIMUM_TCP_BATCH_BYTES, MAXIMUM_UDP_PAYLOAD_BYTES, Options, Pattern,
};

/// The default payload of the baseline: the literal text below, sent as ASCII.
pub const DEFAULT_TEXT_PREFIX: &str = "echo from ";

/// Payload validation and allocation remain separate error classes in production.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BuildError {
    Invalid(&'static str),
    // The C++ pattern builder returns null on OOM; its caller reports ERROR_INVALID_DATA.
    Allocation,
}

impl From<crate::types::Failure> for BuildError {
    fn from(_error: crate::types::Failure) -> Self {
        Self::Allocation
    }
}

fn compatibility_error(error: BuildError) -> ArgumentError {
    ArgumentError(match error {
        BuildError::Invalid(reason) => reason,
        BuildError::Allocation => "payload allocation failed",
    })
}

/// Cold compatibility entry point; production retains the structured allocation error.
pub fn build(options: &Options) -> Result<Vec<u8>, ArgumentError> {
    try_build(options).map_err(compatibility_error)
}

pub(crate) fn try_build(options: &Options) -> Result<Vec<u8>, BuildError> {
    use crate::types::try_vec_with_capacity;
    match options.pattern {
        Pattern::DefaultText => {
            let length = options
                .host
                .utf8_bytes()
                .ok_or(BuildError::Invalid("invalid UTF-16 payload"))?;
            let mut bytes = try_vec_with_capacity(
                DEFAULT_TEXT_PREFIX.len().saturating_add(length),
                "payload allocation",
            )?;
            bytes.extend_from_slice(DEFAULT_TEXT_PREFIX.as_bytes());
            if !options.host.append_utf8(&mut bytes) {
                return Err(BuildError::Invalid("invalid UTF-16 payload"));
            }
            Ok(bytes)
        }
        Pattern::LiteralText => {
            let length = options
                .literal_pattern
                .utf8_bytes()
                .ok_or(BuildError::Invalid("invalid UTF-16 payload"))?;
            let mut bytes = try_vec_with_capacity(length, "payload allocation")?;
            if !options.literal_pattern.append_utf8(&mut bytes) {
                return Err(BuildError::Invalid("invalid UTF-16 payload"));
            }
            Ok(bytes)
        }
        Pattern::BinaryCounter => try_binary_counter(options.pattern_bytes),
        Pattern::PrintableCounter => try_printable_counter(options.pattern_bytes),
    }
}

/// Deterministic counter: byte i holds i as u8, so the sequence wraps every 256 bytes.
pub fn binary_counter(length: u32) -> Result<Vec<u8>, ArgumentError> {
    try_binary_counter(length).map_err(compatibility_error)
}

fn try_binary_counter(length: u32) -> Result<Vec<u8>, BuildError> {
    if length == 0 || u64::from(length) > MAXIMUM_UDP_PAYLOAD_BYTES.max(MAXIMUM_TCP_BATCH_BYTES) {
        return Err(BuildError::Invalid("binary payload length out of range"));
    }
    Ok(crate::types::try_vec_with(
        length as usize,
        "payload allocation",
        |index| index as u8,
    )?)
}

/// Printable counter: eight decimal digits and a space per nine-byte record.
/// /zt 9 is "00000000 " and /zt 18 is "00000000 00000001 ".
pub fn printable_counter(length: u32) -> Result<Vec<u8>, ArgumentError> {
    try_printable_counter(length).map_err(compatibility_error)
}

fn try_printable_counter(length: u32) -> Result<Vec<u8>, BuildError> {
    if length == 0 || u64::from(length) > MAXIMUM_UDP_PAYLOAD_BYTES.max(MAXIMUM_TCP_BATCH_BYTES) {
        return Err(BuildError::Invalid("printable payload length out of range"));
    }
    let mut bytes = crate::types::try_vec_with_capacity(length as usize, "payload allocation")?;
    for index in 0..length as usize {
        let record_offset = index % 9;
        if record_offset == 8 {
            bytes.push(b' ');
            continue;
        }
        let record = index / 9;
        let mut divisor = 10_000_000usize;
        for _ in 0..record_offset {
            divisor /= 10;
        }
        bytes.push(b'0' + ((record / divisor) % 10) as u8);
    }
    Ok(bytes)
}

/// The transport limits that apply to one payload, before any session is created.
pub fn payload_limit(options: &Options) -> u64 {
    match options.protocol {
        crate::types::Protocol::Udp => MAXIMUM_UDP_PAYLOAD_BYTES,
        _ => MAXIMUM_TCP_BATCH_BYTES,
    }
}

pub fn validate_payload(options: &Options, payload: &[u8]) -> Result<(), ArgumentError> {
    if payload.is_empty() {
        return Err(ArgumentError("payload is empty"));
    }
    if (payload.len() as u64) > payload_limit(options) {
        return Err(ArgumentError("payload exceeds the transport limit"));
    }
    Ok(())
}

/// Exact comparison: an echo is only accepted when every byte matches. A short read is a
/// failure, never a partial success.
pub fn verify_echo(echoed: &[u8], pattern: &[u8]) -> bool {
    echoed.len() == pattern.len() && echoed == pattern
}

#[cfg(test)]
mod tests {
    use crate::metrics::Statistics;
    use crate::types::ExitCode;

    use super::*;
    use crate::contract::parse;

    fn options(values: &[&str]) -> Options {
        let mut arguments = vec!["rust-echo-client".to_string()];
        arguments.extend(values.iter().map(|value| value.to_string()));
        parse(&arguments).expect("valid options")
    }

    #[test]
    fn default_payload_matches_the_baseline_text() {
        let built = build(&options(&["127.0.0.1", "/p", "tcp"])).expect("payload");
        assert_eq!(String::from_utf8(built).unwrap(), "echo from 127.0.0.1");
    }

    #[test]
    fn counters_are_deterministic_and_validated() {
        let binary = binary_counter(300).expect("binary");
        assert_eq!(binary.len(), 300);
        assert_eq!(binary[0], 0);
        assert_eq!(binary[255], 255);
        assert_eq!(binary[256], 0);
        let printable = printable_counter(30).expect("printable");
        // The reference pattern: records of eight decimal digits and a space, counting from zero.
        assert_eq!(printable[0], b'0');
        assert_eq!(printable[7], b'0');
        assert_eq!(printable[8], b' ');
        assert_eq!(printable[9], b'0');
        assert_eq!(printable[17], b' ');
        assert_eq!(printable[18], b'0');
        assert!(binary_counter(0).is_err());
        assert!(printable_counter(0).is_err());
    }

    #[test]
    fn literal_payload_is_used_verbatim() {
        let built = build(&options(&["127.0.0.1", "/p", "tcp", "/d", "hello"])).expect("payload");
        assert_eq!(built, b"hello");
    }

    #[test]
    fn verification_is_byte_exact() {
        assert!(verify_echo(b"abc", b"abc"));
        assert!(!verify_echo(b"abd", b"abc"));
        assert!(!verify_echo(b"ab", b"abc"));
        assert!(!verify_echo(b"abcd", b"abc"));
        assert!(!verify_echo(b"", b"abc"));
    }

    #[test]
    fn statistics_classify_every_outcome() {
        let mut statistics = Statistics {
            echoes: 5,
            attempted: 5,
            ..Statistics::default()
        };
        assert_eq!(statistics.exit_code(false), ExitCode::Success);
        // /n is a per-session quota, so one session with /n 5 has nothing left unclaimed.
        assert_eq!(statistics.unclaimed(5, 1, false), 0);
        // Four sessions asked for 20 echoes and only 5 were claimed.
        assert_eq!(statistics.unclaimed(5, 4, false), 15);
        assert_eq!(statistics.unclaimed(5, 4, true), 0);

        statistics.corrupted = 1;
        assert_eq!(statistics.exit_code(false), ExitCode::EchoFailure);
        statistics.corrupted = 0;
        statistics.lost = 1;
        assert_eq!(statistics.exit_code(false), ExitCode::EchoFailure);

        statistics.lost = 0;
        statistics.echoes = 5;
        statistics.network_failures = 1;
        assert_eq!(statistics.exit_code(false), ExitCode::Success);
        statistics.network_failures = 0;
        statistics.echoes = 0;
        assert_eq!(statistics.exit_code(false), ExitCode::Network);
        assert_eq!(statistics.exit_code(true), ExitCode::Success);

        statistics.fatal = true;
        assert_eq!(statistics.exit_code(false), ExitCode::Internal);

        let mut other = Statistics {
            echoes: 2,
            sent_bytes: 8,
            ..Statistics::default()
        };
        other.fatal = true;
        let mut merged = Statistics {
            echoes: 1,
            ..Statistics::default()
        };
        merged.merge(&other);
        assert_eq!(merged.echoes, 3);
        assert_eq!(merged.sent_bytes, 8);
        assert!(merged.fatal);
        assert!(
            merged
                .line("worker 0", 1, 0)
                .starts_with("worker 0 elapsed_ms=0 sessions=1 ")
        );
    }
}
