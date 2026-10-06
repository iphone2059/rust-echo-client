//! Echo payload construction and byte-exact verification, plus the run statistics the
//! exit code is derived from.

use crate::contract::{classify_result, unclaimed_echoes};
use crate::types::{ArgumentError, ExitCode, Options, Pattern, MAXIMUM_TCP_BATCH_BYTES, MAXIMUM_UDP_PAYLOAD_BYTES};

/// The default payload of the baseline: the literal text below, sent as ASCII.
pub const DEFAULT_TEXT_PREFIX: &str = "C++ echo from ";

/// Builds the payload for a session. Sizes are validated here as well as in the parser so
/// a caller that builds options by hand cannot smuggle an impossible payload in.
pub fn build(options: &Options) -> Result<Vec<u8>, ArgumentError> {
    let bytes = match options.pattern {
        Pattern::DefaultText => {
            let mut text = String::from(DEFAULT_TEXT_PREFIX);
            text.push_str(&options.host);
            text.into_bytes()
        }
        Pattern::LiteralText => options.literal_pattern.clone().into_bytes(),
        Pattern::BinaryCounter => binary_counter(options.pattern_bytes)?,
        Pattern::PrintableCounter => printable_counter(options.pattern_bytes)?,
    };
    Ok(bytes)
}

/// Deterministic counter: byte i holds i as u8, so the sequence wraps every 256 bytes.
pub fn binary_counter(length: u32) -> Result<Vec<u8>, ArgumentError> {
    if length == 0 || u64::from(length) > MAXIMUM_UDP_PAYLOAD_BYTES.max(MAXIMUM_TCP_BATCH_BYTES) {
        return Err(ArgumentError("binary payload length out of range".to_string()));
    }
    Ok((0..length).map(|index| index as u8).collect())
}

/// Printable counter: a repeating 'a'..'z' cycle, so captures stay readable in logs.
pub fn printable_counter(length: u32) -> Result<Vec<u8>, ArgumentError> {
    if length == 0 || u64::from(length) > MAXIMUM_UDP_PAYLOAD_BYTES.max(MAXIMUM_TCP_BATCH_BYTES) {
        return Err(ArgumentError("printable payload length out of range".to_string()));
    }
    Ok((0..length).map(|index| b'a' + (index % 26) as u8).collect())
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
        return Err(ArgumentError("payload is empty".to_string()));
    }
    if (payload.len() as u64) > payload_limit(options) {
        return Err(ArgumentError("payload exceeds the transport limit".to_string()));
    }
    Ok(())
}

/// Exact comparison: an echo is only accepted when every byte matches. A short read is a
/// failure, never a partial success.
pub fn verify_echo(echoed: &[u8], pattern: &[u8]) -> bool {
    echoed.len() == pattern.len() && echoed == pattern
}

/// Latency histogram resolution and size: one bucket per 64 microseconds plus an overflow
/// bucket. A fixed histogram keeps the completion path allocation-free and makes merging
/// the workers an element-wise add.
pub const LATENCY_BUCKET_MICROS: u32 = 64;
pub const LATENCY_BUCKETS: usize = 512;

/// Counters accumulated by the workers. Nothing here is shared: each worker owns its own
/// instance and the run merges them at the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statistics {
    pub echoes: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub corrupted: u64,
    pub lost: u64,
    pub connections: u64,
    pub reconnects: u64,
    /// Sessions that permanently ended because a transport generation could not recover.
    pub network_failures: u64,
    pub fatal: bool,
    pub latency_buckets: [u32; LATENCY_BUCKETS],
    pub latency_overflow: u32,
    pub latency_samples: u64,
    pub latency_sum_us: u64,
    pub latency_max_us: u32,
    pub elapsed_milliseconds: u64,
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            echoes: 0,
            sent_bytes: 0,
            received_bytes: 0,
            corrupted: 0,
            lost: 0,
            connections: 0,
            reconnects: 0,
            network_failures: 0,
            fatal: false,
            latency_buckets: [0; LATENCY_BUCKETS],
            latency_overflow: 0,
            latency_samples: 0,
            latency_sum_us: 0,
            latency_max_us: 0,
            elapsed_milliseconds: 0,
        }
    }
}

impl Statistics {
    pub fn merge(&mut self, other: &Statistics) {
        self.echoes = self.echoes.saturating_add(other.echoes);
        self.sent_bytes = self.sent_bytes.saturating_add(other.sent_bytes);
        self.received_bytes = self.received_bytes.saturating_add(other.received_bytes);
        self.corrupted = self.corrupted.saturating_add(other.corrupted);
        self.lost = self.lost.saturating_add(other.lost);
        self.connections = self.connections.saturating_add(other.connections);
        self.reconnects = self.reconnects.saturating_add(other.reconnects);
        self.network_failures = self.network_failures.saturating_add(other.network_failures);
        self.fatal |= other.fatal;
        for (target, source) in self.latency_buckets.iter_mut().zip(other.latency_buckets) {
            *target = target.saturating_add(source);
        }
        self.latency_overflow = self.latency_overflow.saturating_add(other.latency_overflow);
        self.latency_samples = self.latency_samples.saturating_add(other.latency_samples);
        self.latency_sum_us = self.latency_sum_us.saturating_add(other.latency_sum_us);
        self.latency_max_us = self.latency_max_us.max(other.latency_max_us);
        self.elapsed_milliseconds = self.elapsed_milliseconds.max(other.elapsed_milliseconds);
    }

    /// Records one echo round trip. The bucket index is clamped through the overflow bucket
    /// so an unexpectedly slow sample cannot write past the histogram.
    pub fn record_latency(&mut self, micros: u32) {
        self.latency_samples = self.latency_samples.saturating_add(1);
        self.latency_sum_us = self.latency_sum_us.saturating_add(u64::from(micros));
        self.latency_max_us = self.latency_max_us.max(micros);
        let bucket = (micros / LATENCY_BUCKET_MICROS) as usize;
        if bucket < LATENCY_BUCKETS {
            self.latency_buckets[bucket] = self.latency_buckets[bucket].saturating_add(1);
        } else {
            self.latency_overflow = self.latency_overflow.saturating_add(1);
        }
    }

    /// Percentile from the histogram: the upper edge of the first bucket that crosses the
    /// requested fraction of samples.
    pub fn percentile(&self, numerator: u64, denominator: u64) -> u32 {
        if self.latency_samples == 0 || denominator == 0 {
            return 0;
        }
        let target = self
            .latency_samples
            .saturating_mul(numerator)
            .div_ceil(denominator);
        let mut seen = 0u64;
        for (index, count) in self.latency_buckets.iter().enumerate() {
            seen = seen.saturating_add(u64::from(*count));
            if seen >= target {
                return (index as u32 + 1) * LATENCY_BUCKET_MICROS;
            }
        }
        // Only the overflow bucket is left, so the maximum observed is the honest answer.
        self.latency_max_us
    }

    pub fn mean_latency_us(&self) -> u32 {
        if self.latency_samples == 0 {
            0
        } else {
            (self.latency_sum_us / self.latency_samples) as u32
        }
    }

    pub fn echo_per_second(&self) -> f64 {
        if self.elapsed_milliseconds == 0 {
            0.0
        } else {
            self.echoes as f64 * 1_000.0 / self.elapsed_milliseconds as f64
        }
    }

    pub fn mib_per_second(&self) -> f64 {
        if self.elapsed_milliseconds == 0 {
            0.0
        } else {
            let mib = self.received_bytes as f64 / (1024.0 * 1024.0);
            mib * 1_000.0 / self.elapsed_milliseconds as f64
        }
    }

    /// Echoes that were asked for but never completed. A controlled stop is not a loss.
    pub fn unclaimed(&self, limit: u64, controlled_stop: bool) -> u64 {
        unclaimed_echoes(limit, self.echoes, controlled_stop)
    }

    pub fn exit_code(&self, controlled_stop: bool) -> ExitCode {
        classify_result(
            self.echoes,
            self.corrupted,
            self.lost,
            self.network_failures,
            self.fatal,
            controlled_stop,
        )
    }

    /// One stats line per worker plus a total, mirroring the shape of the baseline report.
    pub fn line(&self, label: &str) -> String {
        format!(
            "{} echoed={} sent={} bytes={} corrupted={} lost={} connections={} reconnects={} network_errors={} \
elapsed_ms={} echo_per_sec={:.2} MiB_per_sec={:.2} p50_us~{} p99_us~{} p999_us~{} mean_us~{} max_us~{} latency_sample=fifo_echo",
            label,
            self.echoes,
            self.sent_bytes,
            self.received_bytes,
            self.corrupted,
            self.lost,
            self.connections,
            self.reconnects,
            self.network_failures,
            self.elapsed_milliseconds,
            self.echo_per_second(),
            self.mib_per_second(),
            self.percentile(50, 100),
            self.percentile(99, 100),
            self.percentile(999, 1_000),
            self.mean_latency_us(),
            self.latency_max_us
        )
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(String::from_utf8(built).unwrap(), "C++ echo from 127.0.0.1");
    }

    #[test]
    fn counters_are_deterministic_and_validated() {
        let binary = binary_counter(300).expect("binary");
        assert_eq!(binary.len(), 300);
        assert_eq!(binary[0], 0);
        assert_eq!(binary[255], 255);
        assert_eq!(binary[256], 0);
        let printable = printable_counter(30).expect("printable");
        assert_eq!(printable[0], b'a');
        assert_eq!(printable[25], b'z');
        assert_eq!(printable[26], b'a');
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
        let mut statistics = Statistics { echoes: 5, ..Statistics::default() };
        assert_eq!(statistics.exit_code(false), ExitCode::Success);
        assert_eq!(statistics.unclaimed(5, false), 0);

        statistics.echoes = 3;
        assert_eq!(statistics.unclaimed(5, false), 2);
        assert_eq!(statistics.unclaimed(5, true), 0);

        statistics.corrupted = 1;
        assert_eq!(statistics.exit_code(false), ExitCode::EchoFailure);
        statistics.corrupted = 0;
        statistics.lost = 1;
        assert_eq!(statistics.exit_code(false), ExitCode::EchoFailure);

        statistics.lost = 0;
        statistics.echoes = 5;
        statistics.network_failures = 1;
        assert_eq!(statistics.exit_code(false), ExitCode::Network);
        statistics.network_failures = 0;
        statistics.echoes = 0;
        assert_eq!(statistics.exit_code(false), ExitCode::Network);
        assert_eq!(statistics.exit_code(true), ExitCode::Success);

        statistics.fatal = true;
        assert_eq!(statistics.exit_code(false), ExitCode::Internal);

        let mut other = Statistics { echoes: 2, sent_bytes: 8, ..Statistics::default() };
        other.fatal = true;
        let mut merged = Statistics { echoes: 1, ..Statistics::default() };
        merged.merge(&other);
        assert_eq!(merged.echoes, 3);
        assert_eq!(merged.sent_bytes, 8);
        assert!(merged.fatal);
        assert!(merged.line("worker 0").starts_with("worker 0 echoed=3 "));
    }
}
