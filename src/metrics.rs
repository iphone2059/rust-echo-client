//! Run statistics: the counters the final line reports, the latency histogram and the exit-code
//! classification. Nothing here is shared: each worker owns an instance and the run merges them.

use crate::contract::{classify_result, unclaimed_echoes};
use crate::types::ExitCode;

/// The reference buckets latency by the power of two below the sample, so bin i means
/// [2^i, 2^(i+1)) microseconds and the reported value is that lower bound rather than the
/// sample. Sixty-four bins cover the whole u64 range because the index is clamped.
pub const LATENCY_BUCKETS: usize = 64;

/// Counters accumulated by the workers. Nothing here is shared: each worker owns its own
/// instance and the run merges them at the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statistics {
    pub echoes: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    /// Echo bytes that were verified against the payload. The reference counts only validated
    /// echoes here, while `received_bytes` counts everything the socket delivered.
    pub bytes: u64,
    pub corrupted: u64,
    pub lost: u64,
    /// Attempts the scheduler claimed. The identity is attempted = pending + echoed + corrupted
    /// + lost + cancelled, exactly as the reference reports it.
    pub attempted: u64,
    /// Attempts that were claimed but never finished when the run stopped under control.
    pub cancelled: u64,
    pub connections: u64,
    pub reconnects: u64,
    /// Connection failures, including failed generations that will reconnect.
    pub network_failures: u64,
    pub fatal: bool,
    pub latency_buckets: [u64; LATENCY_BUCKETS],
    pub latency_samples: u64,
    pub latency_sum_us: u64,
    pub latency_max_us: u64,
    pub elapsed_milliseconds: u64,
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            echoes: 0,
            sent_bytes: 0,
            received_bytes: 0,
            bytes: 0,
            corrupted: 0,
            lost: 0,
            attempted: 0,
            cancelled: 0,
            connections: 0,
            reconnects: 0,
            network_failures: 0,
            fatal: false,
            latency_buckets: [0; LATENCY_BUCKETS],
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
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.corrupted = self.corrupted.saturating_add(other.corrupted);
        self.lost = self.lost.saturating_add(other.lost);
        self.attempted = self.attempted.saturating_add(other.attempted);
        self.cancelled = self.cancelled.saturating_add(other.cancelled);
        self.connections = self.connections.saturating_add(other.connections);
        self.reconnects = self.reconnects.saturating_add(other.reconnects);
        self.network_failures = self.network_failures.saturating_add(other.network_failures);
        self.fatal |= other.fatal;
        for (target, source) in self.latency_buckets.iter_mut().zip(other.latency_buckets) {
            *target = target.saturating_add(source);
        }
        self.latency_samples = self.latency_samples.saturating_add(other.latency_samples);
        self.latency_sum_us = self.latency_sum_us.saturating_add(other.latency_sum_us);
        self.latency_max_us = self.latency_max_us.max(other.latency_max_us);
        self.elapsed_milliseconds = self.elapsed_milliseconds.max(other.elapsed_milliseconds);
    }

    /// Records one completed attempt, which is one latency sample because the histogram samples
    /// batches rather than echoes. The bucket is the reference's: the power of two below the
    /// sample, with the index clamped so no sample can write past the histogram. Like the
    /// reference's tick conversion, zero and sub-microsecond samples count as one microsecond.
    pub fn record_latency(&mut self, micros: u64) {
        let micros = micros.max(1);
        self.latency_samples = self.latency_samples.saturating_add(1);
        self.latency_sum_us = self.latency_sum_us.saturating_add(micros);
        self.latency_max_us = self.latency_max_us.max(micros);
        let bucket = ((u64::BITS - 1 - micros.leading_zeros()) as usize).min(LATENCY_BUCKETS - 1);
        self.latency_buckets[bucket] = self.latency_buckets[bucket].saturating_add(1);
    }

    /// Percentile from the histogram: the lower bound of the first bucket that crosses the
    /// requested fraction of samples, which is what the reference's "~" marks as approximate.
    pub fn percentile(&self, numerator: u64, denominator: u64) -> u64 {
        let total = self.sample_count();
        if total == 0 || numerator == 0 || denominator == 0 || numerator > denominator {
            return 0;
        }
        // ceil(total * numerator / denominator) without overflowing the product.
        let quotient = total / denominator;
        let remainder = total % denominator;
        let target = quotient
            .saturating_mul(numerator)
            .saturating_add(remainder.saturating_mul(numerator).div_ceil(denominator));
        let mut seen = 0u64;
        for (index, count) in self.latency_buckets.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= target {
                return 1u64 << index.min(63);
            }
        }
        0
    }

    pub fn sample_count(&self) -> u64 {
        let mut total = 0u64;
        for count in self.latency_buckets {
            total = total.saturating_add(count);
        }
        total
    }

    pub fn mean_latency_us(&self) -> u64 {
        if self.latency_samples == 0 {
            0
        } else {
            self.latency_sum_us / self.latency_samples
        }
    }

    pub fn echo_per_second(&self) -> f64 {
        self.echoes as f64 * 1_000.0 / self.elapsed_milliseconds.max(1) as f64
    }

    pub fn mib_per_second(&self) -> f64 {
        let mib = self.bytes as f64 / (1024.0 * 1024.0);
        mib * 1_000.0 / self.elapsed_milliseconds.max(1) as f64
    }

    /// Echoes that were asked for but never claimed. `/n` is a per-session quota, so the run
    /// described by the command line is `/n` times the session count. A controlled stop is not a
    /// loss.
    pub fn unclaimed(&self, limit: u64, sessions: u32, controlled_stop: bool) -> u64 {
        unclaimed_echoes(
            limit.saturating_mul(u64::from(sessions)),
            self.attempted,
            controlled_stop,
        )
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

    /// The terminal line. Its fields, their order and their separators are the baseline's, so a run
    /// can be compared across ports by reading the line alone. Pending is derived, because an attempt
    /// is pending exactly while it has been claimed and has not reached a terminal state.
    pub fn line(&self, label: &str, sessions: u32, active: u32) -> String {
        let terminal = self
            .echoes
            .saturating_add(self.corrupted)
            .saturating_add(self.lost)
            .saturating_add(self.cancelled);
        let pending = self.attempted.saturating_sub(terminal);
        format!(
            "{} elapsed_ms={} sessions={} active={} attempted={} pending={} echoed={} corrupted={} lost={} cancelled={} \
sent_bytes={} received_bytes={} bytes={} connections={} reconnects={} network_errors={} echo_per_sec={:.2} MiB_per_sec={:.2} \
p50_us~{} p99_us~{} p999_us~{} mean_us={} max_us~{} latency_sample=batch",
            label,
            self.elapsed_milliseconds,
            sessions,
            active,
            self.attempted,
            pending,
            self.echoes,
            self.corrupted,
            self.lost,
            self.cancelled,
            self.sent_bytes,
            self.received_bytes,
            self.bytes,
            self.connections,
            self.reconnects,
            self.network_failures,
            self.echo_per_second(),
            self.mib_per_second(),
            self.percentile(50, 100),
            self.percentile(99, 100),
            self.percentile(999, 1_000),
            self.mean_latency_us(),
            // The reference reports the maximum as the same histogram percentile, so this field is
            // a bucket lower bound like the others rather than the exact maximum observed.
            self.percentile(1, 1)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_buckets_follow_the_reference() {
        let mut statistics = Statistics::default();
        // One sample per completed attempt, bucketed by the power of two below it: 3 us lands in
        // bin 1 and 5 us in bin 2.
        statistics.record_latency(3);
        statistics.record_latency(5);
        assert_eq!(statistics.sample_count(), 2);
        // ceil(2 * 50 / 100) = 1, so the first non-empty bucket answers the median.
        assert_eq!(statistics.percentile(50, 100), 2);
        // The maximum uses the same percentile rule, so it is a bucket lower bound as well.
        assert_eq!(statistics.percentile(1, 1), 4);
        assert_eq!(statistics.mean_latency_us(), 4);
        // An empty histogram reports zero rather than the first bucket.
        assert_eq!(Statistics::default().percentile(50, 100), 0);
    }

    #[test]
    fn latency_clamps_extreme_samples_into_the_last_bucket() {
        let mut statistics = Statistics::default();
        // The largest u64 sample lands in bin 63; the largest u32 sample lands in bin 31.
        statistics.record_latency(u64::MAX);
        statistics.record_latency(u64::from(u32::MAX));
        assert_eq!(statistics.sample_count(), 2);
        assert_eq!(statistics.percentile(1, 1), 1u64 << 63);
        assert_eq!(statistics.percentile(50, 100), 1u64 << 31);
    }

    #[test]
    fn zero_latency_uses_the_reference_one_microsecond_floor() {
        let mut statistics = Statistics::default();
        statistics.record_latency(0);
        assert_eq!(statistics.latency_samples, 1);
        assert_eq!(statistics.sample_count(), 1);
        assert_eq!(statistics.latency_sum_us, 1);
        assert_eq!(statistics.latency_max_us, 1);
        assert_eq!(statistics.mean_latency_us(), 1);
        assert_eq!(statistics.percentile(50, 100), 1);
        assert_eq!(statistics.percentile(1, 1), 1);
        assert_eq!(statistics.latency_buckets[0], 1);
        assert_eq!(statistics.latency_buckets[63], 0);
    }

    #[test]
    fn submicrosecond_latency_uses_the_reference_one_microsecond_floor() {
        let mut statistics = Statistics::default();
        let micros = std::time::Duration::from_nanos(999).as_micros() as u64;
        statistics.record_latency(micros);
        assert_eq!(statistics.mean_latency_us(), 1);
        assert_eq!(statistics.percentile(1, 1), 1);
    }

    #[test]
    fn long_latency_samples_and_submillisecond_rates_preserve_the_reference_range() {
        let mut statistics = Statistics {
            echoes: 2,
            bytes: 1_048_576,
            ..Statistics::default()
        };
        statistics.record_latency(1u64 << 40);
        assert_eq!(statistics.mean_latency_us(), 1u64 << 40);
        assert_eq!(statistics.percentile(1, 1), 1u64 << 40);
        assert_eq!(statistics.echo_per_second(), 2_000.0);
        assert_eq!(statistics.mib_per_second(), 1_000.0);
    }
}
