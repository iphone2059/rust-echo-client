//! Run statistics: the counters the final line reports, the latency histogram and the exit-code
//! classification. Nothing here is shared: each worker owns an instance and the run merges them.

use crate::contract::{classify_result, unclaimed_echoes};
use crate::types::ExitCode;

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
