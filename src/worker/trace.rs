//! Stage tracing for the completion-driven engine.
//!
//! Off by default: set CEC_TRACE=1 and every stage transition prints one line. The flag is
//! cached once and formatted trace details use `format_args!`, so disabled tracing performs
//! no heap allocation on the completion path.

use std::fmt;
use std::sync::OnceLock;

static ENABLED: OnceLock<bool> = OnceLock::new();

/// Whether tracing is requested for this process.
pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var_os("CEC_TRACE").is_some())
}

/// Records a stage with an already-borrowed string detail.
pub fn event(stage: &str, detail: &str) {
    if enabled() {
        if detail.is_empty() {
            eprintln!("{stage}");
        } else {
            eprintln!("{stage} {detail}");
        }
    }
}

/// Allocation-free formatted tracing. `format_args!` only renders when tracing is enabled.
pub fn event_args(stage: &str, detail: fmt::Arguments<'_>) {
    if enabled() {
        eprintln!("{stage} {detail}");
    }
}
