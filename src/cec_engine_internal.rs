//! Engine internals: the registered arena, the completion-port bookkeeping, the overlapped storage
//! and the Registered I/O queue wrappers the engine drives.
//!
//! The reference keeps these in one engine-internal file; Rust keeps the same roles split across the
//! submodules below, which are reachable only through this module.

pub mod arena;
pub mod completion;
pub mod overlapped;
pub mod rio;
