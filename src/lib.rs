//! Windows x64 RIO echo client core.
//!
//! The module tree mirrors the C++ baseline file for file:
//! contract -> native (Winsock/RIO/ConnectEx) -> engine (transport and run) -> internal
//! (worker, session, scheduler) -> main. The two internal module names are re-exported so the
//! historical `crate::worker` and `crate::session` paths keep working.

#[cfg(not(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")))]
compile_error!("cec targets Windows x64 (x86_64-pc-windows-msvc) only");

pub mod contract;
pub mod engine;
pub mod internal;
pub mod metrics;
pub mod native;
pub mod payload;
pub mod types;

pub use internal::session;
pub use internal::worker;
