//! Windows x64 RIO echo client core.
//!
//! Layering mirrors the C++ baseline and the Swift port:
//! contract -> native (Winsock/RIO/ConnectEx) -> engine -> main.

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
compile_error!("cec targets Windows x64 (x86_64-pc-windows-msvc) only");

pub mod arena;
pub mod clock;
pub mod completion;
pub mod contract;
pub mod endpoint;
pub mod native;
pub mod overlapped;
pub mod payload;
pub mod scheduler;
pub mod session;
pub mod rio;
pub mod timer;
pub mod trace;
pub mod transport;
pub mod types;
pub mod worker;
