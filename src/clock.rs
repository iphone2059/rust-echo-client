//! Production clock: real time from GetTickCount64.
//!
//! The blocking wait lives in the transport (Transport::wait_and_drain), because only that
//! layer can see both the completion port and the RIO completion queue.

use windows::Win32::sysinfoapi::GetTickCount64;

use crate::worker::Clock;

/// Real time for the worker loop.
#[derive(Debug, Default)]
pub struct RioClock;

impl RioClock {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for RioClock {
    fn now_milliseconds(&mut self) -> u64 {
        unsafe { GetTickCount64() }
    }

    fn wait(&mut self, _milliseconds: u32) {
        // Intentionally empty: the transport performs the blocking wait so that ConnectEx
        // completions and RIO completions are observed together.
    }
}
