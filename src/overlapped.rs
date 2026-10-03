//! Stable ownership for one ConnectEx `OVERLAPPED`.
//!
//! The address of the structure never changes while an operation is outstanding. A
//! synchronous post failure may explicitly roll the logical arm back because Windows did
//! not accept the operation and therefore cannot later reference the structure.

use windows::Win32::minwinbase::OVERLAPPED;

use crate::native::NativeError;

pub struct PendingOverlapped {
    inner: OVERLAPPED,
    armed: bool,
}

impl Default for PendingOverlapped {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingOverlapped {
    pub fn new() -> Self {
        Self {
            inner: OVERLAPPED::default(),
            armed: false,
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut OVERLAPPED {
        &mut self.inner
    }

    pub fn arm(&mut self) -> Result<(), NativeError> {
        if self.armed {
            return Err(NativeError {
                stage: "OVERLAPPED armed twice",
                code: 13,
            });
        }
        self.armed = true;
        Ok(())
    }

    pub fn complete(&mut self) -> Result<(), NativeError> {
        if !self.armed {
            return Err(NativeError {
                stage: "OVERLAPPED completed while unarmed",
                code: 13,
            });
        }
        self.armed = false;
        Ok(())
    }

    /// Rolls back `arm()` after the native post failed synchronously. This must never be
    /// used for cancellation: canceled operations still own the OVERLAPPED until completion.
    pub fn post_failed(&mut self) -> Result<(), NativeError> {
        if !self.armed {
            return Err(NativeError {
                stage: "OVERLAPPED post failure while unarmed",
                code: 13,
            });
        }
        self.armed = false;
        self.inner = OVERLAPPED::default();
        Ok(())
    }

    pub fn is_armed(&self) -> bool {
        self.armed
    }

    pub fn reset_after_drain(&mut self) -> Result<(), NativeError> {
        if self.armed {
            return Err(NativeError {
                stage: "OVERLAPPED reset while armed",
                code: 13,
            });
        }
        self.inner = OVERLAPPED::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_is_strict() {
        let mut overlapped = PendingOverlapped::new();
        assert!(overlapped.complete().is_err());
        assert!(overlapped.arm().is_ok());
        assert!(overlapped.arm().is_err());
        assert!(overlapped.complete().is_ok());
        assert!(overlapped.reset_after_drain().is_ok());

        assert!(overlapped.arm().is_ok());
        assert!(overlapped.post_failed().is_ok());
        assert!(!overlapped.is_armed());
    }
}
