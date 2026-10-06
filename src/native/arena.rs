//! Registered RIO memory pools.
//!
//! Receive and send have deliberately different registration layouts:
//! * RX: aggregated registrations with non-overlapping per-session slices. RIO receive permits
//!   other portions of the same registered buffer to be used while one slice is pending.
//! * TX: one registration per pipeline slot. RIOSend reserves the *entire registration* for
//!   the duration of an outstanding send, so concurrent sends cannot share a BufferId.

use core::ffi::c_void;

use windows::Win32::memoryapi::{VirtualAlloc, VirtualFree};
use windows::Win32::mswsockdef::RIO_BUF;

use crate::native::{NativeError, RioFunctions};
use crate::native::rio::RegisteredBuffer;

const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_RELEASE: u32 = 0x0000_8000;
const PAGE_READWRITE: u32 = 0x04;

fn release_pages(base: *mut u8) -> bool {
    unsafe { VirtualFree(base as *mut c_void, 0, MEM_RELEASE) }.as_bool()
}

/// Always performs the release; the debug assertion only verifies its result. Never put
/// cleanup itself inside `debug_assert!`, because release builds compile the assertion away.
fn release_pages_checked(base: *mut u8) {
    let released = release_pages(base);
    debug_assert!(released, "VirtualFree(registered arena) failed");
}

pub fn checked_pool_bytes(slots: usize, stride: usize) -> Option<usize> {
    if slots == 0 || stride == 0 {
        return None;
    }
    slots.checked_mul(stride)
}

pub fn checked_slot_offset(slot: usize, stride: usize, total: usize) -> Option<usize> {
    if stride == 0 {
        return None;
    }
    let offset = slot.checked_mul(stride)?;
    let end = offset.checked_add(stride)?;
    (end <= total).then_some(offset)
}

/// Ownership container for the RIO registrations backing the pool. RX stores a small
/// set of aggregated registrations; TX stores one registration per concurrent send slot.
type Registrations = Vec<RegisteredBuffer>;

/// A fixed-stride VirtualAlloc pool with aggregated RX registrations or one TX registration
/// per slot. Registrations are always destroyed before the backing pages are released.
pub struct Arena {
    base: *mut u8,
    bytes: usize,
    stride: u32,
    slots: u32,
    registrations: Option<Registrations>,
    views: Vec<RIO_BUF>,
}

impl Arena {
    /// Receive pool: registrations are aggregated, while every session gets a disjoint
    /// RIO_BUF slice. This minimizes registration overhead without crossing the DWORD limit.
    pub fn create_receive(
        rio: &RioFunctions,
        slots: u32,
        stride: u32,
    ) -> Result<Self, NativeError> {
        let (base, bytes) = Self::allocate(slots, stride)?;
        let slots_per_chunk = (u32::MAX / stride).max(1);
        let mut registrations = Vec::new();
        let mut views = Vec::with_capacity(slots as usize);
        let mut first_slot = 0u32;

        while first_slot < slots {
            let chunk_slots = (slots - first_slot).min(slots_per_chunk);
            let Some(chunk_offset) = (first_slot as usize).checked_mul(stride as usize) else {
                drop(registrations);
                release_pages_checked(base);
                return Err(NativeError {
                    stage: "receive arena chunk offset overflow",
                    code: 13,
                });
            };
            let Some(chunk_bytes_u32) = chunk_slots.checked_mul(stride) else {
                drop(registrations);
                release_pages_checked(base);
                return Err(NativeError {
                    stage: "receive arena chunk length overflow",
                    code: 13,
                });
            };
            let chunk = unsafe {
                core::slice::from_raw_parts_mut(base.add(chunk_offset), chunk_bytes_u32 as usize)
            };
            let registration = match RegisteredBuffer::register(rio, chunk) {
                Ok(registration) => registration,
                Err(error) => {
                    drop(registrations);
                    release_pages_checked(base);
                    return Err(error);
                }
            };

            for local_slot in 0..chunk_slots {
                let Some(offset) = local_slot.checked_mul(stride) else {
                    drop(registration);
                    drop(registrations);
                    release_pages_checked(base);
                    return Err(NativeError {
                        stage: "receive arena RIO offset overflow",
                        code: 13,
                    });
                };
                let view = match registration.slice(offset, stride) {
                    Ok(view) => view,
                    Err(error) => {
                        drop(registration);
                        drop(registrations);
                        release_pages_checked(base);
                        return Err(error);
                    }
                };
                views.push(view);
            }
            registrations.push(registration);
            first_slot += chunk_slots;
        }

        Ok(Self {
            base,
            bytes,
            stride,
            slots,
            registrations: Some(registrations),
            views,
        })
    }

    /// Send pool: every pipeline slot has its own BufferId and a private payload copy.
    pub fn create_send(
        rio: &RioFunctions,
        slots: u32,
        payload: &[u8],
    ) -> Result<Self, NativeError> {
        let stride = u32::try_from(payload.len()).map_err(|_| NativeError {
            stage: "send arena payload length",
            code: 13,
        })?;
        if stride == 0 {
            return Err(NativeError {
                stage: "send arena payload length",
                code: 13,
            });
        }
        let (base, bytes) = Self::allocate(slots, stride)?;
        let mut registrations = Vec::with_capacity(slots as usize);
        let mut views = Vec::with_capacity(slots as usize);

        for slot in 0..slots as usize {
            let Some(offset) = checked_slot_offset(slot, stride as usize, bytes) else {
                drop(registrations);
                release_pages_checked(base);
                return Err(NativeError {
                    stage: "send arena slot offset",
                    code: 13,
                });
            };
            let slice = unsafe { core::slice::from_raw_parts_mut(base.add(offset), stride as usize) };
            slice.copy_from_slice(payload);
            let registration = match RegisteredBuffer::register(rio, slice) {
                Ok(registration) => registration,
                Err(error) => {
                    drop(registrations);
                    release_pages_checked(base);
                    return Err(error);
                }
            };
            let view = match registration.slice(0, stride) {
                Ok(view) => view,
                Err(error) => {
                    drop(registration);
                    drop(registrations);
                    release_pages_checked(base);
                    return Err(error);
                }
            };
            registrations.push(registration);
            views.push(view);
        }

        Ok(Self {
            base,
            bytes,
            stride,
            slots,
            registrations: Some(registrations),
            views,
        })
    }

    fn allocate(slots: u32, stride: u32) -> Result<(*mut u8, usize), NativeError> {
        if slots == 0 || stride == 0 {
            return Err(NativeError {
                stage: "registered arena dimensions",
                code: 13,
            });
        }
        let bytes = checked_pool_bytes(slots as usize, stride as usize).ok_or(NativeError {
            stage: "registered arena size overflow",
            code: 13,
        })?;
        if bytes > isize::MAX as usize {
            return Err(NativeError {
                stage: "registered arena exceeds Rust pointer-offset range",
                code: 13,
            });
        }
        let base = unsafe { VirtualAlloc(None, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) }
            as *mut u8;
        if base.is_null() {
            return Err(NativeError {
                stage: "VirtualAlloc(registered arena)",
                code: unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32,
            });
        }
        Ok((base, bytes))
    }

    pub fn slots(&self) -> u32 {
        self.slots
    }

    pub fn stride(&self) -> u32 {
        self.stride
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn view(&self, slot: u32, length: u32) -> Result<RIO_BUF, NativeError> {
        if self.registrations.is_none() || slot >= self.slots || length == 0 || length > self.stride {
            return Err(NativeError {
                stage: "registered arena view bounds",
                code: 13,
            });
        }
        let mut view = self.views[slot as usize];
        view.Length = length;
        Ok(view)
    }

    /// Reads bytes written by a completed receive. The caller must only call this after the
    /// corresponding completion has been dequeued and before that slot is reposted.
    pub fn read(&self, slot: u32, length: u32) -> &[u8] {
        if self.registrations.is_none() || slot >= self.slots || length == 0 || length > self.stride {
            return &[];
        }
        let offset = match checked_slot_offset(slot as usize, self.stride as usize, self.bytes) {
            Some(offset) => offset,
            None => return &[],
        };
        unsafe { core::slice::from_raw_parts(self.base.add(offset), length as usize) }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        self.views.clear();
        // Deregister every BufferId while its virtual memory is still mapped.
        drop(self.registrations.take());
        release_pages_checked(self.base);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_arithmetic_is_checked() {
        assert_eq!(checked_pool_bytes(4, 1024), Some(4096));
        assert_eq!(checked_pool_bytes(0, 1024), None);
        assert_eq!(checked_pool_bytes(usize::MAX, 2), None);
        assert_eq!(checked_slot_offset(0, 1024, 4096), Some(0));
        assert_eq!(checked_slot_offset(3, 1024, 4096), Some(3072));
        assert_eq!(checked_slot_offset(4, 1024, 4096), None);
    }
}



