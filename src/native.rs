//! Win32/Winsock ownership, socket creation and runtime failure reporting.
//!
//! windows-rs 0.100 organises its generated surface by Windows header, and its
//! signatures differ from the published 0.6x line (for example `WSASocketW` returns a
//! raw `SOCKET` and `WSAStartup` returns an `i32` status). Every path and signature
//! used here was read from the committed bindings under
//! `crates/libs/windows/src/Windows/Win32/<header>/mod.rs` in the resolved revision.

use core::ffi::c_void;
use core::mem::size_of;

use windows::Win32::winsock2::WSAGetLastError;
use windows::Win32::mswsock::{LPFN_CONNECTEX, RIO_EXTENSION_FUNCTION_TABLE};
use windows::Win32::winsock2::{
    SOCKET, WSA_FLAG_OVERLAPPED, WSA_FLAG_REGISTERED_IO, WSACleanup, WSADATA, WSASocketW,
    WSAStartup, WSAIoctl, closesocket, setsockopt, INVALID_SOCKET,
};
use windows::Win32::ws2::{
    AF_INET, IPPROTO_TCP, IPPROTO_UDP, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, SO_RCVBUF,
    SO_SNDBUF, SOL_SOCKET, SOCK_DGRAM, SOCK_STREAM, TCP_NODELAY,
};
use windows::core::GUID;

use crate::types::Protocol;

/// A Win32 failure together with the API stage that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeError {
    pub stage: &'static str,
    pub code: i32,
}

impl NativeError {
    pub(crate) fn winsock_last(stage: &'static str) -> Self {
        // The code is captured at the failing call site; GetLastError is never read later.
        Self { stage, code: unsafe { WSAGetLastError() } }
    }
}

/// Winsock lifetime guard: construction starts Winsock, drop cleans it up.
pub struct Winsock {
    started: bool,
}

impl Winsock {
    pub fn start() -> Result<Self, NativeError> {
        let mut data = WSADATA::default();
        let status = unsafe { WSAStartup(0x0202, &mut data) };
        if status != 0 {
            return Err(NativeError { stage: "WSAStartup", code: status });
        }
        Ok(Self { started: true })
    }
}

impl Drop for Winsock {
    fn drop(&mut self) {
        if self.started {
            unsafe {
                WSACleanup();
            }
        }
    }
}

/// Sole owner of a socket. The numeric value never escapes without an explicit release,
/// which mirrors the move-only socket owners of the C++ and Swift ports.
pub struct SocketOwner {
    socket: SOCKET,
}

impl SocketOwner {
    pub fn new(socket: SOCKET) -> Self {
        Self { socket }
    }

    pub fn raw(&self) -> SOCKET {
        self.socket
    }

    /// Transfers ownership out of the guard; the guard no longer closes the socket.
    pub fn release(&mut self) -> SOCKET {
        core::mem::replace(&mut self.socket, INVALID_SOCKET)
    }
}

impl Drop for SocketOwner {
    fn drop(&mut self) {
        if self.socket != INVALID_SOCKET {
            unsafe {
                closesocket(self.socket);
            }
        }
    }
}

/// Creates a socket that is both overlapped and registered with RIO. Registration is a
/// hard requirement: RIO refuses to associate an unregistered socket with a queue.
pub fn registered_socket(protocol: Protocol) -> Result<SocketOwner, NativeError> {
    let (kind, transport) = match protocol {
        Protocol::Tcp => (SOCK_STREAM, IPPROTO_TCP),
        Protocol::Udp => (SOCK_DGRAM, IPPROTO_UDP),
        Protocol::None => {
            // 87 = ERROR_INVALID_PARAMETER, matching the baseline's rejected-protocol path.
            return Err(NativeError { stage: "registered_socket(protocol)", code: 87 });
        }
    };
    // The bindings expose the WSA_FLAG_* constants as i32; dwflags is u32.
    let flags = (WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO) as u32;
    let socket = unsafe {
        WSASocketW(AF_INET, kind, transport, None, Default::default(), flags)
    };
    if socket == INVALID_SOCKET {
        return Err(NativeError::winsock_last("WSASocketW(AF_INET, registered)"));
    }
    Ok(SocketOwner::new(socket))
}

/// Configures a connected socket. Zero buffer sizes leave the system default in place,
/// which is what the baseline does when /b is absent.
pub fn configure_socket(
    socket: SOCKET,
    no_delay: bool,
    send_buffer_bytes: u32,
    receive_buffer_bytes: u32,
) -> Result<(), NativeError> {
    if no_delay {
        let value: i32 = 1;
        let status = unsafe {
            setsockopt(
                socket,
                IPPROTO_TCP,
                TCP_NODELAY,
                Some(&value as *const i32 as *const i8),
                size_of::<i32>() as i32,
            )
        };
        if status != 0 {
            return Err(NativeError::winsock_last("setsockopt(TCP_NODELAY)"));
        }
    }
    for (stage, option, bytes) in [
        ("setsockopt(SO_SNDBUF)", SO_SNDBUF, send_buffer_bytes),
        ("setsockopt(SO_RCVBUF)", SO_RCVBUF, receive_buffer_bytes),
    ] {
        if bytes == 0 {
            continue;
        }
        let value = bytes as i32;
        let status = unsafe {
            setsockopt(
                socket,
                SOL_SOCKET,
                option,
                Some(&value as *const i32 as *const i8),
                size_of::<i32>() as i32,
            )
        };
        if status != 0 {
            return Err(NativeError::winsock_last(stage));
        }
    }
    Ok(())
}

/// {8509E081-96DD-4005-B165-9E2EE8C79E3F}: the RIO extension identifier. windows-rs
/// 0.100 does not export the WSAID_* constants, so it is declared here with the value
/// the Swift port already runs against.
const WSAID_MULTIPLE_RIO: GUID = GUID::from_u128(0x8509_e081_96dd_4005_b165_9e2e_e8c7_9e3f);

/// The RIO entry points. RIO is never imported as a flat symbol: every function is
/// reached through this table, which the provider fills in for the running stack.
pub struct RioFunctions {
    table: RIO_EXTENSION_FUNCTION_TABLE,
}

impl RioFunctions {
    pub fn load(socket: SOCKET) -> Result<Self, NativeError> {
        let expected = size_of::<RIO_EXTENSION_FUNCTION_TABLE>() as u32;
        // The table is written by the provider, so it starts zeroed and cbSize is set.
        let mut table: RIO_EXTENSION_FUNCTION_TABLE = unsafe { core::mem::zeroed() };
        table.cbSize = expected;
        let mut returned: u32 = 0;
        let status = unsafe {
            WSAIoctl(
                socket,
                SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
                Some(&WSAID_MULTIPLE_RIO as *const GUID as *const c_void),
                size_of::<GUID>() as u32,
                Some(&mut table as *mut RIO_EXTENSION_FUNCTION_TABLE as *mut c_void),
                expected,
                &mut returned,
                None,
                None,
            )
        };
        if status != 0 {
            return Err(NativeError::winsock_last(
                "WSAIoctl(SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER)",
            ));
        }
        if returned != expected || table.cbSize != expected {
            return Err(NativeError { stage: "RIO table size", code: 13 });
        }
        Ok(Self { table })
    }

    pub fn table(&self) -> &RIO_EXTENSION_FUNCTION_TABLE {
        &self.table
    }
}

/// {25A207B9-DDF3-4660-8EE9-76E58C74063E}: the ConnectEx extension identifier.
/// Like the RIO id it is not exported by the bindings and is declared here.
const WSAID_CONNECTEX: GUID = GUID::from_u128(0x25a2_07b9_ddf3_4660_8ee9_76e5_8c74_063e);

/// Loads the ConnectEx entry point for a socket. Asynchronous connect has no plain
/// Winsock equivalent, so the peer address is bound first and the connect is issued
/// through this pointer with an OVERLAPPED.
pub fn load_connect_ex(socket: SOCKET) -> Result<LPFN_CONNECTEX, NativeError> {
    let mut function: LPFN_CONNECTEX = None;
    let mut returned: u32 = 0;
    let status = unsafe {
        WSAIoctl(
            socket,
            // A single extension uses SIO_GET_EXTENSION_FUNCTION_POINTER; the MULTIPLE
            // variant is only valid for the RIO table and fails here with WSAEOPNOTSUPP.
            crate::native::endpoint::SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some(&WSAID_CONNECTEX as *const GUID as *const c_void),
            size_of::<GUID>() as u32,
            Some(&mut function as *mut LPFN_CONNECTEX as *mut c_void),
            size_of::<LPFN_CONNECTEX>() as u32,
            &mut returned,
            None,
            None,
        )
    };
    if status != 0 {
        return Err(NativeError::winsock_last("WSAIoctl(WSAID_CONNECTEX)"));
    }
    if function.is_none() {
        return Err(NativeError { stage: "ConnectEx entry point", code: 13 });
    }
    Ok(function)
}

// The Windows substrate is grouped here: the queue wrappers, the completion bookkeeping, the
// overlapped storage, the registered arena and the endpoint helpers are submodules of this module.

pub mod arena {
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

        /// A view of part of a slot, used to re-post the remainder of a partially completed send.
        pub fn view_from(&self, slot: u32, offset: u32, length: u32) -> Result<RIO_BUF, NativeError> {
            let mut view = self.view(slot, length)?;
            if u64::from(offset).saturating_add(u64::from(length)) > u64::from(self.stride) {
                return Err(NativeError {
                    stage: "registered arena view offset bounds",
                    code: 13,
                });
            }
            view.Offset = view.Offset.wrapping_add(offset);
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
}

pub mod clock {
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
}

pub mod completion {
    //! Completion routing for RIO/IOCP.
    //!
    //! The 64-bit request context is self-contained: operation, session, send slot and
    //! connection generation are encoded directly, so no pointer-valued side table is needed.
    //! A generation mismatch is a stale completion and must never steer the live state machine.

    use core::ffi::c_void;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum Operation {
        Connect = 1,
        Send = 2,
        Receive = 3,
        /// Internal transport event; never encoded into an OS request context.
        GenerationDrained = 4,
    }

    impl Operation {
        fn from_tag(tag: u64) -> Option<Self> {
            match tag {
                1 => Some(Self::Connect),
                2 => Some(Self::Send),
                3 => Some(Self::Receive),
                _ => None,
            }
        }
    }

    /// Context layout on Windows x64:
    ///
    /// * bits 0..=2   : operation (3 bits)
    /// * bits 3..=22  : session index (20 bits)
    /// * bits 23..=38 : send slot (16 bits; zero for connect/receive)
    /// * bits 39..=46 : generation (8 bits)
    ///
    /// The value is carried through APIs typed as `PVOID`, so the packed integer deliberately
    /// stays below 2^47 instead of manufacturing a non-canonical x64 pointer bit pattern. Eight
    /// generation bits are sufficient because a generation number is never reused until the
    /// previous generation has fully drained; wrapping therefore cannot alias a still-live request.
    const OP_BITS: u32 = 3;
    const SESSION_BITS: u32 = 20;
    const SLOT_BITS: u32 = 16;
    const GENERATION_BITS: u32 = 8;
    const CONTEXT_BITS: u32 = OP_BITS + SESSION_BITS + SLOT_BITS + GENERATION_BITS;
    const _: () = assert!(CONTEXT_BITS == 47);
    const CONTEXT_MASK: u64 = (1u64 << CONTEXT_BITS) - 1;

    const OP_MASK: u64 = (1u64 << OP_BITS) - 1;
    const SESSION_MASK: u64 = (1u64 << SESSION_BITS) - 1;
    const SLOT_MASK: u64 = (1u64 << SLOT_BITS) - 1;
    const GENERATION_MASK: u64 = (1u64 << GENERATION_BITS) - 1;

    pub const MAXIMUM_SESSION_INDEX: u32 = SESSION_MASK as u32;
    pub const MAXIMUM_SEND_SLOT: u32 = SLOT_MASK as u32;
    pub const MAXIMUM_GENERATION: u32 = GENERATION_MASK as u32;
    pub const NO_SEND_SLOT: u32 = 0;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RequestContext {
        pub index: u32,
        pub generation: u32,
        pub slot: u32,
        pub operation: Operation,
    }

    pub fn encode_context(
        index: u32,
        generation: u32,
        slot: u32,
        operation: Operation,
    ) -> *mut c_void {
        debug_assert!(operation != Operation::GenerationDrained);
        debug_assert!(index <= MAXIMUM_SESSION_INDEX);
        debug_assert!(generation > 0 && generation <= MAXIMUM_GENERATION);
        debug_assert!(slot <= MAXIMUM_SEND_SLOT);
        debug_assert!(operation == Operation::Send || slot == NO_SEND_SLOT);

        let value = (operation as u64)
            | ((u64::from(index) & SESSION_MASK) << OP_BITS)
            | ((u64::from(slot) & SLOT_MASK) << (OP_BITS + SESSION_BITS))
            | ((u64::from(generation) & GENERATION_MASK)
                << (OP_BITS + SESSION_BITS + SLOT_BITS));
        value as usize as *mut c_void
    }

    pub fn decode_context(context: u64) -> Option<RequestContext> {
        // Reject rather than mask any bits outside the documented canonical payload. This turns
        // a corrupted/forged completion key into an error instead of aliasing a live request.
        if context & !CONTEXT_MASK != 0 {
            return None;
        }
        let operation = Operation::from_tag(context & OP_MASK)?;
        let index = (context >> OP_BITS) & SESSION_MASK;
        let slot = (context >> (OP_BITS + SESSION_BITS)) & SLOT_MASK;
        let generation =
            (context >> (OP_BITS + SESSION_BITS + SLOT_BITS)) & GENERATION_MASK;

        if generation == 0 {
            return None;
        }
        if operation != Operation::Send && slot != u64::from(NO_SEND_SLOT) {
            return None;
        }

        Some(RequestContext {
            index: index as u32,
            generation: generation as u32,
            slot: slot as u32,
            operation,
        })
    }

    pub fn next_generation(current: u32) -> u32 {
        if current == 0 || current >= MAXIMUM_GENERATION {
            1
        } else {
            current + 1
        }
    }

    pub fn status_is_success(status: i32) -> bool {
        status == 0
    }

    pub const ERROR_NETNAME_DELETED: i32 = 64;
    pub const ERROR_SEM_TIMEOUT: i32 = 121;
    pub const ERROR_OPERATION_ABORTED: i32 = 995;
    pub const ERROR_CONNECTION_REFUSED: i32 = 1_225;
    pub const ERROR_NETWORK_UNREACHABLE: i32 = 1_231;
    pub const ERROR_HOST_UNREACHABLE: i32 = 1_232;
    pub const ERROR_PROTOCOL_UNREACHABLE: i32 = 1_233;
    pub const ERROR_PORT_UNREACHABLE: i32 = 1_234;
    pub const ERROR_CONNECTION_ABORTED: i32 = 1_236;
    pub const WSAEMSGSIZE: i32 = 10_040;
    pub const WSAENETDOWN: i32 = 10_050;
    pub const WSAENETUNREACH: i32 = 10_051;
    pub const WSAENETRESET: i32 = 10_052;
    pub const WSAECONNABORTED: i32 = 10_053;
    pub const WSAECONNRESET: i32 = 10_054;
    pub const WSAESHUTDOWN: i32 = 10_058;
    pub const WSAETIMEDOUT: i32 = 10_060;
    pub const WSAECONNREFUSED: i32 = 10_061;
    pub const WSAEHOSTDOWN: i32 = 10_064;
    pub const WSAEHOSTUNREACH: i32 = 10_065;

    /// Completion statuses that can be contained to one connection generation. Unknown native
    /// completion failures are treated as process-level transport faults by the worker instead
    /// of being hidden behind an endless reconnect loop.
    pub fn is_connection_level(status: i32) -> bool {
        matches!(
            status,
            ERROR_NETNAME_DELETED
                | ERROR_SEM_TIMEOUT
                | ERROR_OPERATION_ABORTED
                | ERROR_CONNECTION_REFUSED
                | ERROR_NETWORK_UNREACHABLE
                | ERROR_HOST_UNREACHABLE
                | ERROR_PROTOCOL_UNREACHABLE
                | ERROR_PORT_UNREACHABLE
                | ERROR_CONNECTION_ABORTED
                | WSAEMSGSIZE
                | WSAENETDOWN
                | WSAENETUNREACH
                | WSAENETRESET
                | WSAECONNABORTED
                | WSAECONNRESET
                | WSAESHUTDOWN
                | WSAETIMEDOUT
                | WSAECONNREFUSED
                | WSAEHOSTDOWN
                | WSAEHOSTUNREACH
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn contexts_round_trip_with_send_slots() {
            for context in [
                RequestContext {
                    index: 0,
                    generation: 1,
                    slot: 0,
                    operation: Operation::Connect,
                },
                RequestContext {
                    index: 123_456,
                    generation: 77,
                    slot: 65_535,
                    operation: Operation::Send,
                },
                RequestContext {
                    index: MAXIMUM_SESSION_INDEX,
                    generation: MAXIMUM_GENERATION,
                    slot: 0,
                    operation: Operation::Receive,
                },
            ] {
                let encoded = encode_context(
                    context.index,
                    context.generation,
                    context.slot,
                    context.operation,
                );
                assert_eq!(decode_context(encoded as usize as u64), Some(context));
            }
        }

        #[test]
        fn invalid_tags_and_zero_generation_are_rejected() {
            assert!(decode_context(0).is_none());
            assert!(decode_context(7).is_none());
            let valid = encode_context(1, 1, 0, Operation::Receive) as usize as u64;
            assert!(decode_context(valid | (1u64 << CONTEXT_BITS)).is_none());
            let forged_receive_slot = valid | (7u64 << (OP_BITS + SESSION_BITS));
            assert!(decode_context(forged_receive_slot).is_none());
        }

        #[test]
        fn generation_wraps_without_using_zero() {
            assert_eq!(next_generation(0), 1);
            assert_eq!(next_generation(1), 2);
            assert_eq!(next_generation(MAXIMUM_GENERATION), 1);
        }

        #[test]
        fn completion_failure_classification_is_not_catch_all() {
            assert!(is_connection_level(WSAECONNRESET));
            assert!(is_connection_level(WSAECONNREFUSED));
            assert!(is_connection_level(ERROR_OPERATION_ABORTED));
            assert!(!is_connection_level(87));
            assert!(!is_connection_level(12_345));
        }
    }
}

pub mod endpoint {
    //! IPv4 endpoint construction and the asynchronous connect handshake.
    //!
    //! The generated tree does not export SO_UPDATE_CONNECT_CONTEXT or INFINITE, so both are
    //! declared here with the values from the Windows headers.

    use core::mem::{size_of, zeroed};
    use core::ptr;

    use windows::Win32::mswsock::LPFN_CONNECTEX;
    use windows::Win32::minwinbase::OVERLAPPED;
    use windows::Win32::winsock2::{SOCKET, bind, setsockopt};
    use windows::Win32::ws2::{
        ADDRINFOW, AF_INET, FreeAddrInfoW, GetAddrInfoW, PADDRINFOW, SOCKADDR, SOCKADDR_IN,
        SOL_SOCKET,
    };
    use windows::core::PCWSTR;

    use crate::native::NativeError;

    /// winsock2.h: SO_UPDATE_CONNECT_CONTEXT, applied after ConnectEx completes so the
    /// socket carries the peer address for getpeername and friends.
    pub const SO_UPDATE_CONNECT_CONTEXT: i32 = 0x7010;
    /// winbase.h: an infinite wait, passed to GetQueuedCompletionStatus.
    pub const INFINITE: u32 = 0xFFFF_FFFF;

    /// ws2def.h: SIO_GET_EXTENSION_FUNCTION_POINTER. A single extension (ConnectEx) is loaded
    /// with this ioctl; SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER (0xC8000024) is only for
    /// the RIO table and rejects a one-entry output buffer with WSAEOPNOTSUPP.
    pub const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;

    /// Resolves the target to an IPv4 endpoint exactly as the reference does: `GetAddrInfoW` with
    /// an AF_INET hint and the port as the service string, so a name is resolved by the system
    /// resolver and an unresolvable one reports the Winsock status rather than a usage error.
    /// The first answer is copied out, matching the reference's single `memcpy`.
    pub fn resolve_ipv4(host: &str, port: u16) -> Result<SOCKADDR_IN, i32> {
        let mut node: Vec<u16> = host.encode_utf16().chain(core::iter::once(0)).collect();
        let mut service: Vec<u16> = port.to_string().encode_utf16().chain(core::iter::once(0)).collect();
        let mut hints: ADDRINFOW = unsafe { zeroed() };
        hints.ai_family = AF_INET as _;
        let mut results: PADDRINFOW = core::ptr::null_mut();
        let status = unsafe {
            GetAddrInfoW(
                PCWSTR(node.as_mut_ptr()),
                PCWSTR(service.as_mut_ptr()),
                Some(&hints),
                &mut results,
            )
        };
        if status != 0 || results.is_null() {
            return Err(status);
        }
        let mut address: SOCKADDR_IN = unsafe { zeroed() };
        unsafe {
            let first = &*results;
            if first.ai_addr.is_null() {
                FreeAddrInfoW(Some(results));
                return Err(WSAEINVAL_LIKE);
            }
            core::ptr::copy_nonoverlapping(
                first.ai_addr as *const SOCKADDR_IN,
                &mut address,
                1,
            );
            FreeAddrInfoW(Some(results));
        }
        Ok(address)
    }

    /// ws2def.h: WSAEINVAL, reported when a resolution succeeded but carried no address. The
    /// reference cannot observe this case because it copies the answer without checking.
    const WSAEINVAL_LIKE: i32 = 10022;

    pub fn sockaddr_ptr(address: &SOCKADDR_IN) -> *const SOCKADDR {
        address as *const SOCKADDR_IN as *const SOCKADDR
    }

    /// A zeroed local address (0.0.0.0:0 unless a fixed local port was requested). ConnectEx
    /// requires the socket to be bound before it is used.
    pub fn local_endpoint(port: u16) -> SOCKADDR_IN {
        let mut address: SOCKADDR_IN = unsafe { zeroed() };
        address.sin_family = AF_INET as _;
        address.sin_port = port.to_be();
        address
    }

    /// Binds the socket to the requested local port, or to an ephemeral wildcard port when
    /// `port == 0`. ConnectEx requires a bound socket, so TCP must not defer this step.
    pub fn bind_local(socket: SOCKET, port: u16) -> Result<(), NativeError> {
        let address = local_endpoint(port);
        let status = unsafe { bind(socket, sockaddr_ptr(&address), size_of::<SOCKADDR_IN>() as i32) };
        if status != 0 {
            return Err(NativeError { stage: "bind(local port)", code: unsafe { windows::Win32::winsock2::WSAGetLastError() } });
        }
        Ok(())
    }

    /// Sets the default peer of a datagram socket. UDP connect performs no network round trip,
    /// so it is synchronous; afterwards RIOReceive/RIOSend work without explicit addresses.
    pub fn connect_udp(socket: SOCKET, target: &SOCKADDR_IN) -> Result<(), NativeError> {
        let status = unsafe { windows::Win32::winsock2::connect(socket, sockaddr_ptr(target), size_of::<SOCKADDR_IN>() as i32) };
        if status != 0 {
            return Err(NativeError {
                stage: "connect(udp peer)",
                code: unsafe { windows::Win32::winsock2::WSAGetLastError() },
            });
        }
        Ok(())
    }

    /// Posts an overlapped ConnectEx. A synchronous TRUE return still produces an IOCP packet
    /// because this client never enables FILE_SKIP_COMPLETION_PORT_ON_SUCCESS; therefore the
    /// caller always waits for exactly one completion and keeps `overlapped` alive until then.
    pub fn begin_connect(
        connect_ex: LPFN_CONNECTEX,
        socket: SOCKET,
        target: &SOCKADDR_IN,
        overlapped: *mut OVERLAPPED,
    ) -> Result<(), NativeError> {
        let connect = connect_ex.ok_or(NativeError { stage: "ConnectEx entry point", code: 13 })?;
        let ok = unsafe {
            connect(
                socket,
                sockaddr_ptr(target),
                size_of::<SOCKADDR_IN>() as i32,
                ptr::null(),
                0,
                ptr::null_mut(),
                overlapped,
            )
        };
        if ok.as_bool() {
            return Ok(());
        }
        // ERROR_IO_PENDING (997) means the operation was accepted and will complete later.
        let code = unsafe { windows::Win32::winsock2::WSAGetLastError() };
        if code == 997 {
            Ok(())
        } else {
            Err(NativeError { stage: "ConnectEx", code })
        }
    }

    /// Applies the connect context once ConnectEx reports completion.
    pub fn update_connect_context(socket: SOCKET) -> Result<(), NativeError> {
        // The documented form of this option passes no value at all.
        let status = unsafe { setsockopt(socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, None, 0) };
        if status != 0 {
            return Err(NativeError {
                stage: "setsockopt(SO_UPDATE_CONNECT_CONTEXT)",
                code: unsafe { windows::Win32::winsock2::WSAGetLastError() },
            });
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn resolution_reports_the_winsock_status() {
            let _winsock = crate::native::Winsock::start().expect("WSAStartup");
            let address = resolve_ipv4("127.0.0.1", 7000).expect("literal address");
            assert_eq!(address.sin_port, 7000u16.to_be());
            assert_eq!(address.sin_family, AF_INET as _);
            // A name is resolved too: this host answers for arbitrary names, so the target below
            // is a name only in shape and the resolution is checked through a name the resolver
            // rejects as a malformed numeric address, which is the case the kit pins.
            assert!(resolve_ipv4("localhost", 7).is_ok());
            let code = match resolve_ipv4("256.256.256.256", 7) {
                Err(code) => code,
                Ok(_) => panic!("an unresolvable address must not produce a socket address"),
            };
            assert_ne!(code, 0);
        }

        #[test]
        fn local_endpoint_defaults_to_the_wildcard_port() {
            let address = local_endpoint(0);
            assert_eq!(address.sin_port, 0);
            assert_eq!(address.sin_family, AF_INET as _);
        }
    }
}

pub mod overlapped {
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
}

pub mod rio {
    //! RIO objects: completion queue, IOCP wake-up, registered buffers and request queues.
    //!
    //! Every call goes through the extension table loaded in `native`: RIO exports no
    //! importable symbols, so a table entry that is missing is a hard error rather than a
    //! silent fallback.

    use core::ffi::c_void;
    use core::ptr;

    use windows::Win32::ioapiset::CreateIoCompletionPort;
    use windows::Win32::{HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::mswsock::{
        LPFN_RIOCLOSECOMPLETIONQUEUE, LPFN_RIODEREGISTERBUFFER, RIO_EVENT_COMPLETION,
        RIO_IOCP_COMPLETION, RIO_NOTIFICATION_COMPLETION,
        RIO_NOTIFICATION_COMPLETION_0, RIO_NOTIFICATION_COMPLETION_0_1,
    };
    use windows::Win32::mswsockdef::{RIO_BUF, RIO_BUFFERID, RIO_CQ, RIO_RQ, RIORESULT};
    use windows::Win32::winsock2::SOCKET;

    use crate::native::{NativeError, RioFunctions};

    /// The IOCP handle RIO signals when a completion queue becomes readable.
    pub struct CompletionPort {
        handle: HANDLE,
    }

    impl CompletionPort {
        pub fn create() -> Result<Self, NativeError> {
            // NumberOfConcurrentThreads == 0 asks Windows to use its processor-count default.
            // This client still owns the worker threads that call GetQueuedCompletionStatus.
            let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 0) };
            // CreateIoCompletionPort reports failure with a null handle (not
            // INVALID_HANDLE_VALUE), and the reason has to be captured at the call site.
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(NativeError {
                    stage: "CreateIoCompletionPort",
                    code: unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32,
                });
            }
            Ok(Self { handle })
        }

        pub fn raw(&self) -> HANDLE {
            self.handle
        }
    }

    impl Drop for CompletionPort {
        fn drop(&mut self) {
            // The port is a kernel handle, so it is closed explicitly rather than at exit,
            // and the result is inspected rather than assumed.
            let closed = unsafe { windows::Win32::handleapi::CloseHandle(self.handle) }.as_bool();
            debug_assert!(closed, "CloseHandle(completion port) failed");
        }
    }

    /// A RIO completion queue bound to an IOCP. Dropping it closes the queue through the
    /// table; the port itself is owned separately.
    pub struct CompletionQueue {
        queue: RIO_CQ,
        capacity: u32,
        armed: bool,
        /// Kept so the queue can be closed without borrowing the transport that owns the
        /// function table; RIO entries are only reachable through that table.
        close: LPFN_RIOCLOSECOMPLETIONQUEUE,
    }

    impl CompletionQueue {
        pub fn create(
            rio: &RioFunctions,
            port: &CompletionPort,
            capacity: u32,
            completion_key: *mut c_void,
            overlapped: *mut c_void,
        ) -> Result<Self, NativeError> {
            let create = rio
                .table()
                .RIOCreateCompletionQueue
                .ok_or(NativeError { stage: "RIOCreateCompletionQueue entry point", code: 13 })?;
            let mut notification = RIO_NOTIFICATION_COMPLETION::default();
            notification.Type = RIO_IOCP_COMPLETION;
            notification.Anonymous = RIO_NOTIFICATION_COMPLETION_0 {
                Iocp: RIO_NOTIFICATION_COMPLETION_0_1 {
                    IocpHandle: port.raw(),
                    CompletionKey: completion_key,
                    Overlapped: overlapped,
                },
            };
            let queue = unsafe { create(capacity, &mut notification as *mut RIO_NOTIFICATION_COMPLETION) };
            if queue.is_null() {
                // The table entry reports through its return value; the reason is captured here
                // rather than being replaced by a placeholder code.
                return Err(NativeError {
                    stage: "RIOCreateCompletionQueue",
                    code: unsafe { windows::Win32::winsock2::WSAGetLastError() },
                });
            }
            Ok(Self {
                queue,
                capacity,
                armed: false,
                close: rio.table().RIOCloseCompletionQueue,
            })
        }

        pub fn raw(&self) -> RIO_CQ {
            self.queue
        }

        pub fn capacity(&self) -> u32 {
            self.capacity
        }

        /// Arms the IOCP notification. The queue is only armed while work is in flight, so a
        /// busy worker never pays for a redundant RIONotify.
        pub fn arm(&mut self, rio: &RioFunctions) -> Result<(), NativeError> {
            if self.armed {
                return Ok(());
            }
            let notify = rio
                .table()
                .RIONotify
                .ok_or(NativeError { stage: "RIONotify entry point", code: 13 })?;
            // Only ERROR_SUCCESS is accepted: any other status leaves the queue unarmed and
            // the caller must not assume a wake-up is coming.
            let status = unsafe { notify(self.queue) };
            // WSAEALREADY (10037) means a notification is already pending for this queue: the
            // queue is armed, which is exactly the requested state. Treating it as a failure
            // would kill sessions that are merely re-arming after an unrelated delivery.
            if status != 0 && status != WSAEALREADY {
                return Err(NativeError { stage: "RIONotify", code: status });
            }
            self.armed = true;
            Ok(())
        }

        /// A delivery clears the armed state; the next queued operation re-arms it.
        pub fn on_delivery(&mut self) {
            self.armed = false;
        }

        pub fn is_armed(&self) -> bool {
            self.armed
        }

        /// Drains up to `results.len()` completions. RIO_CORRUPT_CQ is reported as a hard
        /// failure instead of being mistaken for "no work".
        pub fn dequeue(
            &mut self,
            rio: &RioFunctions,
            results: &mut [RIORESULT],
        ) -> Result<u32, NativeError> {
            let dequeue = rio
                .table()
                .RIODequeueCompletion
                .ok_or(NativeError { stage: "RIODequeueCompletion entry point", code: 13 })?;
            let capacity = u32::try_from(results.len())
                .map_err(|_| NativeError { stage: "RIODequeueCompletion capacity", code: 13 })?;
            if capacity == 0 || capacity > self.capacity {
                return Err(NativeError { stage: "RIODequeueCompletion capacity", code: 13 });
            }
            let count = unsafe { dequeue(self.queue, results.as_mut_ptr(), capacity) };
            if count == u32::MAX {
                return Err(NativeError { stage: "RIODequeueCompletion(RIO_CORRUPT_CQ)", code: 13 });
            }
            if count > capacity {
                return Err(NativeError { stage: "RIODequeueCompletion count", code: 13 });
            }
            Ok(count)
        }
    }

    impl Drop for CompletionQueue {
        fn drop(&mut self) {
            // The queue must be released through the RIO table; leaving it to process exit
            // would leak the provider-side object for the whole run.
            if let Some(close) = self.close {
                unsafe { close(self.queue) };
            }
        }
    }

    /// A registered memory region. RIO requires every buffer to be registered before it can
    /// be referenced by a RIO_BUF.
    pub struct RegisteredBuffer {
        id: RIO_BUFFERID,
        length: u32,
        /// Kept for the same reason as the queue's close pointer.
        deregister: LPFN_RIODEREGISTERBUFFER,
    }

    impl RegisteredBuffer {
        pub fn register(rio: &RioFunctions, bytes: &mut [u8]) -> Result<Self, NativeError> {
            let register = rio
                .table()
                .RIORegisterBuffer
                .ok_or(NativeError { stage: "RIORegisterBuffer entry point", code: 13 })?;
            let length = u32::try_from(bytes.len())
                .map_err(|_| NativeError { stage: "RIORegisterBuffer length", code: 13 })?;
            let id = unsafe { register(bytes.as_mut_ptr() as *mut i8, length) };
            if id.is_null() {
                return Err(NativeError::winsock_last("RIORegisterBuffer"));
            }
            Ok(Self { id, length, deregister: rio.table().RIODeregisterBuffer })
        }

        pub fn raw(&self) -> RIO_BUFFERID {
            self.id
        }

        pub fn length(&self) -> u32 {
            self.length
        }

        /// Builds a descriptor for a slice of the registered region. Bounds are checked here
        /// so the engine can never hand RIO an out-of-range view.
        pub fn slice(&self, offset: u32, length: u32) -> Result<RIO_BUF, NativeError> {
            if length == 0 || offset > self.length || length > self.length - offset {
                return Err(NativeError { stage: "RIO_BUF slice bounds", code: 13 });
            }
            Ok(RIO_BUF { BufferId: self.id, Offset: offset, Length: length })
        }
    }

    impl Drop for RegisteredBuffer {
        fn drop(&mut self) {
            // Deregistering is only legal once no I/O references the region, which the arena
            // guarantees by being dropped after every socket and request queue.
            if let Some(deregister) = self.deregister {
                unsafe { deregister(self.id) };
            }
        }
    }

    /// A request queue over one socket, using the same queue for receive and send.
    pub struct RequestQueue {
        queue: RIO_RQ,
    }

    impl RequestQueue {
        #[allow(clippy::too_many_arguments)]
        pub fn create(
            rio: &RioFunctions,
            socket: SOCKET,
            receive_depth: u32,
            receive_buffers: u32,
            send_depth: u32,
            send_buffers: u32,
            receive_queue: RIO_CQ,
            send_queue: RIO_CQ,
            socket_context: *mut c_void,
        ) -> Result<Self, NativeError> {
            let create = rio
                .table()
                .RIOCreateRequestQueue
                .ok_or(NativeError { stage: "RIOCreateRequestQueue entry point", code: 13 })?;
            let queue = unsafe {
                create(
                    socket,
                    receive_depth,
                    receive_buffers,
                    send_depth,
                    send_buffers,
                    receive_queue,
                    send_queue,
                    socket_context,
                )
            };
            if queue.is_null() {
                return Err(NativeError::winsock_last("RIOCreateRequestQueue"));
            }
            Ok(Self { queue })
        }

        pub fn raw(&self) -> RIO_RQ {
            self.queue
        }

        /// Posts a receive. The request context is what comes back in RIORESULT.
        pub fn receive(
            &self,
            rio: &RioFunctions,
            buffer: &RIO_BUF,
            request_context: *mut c_void,
        ) -> Result<(), NativeError> {
            let receive = rio
                .table()
                .RIOReceive
                .ok_or(NativeError { stage: "RIOReceive entry point", code: 13 })?;
            let ok = unsafe { receive(self.queue, buffer as *const RIO_BUF as *mut RIO_BUF, 1, 0, request_context) };
            if !ok.as_bool() {
                return Err(NativeError::winsock_last("RIOReceive"));
            }
            Ok(())
        }

        /// Posts a send of one buffer.
        pub fn send(
            &self,
            rio: &RioFunctions,
            buffer: &RIO_BUF,
            request_context: *mut c_void,
        ) -> Result<(), NativeError> {
            let send = rio
                .table()
                .RIOSend
                .ok_or(NativeError { stage: "RIOSend entry point", code: 13 })?;
            let ok = unsafe { send(self.queue, buffer as *const RIO_BUF as *mut RIO_BUF, 1, 0, request_context) };
            if !ok.as_bool() {
                return Err(NativeError::winsock_last("RIOSend"));
            }
            Ok(())
        }
    }

    /// IOCP completion key used to distinguish a queue notification from other events.
    pub const RIO_COMPLETION_KEY: usize = 0x5249_4f00;

    /// Winsock's "a notification is already pending" status, reported by RIONotify.
    pub const WSAEALREADY: i32 = 10_037;

    /// Zeroed result slot: RIO writes every field of each dequeued entry.
    pub fn empty_result() -> RIORESULT {
        RIORESULT { Status: 0, BytesTransferred: 0, SocketContext: 0, RequestContext: 0 }
    }

    /// Keeps the unused imports honest: the event-driven completion mode stays available for
    /// builds that want a waitable handle instead of an IOCP wake-up.
    pub const EVENT_COMPLETION_MODE: i32 = RIO_EVENT_COMPLETION;

    /// Null pointer helper so call sites read as intent rather than as casts.
    pub fn no_context() -> *mut c_void {
        ptr::null_mut()
    }
}
