//! Win32/Winsock ownership, socket creation and runtime failure reporting.
//!
//! windows-rs 0.100 organises its generated surface by Windows header, and its
//! signatures differ from the published 0.6x line (for example `WSASocketW` returns a
//! raw `SOCKET` and `WSAStartup` returns an `i32` status). Every path and signature
//! used here was read from the committed bindings under
//! `crates/libs/windows/src/Windows/Win32/<header>/mod.rs` in the resolved revision.

use core::ffi::c_void;
use core::mem::size_of;

use windows::Win32::mswsock::{LPFN_CONNECTEX, RIO_EXTENSION_FUNCTION_TABLE};
use windows::Win32::winsock2::WSAGetLastError;
use windows::Win32::winsock2::{
    INVALID_SOCKET, SOCKET, WSA_FLAG_OVERLAPPED, WSA_FLAG_REGISTERED_IO, WSACleanup, WSADATA,
    WSAIoctl, WSASocketW, WSAStartup, closesocket, setsockopt,
};
use windows::Win32::ws2::{
    AF_INET, IPPROTO_TCP, IPPROTO_UDP, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, SO_RCVBUF,
    SO_SNDBUF, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, TCP_NODELAY,
};
use windows::core::GUID;

use crate::types::Protocol;

/// A Win32 failure together with the API stage that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeError {
    pub stage: &'static str,
    pub code: i32,
    pub origin: crate::types::FailureDomain,
}

/// Borrow the process-owned CRT wide argv, using the same quoting rules as C++ wmain.
/// Initialization occurs once: subsequent safe calls cannot invalidate a prior argv view.
#[derive(Clone, Copy)]
pub struct NativeArguments {
    arguments: &'static [*mut u16],
}

// The CRT owns this read-only array through process shutdown. Only current() initializes it,
// under OnceLock; this wrapper exposes no mutation or reconfiguration operation.
unsafe impl Send for NativeArguments {}
unsafe impl Sync for NativeArguments {}

#[link(name = "ucrt")]
unsafe extern "C" {
    fn _configure_wide_argv(mode: i32) -> i32;
    fn __p___argc() -> *mut i32;
    fn __p___wargv() -> *mut *mut *mut u16;
}

impl NativeArguments {
    pub fn current() -> Result<Self, NativeError> {
        static ARGUMENTS: std::sync::OnceLock<Result<NativeArguments, NativeError>> =
            std::sync::OnceLock::new();
        *ARGUMENTS.get_or_init(|| {
            // _crt_argv_unexpanded = 1, matching the reference's default CRT startup.
            if unsafe { *__p___wargv() }.is_null() && unsafe { _configure_wide_argv(1) } != 0 {
                return Err(crate::types::Failure::allocation("command line arguments").into());
            }
            let count = unsafe { *__p___argc() };
            let pointer = unsafe { *__p___wargv() };
            if count < 1 || pointer.is_null() {
                return Err(NativeError {
                    stage: "command line arguments",
                    code: 87,
                    origin: crate::types::FailureDomain::Win32,
                });
            }
            // SAFETY: successful CRT configuration publishes count initialized, NUL-terminated
            // arguments. Their owners live through CRT process shutdown, after Rust main exits.
            let arguments = unsafe { core::slice::from_raw_parts(pointer, count as usize) };
            if arguments.iter().any(|argument| argument.is_null()) {
                return Err(NativeError {
                    stage: "command line arguments",
                    code: 87,
                    origin: crate::types::FailureDomain::Win32,
                });
            }
            Ok(Self { arguments })
        })
    }
    pub fn len(&self) -> usize {
        self.arguments.len()
    }
    pub fn is_empty(&self) -> bool {
        self.arguments.is_empty()
    }
    pub(crate) fn argument(&self, index: usize) -> &[u16] {
        let pointer = self.arguments[index];
        let mut length = 0;
        // SAFETY: current() accepts only the CRT's initialized NUL-terminated argument pointers.
        unsafe {
            while *pointer.add(length) != 0 {
                length += 1;
            }
            core::slice::from_raw_parts(pointer, length)
        }
    }
}

#[link(name = "Kernel32")]
unsafe extern "system" {
    fn GetStdHandle(kind: u32) -> *mut c_void;
    fn WriteFile(
        handle: *mut c_void,
        bytes: *const c_void,
        count: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn GetEnvironmentVariableW(name: *const u16, value: *mut u16, capacity: u32) -> u32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        sharing: u32,
        security: *const c_void,
        creation: u32,
        attributes: u32,
        template: *mut c_void,
    ) -> *mut c_void;
}

/// Rendering and output use stack storage rather than stdio's lazy heap buffer. As in the
/// reference, an unavailable or broken output stream does not change the program's exit code.
pub fn write_stdout(arguments: core::fmt::Arguments<'_>) {
    write_output(unsafe { GetStdHandle((-11i32) as u32) }, arguments);
}
pub fn write_stderr(arguments: core::fmt::Arguments<'_>) {
    write_output(unsafe { GetStdHandle((-12i32) as u32) }, arguments);
}

struct OutputBuffer<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    length: usize,
}
impl<const CAPACITY: usize> core::fmt::Write for OutputBuffer<CAPACITY> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self
            .length
            .checked_add(text.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(core::fmt::Error)?;
        self.bytes[self.length..end].copy_from_slice(text.as_bytes());
        self.length = end;
        Ok(())
    }
}

fn write_output(handle: *mut c_void, arguments: core::fmt::Arguments<'_>) -> bool {
    let mut output = OutputBuffer {
        bytes: [0; 4_096],
        length: 0,
    };
    if core::fmt::write(&mut output, arguments).is_err() {
        return false;
    }
    if handle.is_null() || handle == (-1isize) as *mut c_void {
        return false;
    }
    static OUTPUT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = OUTPUT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut offset = 0;
    while offset < output.length {
        let mut written = 0;
        let ok = unsafe {
            WriteFile(
                handle,
                output.bytes[offset..output.length].as_ptr().cast(),
                (output.length - offset) as u32,
                &mut written,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 || written as usize > output.length - offset {
            return false;
        }
        offset += written as usize;
    }
    true
}

pub(crate) fn environment_present(name: &str) -> bool {
    let mut units = [0u16; 64];
    if name.len() >= units.len() || !name.is_ascii() {
        return false;
    }
    for (unit, byte) in units.iter_mut().zip(name.bytes()) {
        *unit = u16::from(byte);
    }
    unsafe {
        windows::Win32::errhandlingapi::SetLastError(0);
        let required = GetEnvironmentVariableW(units.as_ptr(), core::ptr::null_mut(), 0);
        required != 0 || windows::Win32::errhandlingapi::GetLastError() != 203
    }
}

/// Optional diagnostics mirror the reference's fixed 512-wide-character path and file flags.
pub(crate) struct DiagnosticFile {
    handle: *mut c_void,
}
impl DiagnosticFile {
    pub(crate) fn open() -> Option<Self> {
        let name: [u16; 14] = [67, 69, 67, 95, 68, 73, 65, 71, 95, 70, 73, 76, 69, 0];
        let required = unsafe { GetEnvironmentVariableW(name.as_ptr(), core::ptr::null_mut(), 0) };
        if required == 0 || required > 512 {
            return None;
        }
        let mut path = [0u16; 512];
        let count =
            unsafe { GetEnvironmentVariableW(name.as_ptr(), path.as_mut_ptr(), path.len() as u32) };
        if count == 0 || count >= path.len() as u32 {
            return None;
        }
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0x4000_0000,
                1,
                core::ptr::null(),
                2,
                0x80,
                core::ptr::null_mut(),
            )
        };
        (handle != (-1isize) as *mut c_void).then_some(Self { handle })
    }
    pub(crate) fn write(&self, arguments: core::fmt::Arguments<'_>) -> bool {
        let mut output = OutputBuffer {
            bytes: [0; 191],
            length: 0,
        };
        // C++ _snprintf_s rejects a line that cannot fit, including the trailing NUL, in 192 bytes.
        if core::fmt::write(&mut output, arguments).is_err() {
            return true;
        }
        let mut written = 0;
        unsafe {
            WriteFile(
                self.handle,
                output.bytes.as_ptr().cast(),
                output.length as u32,
                &mut written,
                core::ptr::null_mut(),
            ) != 0
                && written == output.length as u32
        }
    }
}
impl Drop for DiagnosticFile {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::handleapi::CloseHandle(self.handle);
        }
    }
}

struct ThreadState<T> {
    value: core::cell::UnsafeCell<Option<T>>,
    run: fn(&mut T),
    finished: core::sync::atomic::AtomicBool,
}

/// One fallible packet allocation replaces std::thread's infallible Arc/Box setup. The packet
/// stays at its boxed address until the native Join barrier; only the worker mutates its value.
pub(crate) struct NativeThread<T> {
    handle: *mut c_void,
    state: Option<core::ptr::NonNull<ThreadState<T>>>,
}

impl<T: Send + 'static> NativeThread<T> {
    pub(crate) fn spawn(
        value: T,
        run: fn(&mut T),
        stage: &'static str,
    ) -> Result<Self, NativeError> {
        let state = crate::types::try_box(
            ThreadState {
                value: core::cell::UnsafeCell::new(Some(value)),
                run,
                finished: core::sync::atomic::AtomicBool::new(false),
            },
            "client worker allocation",
        )
        .map_err(NativeError::from)?;
        // Convert the Box into raw ownership before publishing: moving a live Box after deriving
        // the callback pointer could invalidate that pointer's exclusive provenance.
        let state = core::ptr::NonNull::new(Box::into_raw(state))
            .unwrap_or_else(|| fail_fast("native thread packet", 13));
        let parameter = state.as_ptr().cast::<c_void>();
        // SAFETY: failure starts no callback; success keeps raw packet ownership until Join.
        // No Box or value reference is reconstructed while the callback can access the packet.
        let handle = unsafe {
            windows::Win32::processthreadsapi::CreateThread(
                None,
                0,
                Some(native_thread_entry::<T>),
                Some(parameter),
                0,
                None,
            )
        };
        if handle.is_null() {
            let error = NativeError {
                stage,
                code: unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32,
                origin: crate::types::FailureDomain::Win32,
            };
            // SAFETY: failed CreateThread starts no callback and the packet accepted no I/O.
            unsafe {
                drop(Box::from_raw(state.as_ptr()));
            }
            return Err(error);
        }
        Ok(Self {
            handle,
            state: Some(state),
        })
    }
    pub(crate) fn is_finished(&self) -> bool {
        match unsafe { windows::Win32::synchapi::WaitForSingleObject(self.handle, 0) } {
            0 => true,
            258 => false,
            _ => fail_fast("WaitForSingleObject(client worker)", unsafe {
                windows::Win32::errhandlingapi::GetLastError()
            } as i32),
        }
    }
    pub(crate) fn join(&mut self) -> T {
        if unsafe { windows::Win32::synchapi::WaitForSingleObject(self.handle, u32::MAX) } != 0 {
            fail_fast("WaitForSingleObject(client worker)", unsafe {
                windows::Win32::errhandlingapi::GetLastError()
            } as i32);
        }
        let state = self
            .state
            .take()
            .unwrap_or_else(|| fail_fast("native thread join state", 13));
        // SAFETY: native termination plus Acquire publication end every worker borrow before
        // recovering exclusive Box ownership and moving the result to the coordinator.
        if !unsafe { state.as_ref() }
            .finished
            .load(core::sync::atomic::Ordering::Acquire)
        {
            fail_fast("native thread result publication", 13);
        }
        let ThreadState { value, .. } = *unsafe { Box::from_raw(state.as_ptr()) };
        value
            .into_inner()
            .unwrap_or_else(|| fail_fast("native thread result ownership", 13))
    }
}

impl<T> Drop for NativeThread<T> {
    fn drop(&mut self) {
        // Checking inside this owner prevents every caller from freeing a live callback packet.
        if self.state.is_some() {
            fail_fast("native thread release before join", 996);
        }
        if !self.handle.is_null() {
            unsafe {
                let _ = windows::Win32::handleapi::CloseHandle(self.handle);
            }
        }
    }
}

unsafe extern "system" fn native_thread_entry<T: Send + 'static>(parameter: *mut c_void) -> u32 {
    // SAFETY: the typed packet is stable and exclusively borrowed by this callback until Join.
    let state = unsafe { &*parameter.cast::<ThreadState<T>>() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let value = unsafe { &mut *state.value.get() };
        let value = value
            .as_mut()
            .unwrap_or_else(|| fail_fast("native thread entry ownership", 13));
        (state.run)(value);
    }));
    if result.is_err() {
        fail_fast("native thread panic", 13);
    }
    state
        .finished
        .store(true, core::sync::atomic::Ordering::Release);
    0
}

/// Ownership/CQ faults cannot unwind through resources still borrowed by Windows.
pub fn fail_fast(stage: &str, code: i32) -> ! {
    write_stderr(format_args!("{stage} failed: native_error={code}\n"));
    unsafe {
        let _ = windows::Win32::processthreadsapi::TerminateProcess(
            windows::Win32::processthreadsapi::GetCurrentProcess(),
            crate::types::ExitCode::Internal as u32,
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

impl NativeError {
    pub fn invariant(stage: &'static str) -> Self {
        fail_fast(stage, 13)
    }
    pub(crate) fn winsock_last(stage: &'static str) -> Self {
        // The code is captured at the failing call site; GetLastError is never read later.
        Self {
            stage,
            code: unsafe { WSAGetLastError() },
            origin: crate::types::FailureDomain::Winsock,
        }
    }
}

impl From<crate::types::Failure> for NativeError {
    fn from(error: crate::types::Failure) -> Self {
        Self {
            stage: error.stage,
            code: error.code,
            origin: error.domain,
        }
    }
}

impl From<NativeError> for String {
    fn from(error: NativeError) -> Self {
        format!("{} failed: native_error={}", error.stage, error.code)
    }
}

impl core::fmt::Display for NativeError {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "{} failed: native_error={}", self.stage, self.code)
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
            return Err(NativeError {
                origin: crate::types::FailureDomain::Winsock,
                stage: "WSAStartup",
                code: status,
            });
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
            return Err(NativeError {
                origin: crate::types::FailureDomain::Winsock,
                stage: "registered_socket(protocol)",
                code: 87,
            });
        }
    };
    // The bindings expose the WSA_FLAG_* constants as i32; dwflags is u32.
    let flags = (WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO) as u32;
    let socket = unsafe { WSASocketW(AF_INET, kind, transport, None, Default::default(), flags) };
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
    for (stage, option, bytes) in [
        (
            "setsockopt(SO_SNDBUF/SO_RCVBUF)",
            SO_SNDBUF,
            send_buffer_bytes,
        ),
        (
            "setsockopt(SO_SNDBUF/SO_RCVBUF)",
            SO_RCVBUF,
            receive_buffer_bytes,
        ),
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
    Ok(())
}

/// {8509E081-96DD-4005-B165-9E2EE8C79E3F}: the RIO extension identifier. windows-rs
/// 0.100 does not export the WSAID_* constants, so it is declared here with the value
/// the Swift port already runs against.
const WSAID_MULTIPLE_RIO: GUID = GUID::from_u128(0x8509_e081_96dd_4005_b165_9e2e_e8c7_9e3f);

/// The RIO entry points. RIO is never imported as a flat symbol: every function is
/// reached through this table, which the provider fills in for the running stack.
#[derive(Clone, Copy)]
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
                "SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER(RIO)",
            ));
        }
        if returned != expected || table.cbSize != expected {
            return Err(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIO table size",
                code: 13,
            });
        }
        if table.RIOReceive.is_none()
            || table.RIOSend.is_none()
            || table.RIOCreateCompletionQueue.is_none()
            || table.RIOCloseCompletionQueue.is_none()
            || table.RIOCreateRequestQueue.is_none()
            || table.RIORegisterBuffer.is_none()
            || table.RIODeregisterBuffer.is_none()
            || table.RIODequeueCompletion.is_none()
            || table.RIONotify.is_none()
        {
            return Err(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIO table entry points",
                code: 13,
            });
        }
        Ok(Self { table })
    }

    pub fn table(&self) -> &RIO_EXTENSION_FUNCTION_TABLE {
        &self.table
    }

    #[cfg(test)]
    pub(crate) fn from_test_table(table: RIO_EXTENSION_FUNCTION_TABLE) -> Self {
        Self { table }
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
        return Err(NativeError::winsock_last(
            "SIO_GET_EXTENSION_FUNCTION_POINTER(ConnectEx)",
        ));
    }
    if function.is_none() || returned != size_of::<LPFN_CONNECTEX>() as u32 {
        return Err(NativeError {
            origin: crate::types::FailureDomain::Invariant,
            stage: "ConnectEx entry point",
            code: 13,
        });
    }
    Ok(function)
}

// The Windows substrate is grouped here: the queue wrappers, the completion bookkeeping, the
// overlapped storage, the registered arena and the endpoint helpers are submodules of this module.

pub mod arena {
    //! One worker-owned virtual allocation for both directions of registered RIO memory.
    //!
    //! TX windows precede RX windows, and each session has a disjoint window in each region.
    //! RX and TX use one registration per session window: the
    //! documented RIOSend contract prohibits using any other portion of its registration while
    //! the send is pending, even when those portions would otherwise be disjoint.

    use core::ffi::c_void;

    use windows::Win32::memoryapi::{VirtualAlloc, VirtualFree};
    use windows::Win32::mswsockdef::RIO_BUF;

    use crate::native::rio::RegisteredBuffer;
    use crate::native::{NativeError, RioFunctions};

    const MEM_COMMIT: u32 = 0x0000_1000;
    const MEM_RESERVE: u32 = 0x0000_2000;
    const MEM_RELEASE: u32 = 0x0000_8000;
    const PAGE_READWRITE: u32 = 0x04;

    fn release_pages(base: *mut u8) -> bool {
        unsafe { VirtualFree(base as *mut c_void, 0, MEM_RELEASE) }.as_bool()
    }

    /// Always performs the release, and fails fast when the region is still mapped. A failed
    /// `VirtualFree` means Windows still holds the pages, which is a release-boundary invariant
    /// exactly like the outstanding-operation checks, not a diagnostic to compile away: the C++ and
    /// .NET clients fail fast on the same result.
    fn release_pages_checked(base: *mut u8) {
        if !release_pages(base) {
            let code = unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32;
            crate::native::fail_fast("VirtualFree(registered arena)", code);
        }
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

    fn checked_worker_bytes(slots: u32, stride: u32) -> Option<u32> {
        if slots == 0 || stride == 0 {
            return None;
        }
        slots.checked_mul(stride)?.checked_mul(2)
    }

    /// A fixed-stride worker arena. Its complete TX/RX footprint fits in a DWORD, matching the
    /// reference's worker storage budget. All registrations retire before the sole page owner.
    pub struct Arena {
        base: *mut u8,
        bytes: usize,
        stride: u32,
        slots: u32,
        receive_offset: usize,
        send_registrations: Vec<RegisteredBuffer>,
        receive_registrations: Vec<RegisteredBuffer>,
    }

    impl Arena {
        /// Fill each TX window directly from the payload, avoiding an intermediate batch copy.
        /// Construction failures use the same deregister-before-unmap ownership order as Drop.
        pub fn create_worker(
            rio: &RioFunctions,
            slots: u32,
            stride: u32,
            payload: &[u8],
        ) -> Result<Self, NativeError> {
            if payload.is_empty() || stride as usize % payload.len() != 0 {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "worker arena payload dimensions",
                    code: 13,
                });
            }
            let bytes = checked_worker_bytes(slots, stride).ok_or(NativeError {
                origin: crate::types::FailureDomain::Allocation,
                stage: "worker arena DWORD capacity",
                code: 8,
            })? as usize;
            let receive_offset = bytes / 2;
            if bytes > isize::MAX as usize {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "worker arena exceeds Rust pointer-offset range",
                    code: 13,
                });
            }
            let base =
                unsafe { VirtualAlloc(None, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) }
                    as *mut u8;
            if base.is_null() {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Win32,
                    stage: "VirtualAlloc(client arena)",
                    code: unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32,
                });
            }
            let mut arena = Self {
                base,
                bytes,
                stride,
                slots,
                receive_offset,
                send_registrations: Vec::new(),
                receive_registrations: Vec::new(),
            };
            // VirtualAlloc has the reference's failure priority over registration-owner storage.
            // The arena guard already owns the pages, so either reserve failure releases them.
            arena
                .send_registrations
                .try_reserve_exact(slots as usize)
                .map_err(|_| NativeError {
                    origin: crate::types::FailureDomain::Allocation,
                    stage: "client registration owners",
                    code: 8,
                })?;
            arena
                .receive_registrations
                .try_reserve_exact(slots as usize)
                .map_err(|_| NativeError {
                    origin: crate::types::FailureDomain::Allocation,
                    stage: "client registration owners",
                    code: 8,
                })?;
            for slot in 0..slots as usize {
                let offset = checked_slot_offset(slot, stride as usize, receive_offset).ok_or(
                    NativeError {
                        origin: crate::types::FailureDomain::Invariant,
                        stage: "worker arena send slot bounds",
                        code: 13,
                    },
                )?;
                let send =
                    unsafe { core::slice::from_raw_parts_mut(base.add(offset), stride as usize) };
                for unit in send.chunks_exact_mut(payload.len()) {
                    unit.copy_from_slice(payload);
                }
                arena
                    .send_registrations
                    .push(RegisteredBuffer::register(rio, send)?);
            }
            for slot in 0..slots as usize {
                let offset = checked_slot_offset(slot, stride as usize, receive_offset).ok_or(
                    NativeError {
                        origin: crate::types::FailureDomain::Invariant,
                        stage: "worker arena receive slot bounds",
                        code: 13,
                    },
                )?;
                let receive = unsafe {
                    core::slice::from_raw_parts_mut(
                        base.add(receive_offset + offset),
                        stride as usize,
                    )
                };
                arena
                    .receive_registrations
                    .push(RegisteredBuffer::register(rio, receive)?);
            }
            Ok(arena)
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

        pub fn send_view(&self, slot: u32, length: u32) -> Result<RIO_BUF, NativeError> {
            self.send_view_from(slot, 0, length)
        }

        /// A view of part of a slot, used to re-post the remainder of a partially completed send.
        pub fn send_view_from(
            &self,
            slot: u32,
            offset: u32,
            length: u32,
        ) -> Result<RIO_BUF, NativeError> {
            let registration = self
                .send_registrations
                .get(slot as usize)
                .ok_or(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "worker arena send view bounds",
                    code: 13,
                })?;
            registration.slice(offset, length)
        }

        pub fn receive_view(&self, slot: u32, length: u32) -> Result<RIO_BUF, NativeError> {
            let _offset =
                checked_slot_offset(slot as usize, self.stride as usize, self.receive_offset)
                    .filter(|_| length != 0 && length <= self.stride)
                    .ok_or(NativeError {
                        origin: crate::types::FailureDomain::Invariant,
                        stage: "worker arena receive view bounds",
                        code: 13,
                    })?;
            self.receive_registrations
                .get(slot as usize)
                .ok_or(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "worker arena receive registration unavailable",
                    code: 13,
                })?
                .slice(0, length)
        }

        /// Reads bytes written by a completed receive. The caller must only call this after the
        /// corresponding completion has been dequeued and before that slot is reposted.
        pub fn read_receive(&self, slot: u32, length: u32) -> &[u8] {
            if self.receive_registrations.get(slot as usize).is_none()
                || slot >= self.slots
                || length == 0
                || length > self.stride
            {
                return &[];
            }
            let offset =
                match checked_slot_offset(slot as usize, self.stride as usize, self.receive_offset)
                {
                    Some(offset) => offset,
                    None => return &[],
                };
            unsafe {
                core::slice::from_raw_parts(
                    self.base.add(self.receive_offset + offset),
                    length as usize,
                )
            }
        }
    }

    impl Drop for Arena {
        fn drop(&mut self) {
            // Deregister every BufferId while its virtual memory is still mapped.
            self.send_registrations.clear();
            self.receive_registrations.clear();
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

        #[test]
        fn worker_footprint_reserves_both_directions_and_fits_dword() {
            assert_eq!(checked_worker_bytes(4, 1024), Some(8192));
            assert_eq!(checked_worker_bytes(0, 1024), None);
            assert_eq!(checked_worker_bytes(4, 0), None);
            assert_eq!(checked_worker_bytes(1, u32::MAX / 2), Some(u32::MAX - 1));
            assert_eq!(checked_worker_bytes(1, u32::MAX / 2 + 1), None);
            assert_eq!(checked_worker_bytes(u32::MAX, 2), None);
        }
    }
}

pub mod clock {
    //! Production clock: the reference's raw high-resolution performance counter. Deadlines
    //! keep tick precision; only the blocking IOCP wait is rounded up to milliseconds.
    //!
    //! The blocking wait lives in the transport (Transport::wait_and_drain), because only that
    //! layer can see both the completion port and the RIO completion queue.

    use windows::Win32::errhandlingapi::GetLastError;
    use windows::Win32::profileapi::{QueryPerformanceCounter, QueryPerformanceFrequency};
    use windows::Win32::winnt::LARGE_INTEGER;

    use crate::native::NativeError;
    use crate::worker::Clock;

    fn ticks_to_milliseconds(ticks: u64, frequency: u64) -> u64 {
        // Keep the ordinary path to one native-width division; use wider arithmetic only
        // when the scaled counter would overflow, and never wrap a deadline backwards.
        if let Some(scaled) = ticks.checked_mul(1_000) {
            scaled / frequency
        } else {
            ((u128::from(ticks) * 1_000) / u128::from(frequency)).min(u128::from(u64::MAX)) as u64
        }
    }

    pub(crate) fn milliseconds_to_ticks(milliseconds: u64, frequency: u64) -> u64 {
        if let Some(scaled) = milliseconds.checked_mul(frequency) {
            scaled.div_ceil(1_000)
        } else {
            (u128::from(milliseconds) * u128::from(frequency))
                .div_ceil(1_000)
                .min(u128::from(u64::MAX)) as u64
        }
    }

    pub(crate) fn ticks_to_wait_milliseconds(ticks: u64, frequency: u64) -> u64 {
        if let Some(scaled) = ticks.checked_mul(1_000) {
            scaled.div_ceil(frequency)
        } else {
            (u128::from(ticks) * 1_000)
                .div_ceil(u128::from(frequency))
                .min(u128::from(u64::MAX)) as u64
        }
    }

    fn counter() -> Result<u64, NativeError> {
        let mut value = LARGE_INTEGER::default();
        if !unsafe { QueryPerformanceCounter(&mut value) }.as_bool() {
            return Err(NativeError {
                origin: crate::types::FailureDomain::Win32,
                stage: "QueryPerformanceCounter(client timer)",
                code: unsafe { GetLastError() } as i32,
            });
        }
        u64::try_from(unsafe { value.QuadPart }).map_err(|_| NativeError {
            origin: crate::types::FailureDomain::Invariant,
            stage: "QueryPerformanceCounter(client timer value)",
            code: 13,
        })
    }

    /// Real time for the worker loop.
    #[derive(Debug)]
    pub struct RioClock {
        ticks_per_second: u64,
    }

    impl RioClock {
        pub fn new() -> Result<Self, NativeError> {
            let mut frequency = LARGE_INTEGER::default();
            if !unsafe { QueryPerformanceFrequency(&mut frequency) }.as_bool() {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Win32,
                    stage: "QueryPerformanceFrequency",
                    code: unsafe { GetLastError() } as i32,
                });
            }
            let ticks_per_second = unsafe { frequency.QuadPart };
            if ticks_per_second <= 0 {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Win32,
                    stage: "QueryPerformanceFrequency",
                    code: unsafe { GetLastError() } as i32,
                });
            }
            Ok(Self {
                ticks_per_second: ticks_per_second as u64,
            })
        }
    }

    impl Clock for RioClock {
        fn now_milliseconds(&mut self) -> u64 {
            ticks_to_milliseconds(self.now_ticks(), self.ticks_per_second)
        }

        fn ticks_per_second(&self) -> u64 {
            self.ticks_per_second
        }

        fn now_ticks(&mut self) -> u64 {
            // A failed timer cannot unwind through provider-owned I/O or change clock domains.
            counter().unwrap_or_else(|error| crate::native::fail_fast(error.stage, error.code))
        }

        fn wait(&mut self, _milliseconds: u32) {
            // Intentionally empty: the transport performs the blocking wait so that ConnectEx
            // completions and RIO completions are observed together.
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{milliseconds_to_ticks, ticks_to_milliseconds, ticks_to_wait_milliseconds};

        #[test]
        fn performance_counter_preserves_millisecond_boundaries() {
            assert_eq!(ticks_to_milliseconds(0, 1_000_000), 0);
            assert_eq!(ticks_to_milliseconds(999, 1_000_000), 0);
            assert_eq!(ticks_to_milliseconds(1_000, 1_000_000), 1);
            assert_eq!(ticks_to_milliseconds(1_999, 1_000_000), 1);
            assert_eq!(ticks_to_milliseconds(2_000, 1_000_000), 2);
        }

        #[test]
        fn large_counter_values_do_not_wrap_the_clock() {
            assert_eq!(ticks_to_milliseconds(u64::MAX, 1_000), u64::MAX);
            assert_eq!(ticks_to_milliseconds(u64::MAX, 1), u64::MAX);
            assert_eq!(ticks_to_milliseconds(u64::MAX, u64::MAX), 1_000);
        }

        #[test]
        fn tick_deadlines_and_waits_round_up_without_overflow() {
            assert_eq!(milliseconds_to_ticks(1, 1_000_000), 1_000);
            assert_eq!(milliseconds_to_ticks(1, 1_001), 2);
            assert_eq!(milliseconds_to_ticks(u64::MAX, u64::MAX), u64::MAX);
            assert_eq!(ticks_to_wait_milliseconds(0, 1_000_000), 0);
            assert_eq!(ticks_to_wait_milliseconds(1, 1_000_000), 1);
            assert_eq!(ticks_to_wait_milliseconds(1_001, 1_000_000), 2);
            assert_eq!(ticks_to_wait_milliseconds(u64::MAX, 1), u64::MAX);
            assert_eq!(ticks_to_wait_milliseconds(u64::MAX, u64::MAX), 1_000);
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
            | ((u64::from(generation) & GENERATION_MASK) << (OP_BITS + SESSION_BITS + SLOT_BITS));
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
        let generation = (context >> (OP_BITS + SESSION_BITS + SLOT_BITS)) & GENERATION_MASK;

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

    use windows::Win32::minwinbase::OVERLAPPED;
    use windows::Win32::mswsock::LPFN_CONNECTEX;
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
        try_resolve_ipv4(host, port).map_err(|error| error.code)
    }

    pub(crate) fn try_resolve_ipv4(host: &str, port: u16) -> Result<SOCKADDR_IN, NativeError> {
        let mut node = crate::types::try_vec_with_capacity(
            host.len().saturating_add(1),
            "target address allocation",
        )?;
        node.extend(host.encode_utf16());
        node.push(0);
        resolve_ipv4_wide(node.as_ptr(), port)
    }

    pub(crate) fn try_resolve_options(
        host: &crate::types::OptionText<256>,
        port: u16,
    ) -> Result<SOCKADDR_IN, NativeError> {
        resolve_ipv4_wide(host.as_ptr(), port)
    }

    fn resolve_ipv4_wide(node: *const u16, port: u16) -> Result<SOCKADDR_IN, NativeError> {
        // A decimal u16 and its terminator fit in fixed stack storage.
        let mut service = [0u16; 6];
        let mut number = port;
        let mut begin = 5;
        loop {
            begin -= 1;
            service[begin] = u16::from(b'0') + number % 10;
            number /= 10;
            if number == 0 {
                break;
            }
        }
        let mut hints: ADDRINFOW = unsafe { zeroed() };
        hints.ai_family = AF_INET as _;
        let mut results: PADDRINFOW = core::ptr::null_mut();
        let status = unsafe {
            GetAddrInfoW(
                PCWSTR(node),
                PCWSTR(service[begin..].as_ptr()),
                Some(&hints),
                &mut results,
            )
        };
        if status != 0 || results.is_null() {
            return Err(NativeError {
                stage: "GetAddrInfoW(IPv4)",
                code: status,
                origin: crate::types::FailureDomain::Winsock,
            });
        }
        let mut address: SOCKADDR_IN = unsafe { zeroed() };
        unsafe {
            let first = &*results;
            if first.ai_addr.is_null() {
                FreeAddrInfoW(Some(results));
                return Err(NativeError {
                    stage: "GetAddrInfoW(IPv4)",
                    code: WSAEINVAL_LIKE,
                    origin: crate::types::FailureDomain::Winsock,
                });
            }
            core::ptr::copy_nonoverlapping(first.ai_addr as *const SOCKADDR_IN, &mut address, 1);
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
        let status = unsafe {
            bind(
                socket,
                sockaddr_ptr(&address),
                size_of::<SOCKADDR_IN>() as i32,
            )
        };
        if status != 0 {
            return Err(NativeError {
                origin: crate::types::FailureDomain::Winsock,
                stage: "bind(client)",
                code: unsafe { windows::Win32::winsock2::WSAGetLastError() },
            });
        }
        Ok(())
    }

    /// Sets the default peer of a datagram socket. UDP connect performs no network round trip,
    /// so it is synchronous; afterwards RIOReceive/RIOSend work without explicit addresses.
    pub fn connect_udp(socket: SOCKET, target: &SOCKADDR_IN) -> Result<(), NativeError> {
        let status = unsafe {
            windows::Win32::winsock2::connect(
                socket,
                sockaddr_ptr(target),
                size_of::<SOCKADDR_IN>() as i32,
            )
        };
        if status != 0 {
            return Err(NativeError {
                origin: crate::types::FailureDomain::Winsock,
                stage: "connect/RQ(UDP client)",
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
        let connect = connect_ex.ok_or(NativeError {
            origin: crate::types::FailureDomain::Invariant,
            stage: "ConnectEx entry point",
            code: 13,
        })?;
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
            Err(NativeError {
                origin: crate::types::FailureDomain::Winsock,
                stage: "ConnectEx",
                code,
            })
        }
    }

    /// Applies the connect context once ConnectEx reports completion.
    pub fn update_connect_context(socket: SOCKET) -> Result<(), NativeError> {
        // The documented form of this option passes no value at all.
        let status = unsafe { setsockopt(socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, None, 0) };
        if status != 0 {
            return Err(NativeError {
                origin: crate::types::FailureDomain::Winsock,
                stage: "ConnectEx completion",
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
                    origin: crate::types::FailureDomain::Invariant,
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
                    origin: crate::types::FailureDomain::Invariant,
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
                    origin: crate::types::FailureDomain::Invariant,
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
                    origin: crate::types::FailureDomain::Invariant,
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
    use windows::Win32::mswsock::{
        LPFN_RIOCLOSECOMPLETIONQUEUE, LPFN_RIODEREGISTERBUFFER, RIO_EVENT_COMPLETION,
        RIO_IOCP_COMPLETION, RIO_NOTIFICATION_COMPLETION, RIO_NOTIFICATION_COMPLETION_0,
        RIO_NOTIFICATION_COMPLETION_0_1,
    };
    use windows::Win32::mswsockdef::{
        RIO_BUF, RIO_BUFFERID, RIO_CQ, RIO_INVALID_BUFFERID, RIO_RQ, RIORESULT,
    };
    use windows::Win32::winsock2::SOCKET;
    use windows::Win32::{HANDLE, INVALID_HANDLE_VALUE};

    use crate::native::{NativeError, RioFunctions};

    /// The IOCP handle RIO signals when a completion queue becomes readable.
    pub struct CompletionPort {
        handle: HANDLE,
    }

    impl CompletionPort {
        pub fn create() -> Result<Self, NativeError> {
            // NumberOfConcurrentThreads == 0 asks Windows to use its processor-count default.
            // This client still owns the worker threads that call GetQueuedCompletionStatus.
            let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1) };
            // CreateIoCompletionPort reports failure with a null handle (not
            // INVALID_HANDLE_VALUE), and the reason has to be captured at the call site.
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Win32,
                    stage: "CreateIoCompletionPort(client worker)",
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
            // The port is a kernel handle, so it is closed explicitly rather than at exit. A failed
            // close leaves the handle open, which is a release-boundary invariant: fail fast instead
            // of leaking it, as the C++ and .NET clients do.
            if !unsafe { windows::Win32::handleapi::CloseHandle(self.handle) }.as_bool() {
                let code = unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32;
                crate::native::fail_fast("CloseHandle(completion port)", code);
            }
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
            let create = rio.table().RIOCreateCompletionQueue.ok_or(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIOCreateCompletionQueue entry point",
                code: 13,
            })?;
            let mut notification = RIO_NOTIFICATION_COMPLETION::default();
            notification.Type = RIO_IOCP_COMPLETION;
            notification.Anonymous = RIO_NOTIFICATION_COMPLETION_0 {
                Iocp: RIO_NOTIFICATION_COMPLETION_0_1 {
                    IocpHandle: port.raw(),
                    CompletionKey: completion_key,
                    Overlapped: overlapped,
                },
            };
            let queue = unsafe {
                create(
                    capacity,
                    &mut notification as *mut RIO_NOTIFICATION_COMPLETION,
                )
            };
            if queue.is_null() {
                // The table entry reports through its return value; the reason is captured here
                // rather than being replaced by a placeholder code.
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Winsock,
                    stage: "RIOCreateCompletionQueue(client)",
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
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "RIO notification duplicate arm",
                    code: 5023,
                });
            }
            let notify = rio.table().RIONotify.ok_or(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIONotify entry point",
                code: 13,
            })?;
            // Only ERROR_SUCCESS is accepted: any other status leaves the queue unarmed and
            // the caller must not assume a wake-up is coming.
            let status = unsafe { notify(self.queue) };
            // WSAEALREADY means our ownership state disagrees with the provider. Keep it as an
            // internal error instead of taking ownership of an untracked notification.
            if status != 0 {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Winsock,
                    stage: "RIONotify",
                    code: status,
                });
            }
            self.armed = true;
            Ok(())
        }

        /// A delivery clears the armed state; the next queued operation re-arms it.
        pub fn on_delivery(&mut self) -> Result<(), NativeError> {
            if !self.armed {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "RIO notification delivery transition",
                    code: 5023,
                });
            }
            self.armed = false;
            Ok(())
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
            let dequeue = rio.table().RIODequeueCompletion.ok_or(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIODequeueCompletion entry point",
                code: 13,
            })?;
            let capacity = u32::try_from(results.len()).map_err(|_| NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIODequeueCompletion capacity",
                code: 13,
            })?;
            if capacity == 0 {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "RIODequeueCompletion capacity",
                    code: 13,
                });
            }
            let count = unsafe { dequeue(self.queue, results.as_mut_ptr(), capacity) };
            if count == u32::MAX {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "RIODequeueCompletion(RIO_CORRUPT_CQ)",
                    code: 13,
                });
            }
            if count > capacity {
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "RIODequeueCompletion count",
                    code: 13,
                });
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
            let register = rio.table().RIORegisterBuffer.ok_or(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIORegisterBuffer entry point",
                code: 13,
            })?;
            let length = u32::try_from(bytes.len()).map_err(|_| NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIORegisterBuffer length",
                code: 13,
            })?;
            let id = unsafe { register(bytes.as_mut_ptr() as *mut i8, length) };
            if id.is_null() || id == RIO_INVALID_BUFFERID {
                return Err(NativeError::winsock_last(
                    "RIORegisterBuffer(client windows)",
                ));
            }
            Ok(Self {
                id,
                length,
                deregister: rio.table().RIODeregisterBuffer,
            })
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
                return Err(NativeError {
                    origin: crate::types::FailureDomain::Invariant,
                    stage: "RIO_BUF slice bounds",
                    code: 13,
                });
            }
            Ok(RIO_BUF {
                BufferId: self.id,
                Offset: offset,
                Length: length,
            })
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
            let create = rio.table().RIOCreateRequestQueue.ok_or(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIOCreateRequestQueue entry point",
                code: 13,
            })?;
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
                return Err(NativeError::winsock_last("RIOCreateRequestQueue(client)"));
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
            flags: u32,
        ) -> Result<(), NativeError> {
            let receive = rio.table().RIOReceive.ok_or(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIOReceive entry point",
                code: 13,
            })?;
            let ok = unsafe {
                receive(
                    self.queue,
                    buffer as *const RIO_BUF as *mut RIO_BUF,
                    1,
                    flags,
                    request_context,
                )
            };
            if !ok.as_bool() {
                return Err(NativeError::winsock_last("RIOReceive(client)"));
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
            let send = rio.table().RIOSend.ok_or(NativeError {
                origin: crate::types::FailureDomain::Invariant,
                stage: "RIOSend entry point",
                code: 13,
            })?;
            let ok = unsafe {
                send(
                    self.queue,
                    buffer as *const RIO_BUF as *mut RIO_BUF,
                    1,
                    0,
                    request_context,
                )
            };
            if !ok.as_bool() {
                return Err(NativeError::winsock_last("RIOSend(client)"));
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
        RIORESULT {
            Status: 0,
            BytesTransferred: 0,
            SocketContext: 0,
            RequestContext: 0,
        }
    }

    /// Keeps the unused imports honest: the event-driven completion mode stays available for
    /// builds that want a waitable handle instead of an IOCP wake-up.
    pub const EVENT_COMPLETION_MODE: i32 = RIO_EVENT_COMPLETION;

    /// Null pointer helper so call sites read as intent rather than as casts.
    pub fn no_context() -> *mut c_void {
        ptr::null_mut()
    }
}
