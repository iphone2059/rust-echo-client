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
pub mod arena;
pub mod completion;
pub mod endpoint;
pub mod overlapped;
pub mod rio;


