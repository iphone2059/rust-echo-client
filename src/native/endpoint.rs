//! IPv4 endpoint construction and the asynchronous connect handshake.
//!
//! The generated tree does not export SO_UPDATE_CONNECT_CONTEXT or INFINITE, so both are
//! declared here with the values from the Windows headers.

use core::ffi::c_void;
use core::mem::{size_of, zeroed};
use core::ptr;

use windows::Win32::mswsock::LPFN_CONNECTEX;
use windows::Win32::minwinbase::OVERLAPPED;
use windows::Win32::winsock2::{SOCKET, bind, setsockopt};
use windows::core::PCSTR;
use windows::Win32::ws2::{AF_INET, SOCKADDR, SOCKADDR_IN, SOL_SOCKET, inet_pton};

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

/// Builds an IPv4 sockaddr. The port is converted with to_be, which is exactly what
/// htons does, so no extra Winsock import is needed.
pub fn ipv4_endpoint(host: &str, port: u16) -> Result<SOCKADDR_IN, NativeError> {
    let mut address: SOCKADDR_IN = unsafe { zeroed() };
    address.sin_family = AF_INET as _;
    address.sin_port = port.to_be();
    if host.is_empty() {
        return Err(NativeError { stage: "ipv4_endpoint(host)", code: 87 });
    }
    let mut text = host.as_bytes().to_vec();
    text.push(0);
    // PCSTR is what the generic parameter of inet_pton is bound to, and the address
    // field is written through without naming its union type.
    let status = unsafe {
        inet_pton(
            AF_INET,
            PCSTR(text.as_ptr()),
            &mut address.sin_addr as *mut _ as *mut c_void,
        )
    };
    if status != 1 {
        return Err(NativeError { stage: "inet_pton(target host)", code: 87 });
    }
    Ok(address)
}

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
    fn endpoints_encode_host_and_port() {
        let _winsock = crate::native::Winsock::start().expect("WSAStartup");
        let address = ipv4_endpoint("127.0.0.1", 7000).expect("endpoint");
        assert_eq!(address.sin_port, 7000u16.to_be());
        assert_eq!(address.sin_family, AF_INET as _);
        assert!(ipv4_endpoint("", 7).is_err());
        assert!(ipv4_endpoint("not an address", 7).is_err());
    }

    #[test]
    fn local_endpoint_defaults_to_the_wildcard_port() {
        let address = local_endpoint(0);
        assert_eq!(address.sin_port, 0);
        assert_eq!(address.sin_family, AF_INET as _);
    }
}
