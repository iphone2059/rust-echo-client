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
