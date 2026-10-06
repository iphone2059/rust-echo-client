//! RIO transport with explicit generation retirement.
//!
//! The important ownership rule is simple: closing a socket starts cancellation, it does
//! not end the lifetime of pending I/O. A generation therefore keeps its request queue,
//! ConnectEx OVERLAPPED and registered buffers alive until every completion has actually
//! been dequeued. Only then is `GenerationDrained` reported to the scheduler.

use core::ffi::c_void;
use core::ptr;
use std::time::{Duration, Instant};

use windows::Win32::ioapiset::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows::Win32::minwinbase::OVERLAPPED;
use windows::Win32::mswsock::LPFN_CONNECTEX;
use windows::Win32::mswsockdef::RIORESULT;
use windows::Win32::winsock2::SOCKET;
use windows::Win32::ws2::SOCKADDR_IN;

use crate::native::arena::Arena;
use crate::native::completion::{
    MAXIMUM_SEND_SLOT, MAXIMUM_SESSION_INDEX, NO_SEND_SLOT, Operation, RequestContext,
    WSAEMSGSIZE, decode_context, encode_context, next_generation,
};
use crate::native::endpoint::{
    begin_connect, bind_local, connect_udp, ipv4_endpoint, update_connect_context,
};
use crate::native::{
    NativeError, RioFunctions, SocketOwner, configure_socket, load_connect_ex, registered_socket,
};
use crate::native::overlapped::PendingOverlapped;
use crate::native::rio::{CompletionPort, CompletionQueue, RequestQueue};
use crate::types::{Options, Protocol};
use crate::engine::{Completion, Transport};

pub const MAX_RECEIVE: u32 = 1;
pub const COMPLETION_BATCH_SIZE: usize = 256;
const WAIT_TIMEOUT: i32 = 258;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn stage(error: NativeError) -> String {
    crate::trace::event_args(
        "TRANSPORT_ERROR",
        format_args!("{} code={}", error.stage, error.code),
    );
    format!("{} (code {})", error.stage, error.code)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenerationState {
    Empty,
    Connecting,
    Active,
    Closing,
}

struct SessionTransport {
    generation: u32,
    state: GenerationState,
    connect_outstanding: bool,
    send_outstanding: u32,
    receive_outstanding: u32,
    /// Exact length of the one posted RIOReceive; zero when no receive is outstanding.
    receive_posted_bytes: u32,
    socket: Option<SocketOwner>,
    request_queue: Option<RequestQueue>,
    connect_ex: Option<LPFN_CONNECTEX>,
    overlapped: PendingOverlapped,
    target: SOCKADDR_IN,
    tx_in_use: Vec<bool>,
    free_tx_slots: Vec<u32>,
}

impl SessionTransport {
    fn new(target: SOCKADDR_IN, max_send: u32) -> Self {
        Self {
            generation: 0,
            state: GenerationState::Empty,
            connect_outstanding: false,
            send_outstanding: 0,
            receive_outstanding: 0,
            receive_posted_bytes: 0,
            socket: None,
            request_queue: None,
            connect_ex: None,
            overlapped: PendingOverlapped::new(),
            target,
            tx_in_use: vec![false; max_send as usize],
            free_tx_slots: (0..max_send).rev().collect(),
        }
    }

    fn socket(&self) -> Result<SOCKET, String> {
        self.socket
            .as_ref()
            .map(SocketOwner::raw)
            .ok_or_else(|| "session has no socket".to_string())
    }

    fn queue(&self) -> Result<&RequestQueue, String> {
        self.request_queue
            .as_ref()
            .ok_or_else(|| "session has no request queue".to_string())
    }

    fn generation_drained(&self) -> bool {
        !self.connect_outstanding
            && self.send_outstanding == 0
            && self.receive_outstanding == 0
    }

    fn allocate_send_slot(&mut self) -> Option<u32> {
        let slot = self.free_tx_slots.pop()?;
        let used = self.tx_in_use.get_mut(slot as usize)?;
        debug_assert!(!*used, "free-list returned an in-use TX slot");
        if *used {
            return None;
        }
        *used = true;
        Some(slot)
    }

    fn release_send_slot(&mut self, slot: u32) -> Result<(), String> {
        let Some(used) = self.tx_in_use.get_mut(slot as usize) else {
            return Err("send completion has an out-of-range slot".to_string());
        };
        if !*used {
            return Err("send completion references a free slot".to_string());
        }
        *used = false;
        self.free_tx_slots.push(slot);
        Ok(())
    }

    fn reset_generation_storage(&mut self) -> Result<(), String> {
        if !self.generation_drained() {
            return Err("generation released before all completions drained".to_string());
        }
        if self.tx_in_use.iter().any(|used| *used) {
            return Err("generation drained while a send slot is still busy".to_string());
        }
        if self.free_tx_slots.len() != self.tx_in_use.len() {
            return Err("generation drained with an inconsistent TX free-list".to_string());
        }
        if self.receive_posted_bytes != 0 {
            return Err("generation drained with a stale receive length".to_string());
        }
        if self.overlapped.is_armed() {
            return Err("generation drained while ConnectEx OVERLAPPED is armed".to_string());
        }
        self.request_queue = None;
        self.connect_ex = None;
        self.socket = None;
        self.overlapped.reset_after_drain().map_err(stage)?;
        self.state = GenerationState::Empty;
        Ok(())
    }
}

pub struct RioTransport {
    // Safe fallback drop order if explicit shutdown cannot run to completion:
    // sessions -> CQ -> IOCP -> CQ notification OVERLAPPED -> registered arenas.
    sessions: Vec<SessionTransport>,
    queue: Option<CompletionQueue>,
    port: Option<CompletionPort>,
    notification_overlapped: Option<Box<OVERLAPPED>>,
    send_arena: Option<Arena>,
    receive_arena: Option<Arena>,
    rio: RioFunctions,
    results: Vec<RIORESULT>,
    protocol: Protocol,
    pending: Vec<Completion>,
    no_delay: bool,
    send_buffer_bytes: u32,
    receive_buffer_bytes: u32,
    local_port: u16,
    max_send: u32,
    payload_bytes: u32,
    shutdown_started: bool,
    resources_leaked: bool,
}

impl RioTransport {
    pub fn new(
        options: &Options,
        session_count: u32,
        payload: std::sync::Arc<[u8]>,
        memory_bytes: u64,
    ) -> Result<Self, String> {
        if session_count == 0 || payload.is_empty() {
            return Err("transport requires at least one session and one payload byte".to_string());
        }
        let payload_bytes = u32::try_from(payload.len())
            .map_err(|_| "payload is too large for a RIO_BUF".to_string())?;
        let max_send = options.pipeline_depth.max(1);
        if u64::from(session_count) > u64::from(MAXIMUM_SESSION_INDEX) + 1 {
            return Err("session count exceeds request-context capacity".to_string());
        }
        if u64::from(max_send) > u64::from(MAXIMUM_SEND_SLOT) + 1 {
            return Err("pipeline depth exceeds request-context send-slot capacity".to_string());
        }
        if options.cq_capacity == 0 {
            return Err("completion queue capacity must be non-zero".to_string());
        }

        let probe = registered_socket(options.protocol).map_err(stage)?;
        let rio = RioFunctions::load(probe.raw()).map_err(stage)?;

        // RQ reservations are charged against the shared CQ. With one receive and /k sends
        // per session the sum is exact, not an estimate.
        let per_session = u64::from(MAX_RECEIVE)
            .checked_add(u64::from(max_send))
            .ok_or_else(|| "request queue reservation overflow".to_string())?;
        let required_cq = u64::from(session_count)
            .checked_mul(per_session)
            .ok_or_else(|| "completion queue reservation overflow".to_string())?;
        if required_cq > u64::from(options.cq_capacity) {
            return Err(format!(
                "completion queue capacity {} is smaller than the {required_cq} entries reserved by {session_count} sessions at /k {max_send}",
                options.cq_capacity
            ));
        }

        let send_slots = u64::from(session_count)
            .checked_mul(u64::from(max_send))
            .ok_or_else(|| "send slot count overflow".to_string())?;
        let receive_bytes = u64::from(session_count)
            .checked_mul(u64::from(payload_bytes))
            .ok_or_else(|| "receive arena size overflow".to_string())?;
        let send_bytes = send_slots
            .checked_mul(u64::from(payload_bytes))
            .ok_or_else(|| "send arena size overflow".to_string())?;
        let required_memory = receive_bytes
            .checked_add(send_bytes)
            .ok_or_else(|| "registered memory size overflow".to_string())?;
        if required_memory > memory_bytes {
            return Err(format!(
                "RIO registered memory needs {required_memory} bytes (RX {receive_bytes} + TX {send_bytes}) but this worker budget is {memory_bytes}"
            ));
        }
        let send_slots_u32 = u32::try_from(send_slots)
            .map_err(|_| "too many TX slots for the registered arena".to_string())?;

        // Local declaration order is chosen for the constructor-error path too: Rust drops
        // locals in reverse order, giving CQ -> IOCP -> notification OVERLAPPED if anything
        // after queue creation fails. The steady-state shutdown uses the same ordering.
        let mut notification_overlapped = Box::new(OVERLAPPED::default());
        let port = CompletionPort::create().map_err(stage)?;
        let queue = CompletionQueue::create(
            &rio,
            &port,
            options.cq_capacity,
            crate::native::rio::RIO_COMPLETION_KEY as *mut c_void,
            &mut *notification_overlapped as *mut OVERLAPPED as *mut c_void,
        )
        .map_err(stage)?;

        // RX sessions use disjoint slices of aggregated registrations; each concurrent TX
        // slot has its own RIO_BUFFERID. The latter is required by the RIOSend buffer rules.
        let receive_arena = Arena::create_receive(&rio, session_count, payload_bytes).map_err(stage)?;
        let send_arena = Arena::create_send(&rio, send_slots_u32, &payload).map_err(stage)?;
        let target = ipv4_endpoint(&options.host, options.remote_port).map_err(stage)?;
        let sessions = (0..session_count)
            .map(|_| SessionTransport::new(target, max_send))
            .collect();

        Ok(Self {
            sessions,
            queue: Some(queue),
            port: Some(port),
            notification_overlapped: Some(notification_overlapped),
            send_arena: Some(send_arena),
            receive_arena: Some(receive_arena),
            rio,
            results: vec![
                RIORESULT::default();
                COMPLETION_BATCH_SIZE
                    .min(options.cq_capacity as usize)
                    .max(1)
            ],
            protocol: options.protocol,
            pending: Vec::new(),
            no_delay: options.protocol == Protocol::Tcp,
            send_buffer_bytes: options.socket_buffer_bytes,
            receive_buffer_bytes: options.socket_buffer_bytes,
            local_port: options.local_port,
            max_send,
            payload_bytes,
            shutdown_started: false,
            resources_leaked: false,
        })
    }

    fn queue(&self) -> Result<&CompletionQueue, String> {
        self.queue
            .as_ref()
            .ok_or_else(|| "transport completion queue is closed".to_string())
    }

    fn arm_queue(&mut self) -> Result<(), String> {
        let rio = &self.rio;
        let queue = self
            .queue
            .as_mut()
            .ok_or_else(|| "transport completion queue is closed".to_string())?;
        queue.arm(rio).map_err(stage)
    }

    fn port(&self) -> Result<&CompletionPort, String> {
        self.port
            .as_ref()
            .ok_or_else(|| "transport completion port is closed".to_string())
    }

    fn has_native_outstanding(&self) -> bool {
        self.sessions.iter().any(|slot| {
            slot.connect_outstanding || slot.send_outstanding != 0 || slot.receive_outstanding != 0
        })
    }

    fn generation_of(&self, index: u32) -> Result<u32, String> {
        self.sessions
            .get(index as usize)
            .map(|slot| slot.generation)
            .ok_or_else(|| "session index out of range".to_string())
    }

    fn prepare(&mut self, index: u32) -> Result<(), String> {
        if self.shutdown_started {
            return Err("transport is shutting down".to_string());
        }
        let slot_index = index as usize;
        let current_generation = self
            .sessions
            .get(slot_index)
            .ok_or_else(|| "session index out of range".to_string())?
            .generation;
        if self.sessions[slot_index].state != GenerationState::Empty {
            return Err("previous connection generation has not drained".to_string());
        }
        let generation = next_generation(current_generation);

        let socket = registered_socket(self.protocol).map_err(stage)?;
        let associated = unsafe {
            CreateIoCompletionPort(
                socket.raw() as *mut c_void,
                Some(self.port()?.raw()),
                encode_context(index, generation, NO_SEND_SLOT, Operation::Connect) as usize,
                0,
            )
        };
        if associated.is_null() {
            return Err(format!(
                "CreateIoCompletionPort(socket) failed with {}",
                unsafe { windows::Win32::errhandlingapi::GetLastError() }
            ));
        }

        configure_socket(
            socket.raw(),
            self.no_delay,
            self.send_buffer_bytes,
            self.receive_buffer_bytes,
        )
        .map_err(stage)?;
        bind_local(socket.raw(), self.local_port).map_err(stage)?;
        let connect_ex = match self.protocol {
            Protocol::Udp => None,
            Protocol::Tcp => Some(load_connect_ex(socket.raw()).map_err(stage)?),
            Protocol::None => return Err("protocol is not selected".to_string()),
        };
        let queue_raw = self.queue()?.raw();
        let request_queue = RequestQueue::create(
            &self.rio,
            socket.raw(),
            MAX_RECEIVE,
            1,
            self.max_send,
            1,
            queue_raw,
            queue_raw,
            encode_context(index, generation, NO_SEND_SLOT, Operation::Connect),
        )
        .map_err(stage)?;

        // Copy scalar configuration before taking the mutable session borrow. This keeps
        // the initialization block trivially disjoint even on stricter borrow-check paths.
        let max_send = self.max_send;
        let slot = &mut self.sessions[slot_index];
        slot.generation = generation;
        slot.state = GenerationState::Connecting;
        slot.connect_outstanding = false;
        slot.send_outstanding = 0;
        slot.receive_outstanding = 0;
        slot.receive_posted_bytes = 0;
        slot.tx_in_use.fill(false);
        slot.free_tx_slots.clear();
        slot.free_tx_slots.extend((0..max_send).rev());
        slot.connect_ex = connect_ex;
        slot.request_queue = Some(request_queue);
        slot.socket = Some(socket);
        slot.overlapped.reset_after_drain().map_err(stage)?;

        crate::trace::event_args(
            "GENERATION_BEGIN",
            format_args!("session={index} generation={generation}"),
        );
        Ok(())
    }

    fn tx_global_slot(&self, index: u32, slot: u32) -> Result<u32, String> {
        let global = u64::from(index)
            .checked_mul(u64::from(self.max_send))
            .and_then(|base| base.checked_add(u64::from(slot)))
            .ok_or_else(|| "TX slot index overflow".to_string())?;
        u32::try_from(global).map_err(|_| "TX slot index exceeds arena".to_string())
    }

    fn finish_generation(&mut self, index: u32) -> Result<Completion, String> {
        let slot = self
            .sessions
            .get_mut(index as usize)
            .ok_or_else(|| "session index out of range".to_string())?;
        let generation = slot.generation;
        slot.reset_generation_storage()?;
        crate::trace::event_args(
            "GENERATION_DRAINED",
            format_args!("session={index} generation={generation}"),
        );
        Ok(Completion {
            index,
            generation,
            slot: NO_SEND_SLOT,
            operation: Operation::GenerationDrained,
            status: 0,
            bytes: 0,
        })
    }

    fn begin_close(&mut self, index: u32) -> Result<(), String> {
        let slot_index = index as usize;
        let Some(slot) = self.sessions.get_mut(slot_index) else {
            return Err("session index out of range".to_string());
        };
        if slot.state == GenerationState::Closing {
            return Ok(());
        }
        if slot.state == GenerationState::Empty {
            // A connect/setup post can fail before a native generation exists. The scheduler
            // has already moved to Closing and still needs the same retirement handshake to
            // decide between permanent failure and reconnect. Emit the internal drain event
            // immediately because there is no native resource left to wait for.
            if !self.shutdown_started {
                self.pending.push(Completion {
                    index,
                    generation: slot.generation,
                    slot: NO_SEND_SLOT,
                    operation: Operation::GenerationDrained,
                    status: 0,
                    bytes: 0,
                });
            }
            return Ok(());
        }

        crate::trace::event_args(
            "CLOSE_BEGIN",
            format_args!("session={index} generation={}", slot.generation),
        );
        slot.state = GenerationState::Closing;
        // closesocket releases the RQ and starts cancellation. Keep the RQ value,
        // OVERLAPPED and registered buffers alive until their completions are dequeued.
        drop(slot.socket.take());
        let drained = slot.generation_drained();

        if drained {
            let completion = self.finish_generation(index)?;
            self.pending.push(completion);
        } else if let Err(error) = self.arm_queue() {
            return Err(error);
        }
        Ok(())
    }

    /// Retires exactly one native completion into the caller-owned batch. Cancellation
    /// completions for a generation already in Closing are consumed internally; only the
    /// final GenerationDrained event is exposed to the scheduler. The caller owns the Vec so
    /// this hot path performs no per-completion heap allocation.
    fn retire_into(
        &mut self,
        context: RequestContext,
        status: i32,
        bytes: u32,
        completions: &mut Vec<Completion>,
    ) -> Result<(), String> {
        let slot_index = context.index as usize;
        let Some(session) = self.sessions.get_mut(slot_index) else {
            return Err("completion has an out-of-range session index".to_string());
        };
        if context.generation != session.generation {
            crate::trace::event_args(
                "STALE_COMPLETION",
                format_args!(
                    "session={} generation={} live={}",
                    context.index, context.generation, session.generation
                ),
            );
            return Ok(());
        }

        let closing = session.state == GenerationState::Closing;
        match context.operation {
            Operation::Connect => {
                if !session.connect_outstanding {
                    return Err("duplicate/unexpected ConnectEx completion".to_string());
                }
                session.connect_outstanding = false;
                session.overlapped.complete().map_err(stage)?;
            }
            Operation::Send => {
                if session.send_outstanding == 0 {
                    return Err("send completion arrived with no send outstanding".to_string());
                }
                session.release_send_slot(context.slot)?;
                session.send_outstanding -= 1;
            }
            Operation::Receive => {
                if session.receive_outstanding != 1 || session.receive_posted_bytes == 0 {
                    return Err(
                        "receive completion arrived without exactly one receive outstanding"
                            .to_string(),
                    );
                }
                if bytes > session.receive_posted_bytes && status != WSAEMSGSIZE {
                    return Err(format!(
                        "receive completion transferred {bytes} bytes into a {}-byte request",
                        session.receive_posted_bytes
                    ));
                }
                session.receive_outstanding = 0;
                session.receive_posted_bytes = 0;
            }
            Operation::GenerationDrained => {
                return Err("GenerationDrained cannot come from an OS request".to_string());
            }
        }

        if !closing {
            completions.push(Completion {
                index: context.index,
                generation: context.generation,
                slot: context.slot,
                operation: context.operation,
                status,
                bytes,
            });
        }

        if self.sessions[slot_index].state == GenerationState::Closing
            && self.sessions[slot_index].generation_drained()
        {
            completions.push(self.finish_generation(context.index)?);
        }
        Ok(())
    }

    fn drain_rio_into(
        &mut self,
        budget: u32,
        completions: &mut Vec<Completion>,
    ) -> Result<(), String> {
        for _ in 0..budget {
            let count = {
                let rio = &self.rio;
                let results = &mut self.results;
                let queue = self
                    .queue
                    .as_mut()
                    .ok_or_else(|| "transport completion queue is closed".to_string())?;
                queue.dequeue(rio, results).map_err(stage)?
            };
            if count == 0 {
                break;
            }
            // Do not clear the RIONotify armed state merely because CQ entries were
            // dequeued. The one-shot notification is retired only when its IOCP packet is
            // actually consumed by GetQueuedCompletionStatus (RIO_COMPLETION_KEY). An
            // unrelated ConnectEx packet may be observed first while the RIO notification
            // is still queued.
            for position in 0..count as usize {
                let item = self.results[position];
                let context = decode_context(item.RequestContext)
                    .ok_or_else(|| "completion has an invalid request context".to_string())?;
                self.retire_into(context, item.Status, item.BytesTransferred, completions)?;
            }
        }
        Ok(())
    }

    fn wait_iocp_once_into(
        &mut self,
        wait_ms: u32,
        completions: &mut Vec<Completion>,
    ) -> Result<(), String> {
        let mut bytes = 0u32;
        let mut key = 0u64;
        let mut overlapped: *mut OVERLAPPED = ptr::null_mut();
        let signaled = unsafe {
            GetQueuedCompletionStatus(
                self.port()?.raw(),
                &mut bytes,
                &mut key,
                &mut overlapped,
                wait_ms,
            )
        };

        if signaled.as_bool() {
            if key as usize == crate::native::rio::RIO_COMPLETION_KEY {
                self.queue
                    .as_mut()
                    .ok_or_else(|| "transport completion queue is closed".to_string())?
                    .on_delivery();
                return Ok(());
            }
            let context = decode_context(key)
                .ok_or_else(|| "IOCP completion has an invalid completion key".to_string())?;
            self.retire_into(context, 0, bytes, completions)?;
            return Ok(());
        }

        let error = unsafe { windows::Win32::errhandlingapi::GetLastError() } as i32;
        if !overlapped.is_null() {
            let context = decode_context(key)
                .ok_or_else(|| "failed IOCP completion has an invalid completion key".to_string())?;
            self.retire_into(context, error, bytes, completions)?;
            return Ok(());
        }
        if error == WAIT_TIMEOUT {
            Ok(())
        } else {
            Err(format!("GetQueuedCompletionStatus failed ({error})"))
        }
    }

    fn release_resources(&mut self) {
        // The notification OVERLAPPED and IOCP both outlive the CQ configuration. Close the
        // CQ first, then close the IOCP so any already-queued notification packet can no
        // longer be retrieved, and only then free the notification OVERLAPPED. Registered
        // buffers are released last; all native requests have already been retired here.
        drop(self.queue.take());
        drop(self.port.take());
        drop(self.notification_overlapped.take());
        drop(self.send_arena.take());
        drop(self.receive_arena.take());
    }

    fn leak_resources(&mut self, reason: &str) {
        crate::trace::event("SHUTDOWN_LEAK", reason);
        // Memory safety wins over cleanup if Windows/provider state is no longer observable.
        // The process will reclaim these objects; freeing them while I/O may still reference
        // them would be undefined behaviour.
        for session in &mut self.sessions {
            drop(session.socket.take());
        }
        let sessions = core::mem::take(&mut self.sessions);
        core::mem::forget(sessions);
        if let Some(value) = self.queue.take() {
            core::mem::forget(value);
        }
        if let Some(value) = self.send_arena.take() {
            core::mem::forget(value);
        }
        if let Some(value) = self.receive_arena.take() {
            core::mem::forget(value);
        }
        if let Some(value) = self.notification_overlapped.take() {
            core::mem::forget(value);
        }
        if let Some(value) = self.port.take() {
            core::mem::forget(value);
        }
        self.resources_leaked = true;
    }

    pub fn shutdown_with_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        if self.resources_leaked || self.queue.is_none() {
            return Ok(());
        }
        if !self.shutdown_started {
            self.shutdown_started = true;
            self.pending.clear();
            for index in 0..self.sessions.len() as u32 {
                if let Err(error) = self.begin_close(index) {
                    self.leak_resources(&error);
                    return Err(error);
                }
            }
        }

        let started = Instant::now();
        loop {
            if self
                .sessions
                .iter()
                .all(|session| session.state == GenerationState::Empty)
            {
                self.pending.clear();
                self.release_resources();
                crate::trace::event("SHUTDOWN", "all generations drained");
                return Ok(());
            }
            if started.elapsed() >= timeout {
                let reason = "shutdown timed out before all connection generations drained";
                self.leak_resources(reason);
                return Err(reason.to_string());
            }

            match self.wait_and_drain(50, 64) {
                Ok(_) => {}
                Err(error) => {
                    self.leak_resources(&error);
                    return Err(error);
                }
            }
        }
    }
}

impl Drop for RioTransport {
    fn drop(&mut self) {
        let _ = self.shutdown_with_timeout(SHUTDOWN_TIMEOUT);
    }
}

impl Transport for RioTransport {
    fn connect(&mut self, index: u32) -> Result<(), String> {
        self.prepare(index)?;
        let slot_index = index as usize;
        let generation = self.generation_of(index)?;

        if self.protocol == Protocol::Udp {
            let (socket, target) = {
                let slot = &self.sessions[slot_index];
                (slot.socket()?, slot.target)
            };
            connect_udp(socket, &target).map_err(stage)?;
            // Keep the transport in Connecting until the synthetic completion is consumed
            // by the worker and `connected()` performs the same state transition as TCP.
            self.pending.push(Completion {
                index,
                generation,
                slot: NO_SEND_SLOT,
                operation: Operation::Connect,
                status: 0,
                bytes: 0,
            });
            crate::trace::event_args(
                "CONNECT_POST",
                format_args!("session={index} generation={generation} udp=1"),
            );
            return Ok(());
        }

        let result = {
            let slot = &mut self.sessions[slot_index];
            slot.overlapped.arm().map_err(stage)?;
            let socket = slot.socket()?;
            let connect_ex = slot.connect_ex.flatten();
            let target = slot.target;
            let overlapped = slot.overlapped.as_mut_ptr();
            begin_connect(connect_ex, socket, &target, overlapped)
        };
        match result {
            Ok(_) => {
                self.sessions[slot_index].connect_outstanding = true;
                crate::trace::event_args(
                    "CONNECT_POST",
                    format_args!("session={index} generation={generation}"),
                );
                Ok(())
            }
            Err(error) => {
                self.sessions[slot_index]
                    .overlapped
                    .post_failed()
                    .map_err(stage)?;
                Err(stage(error))
            }
        }
    }

    fn connected(&mut self, index: u32, generation: u32) -> Result<(), String> {
        let protocol = self.protocol;
        let slot = self
            .sessions
            .get_mut(index as usize)
            .ok_or_else(|| "session index out of range".to_string())?;
        if slot.generation != generation || slot.state != GenerationState::Connecting {
            return Err("connect completion does not belong to the live generation".to_string());
        }
        if protocol == Protocol::Tcp && (slot.connect_outstanding || slot.overlapped.is_armed()) {
            return Err("ConnectEx completion was not retired before connected()".to_string());
        }
        if protocol == Protocol::Tcp {
            update_connect_context(slot.socket()?).map_err(stage)?;
        }
        slot.state = GenerationState::Active;
        crate::trace::event_args(
            "CONNECT_COMPLETE",
            format_args!("session={index} generation={generation}"),
        );
        Ok(())
    }

    fn send(&mut self, index: u32, bytes: u32) -> Result<(), String> {
        if self.shutdown_started {
            return Err("transport is shutting down".to_string());
        }
        let slot_index = index as usize;
        let generation = self.generation_of(index)?;
        if self.sessions[slot_index].state != GenerationState::Active {
            return Err("send attempted outside an active generation".to_string());
        }
        if bytes == 0 || bytes > self.payload_bytes {
            return Err("invalid send length".to_string());
        }
        if self.sessions[slot_index].send_outstanding >= self.max_send {
            return Err("RIO send depth exceeded".to_string());
        }

        // Arm before posting so a successful return from this method has one unambiguous
        // meaning: the native RIOSend is outstanding and will eventually retire exactly once.
        // If RIONotify fails, no request has been posted and the scheduler may roll back the
        // precomputed business step safely.
        self.arm_queue()?;

        let send_slot = self.sessions[slot_index]
            .allocate_send_slot()
            .ok_or_else(|| "no free TX slot despite available send depth".to_string())?;
        let global_slot = self.tx_global_slot(index, send_slot)?;
        let buffer = self
            .send_arena
            .as_ref()
            .ok_or_else(|| "send arena is unavailable".to_string())?
            .view(global_slot, bytes)
            .map_err(stage)?;
        let context = encode_context(index, generation, send_slot, Operation::Send);
        let posted = self.sessions[slot_index]
            .queue()?
            .send(&self.rio, &buffer, context)
            .map_err(stage);
        if let Err(error) = posted {
            self.sessions[slot_index].release_send_slot(send_slot)?;
            return Err(error);
        }
        self.sessions[slot_index].send_outstanding += 1;
        crate::trace::event_args(
            "SEND_POST",
            format_args!(
                "session={index} generation={generation} slot={send_slot} bytes={bytes}"
            ),
        );
        Ok(())
    }

    fn receive(&mut self, index: u32, bytes: u32) -> Result<(), String> {
        if self.shutdown_started {
            return Err("transport is shutting down".to_string());
        }
        let slot_index = index as usize;
        let generation = self.generation_of(index)?;
        if self.sessions[slot_index].state != GenerationState::Active {
            return Err("receive attempted outside an active generation".to_string());
        }
        if self.sessions[slot_index].receive_outstanding != 0 {
            return Err("second RIOReceive posted for the same session".to_string());
        }
        if bytes == 0 || bytes > self.payload_bytes {
            return Err("invalid receive length".to_string());
        }

        // As with send, arm before the native post so Err means that no receive request was
        // accepted and scheduler rollback is exact.
        self.arm_queue()?;

        let buffer = self
            .receive_arena
            .as_ref()
            .ok_or_else(|| "receive arena is unavailable".to_string())?
            .view(index, bytes)
            .map_err(stage)?;
        self.sessions[slot_index]
            .queue()?
            .receive(
                &self.rio,
                &buffer,
                encode_context(index, generation, NO_SEND_SLOT, Operation::Receive),
            )
            .map_err(stage)?;
        self.sessions[slot_index].receive_outstanding = 1;
        self.sessions[slot_index].receive_posted_bytes = bytes;
        crate::trace::event_args(
            "RECV_POST",
            format_args!("session={index} generation={generation} bytes={bytes}"),
        );
        Ok(())
    }

    fn close(&mut self, index: u32) {
        if let Err(error) = self.begin_close(index) {
            crate::trace::event("CLOSE_ERROR", &error);
        }
    }

    fn completion_is_live(&self, index: u32, generation: u32) -> bool {
        self.sessions.get(index as usize).is_some_and(|slot| {
            slot.generation == generation
                && matches!(slot.state, GenerationState::Connecting | GenerationState::Active)
        })
    }

    fn received(&self, index: u32, generation: u32, length: u32) -> &[u8] {
        if !self.completion_is_live(index, generation) {
            return &[];
        }
        if length > self.payload_bytes {
            return &[];
        }
        self.receive_arena
            .as_ref()
            .map(|arena| arena.read(index, length))
            .unwrap_or(&[])
    }

    fn drain(&mut self, budget: u32) -> Result<Vec<Completion>, String> {
        let mut completions = Vec::with_capacity(self.results.len());
        self.drain_rio_into(budget, &mut completions)?;
        // RIONotify is one-shot. If native work remains after a drain, re-arm even when the
        // scheduler did not post a replacement operation (for example, only a receive is
        // still outstanding after several send completions).
        if self.has_native_outstanding() {
            self.arm_queue()?;
        }
        Ok(completions)
    }

    fn wait_and_drain(
        &mut self,
        wait_milliseconds: u32,
        budget: u32,
    ) -> Result<Vec<Completion>, String> {
        let mut completions = core::mem::take(&mut self.pending);
        let wait = if completions.is_empty() {
            wait_milliseconds
        } else {
            0
        };
        self.wait_iocp_once_into(wait, &mut completions)?;
        self.drain_rio_into(budget, &mut completions)?;
        if self.has_native_outstanding() {
            self.arm_queue()?;
        }
        Ok(completions)
    }

    fn shutdown(&mut self) -> Result<(), String> {
        self.shutdown_with_timeout(SHUTDOWN_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_slot_free_list_handles_out_of_order_completion() {
        let target: SOCKADDR_IN = unsafe { core::mem::zeroed() };
        let mut session = SessionTransport::new(target, 4);
        let a = session.allocate_send_slot().expect("slot a");
        let b = session.allocate_send_slot().expect("slot b");
        let c = session.allocate_send_slot().expect("slot c");
        let d = session.allocate_send_slot().expect("slot d");
        assert_eq!([a, b, c, d], [0, 1, 2, 3]);
        assert!(session.allocate_send_slot().is_none());

        session.release_send_slot(b).expect("release b");
        session.release_send_slot(d).expect("release d");
        assert_eq!(session.allocate_send_slot(), Some(d));
        assert_eq!(session.allocate_send_slot(), Some(b));
        assert!(session.allocate_send_slot().is_none());
    }

    #[test]
    fn tx_slot_double_release_is_rejected() {
        let target: SOCKADDR_IN = unsafe { core::mem::zeroed() };
        let mut session = SessionTransport::new(target, 1);
        let slot = session.allocate_send_slot().expect("slot");
        session.release_send_slot(slot).expect("release");
        assert!(session.release_send_slot(slot).is_err());
    }
}





