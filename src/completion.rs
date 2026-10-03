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
