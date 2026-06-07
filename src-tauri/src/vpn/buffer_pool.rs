//! Packet size constants for WireGuard tunnel
//!
//! FIX-2-4: Removed dead thread-local buffer pool code. The pool used
//! `thread_local!` + `RefCell` which is incompatible with Tokio's
//! work-stealing runtime. Only the size constants are used (by wireguard_new.rs).

/// Maximum WireGuard packet size (MTU 1420 + WireGuard overhead)
pub const MAX_PACKET_SIZE: usize = 65536;

/// WireGuard encapsulation overhead.
///
/// The actual on-wire data-message overhead is 32 bytes:
/// - 4 bytes: message type
/// - 4 bytes: receiver index
/// - 8 bytes: nonce (counter)
/// - 16 bytes: AEAD (Poly1305) tag
/// (transport padding rounds the inner packet up to a 16-byte boundary, adding
/// at most 15 further bytes on the plaintext side).
///
/// This constant is intentionally over-provisioned to 148 bytes so it can also
/// size buffers for the larger handshake messages and to keep a conservative
/// safety margin for stack-allocated encryption buffers. Do NOT shrink this to
/// the 32-byte data overhead: it is used as a fixed buffer headroom, not as the
/// exact per-packet data-message overhead.
pub const WIREGUARD_OVERHEAD: usize = 148;
