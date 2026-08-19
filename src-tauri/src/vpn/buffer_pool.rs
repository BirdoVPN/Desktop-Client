//! Packet size constants for WireGuard tunnel
//!
//! FIX-2-4: Removed dead thread-local buffer pool code. The pool used
//! `thread_local!` + `RefCell` which is incompatible with Tokio's
//! work-stealing runtime. Only the size constants are used (by wireguard_new.rs).

/// Upper bound for a received (encrypted) WireGuard UDP datagram buffer.
///
/// Real traffic is ≤ MTU 1420 + WireGuard's 32-byte data-message overhead;
/// `recv_packet` additionally drops anything over 9000 bytes (jumbo-frame
/// headroom). This is sized to the next power of two above that 9148-byte
/// jumbo+overhead ceiling — 16 KiB — rather than the theoretical 64 KiB UDP
/// max, so the per-recv buffer that lives in the recv future is 4× smaller
/// while still comfortably holding any datagram we would actually accept.
/// (Kept a power of two and ≥ 9000 + WIREGUARD_OVERHEAD; see tests.rs.)
pub const MAX_PACKET_SIZE: usize = 16384;

/// WireGuard encapsulation overhead.
///
/// The actual on-wire data-message overhead is 32 bytes:
/// - 4 bytes: message type
/// - 4 bytes: receiver index
/// - 8 bytes: nonce (counter)
/// - 16 bytes: AEAD (Poly1305) tag
///
/// (transport padding rounds the inner packet up to a 16-byte boundary, adding
/// at most 15 further bytes on the plaintext side).
///
/// This constant is intentionally over-provisioned to 148 bytes so it can also
/// size buffers for the larger handshake messages and to keep a conservative
/// safety margin for stack-allocated encryption buffers. Do NOT shrink this to
/// the 32-byte data overhead: it is used as a fixed buffer headroom, not as the
/// exact per-packet data-message overhead.
pub const WIREGUARD_OVERHEAD: usize = 148;

/// A WireGuard handshake-initiation message is exactly 148 bytes, and
/// `update_timers` hands boringtun a buffer of WIREGUARD_OVERHEAD to write one
/// into (wireguard_new.rs). Shrinking this constant below 148 would make every
/// rekey fail with DestinationBufferTooSmall — "upload works, download dies
/// after ~2 minutes" — with no visible error in release builds. Guard it.
const _: () = assert!(
    WIREGUARD_OVERHEAD >= 148,
    "WIREGUARD_OVERHEAD must fit a 148-byte handshake initiation (rekey buffer)"
);
