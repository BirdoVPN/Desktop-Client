//! Packet size constants for WireGuard tunnel
//!
//! FIX-2-4: Removed dead thread-local buffer pool code. The pool used
//! `thread_local!` + `RefCell` which is incompatible with Tokio's
//! work-stealing runtime. Only the size constants are used (by wireguard_new.rs).

/// Maximum WireGuard packet size (MTU 1420 + WireGuard overhead)
pub const MAX_PACKET_SIZE: usize = 65536;

/// WireGuard encapsulation overhead
/// - 4 bytes: message type
/// - 4 bytes: receiver index  
/// - 8 bytes: nonce
/// - 16 bytes: AEAD tag
/// - 16 bytes: padding for alignment
pub const WIREGUARD_OVERHEAD: usize = 148;
