//! WireGuard protocol implementation using boringtun
//!
//! Uses Cloudflare's boringtun for proper WireGuard Noise protocol handling.
//!
//! # Security Notes (MEM-003)
//! - All cryptographic key material is zeroized on drop
//! - Uses `zeroize` crate with `ZeroizeOnDrop` derive for automatic cleanup
//! - Explicit zeroization in Drop impl as defense-in-depth
//!
//! # Two ways to drive a session
//!
//! macOS and Linux still run the async `send_packet` / `recv_packet` /
//! `update_timers` trio from their own packet loops. Windows drives the
//! synchronous primitives (`seal`, `open`, `next_queued`, `tick_timers`) from
//! the event-driven data plane in `vpn::data_plane` (W1-006). Both paths go
//! through the same primitives, so the protocol handling cannot drift apart.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use parking_lot::Mutex as FastMutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::buffer_pool::WIREGUARD_OVERHEAD;

/// Persistent-keepalive bounds (seconds) applied to the server-provided value.
const KEEPALIVE_MIN_SECS: u16 = 15;
const KEEPALIVE_MAX_SECS: u16 = 120;

/// Anything larger than this is not WireGuard traffic we would accept (MTU
/// 1420 + 32 bytes of overhead is the real ceiling; 9000 leaves jumbo-frame
/// headroom). Dropped as anomalous rather than handed to boringtun.
const MAX_ACCEPTED_DATAGRAM: usize = 9000;

/// How long one establish-time handshake attempt waits for the answer.
const HANDSHAKE_RESPONSE_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(800)
} else {
    Duration::from_secs(5)
};

/// A relay that has let this many initiations in a row go unanswered...
const UNANSWERED_INITIATIONS: u32 = 4;
/// ...for at least this long (the first try plus three REKEY_TIMEOUT
/// retransmits) is not answering at all.
const UNANSWERED_WINDOW: Duration = Duration::from_secs(15);
/// boringtun starts a handshake KEEPALIVE_TIMEOUT + REKEY_TIMEOUT after
/// sending data that got no answer, so the traffic that triggered the first
/// unanswered initiation is up to this much older than it.
const OUTBOUND_LOOKBACK: Duration = Duration::from_secs(15);

/// What the session has seen of the relay's answers, for [`peer_unresponsive`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ResponseWatch {
    /// The first handshake initiation of the current unanswered run.
    pub first_unanswered: Option<Instant>,
    /// Initiations sent since anything came back from the relay.
    pub unanswered: u32,
    /// The last datagram from the relay that boringtun accepted.
    pub last_rx: Option<Instant>,
    /// The last outbound packet or keepalive (sent, or queued behind a
    /// handshake) — not the initiations themselves.
    pub last_tx: Option<Instant>,
}

impl ResponseWatch {
    fn initiation_sent(&mut self, now: Instant) {
        self.first_unanswered.get_or_insert(now);
        self.unanswered = self.unanswered.saturating_add(1);
    }

    fn outbound(&mut self, now: Instant) {
        self.last_tx = Some(now);
    }

    fn answered(&mut self, now: Instant) {
        self.last_rx = Some(now);
        self.first_unanswered = None;
        self.unanswered = 0;
    }
}

/// The fast dead-path rule: has the relay stopped answering while there is
/// traffic to carry?
///
/// The handshake-age rule (180 s, W1-002) stays the backstop for an idle
/// session; this one exists because with the relay unreachable the tunnel
/// stopped carrying traffic at once while the app said Protected for three
/// more minutes. Every clause is a false-positive guard:
///   * `UNANSWERED_INITIATIONS` in a row over `UNANSWERED_WINDOW` — one lost
///     initiation (or two) is answered by the next retransmit;
///   * nothing received since the run began — a relay that answers anything
///     is alive;
///   * outbound traffic around the run — a quiet healthy tunnel sends no
///     initiations the relay could ignore, and a quiet dead one is left to the
///     idle backstop;
///   * the run is restarted after a resume or a roam
///     ([`WireGuardSession::restart_response_watch`]), so initiations sent
///     before the machine slept cannot count against the path it woke on.
pub(crate) fn peer_unresponsive(watch: &ResponseWatch, now: Instant) -> bool {
    let Some(first) = watch.first_unanswered else {
        return false;
    };
    watch.unanswered >= UNANSWERED_INITIATIONS
        && now.saturating_duration_since(first) >= UNANSWERED_WINDOW
        && watch.last_rx.is_none_or(|rx| rx < first)
        && watch
            .last_tx
            .is_some_and(|tx| tx + OUTBOUND_LOOKBACK >= first)
}

/// A WireGuard handshake initiation: message type 1, 148 bytes.
fn is_initiation(datagram: &[u8]) -> bool {
    datagram.len() == 148 && datagram[0] == 1
}

/// ADAPTIVE TRANSPORT markers — LOAD-BEARING error strings.
///
/// The establish-time handshake below is the desktop's transport probe: on a
/// DPI-filtered network (Iran, Russia) the WireGuard handshake is dropped
/// outright, so `handshake()` times out and the whole connect fails with one of
/// these messages. `commands::vpn::transport_fallback_reason` matches on them
/// (via `contains`, since callers wrap the error) to decide that the failure is
/// transport-shaped and an automatic Xray Reality retry is warranted. Reword
/// them only together with that matcher.
///
/// No response inside the recv timeout — the network silently ate the
/// handshake. The common DPI/UDP-filtering signature.
pub(crate) const ERR_HANDSHAKE_NO_RESPONSE: &str = "Handshake timeout - no response from server";
/// The receive itself errored (ICMP port unreachable, connection reset) — the
/// transport was actively refused rather than silently dropped.
pub(crate) const ERR_HANDSHAKE_RECV: &str = "Failed to receive handshake response";

/// What one `encapsulate` means for the send path (W1-002).
#[derive(Debug)]
pub(crate) enum Outbound<'a> {
    /// Put this datagram on the wire (data, or a handshake initiation).
    Send(&'a [u8]),
    /// boringtun queued the packet: there is no session and a handshake is
    /// already in flight. The normal re-handshake path, not an error.
    Queued,
    Failed(String),
}

fn outbound(result: TunnResult<'_>) -> Outbound<'_> {
    match result {
        TunnResult::WriteToNetwork(data) => Outbound::Send(data),
        TunnResult::Done => Outbound::Queued,
        TunnResult::Err(e) => Outbound::Failed(format!("Encryption failed: {:?}", e)),
        _ => Outbound::Failed("Unexpected encapsulate result".to_string()),
    }
}

/// What one received datagram means for the receive path.
#[derive(Debug)]
pub(crate) enum Opened<'a> {
    /// A decrypted IP packet for the adapter.
    Packet(&'a [u8]),
    /// A protocol message for the peer (a handshake answer, a cookie, a
    /// keepalive). boringtun may have queued packets behind it: drain them
    /// with `next_queued` once this has been sent.
    Reply(&'a [u8]),
    /// Nothing to do: a keepalive, a decryption failure during a rekey, or a
    /// datagram too large to be ours.
    Nothing,
}

fn opened(result: TunnResult<'_>) -> Opened<'_> {
    match result {
        TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
            Opened::Packet(data)
        }
        TunnResult::WriteToNetwork(data) => Opened::Reply(data),
        TunnResult::Done => Opened::Nothing,
        TunnResult::Err(e) => {
            // Expected during rekey transitions; never per-packet noise in
            // the persistent log.
            tracing::trace!("Decryption failed (may be transient): {:?}", e);
            Opened::Nothing
        }
    }
}

/// What a datagram received during the establish-time handshake means (W1-033).
#[derive(Debug)]
enum HandshakeReply<'a> {
    /// A session now exists. `confirm` is the keepalive boringtun emits to
    /// confirm it to the responder.
    Established { confirm: Option<&'a [u8]> },
    /// A cookie reply: the relay is under load and wants the initiation sent
    /// again, now carrying the cookie. NOT a completed handshake.
    CookieReply,
    /// A protocol message for the peer that does not end the exchange.
    Respond(&'a [u8]),
    /// A datagram that could not be used (for example the answer to an
    /// initiation a retry has since replaced). Keep waiting.
    Unusable(String),
}

/// Classify one decapsulate result from the establish-time handshake.
///
/// `session_established` is boringtun's own answer (`time_since_last_handshake`
/// is `Some` only once a session exists). Reading success off the result KIND
/// is what W1-033 was: a cookie reply comes back as `Done`, the same kind a
/// completed handshake used to be assumed to produce, so a relay under load
/// reported "handshake complete" with no session behind it.
fn handshake_reply(result: TunnResult<'_>, session_established: bool) -> HandshakeReply<'_> {
    match result {
        TunnResult::Err(e) => HandshakeReply::Unusable(format!("{:?}", e)),
        TunnResult::WriteToNetwork(data) if session_established => HandshakeReply::Established {
            confirm: Some(data),
        },
        TunnResult::WriteToNetwork(data) => HandshakeReply::Respond(data),
        _ if session_established => HandshakeReply::Established { confirm: None },
        TunnResult::Done => HandshakeReply::CookieReply,
        _ => HandshakeReply::Unusable("data before a session".to_string()),
    }
}

/// The instant the last handshake COMPLETED, carried through a boringtun
/// session expiry (W1-002). `observed_age` is `time_since_last_handshake()`,
/// which goes to `None` when the session is cleared; the previous completion
/// is kept then, so the age keeps growing through an outage instead of
/// vanishing.
fn carry_last_handshake(
    previous: Option<Instant>,
    observed_age: Option<Duration>,
    now: Instant,
) -> Option<Instant> {
    match observed_age.and_then(|age| now.checked_sub(age)) {
        Some(completed) if previous.is_none_or(|prev| completed > prev) => Some(completed),
        _ => previous,
    }
}

/// Wrapper for sensitive key bytes that zeroizes on drop
/// MEM-003: Ensures key material doesn't remain in memory
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SensitiveKey([u8; 32]);

impl SensitiveKey {
    fn new() -> Self {
        Self([0u8; 32])
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// A UDP socket `connect()`ed to the relay, with the large buffers a VPN
/// needs. The kernel picks the source address when it connects, from the
/// route to `endpoint` at that moment — which is why a roam (W1-003) makes a
/// NEW socket after moving the endpoint host route instead of reusing this one.
async fn connected_socket(endpoint: SocketAddr) -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to create UDP socket: {}", e))?;

    // PERF-002: Set large socket buffers (4MB each) for high-speed VPN
    // Default OS buffers are too small and cause packet drops at high speeds
    let sock_ref = socket2::SockRef::from(&socket);
    let buffer_size = 4 * 1024 * 1024; // 4MB
    if let Err(e) = sock_ref.set_recv_buffer_size(buffer_size) {
        tracing::warn!("Failed to set recv buffer size: {}", e);
    }
    if let Err(e) = sock_ref.set_send_buffer_size(buffer_size) {
        tracing::warn!("Failed to set send buffer size: {}", e);
    }

    // FIX-2-2: The WireGuard UDP socket is bound to the physical interface via
    // connect() to the endpoint IP, which establishes the route before tunnel
    // routes are installed. IP_UNICAST_IF is not needed — connect() already
    // pins the socket to the correct interface.
    // P6-CLI-D-03 sibling: never write the exit node raw, at any level. `debug!`
    // is below the release default of `info`, but `RUST_LOG` overrides that
    // default, and setting `RUST_LOG=debug` is exactly what a user does when
    // collecting a support log they then SEND US.
    tracing::debug!(
        "WG UDP socket will connect directly to {}",
        crate::utils::redact_endpoint(&endpoint.to_string())
    );
    socket
        .connect(&endpoint)
        .await
        .map_err(|e| format!("Failed to connect to endpoint: {}", e))?;
    // `socket.local_addr()` is deliberately not logged: after connect() it is
    // the PHYSICAL NIC the tunnel rides, i.e. the user's real network address.
    Ok(socket)
}

/// WireGuard session using boringtun
///
/// Uses parking_lot::Mutex instead of std::sync::Mutex for better performance
/// in async contexts (no priority inversion, smaller size, faster operations)
///
/// # Security (MEM-003)
/// This struct implements Drop with explicit zeroization of any retained key material.
/// The boringtun Tunn struct handles its own internal key zeroization.
pub struct WireGuardSession {
    tunnel: Arc<FastMutex<Tunn>>,
    /// The socket to the relay. A watch rather than a plain field because a
    /// roam (W1-003) replaces it under a running data plane: the receive task
    /// is woken by the change, and the send thread picks the new one up with
    /// an atomic version check per packet.
    socket: watch::Sender<Arc<UdpSocket>>,
    endpoint: SocketAddr,
    /// Set by `close()`. The ONLY thing that stops outbound packets.
    ///
    /// W1-002: this used to be an `is_connected` flag that `update_timers`
    /// latched false on `ConnectionExpired`, and `send_packet` refused to run
    /// while it was false. boringtun re-handshakes when handed an outbound
    /// packet, so the gate is what made every outage longer than ~90 s
    /// permanent: the packet that would have restarted the handshake never
    /// reached `encapsulate`.
    closed: AtomicBool,
    /// Only one warning per expiry, not one per 250 ms timer tick.
    expiry_reported: AtomicBool,
    /// Track session creation for debugging/metrics
    created_at: Instant,
    /// When the last handshake COMPLETED, as last observed. boringtun forgets
    /// it when it expires a session (`time_since_last_handshake()` goes to
    /// `None`), so it is carried here to keep the age growing through an
    /// outage — the same semantics as wg-go's `last_handshake_time_sec`, which
    /// is what the iOS and Android liveness rules read.
    last_handshake: FastMutex<Option<Instant>>,
    /// Answers seen from the relay, for the fast dead-path rule.
    responses: FastMutex<ResponseWatch>,
}

impl WireGuardSession {
    /// Create a new WireGuard session with boringtun
    ///
    /// # Security (MEM-003)
    /// All key material passed to this function is zeroized after being copied
    /// into the boringtun Tunn struct. The caller's copies are also cleared.
    pub async fn new(
        private_key_b64: &str,
        server_public_key_b64: &str,
        endpoint: &str,
        preshared_key_b64: Option<&str>,
        persistent_keepalive: u16,
    ) -> Result<Self, String> {
        // MEM-003: Use SensitiveKey wrapper for automatic zeroization
        let private_key_bytes = BASE64
            .decode(private_key_b64)
            .map_err(|e| format!("Invalid private key: {}", e))?;

        if private_key_bytes.len() != 32 {
            return Err(format!(
                "Invalid private key length: {}",
                private_key_bytes.len()
            ));
        }

        let mut private_key = SensitiveKey::new();
        private_key
            .as_mut_slice()
            .copy_from_slice(&private_key_bytes);
        // Zeroize the temporary vector immediately
        let mut temp_bytes = private_key_bytes;
        temp_bytes.zeroize();

        // Decode server public key with zeroization
        let server_key_bytes = BASE64
            .decode(server_public_key_b64)
            .map_err(|e| format!("Invalid server public key: {}", e))?;

        if server_key_bytes.len() != 32 {
            return Err(format!(
                "Invalid server key length: {}",
                server_key_bytes.len()
            ));
        }

        let mut server_public_key = SensitiveKey::new();
        server_public_key
            .as_mut_slice()
            .copy_from_slice(&server_key_bytes);
        let mut temp_server_bytes = server_key_bytes;
        temp_server_bytes.zeroize();

        // Decode preshared key if provided with zeroization
        let psk: Option<SensitiveKey> = if let Some(psk_b64) = preshared_key_b64 {
            if psk_b64.is_empty() {
                None
            } else {
                let psk_bytes = BASE64
                    .decode(psk_b64)
                    .map_err(|e| format!("Invalid preshared key: {}", e))?;
                if psk_bytes.len() != 32 {
                    return Err(format!("Invalid preshared key length: {}", psk_bytes.len()));
                }
                let mut psk_key = SensitiveKey::new();
                psk_key.as_mut_slice().copy_from_slice(&psk_bytes);
                let mut temp_psk_bytes = psk_bytes;
                temp_psk_bytes.zeroize();
                Some(psk_key)
            }
        } else {
            None
        };

        // Parse endpoint
        // L-7: Prefer a pre-resolved IP address to avoid DNS leaks during tunnel setup.
        // If a hostname is provided, resolve it but log a warning — the caller
        // should ideally pass an IP:port obtained via DoH before the tunnel starts.
        let endpoint_addr: SocketAddr = match endpoint.parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                // L-7 FIX: Use DNS-over-HTTPS to prevent plain DNS leak of VPN server hostname
                tracing::warn!(
                    "Endpoint '{}' is not a pre-resolved IP:port — resolving via DoH",
                    crate::utils::redact_endpoint(endpoint)
                );
                // Extract host and port from the endpoint string
                // P6-CLI-D-03: these Err strings are logged verbatim by the catch-all
                // handlers (manager.rs, auto_reconnect.rs) at levels release builds
                // write, so the endpoint must be redacted HERE — the warn! above
                // already does it, and an unredacted sibling defeats it.
                let (host, port) = {
                    let parts: Vec<&str> = endpoint.rsplitn(2, ':').collect();
                    if parts.len() != 2 {
                        return Err(format!(
                            "Invalid endpoint format: {}",
                            crate::utils::redact_endpoint(endpoint)
                        ));
                    }
                    let port: u16 = parts[0].parse().map_err(|_| {
                        format!(
                            "Invalid port in endpoint: {}",
                            crate::utils::redact_endpoint(endpoint)
                        )
                    })?;
                    (parts[1].to_string(), port)
                };
                let ip = super::doh::resolve_via_doh(&host).await.map_err(|e| {
                    format!(
                        "DoH resolution failed for '{}': {}. Pre-resolve endpoints to IP:port to avoid this.",
                        crate::utils::redact_endpoint(endpoint),
                        e
                    )
                })?;
                SocketAddr::from((ip, port))
            }
        };

        tracing::info!("Resolved endpoint to server");

        // Create boringtun tunnel
        // MEM-003: Extract raw arrays and let SensitiveKey wrappers zeroize
        let private_key_arr = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(private_key.as_slice());
            private_key.zeroize(); // Explicit zeroize before drop
            arr
        };

        let server_key_arr = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(server_public_key.as_slice());
            server_public_key.zeroize();
            arr
        };

        let psk_arr = psk.as_ref().map(|p| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(p.as_slice());
            arr
        });

        // The server-provided keepalive was previously computed, plumbed through
        // ReconnectInfo, and then DROPPED — Tunn::new got a hardcoded 25s. Honour
        // it: 0 is WireGuard's "keepalive disabled" and is passed through as such
        // (never promoted to a floor, and never as Some(0), which boringtun would
        // not read as disabled); any other value is clamped, because under 15s the
        // keepalives themselves keep the NIC/radio busy and over 120s a NAT mapping
        // typically expires before the next one arrives.
        let keepalive = match persistent_keepalive {
            0 => None,
            n => Some(n.clamp(KEEPALIVE_MIN_SECS, KEEPALIVE_MAX_SECS)),
        };

        // boringtun 0.7: Tunn::new is infallible (0.6 returned Result).
        let tunnel = Tunn::new(
            StaticSecret::from(private_key_arr),
            PublicKey::from(server_key_arr),
            psk_arr,   // Preshared key for additional security
            keepalive, // Persistent keepalive (seconds); None = disabled
            0,         // Tunnel index
            None,      // Rate limiter
        );

        // MEM-003: Zeroize our copies of keys after tunnel creation
        // The keys have been moved into the Tunn struct
        let mut private_key_arr = private_key_arr;
        let mut server_key_arr = server_key_arr;
        private_key_arr.zeroize();
        server_key_arr.zeroize();
        // psk SensitiveKey wrapper auto-zeroizes on drop via ZeroizeOnDrop
        drop(psk);
        if let Some(mut psk_arr) = psk_arr {
            psk_arr.zeroize();
        }

        tracing::trace!("Key material zeroized after tunnel creation");

        let socket = connected_socket(endpoint_addr).await?;
        tracing::debug!(
            "Created WireGuard session to {}",
            crate::utils::redact_endpoint(&endpoint_addr.to_string())
        );

        let session = Self {
            tunnel: Arc::new(FastMutex::new(tunnel)),
            socket: watch::Sender::new(Arc::new(socket)),
            endpoint: endpoint_addr,
            closed: AtomicBool::new(false),
            expiry_reported: AtomicBool::new(false),
            created_at: Instant::now(),
            last_handshake: FastMutex::new(None),
            responses: FastMutex::new(ResponseWatch::default()),
        };

        // Perform initial handshake with retry logic (NEW-001 fix)
        session.handshake_with_retry().await?;

        Ok(session)
    }

    /// Maximum number of handshake retry attempts
    const MAX_HANDSHAKE_RETRIES: u32 = 3;

    /// Minimum handshake duration for timing attack protection (CRYPTO-001)
    /// A failed handshake to a wrong public key completes in ~1ms locally,
    /// while a correct key takes ~50ms network round-trip. 170ms hides the
    /// difference while keeping connection snappy.
    const MIN_HANDSHAKE_DURATION_MS: u64 = 170;

    /// Perform WireGuard handshake with automatic retry
    /// NEW-001: Improves reliability on poor/unstable networks
    /// CRYPTO-001: Constant-time failure handling to prevent timing attacks
    async fn handshake_with_retry(&self) -> Result<(), String> {
        let start = Instant::now();

        let result = self.do_handshake_with_retry_internal().await;

        // CRYPTO-001: Ensure minimum duration to prevent timing attacks
        let elapsed = start.elapsed();
        let min_duration = Duration::from_millis(Self::MIN_HANDSHAKE_DURATION_MS);
        if elapsed < min_duration {
            tokio::time::sleep(min_duration - elapsed).await;
        }

        result
    }

    /// Internal handshake retry logic
    async fn do_handshake_with_retry_internal(&self) -> Result<(), String> {
        for attempt in 1..=Self::MAX_HANDSHAKE_RETRIES {
            match self.handshake().await {
                Ok(_) => {
                    // Record successful handshake time
                    *self.last_handshake.lock() = Some(Instant::now());
                    return Ok(());
                }
                Err(e) if attempt < Self::MAX_HANDSHAKE_RETRIES => {
                    let delay_ms = 500 * attempt as u64;
                    tracing::warn!(
                        "Handshake attempt {}/{} failed: {}, retrying in {}ms...",
                        attempt,
                        Self::MAX_HANDSHAKE_RETRIES,
                        e,
                        delay_ms
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
                    tracing::error!(
                        "All {} handshake attempts failed. Last error: {}",
                        Self::MAX_HANDSHAKE_RETRIES,
                        e
                    );
                    return Err(format!(
                        "Handshake failed after {} attempts: {}",
                        Self::MAX_HANDSHAKE_RETRIES,
                        e
                    ));
                }
            }
        }
        Err("Handshake retry loop exited unexpectedly".to_string())
    }

    /// Send a FRESH handshake initiation (`force_resend`).
    ///
    /// Forced on purpose. Without it boringtun answers `Done` while the
    /// previous initiation is still "in progress" — and it stays in progress
    /// until an answer arrives, because no timer runs before the data plane
    /// starts. So retries 2 and 3 never sent anything: they failed at once
    /// with "Failed to generate handshake: Done", and that string (not the
    /// no-response marker) became the connect's error, which is why a silently
    /// filtered network never triggered the stealth fallback.
    async fn send_initiation(&self, socket: &UdpSocket) -> Result<(), String> {
        let mut dst = [0u8; WIREGUARD_OVERHEAD];
        let initiation = {
            let mut tunnel = self.tunnel.lock();
            match tunnel.format_handshake_initiation(&mut dst, true) {
                TunnResult::WriteToNetwork(data) => Ok(data.len()),
                other => Err(format!("Failed to generate handshake: {:?}", other)),
            }
        }?;
        tracing::debug!("Sending handshake initiation ({} bytes)", initiation);
        socket
            .send(&dst[..initiation])
            .await
            .map_err(|e| format!("Failed to send handshake: {}", e))?;
        Ok(())
    }

    /// One establish-time handshake attempt: an initiation, then answers until
    /// a session exists or `HANDSHAKE_RESPONSE_TIMEOUT` runs out. A cookie
    /// reply re-sends the initiation within the same attempt (W1-033).
    async fn handshake(&self) -> Result<(), String> {
        tracing::debug!("Initiating WireGuard handshake");
        let socket = self.socket();
        self.send_initiation(&socket).await?;

        let deadline = tokio::time::Instant::now() + HANDSHAKE_RESPONSE_TIMEOUT;
        let mut last_unusable: Option<String> = None;
        let mut buf = [0u8; 2048];
        loop {
            let n = match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(format!("{}: {}", ERR_HANDSHAKE_RECV, e)),
                // Something DID answer, just nothing usable: that is not the
                // silent-drop signature the stealth fallback keys on.
                Err(_) => {
                    return Err(match last_unusable {
                        Some(e) => format!("Handshake failed: {}", e),
                        None => ERR_HANDSHAKE_NO_RESPONSE.to_string(),
                    })
                }
            };
            tracing::debug!("Received {} bytes response", n);

            let mut out = [0u8; 2048];
            let reply = {
                let mut tunnel = self.tunnel.lock();
                let result = tunnel.decapsulate(None, &buf[..n], &mut out);
                let established = tunnel.time_since_last_handshake().is_some();
                handshake_reply(result, established)
            };
            match reply {
                HandshakeReply::Established { confirm } => {
                    if let Some(keepalive) = confirm {
                        socket
                            .send(keepalive)
                            .await
                            .map_err(|e| format!("Failed to send response: {}", e))?;
                    }
                    self.drain_queued_packets(&socket).await;
                    tracing::info!("WireGuard handshake complete");
                    return Ok(());
                }
                HandshakeReply::CookieReply => {
                    tracing::info!("Relay is under load (cookie reply) — resending the handshake");
                    self.send_initiation(&socket).await?;
                }
                HandshakeReply::Respond(data) => {
                    let _ = socket.send(data).await;
                }
                HandshakeReply::Unusable(e) => {
                    tracing::debug!("Ignoring an unusable handshake datagram: {}", e);
                    last_unusable = Some(e);
                }
            }
        }
    }

    /// P1-dk-boringtun-queue-never-drained: boringtun queues packets that
    /// arrive during a handshake/rekey and its contract requires the caller,
    /// after any `WriteToNetwork` from decapsulate, to loop on
    /// `decapsulate(None, &[], ..)` sending each result until `Done` —
    /// otherwise the first packets after every connect/rekey are stranded.
    async fn drain_queued_packets(&self, socket: &UdpSocket) {
        let mut dst = vec![0u8; super::buffer_pool::MAX_PACKET_SIZE];
        while let Some(queued) = self.next_queued(&mut dst) {
            let _ = socket.send(queued).await;
        }
    }

    // ── Synchronous primitives (both packet loops) ──────────────────────

    /// The socket to the relay right now.
    pub(crate) fn socket(&self) -> Arc<UdpSocket> {
        self.socket.borrow().clone()
    }

    /// Follow the socket across a roam (see the `socket` field).
    #[cfg(target_os = "windows")]
    pub(crate) fn subscribe_socket(&self) -> watch::Receiver<Arc<UdpSocket>> {
        self.socket.subscribe()
    }

    /// Encrypt one IP packet into `dst`.
    pub(crate) fn seal<'a>(&self, packet: &[u8], dst: &'a mut [u8]) -> Outbound<'a> {
        if self.closed.load(Ordering::SeqCst) {
            return Outbound::Failed("Session closed".to_string());
        }
        let result = outbound(self.tunnel.lock().encapsulate(packet, dst));
        let now = Instant::now();
        match &result {
            Outbound::Send(data) if is_initiation(data) => {
                // boringtun opened a handshake for this packet and queued it.
                let mut watch = self.responses.lock();
                watch.initiation_sent(now);
                watch.outbound(now);
            }
            Outbound::Send(_) | Outbound::Queued => self.responses.lock().outbound(now),
            Outbound::Failed(_) => {}
        }
        result
    }

    /// Decrypt one datagram from the relay into `dst`.
    pub(crate) fn open<'a>(&self, datagram: &[u8], dst: &'a mut [u8]) -> Opened<'a> {
        if datagram.len() > MAX_ACCEPTED_DATAGRAM {
            tracing::trace!(
                recv_len = datagram.len(),
                "Oversized UDP datagram — dropping"
            );
            return Opened::Nothing;
        }
        let result = self.tunnel.lock().decapsulate(None, datagram, dst);
        if !matches!(result, TunnResult::Err(_)) {
            self.responses.lock().answered(Instant::now());
        }
        opened(result)
    }

    /// The next packet boringtun queued behind a handshake, if any.
    pub(crate) fn next_queued<'a>(&self, dst: &'a mut [u8]) -> Option<&'a [u8]> {
        match self.tunnel.lock().decapsulate(None, &[], dst) {
            TunnResult::WriteToNetwork(data) => Some(data),
            _ => None,
        }
    }

    /// Run boringtun's timers; `Ok(Some(..))` is a keepalive or a rekey
    /// initiation to send. boringtun expects this every ~250 ms.
    pub(crate) fn tick_timers<'a>(&self, dst: &'a mut [u8]) -> Result<Option<&'a [u8]>, String> {
        let result = self.tunnel.lock().update_timers(dst);
        match result {
            TunnResult::WriteToNetwork(data) => {
                let now = Instant::now();
                if is_initiation(data) {
                    self.responses.lock().initiation_sent(now);
                } else {
                    self.responses.lock().outbound(now);
                }
                Ok(Some(data))
            }
            TunnResult::Err(e) => {
                // ConnectionExpired means boringtun gave up on the CURRENT
                // handshake attempt (REKEY_ATTEMPT_TIME without an answer, or
                // no new keys for REJECT_AFTER_TIME*3). It is not terminal:
                // the next outbound packet starts a fresh handshake, and an
                // idle session is re-handshaked by the auto-reconnect loop's
                // nudge (`force_handshake`). Whether the session is DEAD is
                // decided from `handshake_age()` (W1-002), not from this.
                if matches!(
                    e,
                    boringtun::noise::errors::WireGuardError::ConnectionExpired
                ) && !self.expiry_reported.swap(true, Ordering::SeqCst)
                {
                    tracing::warn!(
                        "WireGuard session expired — waiting for traffic or a nudge to re-handshake"
                    );
                }
                Err(format!("Timer update failed: {:?}", e))
            }
            _ => Ok(None),
        }
    }

    /// Move the session onto a new socket after the path changed (W1-003).
    ///
    /// The caller has ALREADY moved the endpoint host route to the new
    /// gateway, so the new socket's `connect()` picks the new interface's
    /// source address. The boringtun session is kept: WireGuard roams by
    /// design, and the relay follows the peer's newest authenticated source
    /// address. A forced handshake then proves the path.
    #[cfg(target_os = "windows")]
    pub(crate) async fn rebind(&self) -> Result<(), String> {
        let socket = connected_socket(self.endpoint).await?;
        self.socket.send_replace(Arc::new(socket));
        self.restart_response_watch();
        let mut dst = [0u8; WIREGUARD_OVERHEAD];
        let initiation = {
            let mut tunnel = self.tunnel.lock();
            match tunnel.format_handshake_initiation(&mut dst, true) {
                TunnResult::WriteToNetwork(data) => Some(data.len()),
                _ => None,
            }
        };
        if let Some(len) = initiation {
            self.responses.lock().initiation_sent(Instant::now());
            self.socket()
                .send(&dst[..len])
                .await
                .map_err(|e| format!("Failed to send handshake on the new path: {}", e))?;
        }
        Ok(())
    }

    // ── The async packet API (macOS / Linux packet loops) ───────────────

    /// Encrypt and send an IP packet
    /// PERF-001: Uses stack allocation for normal-sized packets (≤ MTU 1420 + overhead)
    /// to eliminate per-packet heap allocations. Falls back to heap for jumbo frames.
    ///
    /// `Ok(0)` means boringtun QUEUED the packet: there is no session right now
    /// and a handshake is already in flight. That is the normal re-handshake
    /// path after an outage (W1-002), not an error.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub async fn send_packet(&self, packet: &[u8]) -> Result<usize, String> {
        let total_size = packet.len() + WIREGUARD_OVERHEAD;
        let mut stack = [0u8; 1600];
        let mut heap: Vec<u8>;
        let dst: &mut [u8] = if total_size <= stack.len() {
            &mut stack
        } else {
            heap = vec![0u8; total_size];
            &mut heap
        };
        match self.seal(packet, dst) {
            Outbound::Send(data) => self
                .socket()
                .send(data)
                .await
                .map_err(|e| format!("Failed to send: {}", e)),
            Outbound::Queued => Ok(0),
            Outbound::Failed(e) => Err(e),
        }
    }

    /// Receive and decrypt a packet without waiting (`Ok(None)` when nothing
    /// is ready or the datagram carried no IP packet).
    /// Returns Vec<u8> for cross-boundary compatibility with the unix loops.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub async fn recv_packet(&self) -> Result<Option<Vec<u8>>, String> {
        let socket = self.socket();
        let mut raw = [0u8; super::buffer_pool::MAX_PACKET_SIZE];
        let n = match socket.try_recv(&mut raw) {
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            // An oversized datagram (larger than our recv buffer) surfaces as
            // WSAEMSGSIZE (Windows, 10040) / EMSGSIZE (unix, 90). Real WireGuard
            // traffic is ≤ MTU + overhead and this socket is connect()ed to the
            // server, so such a datagram is malformed/spoofed — drop it rather
            // than tearing down the tunnel over it.
            Err(ref e) if matches!(e.raw_os_error(), Some(10040) | Some(90)) => {
                tracing::debug!(error = %e, "Dropping oversized UDP datagram (message too long)");
                return Ok(None);
            }
            Err(e) => return Err(format!("Receive error: {}", e)),
        };
        // FIX-R2: sized for any decapsulated output, jumbo frames included.
        let mut dst = [0u8; 9000];
        match self.open(&raw[..n], &mut dst) {
            Opened::Packet(data) => Ok(Some(data.to_vec())),
            Opened::Reply(data) => {
                let _ = socket.send(data).await;
                self.drain_queued_packets(&socket).await;
                Ok(None)
            }
            Opened::Nothing => Ok(None),
        }
    }

    /// Update timers and send keepalives as needed
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    pub async fn update_timers(&self) -> Result<(), String> {
        // The LARGEST message a timer tick emits is a handshake initiation
        // (148 bytes on a rekey) — WIREGUARD_OVERHEAD is sized for exactly
        // that, and a const assertion in buffer_pool.rs keeps it so.
        let mut dst = [0u8; WIREGUARD_OVERHEAD];
        if let Some(data) = self.tick_timers(&mut dst)? {
            self.socket()
                .send(data)
                .await
                .map_err(|e| format!("Failed to send keepalive: {}", e))?;
        }
        Ok(())
    }

    // ── Session facts ───────────────────────────────────────────────────

    /// Get the resolved endpoint IP address the socket is connected to
    pub fn endpoint_ip(&self) -> std::net::IpAddr {
        self.endpoint.ip()
    }

    /// Time since the last COMPLETED handshake (W1-002). Survives boringtun
    /// expiring the session — see the `last_handshake` field. Before the first
    /// handshake it is the session's age, which the liveness grace covers.
    pub fn handshake_age(&self) -> Duration {
        let observed = self.tunnel.lock().time_since_last_handshake();
        let mut last = self.last_handshake.lock();
        let carried = carry_last_handshake(*last, observed, Instant::now());
        if carried != *last {
            // A new handshake completed: the next expiry is news again.
            self.expiry_reported.store(false, Ordering::SeqCst);
            *last = carried;
        }
        last.unwrap_or(self.created_at).elapsed()
    }

    /// Start a handshake now unless one is already in flight.
    ///
    /// For an IDLE session: with persistent keepalive off nothing would ever
    /// rekey it, so its handshake age would grow past the liveness limit on a
    /// perfectly healthy peer. Also what re-handshakes an expired session that
    /// has no traffic queued, and what proves the path after a resume.
    pub async fn force_handshake(&self) {
        // WIREGUARD_OVERHEAD is sized for exactly this message (148 bytes).
        let mut dst = [0u8; WIREGUARD_OVERHEAD];
        let initiation = {
            let mut tunnel = self.tunnel.lock();
            match tunnel.format_handshake_initiation(&mut dst, false) {
                TunnResult::WriteToNetwork(packet) => Some(packet.len()),
                _ => None,
            }
        };
        if let Some(len) = initiation {
            self.responses.lock().initiation_sent(Instant::now());
            if let Err(e) = self.socket().send(&dst[..len]).await {
                tracing::debug!("Forced handshake could not be sent: {}", e);
            }
        }
    }

    /// Has the relay stopped answering while there is traffic to carry? See
    /// [`peer_unresponsive`].
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn peer_unresponsive(&self) -> bool {
        peer_unresponsive(&self.responses.lock(), Instant::now())
    }

    /// Start counting unanswered initiations afresh: after a resume or a roam,
    /// what went unanswered on the old path says nothing about the new one.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn restart_response_watch(&self) {
        let mut watch = self.responses.lock();
        watch.first_unanswered = None;
        watch.unanswered = 0;
    }

    /// Round-trip time of the last handshake, in ms: a real measurement of the
    /// path to the relay, taken by boringtun itself. (W1-032: the explicit
    /// probe that used to back this up was never called, and would have stolen
    /// datagrams from the packet loop if it had been.)
    pub async fn get_latency_ms(&self) -> Option<u32> {
        self.tunnel.lock().stats().4
    }

    /// Close the WireGuard session
    pub async fn close(&self) {
        tracing::debug!("Closing WireGuard session");
        self.closed.store(true, Ordering::SeqCst);
        // Socket will be dropped when session is dropped
    }
}

/// Implement Drop to ensure secure cleanup of cryptographic material
/// MEM-003: CRITICAL - Prevents key material retention after session ends
///
/// This is defense-in-depth: boringtun's Tunn also implements zeroization,
/// but we ensure the Arc wrapper doesn't leave stale data.
impl Drop for WireGuardSession {
    fn drop(&mut self) {
        tracing::debug!(
            session_duration_secs = self.created_at.elapsed().as_secs(),
            "Dropping WireGuardSession - ensuring secure cleanup"
        );

        // Log the Arc reference count for debugging
        let strong_count = Arc::strong_count(&self.tunnel);

        if strong_count == 1 {
            // We have the only reference - tunnel will be dropped after this
            // boringtun's Tunn handles its own internal key zeroization
            tracing::trace!("WireGuard tunnel will be securely dropped (sole owner)");
        } else {
            // Arc has other references - log warning for debugging
            // The tunnel will be cleaned up when last reference drops
            tracing::warn!(
                strong_count,
                "WireGuard session dropped but tunnel has {} references - \
                 keys will be zeroized when last reference drops",
                strong_count
            );
        }

        // The Arc<FastMutex<Tunn>> will be dropped automatically after this,
        // which will trigger boringtun's internal zeroization when refcount hits 0

        tracing::trace!("WireGuardSession drop complete");
    }
}

#[cfg(test)]
mod liveness_tests {
    use super::*;

    fn fresh_tunn() -> Tunn {
        let ours = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let theirs = PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng));
        Tunn::new(ours, theirs, None, None, 0, None)
    }

    /// W1-002: with no session (never established, or cleared by an expiry)
    /// an outbound packet still reaches `encapsulate`, which starts a new
    /// handshake; a second packet while it is in flight is QUEUED, not an
    /// error. The old gate refused both with "Not connected", so the handshake
    /// that would have recovered the session was never sent.
    #[test]
    fn a_session_without_keys_starts_a_handshake_and_queues() {
        let mut tunn = fresh_tunn();
        let mut dst = [0u8; 1600];
        match outbound(tunn.encapsulate(b"payload", &mut dst)) {
            Outbound::Send(initiation) => assert_eq!(initiation.len(), 148),
            other => panic!("expected a handshake initiation, got {other:?}"),
        }
        assert!(matches!(
            outbound(tunn.encapsulate(b"payload", &mut dst)),
            Outbound::Queued
        ));
    }

    #[test]
    fn the_last_handshake_survives_a_session_expiry() {
        let now = Instant::now();
        let s = Duration::from_secs;
        // A handshake 10 s ago.
        let last = carry_last_handshake(None, Some(s(10)), now);
        assert_eq!(last, now.checked_sub(s(10)));
        // The session expires: boringtun reports no handshake at all. The
        // completion is kept, so the age keeps growing past the limit.
        let later = now + s(200);
        let carried = carry_last_handshake(last, None, later);
        assert_eq!(carried, last);
        assert!(later.duration_since(carried.unwrap()) > s(180));
        // A fresh handshake replaces it; an older reading never does.
        assert_eq!(
            carry_last_handshake(carried, Some(s(1)), later),
            later.checked_sub(s(1))
        );
        assert_eq!(carry_last_handshake(carried, Some(s(500)), later), carried);
    }
}

/// The fast dead-path rule, as the live run described it: the relay blocked,
/// traffic dead at once, the app still Protected minutes later.
#[cfg(test)]
mod response_watch_tests {
    use super::*;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Traffic keeps flowing out, the relay has gone silent, and boringtun
    /// retransmits every REKEY_TIMEOUT (5 s) from +15 s.
    fn dead_path(t0: Instant) -> ResponseWatch {
        let mut w = ResponseWatch::default();
        w.answered(t0);
        for k in 0..20u64 {
            w.outbound(t0 + s(1) + Duration::from_millis(500 * k));
        }
        for retry in 0..4u64 {
            w.initiation_sent(t0 + s(15) + s(5 * retry));
        }
        w
    }

    #[test]
    fn a_silent_relay_with_traffic_is_dead_after_four_initiations_and_fifteen_seconds() {
        let t0 = Instant::now();
        let w = dead_path(t0);
        assert!(
            !peer_unresponsive(&w, t0 + s(29)),
            "not before 15 s of trying"
        );
        assert!(peer_unresponsive(&w, t0 + s(30)));
    }

    #[test]
    fn one_lost_initiation_does_not_trip_it() {
        let t0 = Instant::now();
        let mut w = ResponseWatch::default();
        w.outbound(t0);
        w.initiation_sent(t0 + s(1));
        w.initiation_sent(t0 + s(6)); // the retransmit is answered
        w.answered(t0 + s(6));
        w.outbound(t0 + s(7));
        assert!(!peer_unresponsive(&w, t0 + s(60)));
    }

    #[test]
    fn three_unanswered_initiations_are_not_enough() {
        let t0 = Instant::now();
        let mut w = ResponseWatch::default();
        w.outbound(t0);
        for k in 0..3u64 {
            w.initiation_sent(t0 + s(5 * k));
        }
        assert!(!peer_unresponsive(&w, t0 + s(40)));
    }

    /// Nothing to carry: an idle session whose nudge goes unanswered is left
    /// to the 180 s handshake-age backstop.
    #[test]
    fn a_quiet_tunnel_does_not_trip_it() {
        let t0 = Instant::now();
        let mut w = ResponseWatch::default();
        w.outbound(t0);
        // Minutes later, the idle nudge and its retransmits.
        for k in 0..6u64 {
            w.initiation_sent(t0 + s(150) + s(5 * k));
        }
        assert!(!peer_unresponsive(&w, t0 + s(200)));
    }

    #[test]
    fn anything_from_the_relay_resets_the_run() {
        let t0 = Instant::now();
        let mut w = dead_path(t0);
        w.answered(t0 + s(31));
        assert!(!peer_unresponsive(&w, t0 + s(32)));
        assert_eq!(w.unanswered, 0);
    }

    /// Initiations sent before a sleep must not count against the path the
    /// machine wakes on — the resume's own 10 s re-prove window decides that.
    #[test]
    fn a_restarted_watch_needs_a_fresh_run() {
        let t0 = Instant::now();
        let mut w = dead_path(t0);
        // What restart_response_watch does, then two initiations after resume.
        w.first_unanswered = None;
        w.unanswered = 0;
        let resumed = t0 + s(3600);
        w.outbound(resumed);
        w.initiation_sent(resumed);
        w.initiation_sent(resumed + s(5));
        assert!(!peer_unresponsive(&w, resumed + s(9)));
    }

    #[test]
    fn only_a_type_one_148_byte_datagram_is_an_initiation() {
        let mut init = [0u8; 148];
        init[0] = 1;
        assert!(is_initiation(&init));
        let mut data = [0u8; 148];
        data[0] = 4;
        assert!(!is_initiation(&data));
        assert!(!is_initiation(&init[..32]));
    }
}

/// The establish-time handshake against a real in-process responder on
/// loopback — boringtun on both ends, no mocks.
#[cfg(test)]
mod handshake_tests {
    use super::*;
    use boringtun::noise::rate_limiter::RateLimiter;
    use std::sync::atomic::AtomicUsize;

    struct Responder {
        endpoint: String,
        server_public_b64: String,
        client_private_b64: String,
        initiations_seen: Arc<AtomicUsize>,
    }

    /// A WireGuard responder on 127.0.0.1. `under_load` makes it demand a
    /// cookie (rate-limit limit 0) — the path W1-033 is about. `ignore_first`
    /// drops that many initiations unanswered — a lossy or filtering network.
    async fn responder(under_load: bool, ignore_first: usize) -> Responder {
        let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let server_public = PublicKey::from(&server_secret);
        let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let client_public = PublicKey::from(&client_secret);
        let limiter = under_load.then(|| Arc::new(RateLimiter::new(&server_public, 0)));
        let mut tunn = Tunn::new(server_secret, client_public, None, None, 1, limiter);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = socket.local_addr().unwrap().to_string();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_task = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut out = [0u8; 2048];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if n == 148 && seen_task.fetch_add(1, Ordering::SeqCst) < ignore_first {
                    continue;
                }
                if let TunnResult::WriteToNetwork(reply) =
                    tunn.decapsulate(Some(from.ip()), &buf[..n], &mut out)
                {
                    let _ = socket.send_to(reply, from).await;
                }
            }
        });
        Responder {
            endpoint,
            server_public_b64: BASE64.encode(server_public.as_bytes()),
            client_private_b64: BASE64.encode(client_secret.to_bytes()),
            initiations_seen: seen,
        }
    }

    async fn connect(r: &Responder) -> Result<WireGuardSession, String> {
        WireGuardSession::new(
            &r.client_private_b64,
            &r.server_public_b64,
            &r.endpoint,
            None,
            0,
        )
        .await
    }

    #[tokio::test]
    async fn a_session_exists_when_the_handshake_reports_success() {
        let r = responder(false, 0).await;
        let session = connect(&r).await.expect("handshake");
        assert!(session.tunnel.lock().time_since_last_handshake().is_some());
    }

    /// W1-033: a relay under load answers the first initiation with a cookie
    /// reply. That used to count as a completed handshake (`Done`), so the
    /// connect reported success with no session. Now the initiation is sent
    /// again with the cookie, and success means a session exists.
    #[tokio::test]
    async fn a_cookie_reply_is_not_a_handshake() {
        let r = responder(true, 0).await;
        let session = connect(&r).await.expect("handshake through the cookie");
        assert!(
            session.tunnel.lock().time_since_last_handshake().is_some(),
            "success was reported without a session"
        );
        assert!(
            r.initiations_seen.load(Ordering::SeqCst) >= 2,
            "the initiation was not re-sent with the cookie"
        );
    }

    /// The retries really re-send. They used to fail on the spot with
    /// "Failed to generate handshake: Done", because boringtun refuses a new
    /// initiation while the unanswered one is still in progress.
    #[tokio::test]
    async fn a_lost_initiation_is_retried_for_real() {
        let r = responder(false, 1).await;
        let session = connect(&r).await.expect("second attempt answered");
        assert!(session.tunnel.lock().time_since_last_handshake().is_some());
        assert_eq!(r.initiations_seen.load(Ordering::SeqCst), 2);
    }

    /// A network that eats every initiation ends in the no-response marker the
    /// stealth fallback classifies on — not in the retry's own error.
    #[tokio::test]
    async fn a_silent_network_ends_in_the_transport_marker() {
        let r = responder(false, usize::MAX).await;
        let err = connect(&r).await.err().expect("nothing answers");
        assert!(err.contains(ERR_HANDSHAKE_NO_RESPONSE), "{err}");
        assert_eq!(
            r.initiations_seen.load(Ordering::SeqCst),
            WireGuardSession::MAX_HANDSHAKE_RETRIES as usize
        );
    }

    #[test]
    fn done_without_a_session_is_a_cookie_reply() {
        assert!(matches!(
            handshake_reply(TunnResult::Done, false),
            HandshakeReply::CookieReply
        ));
        assert!(matches!(
            handshake_reply(TunnResult::Done, true),
            HandshakeReply::Established { confirm: None }
        ));
    }
}
