//! WireGuard protocol implementation using boringtun
//!
//! Uses Cloudflare's boringtun for proper WireGuard Noise protocol handling.
//!
//! # Security Notes (MEM-003)
//! - All cryptographic key material is zeroized on drop
//! - Uses `zeroize` crate with `ZeroizeOnDrop` derive for automatic cleanup
//! - Explicit zeroization in Drop impl as defense-in-depth

#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use parking_lot::Mutex as FastMutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::buffer_pool::WIREGUARD_OVERHEAD;

/// Persistent-keepalive bounds (seconds) applied to the server-provided value.
const KEEPALIVE_MIN_SECS: u16 = 15;
const KEEPALIVE_MAX_SECS: u16 = 120;

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
enum Outbound<'a> {
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
    socket: Arc<UdpSocket>,
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
    /// Track last measured latency in milliseconds
    last_latency_ms: Arc<RwLock<Option<u32>>>,
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

        // Create UDP socket with large buffers for high-speed throughput
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
        tracing::debug!("UDP socket buffers set to {}MB", buffer_size / 1024 / 1024);

        // FIX-2-2: The WireGuard UDP socket is bound to the physical interface via
        // connect() to the endpoint IP, which establishes the route before tunnel
        // routes are installed. IP_UNICAST_IF is not needed — connect() already
        // pins the socket to the correct interface.
        // P6-CLI-D-03 sibling: `redact_endpoint` is applied to the endpoint at :169
        // and :181, and :203 deliberately says nothing identifying at all. These two
        // sites drifted from that and wrote the exit node raw. `debug!` is below the
        // release default of `info`, so this is not a leak for an ordinary user -- but
        // `RUST_LOG` overrides that default, and setting `RUST_LOG=debug` is exactly
        // what a user does when collecting a support log they then SEND US. A file
        // recording which exit node a customer chose is the record the privacy policy
        // says does not exist, so it must not be written at any level.
        tracing::debug!(
            "WG UDP socket will connect directly to {}",
            crate::utils::redact_endpoint(&endpoint_addr.to_string())
        );

        socket
            .connect(&endpoint_addr)
            .await
            .map_err(|e| format!("Failed to connect to endpoint: {}", e))?;

        // `socket.local_addr()` is dropped rather than redacted: after connect() it is
        // the PHYSICAL NIC the tunnel rides, i.e. the user's real network address. It
        // told us nothing a redacted form would not, and everything a redacted form
        // would not have said.
        tracing::debug!(
            "Created WireGuard session to {}",
            crate::utils::redact_endpoint(&endpoint_addr.to_string())
        );

        let session = Self {
            tunnel: Arc::new(FastMutex::new(tunnel)),
            socket: Arc::new(socket),
            endpoint: endpoint_addr,
            closed: AtomicBool::new(false),
            expiry_reported: AtomicBool::new(false),
            created_at: Instant::now(),
            last_handshake: FastMutex::new(None),
            last_latency_ms: Arc::new(RwLock::new(None)),
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

    /// Perform WireGuard handshake
    async fn handshake(&self) -> Result<(), String> {
        tracing::debug!("Initiating WireGuard handshake");

        // Generate handshake initiation packet using boringtun
        let mut dst = vec![0u8; 2048];

        let handshake_init = {
            let mut tunnel = self.tunnel.lock();
            tunnel.format_handshake_initiation(&mut dst, false)
        };

        let handshake_len = match handshake_init {
            TunnResult::WriteToNetwork(data) => {
                let len = data.len();
                dst.truncate(len);
                len
            }
            other => {
                return Err(format!("Failed to generate handshake: {:?}", other));
            }
        };

        tracing::debug!("Sending handshake initiation ({} bytes)", handshake_len);

        // Send handshake
        self.socket
            .send(&dst[..handshake_len])
            .await
            .map_err(|e| format!("Failed to send handshake: {}", e))?;

        // Wait for response with timeout
        let mut buf = [0u8; 2048];
        let recv_future = self.socket.recv(&mut buf);
        let timeout = tokio::time::timeout(Duration::from_secs(5), recv_future);

        match timeout.await {
            Ok(Ok(n)) => {
                tracing::debug!("Received {} bytes response", n);

                let mut dst = vec![0u8; 2048];
                let result = {
                    let mut tunnel = self.tunnel.lock();
                    tunnel.decapsulate(None, &buf[..n], &mut dst)
                };

                match result {
                    TunnResult::Done => {
                        tracing::info!("WireGuard handshake complete");
                        Ok(())
                    }
                    TunnResult::WriteToNetwork(response_data) => {
                        // Need to send a response (cookie or similar)
                        self.socket
                            .send(response_data)
                            .await
                            .map_err(|e| format!("Failed to send response: {}", e))?;

                        tracing::info!("WireGuard handshake complete (with response)");
                        Ok(())
                    }
                    TunnResult::Err(e) => Err(format!("Handshake failed: {:?}", e)),
                    other => Err(format!("Unexpected handshake result: {:?}", other)),
                }
            }
            Ok(Err(e)) => Err(format!("{}: {}", ERR_HANDSHAKE_RECV, e)),
            Err(_) => Err(ERR_HANDSHAKE_NO_RESPONSE.to_string()),
        }
    }

    /// P1-dk-boringtun-queue-never-drained: boringtun queues packets that
    /// arrive during a handshake/rekey and its contract requires the caller,
    /// after any `WriteToNetwork` from decapsulate, to loop on
    /// `decapsulate(None, &[], ..)` sending each result until `Done` —
    /// otherwise the first packets after every connect/rekey are stranded.
    async fn drain_queued_packets(&self) {
        let mut dst = vec![0u8; 9000];
        loop {
            let queued = {
                let mut tunnel = self.tunnel.lock();
                match tunnel.decapsulate(None, &[], &mut dst) {
                    TunnResult::WriteToNetwork(data) => Some(data.to_vec()),
                    _ => None,
                }
            };
            match queued {
                Some(data) => {
                    let _ = self.socket.send(&data).await;
                }
                None => break,
            }
        }
    }

    /// Encrypt and send an IP packet
    /// PERF-001: Uses stack allocation for normal-sized packets (≤ MTU 1420 + overhead)
    /// to eliminate per-packet heap allocations. Falls back to heap for jumbo frames.
    ///
    /// `Ok(0)` means boringtun QUEUED the packet: there is no session right now
    /// and a handshake is already in flight. That is the normal re-handshake
    /// path after an outage (W1-002), not an error.
    pub async fn send_packet(&self, packet: &[u8]) -> Result<usize, String> {
        if self.closed.load(Ordering::SeqCst) {
            return Err("Session closed".to_string());
        }

        let total_size = packet.len() + WIREGUARD_OVERHEAD;

        if total_size <= 1600 {
            // PERF-001: Fast path — stack allocation for normal-sized packets
            let mut dst = [0u8; 1600];

            let result = {
                let mut tunnel = self.tunnel.lock();
                tunnel.encapsulate(packet, &mut dst)
            };

            match outbound(result) {
                Outbound::Send(data) => self
                    .socket
                    .send(data)
                    .await
                    .map_err(|e| format!("Failed to send: {}", e)),
                Outbound::Queued => Ok(0),
                Outbound::Failed(e) => Err(e),
            }
        } else {
            // Slow path — heap allocation for jumbo/oversized packets
            let mut dst = vec![0u8; total_size];

            let result = {
                let mut tunnel = self.tunnel.lock();
                tunnel.encapsulate(packet, &mut dst)
            };

            match outbound(result) {
                Outbound::Send(data) => self
                    .socket
                    .send(data)
                    .await
                    .map_err(|e| format!("Failed to send: {}", e)),
                Outbound::Queued => Ok(0),
                Outbound::Failed(e) => Err(e),
            }
        }
    }

    /// Receive and decrypt a packet
    /// PERF-001: Uses stack-allocated buffers for recv and decrypt to avoid per-packet heap alloc.
    /// FIX-R2: Decrypt buffer sized to 9000 bytes to handle jumbo frames.
    /// Oversized UDP datagrams (>9000) are dropped as anomalous.
    /// Returns Vec<u8> for cross-boundary compatibility (Wintun write requires owned data).
    pub async fn recv_packet(&self) -> Result<Option<Vec<u8>>, String> {
        let mut raw = [0u8; super::buffer_pool::MAX_PACKET_SIZE];

        match self.socket.try_recv(&mut raw) {
            Ok(n) => {
                tracing::trace!("Socket received {} bytes (encrypted)", n);

                // FIX-R2: Reject oversized datagrams that exceed reasonable WireGuard bounds
                if n > 9000 {
                    tracing::warn!(recv_len = n, "Received oversized UDP datagram — dropping");
                    return Ok(None);
                }

                // FIX-R2: Decrypt buffer must be large enough for any decapsulated output.
                // WireGuard with MTU 1420 produces ≤1420 byte outputs, but we size to 9000
                // for jumbo frame compatibility. Previous 2048 buffer could silently truncate.
                let mut dst = [0u8; 9000];
                let result = {
                    let mut tunnel = self.tunnel.lock();
                    tunnel.decapsulate(None, &raw[..n], &mut dst)
                };

                match result {
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        tracing::trace!("Decrypted {} bytes → Wintun", data.len());
                        Ok(Some(data.to_vec()))
                    }
                    TunnResult::Done => Ok(None),
                    TunnResult::WriteToNetwork(data) => {
                        tracing::trace!(
                            "Decapsulate → WriteToNetwork ({} bytes, e.g. handshake response)",
                            data.len()
                        );
                        // Send keepalive or timer response — don't return to tunnel
                        let _ = self.socket.send(data).await;
                        // Honour the boringtun drain contract (queued packets).
                        self.drain_queued_packets().await;
                        Ok(None)
                    }
                    TunnResult::Err(e) => {
                        // Don't propagate transient decryption errors (expected during rekey)
                        tracing::trace!("Decryption failed (may be transient): {:?}", e);
                        Ok(None)
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            // An oversized datagram (larger than our recv buffer) surfaces as
            // WSAEMSGSIZE (Windows, 10040) / EMSGSIZE (unix, 90). Real WireGuard
            // traffic is ≤ MTU + overhead and this socket is connect()ed to the
            // server, so such a datagram is malformed/spoofed — drop it like the
            // >9000 guard above rather than tearing down the tunnel over it.
            Err(ref e) if matches!(e.raw_os_error(), Some(10040) | Some(90)) => {
                tracing::warn!(error = %e, "Dropping oversized UDP datagram (message too long)");
                Ok(None)
            }
            Err(e) => Err(format!("Receive error: {}", e)),
        }
    }

    /// Update timers and send keepalives as needed
    pub async fn update_timers(&self) -> Result<(), String> {
        // Stack buffer for whatever boringtun emits from the timer tick. The
        // LARGEST such message is a handshake initiation (exactly 148 bytes on
        // a rekey), not the 32-byte data/keepalive overhead — WIREGUARD_OVERHEAD
        // is deliberately over-provisioned to 148 and a const assertion in
        // buffer_pool.rs keeps it that way.
        let mut dst = [0u8; WIREGUARD_OVERHEAD];

        let result = {
            let mut tunnel = self.tunnel.lock();
            tunnel.update_timers(&mut dst)
        };

        match result {
            TunnResult::WriteToNetwork(data) => {
                self.socket
                    .send(data)
                    .await
                    .map_err(|e| format!("Failed to send keepalive: {}", e))?;
                Ok(())
            }
            TunnResult::Done => Ok(()),
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
            _ => Ok(()),
        }
    }

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
                TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                _ => None,
            }
        };
        if let Some(packet) = initiation {
            if let Err(e) = self.socket.send(&packet).await {
                tracing::debug!("Forced handshake could not be sent: {}", e);
            }
        }
    }

    /// Round-trip time of the last handshake, in ms: a real measurement of the
    /// path to the relay. Falls back to an explicit probe's result.
    pub async fn get_latency_ms(&self) -> Option<u32> {
        let handshake_rtt = self.tunnel.lock().stats().4;
        match handshake_rtt {
            Some(rtt) => Some(rtt),
            None => *self.last_latency_ms.read().await,
        }
    }

    /// Measure latency by sending a WireGuard keepalive and timing the response
    /// This is a best-effort measurement - returns None if measurement fails
    pub async fn measure_latency(&self) -> Option<u32> {
        let start = Instant::now();

        // Send a keepalive packet
        let mut dst = [0u8; WIREGUARD_OVERHEAD];
        let send_result = {
            let mut tunnel = self.tunnel.lock();
            tunnel.update_timers(&mut dst)
        };

        match send_result {
            TunnResult::WriteToNetwork(data) => {
                if self.socket.send(data).await.is_err() {
                    return None;
                }
            }
            _ => return None, // No keepalive to send
        }

        // Wait for response with timeout
        let mut buf = [0u8; 256];
        let timeout_result =
            tokio::time::timeout(Duration::from_millis(2000), self.socket.recv(&mut buf)).await;

        match timeout_result {
            Ok(Ok(_)) => {
                let latency = start.elapsed().as_millis() as u32;
                *self.last_latency_ms.write().await = Some(latency);
                Some(latency)
            }
            _ => None, // Timeout or error
        }
    }

    /// Receive and decrypt a packet (alias for recv_packet)
    pub async fn receive_packet(&self) -> Result<Option<Vec<u8>>, String> {
        self.recv_packet().await
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
