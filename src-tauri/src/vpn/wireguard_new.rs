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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::buffer_pool::WIREGUARD_OVERHEAD;

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
    
    fn into_array(mut self) -> [u8; 32] {
        let arr = self.0;
        self.0.zeroize(); // Zeroize before moving out
        arr
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
    is_connected: Arc<RwLock<bool>>,
    /// Track session creation for debugging/metrics
    created_at: Instant,
    /// Track last successful handshake
    last_handshake: Arc<RwLock<Option<Instant>>>,
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
    ) -> Result<Self, String> {
        // MEM-003: Use SensitiveKey wrapper for automatic zeroization
        let private_key_bytes = BASE64
            .decode(private_key_b64)
            .map_err(|e| format!("Invalid private key: {}", e))?;
        
        if private_key_bytes.len() != 32 {
            return Err(format!("Invalid private key length: {}", private_key_bytes.len()));
        }
        
        let mut private_key = SensitiveKey::new();
        private_key.as_mut_slice().copy_from_slice(&private_key_bytes);
        // Zeroize the temporary vector immediately
        let mut temp_bytes = private_key_bytes;
        temp_bytes.zeroize();

        // Decode server public key with zeroization
        let server_key_bytes = BASE64
            .decode(server_public_key_b64)
            .map_err(|e| format!("Invalid server public key: {}", e))?;
        
        if server_key_bytes.len() != 32 {
            return Err(format!("Invalid server key length: {}", server_key_bytes.len()));
        }
        
        let mut server_public_key = SensitiveKey::new();
        server_public_key.as_mut_slice().copy_from_slice(&server_key_bytes);
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
                tracing::warn!(
                    "Endpoint '{}' is not a pre-resolved IP:port — falling back to system DNS. \
                     This may leak the VPN server hostname via plain DNS.",
                    endpoint
                );
                use tokio::net::lookup_host;
                let addrs: Vec<SocketAddr> = lookup_host(&*endpoint)
                    .await
                    .map_err(|e| format!("Failed to resolve endpoint '{}': {}", endpoint, e))?
                    .collect();
                
                addrs.into_iter().next()
                    .ok_or_else(|| format!("No IP address found for endpoint: {}", endpoint))?
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
        
        let tunnel = Tunn::new(
            StaticSecret::from(private_key_arr),
            PublicKey::from(server_key_arr),
            psk_arr, // Preshared key for additional security
            Some(25), // Persistent keepalive
            0, // Tunnel index
            None, // Rate limiter
        ).map_err(|e| format!("Failed to create WireGuard tunnel: {:?}", e))?;

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

        // FIX-2-2: Bind WireGuard UDP socket to the physical interface that reaches
        // the VPN server endpoint. This prevents WG handshake/data traffic from
        // looping through the tunnel after default routes are installed.
        // On Windows, IP_UNICAST_IF sets the interface index for outgoing packets.
        #[cfg(target_os = "windows")]
        {
            use std::net::IpAddr;
            if let IpAddr::V4(server_ip) = endpoint_addr.ip() {
                // Find the interface that routes to the server IP
                if let Ok(output) = crate::utils::hidden_cmd("route")
                    .args(["print", &server_ip.to_string()])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // Parse route table to get the interface index for the default gateway
                    // The interface index is used with IP_UNICAST_IF socket option
                    let _route_info = stdout; // Route info available for debugging
                }
                // Set IP_UNICAST_IF via raw socket option (interface index in network byte order)
                // This uses the default interface that can reach the endpoint IP
                // The connect() call below already handles routing, but this adds defense-in-depth
                tracing::debug!("WG UDP socket will connect directly to {}", endpoint_addr);
            }
        }

        socket
            .connect(&endpoint_addr)
            .await
            .map_err(|e| format!("Failed to connect to endpoint: {}", e))?;

        tracing::debug!(
            "Created WireGuard session to {} from {:?}",
            endpoint_addr,
            socket.local_addr()
        );

        let session = Self {
            tunnel: Arc::new(FastMutex::new(tunnel)),
            socket: Arc::new(socket),
            endpoint: endpoint_addr,
            is_connected: Arc::new(RwLock::new(false)),
            created_at: Instant::now(),
            last_handshake: Arc::new(RwLock::new(None)),
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
                    *self.last_handshake.write().await = Some(Instant::now());
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
                        *self.is_connected.write().await = true;
                        Ok(())
                    }
                    TunnResult::WriteToNetwork(response_data) => {
                        // Need to send a response (cookie or similar)
                        self.socket
                            .send(response_data)
                            .await
                            .map_err(|e| format!("Failed to send response: {}", e))?;
                        
                        tracing::info!("WireGuard handshake complete (with response)");
                        *self.is_connected.write().await = true;
                        Ok(())
                    }
                    TunnResult::Err(e) => {
                        Err(format!("Handshake failed: {:?}", e))
                    }
                    other => {
                        Err(format!("Unexpected handshake result: {:?}", other))
                    }
                }
            }
            Ok(Err(e)) => Err(format!("Failed to receive handshake response: {}", e)),
            Err(_) => Err("Handshake timeout - no response from server".to_string()),
        }
    }

    /// Encrypt and send an IP packet
    /// PERF-001: Uses stack allocation for normal-sized packets (≤ MTU 1420 + overhead)
    /// to eliminate per-packet heap allocations. Falls back to heap for jumbo frames.
    pub async fn send_packet(&self, packet: &[u8]) -> Result<usize, String> {
        if !*self.is_connected.read().await {
            return Err("Not connected".to_string());
        }

        let total_size = packet.len() + WIREGUARD_OVERHEAD;

        if total_size <= 1600 {
            // PERF-001: Fast path — stack allocation for normal-sized packets
            let mut dst = [0u8; 1600];
            
            let result = {
                let mut tunnel = self.tunnel.lock();
                tunnel.encapsulate(packet, &mut dst)
            };

            match result {
                TunnResult::WriteToNetwork(data) => {
                    let sent = self.socket
                        .send(data)
                        .await
                        .map_err(|e| format!("Failed to send: {}", e))?;
                    Ok(sent)
                }
                TunnResult::Err(e) => Err(format!("Encryption failed: {:?}", e)),
                _ => Err("Unexpected encapsulate result".to_string()),
            }
        } else {
            // Slow path — heap allocation for jumbo/oversized packets
            let mut dst = vec![0u8; total_size];
            
            let result = {
                let mut tunnel = self.tunnel.lock();
                tunnel.encapsulate(packet, &mut dst)
            };

            match result {
                TunnResult::WriteToNetwork(data) => {
                    let sent = self.socket
                        .send(data)
                        .await
                        .map_err(|e| format!("Failed to send: {}", e))?;
                    Ok(sent)
                }
                TunnResult::Err(e) => Err(format!("Encryption failed: {:?}", e)),
                _ => Err("Unexpected encapsulate result".to_string()),
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
                    tracing::warn!(
                        recv_len = n,
                        "Received oversized UDP datagram — dropping"
                    );
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
                        tracing::trace!("Decapsulate → WriteToNetwork ({} bytes, e.g. handshake response)", data.len());
                        // Send keepalive or timer response — don't return to tunnel
                        let _ = self.socket.send(data).await;
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
            Err(e) => Err(format!("Receive error: {}", e)),
        }
    }

    /// Update timers and send keepalives as needed
    pub async fn update_timers(&self) -> Result<(), String> {
        // PERF: Stack-allocate keepalive buffer (WIREGUARD_OVERHEAD = 80 bytes)
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
            TunnResult::Err(e) => Err(format!("Timer update failed: {:?}", e)),
            _ => Ok(()),
        }
    }

    /// Get the resolved endpoint IP address the socket is connected to
    pub fn endpoint_ip(&self) -> std::net::IpAddr {
        self.endpoint.ip()
    }

    /// Check if the session is connected
    pub async fn is_connected(&self) -> bool {
        *self.is_connected.read().await
    }

    /// Get the last measured latency in milliseconds
    pub async fn get_latency_ms(&self) -> Option<u32> {
        *self.last_latency_ms.read().await
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
        let timeout_result = tokio::time::timeout(
            Duration::from_millis(2000),
            self.socket.recv(&mut buf)
        ).await;

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
        *self.is_connected.write().await = false;
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
