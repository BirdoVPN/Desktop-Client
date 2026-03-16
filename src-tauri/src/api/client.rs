//! API client implementation
//!
//! Handles all HTTP communication with the Birdo VPN backend.

use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Sha256, Digest};
use base64::Engine as _;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use super::error::ApiError;
use super::types::*;
use super::endpoints;

// H-1: erased_serde is used for the generic retry interceptor
// that needs to pass serializable bodies through a trait object.
use erased_serde;

/// Production API URL
/// This should match the CSP in tauri.conf.json: connect-src https://birdo.app
const API_BASE_URL: &str = "https://birdo.app/api";
const USER_AGENT: &str = concat!("Birdo-Desktop/", env!("CARGO_PKG_VERSION"), " (Windows)");

/// SEC-C1: SHA-256 hashes of the full DER-encoded **leaf** certificate for birdo.app.
///
/// **IMPORTANT**: reqwest's `TlsInfo::peer_certificate()` returns ONLY the leaf
/// certificate, NOT the full chain. Therefore ONLY leaf cert hashes should be
/// listed here — intermediate/root CA hashes will never match and provide zero
/// backup protection.
///
/// Generate the current leaf pin with:
///   openssl s_client -connect birdo.app:443 </dev/null 2>/dev/null | \
///     openssl x509 -outform DER | \
///     openssl dgst -sha256 -binary | \
///     openssl enc -base64
///
/// Or use the helper script:
///   ./scripts/generate-cert-pins.sh birdo.app
///   (Look for the "Full DER SHA-256 Pin" / "Rust (client.rs)" output lines)
///
/// **PIN ROTATION PROCEDURE** (do this BEFORE Cloudflare rotates the cert):
/// 1. Provision the next certificate on Cloudflare (Advanced Certificate Manager
///    or custom cert upload — aim for ≥1 year validity to reduce churn).
/// 2. Run `./scripts/generate-cert-pins.sh birdo.app` against the NEW cert.
/// 3. Add the new hash to this array alongside the current one ("next" slot).
/// 4. Ship the update so existing clients accept both old and new certs.
/// 5. Activate the new cert on Cloudflare.
/// 6. In a follow-up release, remove the old pin.
///
/// When this array is empty, pinning is DISABLED and a warning is logged on
/// every request. Populate before public release.
const CERT_PINS_SHA256: &[&str] = &[
    // Pins verified 2026-03-07 from live birdo.app edge certificate.
    // These are full DER cert SHA-256 hashes (NOT SPKI).
    //
    // LEAF ONLY — reqwest peer_certificate() does not expose the chain,
    // so intermediate/root pins are omitted (they would never match).
    //
    // Current leaf cert (CN=birdo.app, issuer: Google Trust Services WE1) expires 2026-06-02.
    "EQul2kftgtOaU85XCKuj4SK3DW5256uxNdEvZXZbuJM=",  // leaf: birdo.app (Google/CF, expires 2026-06-02)
    // ── Next cert pin slot ──────────────────────────────────────────────
    // After renewing the certificate on Cloudflare, add the new leaf hash
    // here BEFORE removing the old one. This ensures clients that haven't
    // updated yet still pass pinning against the old cert, while updated
    // clients accept the new one.
    // "<NEW_LEAF_PIN_HERE>",  // leaf: birdo.app (next cert, expires ~YYYY-MM-DD)
];

/// FIX H-3: Build-time guard — release builds MUST have certificate pins populated.
/// This prevents accidentally shipping an unpinned client to production.
#[cfg(not(debug_assertions))]
const _: () = {
    if CERT_PINS_SHA256.is_empty() {
        panic!("SEC-C1: CERT_PINS_SHA256 must be populated before release builds. Run the openssl command in the comment above to generate pins.");
    }
};

pub struct BirdoApi {
    client: Client,
    /// F-23 FIX: Tokens wrapped in Zeroizing<String> so old values are securely
    /// wiped from memory when replaced, matching the SensitiveKey treatment
    /// of VPN private keys in wireguard_new.rs.
    access_token: Arc<RwLock<Option<Zeroizing<String>>>>,
    refresh_token: Arc<RwLock<Option<Zeroizing<String>>>>,
}

impl BirdoApi {
    /// Create a new API client instance
    pub fn new() -> Self {
        // SEC-C1 FIX: TLS hardening — enforce HTTPS, set minimum TLS version,
        // and enable certificate info for runtime SPKI/cert pinning.
        // The Android client has dual-layer pinning; the Windows client must match.
        use reqwest::tls::Version;

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(USER_AGENT)
            .pool_max_idle_per_host(5)
            .https_only(true)
            .min_tls_version(Version::TLS_1_2)
            // SEC-C1: Enable TLS info so we can verify the peer certificate
            // hash against CERT_PINS_SHA256 after every handshake.
            .tls_info(true)
            .tls_built_in_root_certs(true)
            .build()
            // SEC-C1 FIX: Do NOT fall back to Client::new() — that would
            // silently downgrade to an unpinned, un-hardened client.
            .expect("Failed to build hardened HTTP client — cannot proceed without TLS safeguards");

        Self {
            client,
            access_token: Arc::new(RwLock::new(None)),
            refresh_token: Arc::new(RwLock::new(None)),
        }
    }

    /// Set authentication tokens
    pub async fn set_tokens(&self, access: String, refresh: String) {
        *self.access_token.write().await = Some(Zeroizing::new(access));
        *self.refresh_token.write().await = Some(Zeroizing::new(refresh));
    }

    /// Clear authentication tokens
    pub async fn clear_tokens(&self) {
        *self.access_token.write().await = None;
        *self.refresh_token.write().await = None;
    }

    /// Check if user is authenticated
    pub async fn is_authenticated(&self) -> bool {
        self.access_token.read().await.is_some()
    }

    // ========================================================================
    // Authentication Endpoints
    // ========================================================================

    /// Login with email and password (desktop endpoint)
    /// FIX C-2: Returns LoginResult which may be either Success (with tokens)
    /// or TwoFactorChallenge (requiring TOTP code submission).
    pub async fn login(&self, email: &str, password: &str) -> Result<LoginResult, ApiError> {
        let payload = LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        };

        // Use desktop-specific endpoint that returns tokens in body
        let result: LoginResult = self.post(endpoints::auth::LOGIN_DESKTOP, &payload, false).await?;

        // Only store tokens if login succeeded (not 2FA challenge)
        if let LoginResult::Success { ref tokens, .. } = result {
            self.set_tokens(
                tokens.access_token.clone(),
                tokens.refresh_token.clone(),
            )
            .await;
        }

        Ok(result)
    }

    /// FIX C-2: Verify TOTP code for 2FA challenge.
    /// Called after login returns LoginResult::TwoFactorChallenge.
    pub async fn verify_2fa(&self, challenge_token: &str, totp_code: &str) -> Result<TwoFactorVerifyResponse, ApiError> {
        let payload = TwoFactorVerifyRequest {
            challenge_token: challenge_token.to_string(),
            token: totp_code.to_string(),
        };

        let response: TwoFactorVerifyResponse = self.post(endpoints::auth::TWO_FACTOR_VERIFY, &payload, false).await?;

        // Store tokens from successful 2FA verification
        if let Some(ref tokens) = response.tokens {
            self.set_tokens(
                tokens.access_token.clone(),
                tokens.refresh_token.clone(),
            )
            .await;
        }

        Ok(response)
    }

    /// Refresh access token
    /// FIX C-1: Updated to persist the new refresh token when server returns one
    /// (server now returns tokens in JSON body for desktop clients).
    pub async fn refresh_token(&self) -> Result<RefreshResponse, ApiError> {
        let refresh = self
            .refresh_token
            .read()
            .await
            .clone()
            .ok_or(ApiError::NotAuthenticated)?;

        let payload = RefreshRequest {
            refresh_token: (*refresh).clone(),
        };

        let response: RefreshResponse = self.post(endpoints::auth::REFRESH, &payload, false).await?;

        // Update access token
        *self.access_token.write().await = Some(Zeroizing::new(response.access_token.clone()));
        
        // FIX C-1: Also update refresh token if server rotated it
        if let Some(ref new_refresh) = response.refresh_token {
            *self.refresh_token.write().await = Some(Zeroizing::new(new_refresh.clone()));
        }

        Ok(response)
    }

    /// Logout (invalidate tokens on server)
    pub async fn logout(&self) -> Result<(), ApiError> {
        let _ = self.post::<_, serde_json::Value>(endpoints::auth::LOGOUT, &(), true).await;
        self.clear_tokens().await;
        Ok(())
    }

    /// GDPR: Permanently delete account and all associated data
    pub async fn delete_account(&self, password: &str) -> Result<(), ApiError> {
        #[derive(Serialize)]
        struct DeleteBody<'a> {
            password: &'a str,
        }
        self.post::<_, serde_json::Value>(
            endpoints::auth::GDPR_DELETE,
            &DeleteBody { password },
            true,
        ).await?;
        self.clear_tokens().await;
        Ok(())
    }

    /// GDPR: Export all user data (Right to Data Portability, Art. 20)
    pub async fn export_user_data(&self) -> Result<serde_json::Value, ApiError> {
        self.get(endpoints::auth::GDPR_EXPORT, true).await
    }

    // ========================================================================
    // VPN Endpoints
    // ========================================================================

    /// Get list of available VPN servers
    pub async fn get_servers(&self) -> Result<Vec<VpnServer>, ApiError> {
        self.get(endpoints::vpn::SERVERS, true).await
    }

    /// Connect to a VPN server and get WireGuard configuration
    /// FIX-1-1: Accepts optional client_public_key for client-side keygen
    pub async fn connect_vpn(
        &self,
        server_id: &str,
        device_name: &str,
        client_public_key: Option<String>,
        stealth_mode: Option<bool>,
        quantum_protection: Option<bool>,
    ) -> Result<ConnectResponse, ApiError> {
        let payload = ConnectRequest {
            server_node_id: Some(server_id.to_string()),
            device_name: Some(device_name.to_string()),
            preferred_region: None,
            client_public_key,
            stealth_mode,
            quantum_protection,
        };
        
        self.post(endpoints::vpn::CONNECT, &payload, true).await
    }

    /// Disconnect from VPN (revoke key)
    pub async fn disconnect_vpn(&self, key_id: &str) -> Result<(), ApiError> {
        self.delete::<serde_json::Value>(&endpoints::vpn::connection(key_id), true).await?;
        Ok(())
    }

    /// Report connection status to server (heartbeat)
    /// FIX-2-13: Called periodically by auto_reconnect health check loop
    /// P1-9: Now returns HeartbeatResponse so callers can act on valid/serverOnline
    pub async fn heartbeat(&self, key_id: &str) -> Result<HeartbeatResponse, ApiError> {
        self.post::<_, HeartbeatResponse>(&endpoints::vpn::heartbeat(key_id), &(), true)
            .await
    }

    /// P3-25: Rotate the WireGuard key for an active connection.
    /// Sends a new client public key; server returns new server public key and key_id.
    /// The old key is deactivated server-side after rotation succeeds.
    pub async fn rotate_key(&self, key_id: &str, new_public_key: &str) -> Result<super::types::KeyRotationResponse, ApiError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RotateRequest<'a> {
            client_public_key: &'a str,
        }
        self.post(&endpoints::vpn::rotate_key(key_id), &RotateRequest { client_public_key: new_public_key }, true).await
    }

    /// P2-15: Report connection quality telemetry to the backend.
    /// Fire-and-forget — callers should not block on failure.
    pub async fn report_quality(&self, report: &QualityReport) -> Result<(), ApiError> {
        let _: serde_json::Value = self.post(endpoints::vpn::QUALITY_REPORT, report, true).await
            .or_else(|e| {
                // 204 No Content is expected — treat parse errors as success
                if matches!(e, ApiError::Parse(_)) { Ok(serde_json::Value::Null) } else { Err(e) }
            })?;
        Ok(())
    }

    // ========================================================================
    // User Endpoints
    // ========================================================================

    /// Get current user profile
    pub async fn get_profile(&self) -> Result<UserProfile, ApiError> {
        self.get(endpoints::auth::ME, true).await
    }

    /// Get subscription status
    pub async fn get_subscription(&self) -> Result<SubscriptionStatus, ApiError> {
        self.get(endpoints::users::SUBSCRIPTION, true).await
    }

    // ========================================================================
    // Anonymous Login
    // ========================================================================

    /// Login anonymously with a device ID (creates a new RECON account)
    pub async fn login_anonymous(&self, device_id: &str) -> Result<AnonymousLoginResult, ApiError> {
        let payload = AnonymousLoginRequest {
            device_id: device_id.to_string(),
        };

        let result: AnonymousLoginResult = self.post(endpoints::auth::LOGIN_ANONYMOUS, &payload, false).await?;

        if let Some(ref tokens) = result.tokens {
            self.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone()).await;
        }

        Ok(result)
    }

    // ========================================================================
    // Multi-Hop (Double VPN)
    // ========================================================================

    /// Get available multi-hop routes (SOVEREIGN plan only)
    pub async fn get_multi_hop_routes(&self) -> Result<Vec<MultiHopRoute>, ApiError> {
        self.get(endpoints::vpn::MULTI_HOP_ROUTES, true).await
    }

    /// Connect via multi-hop (entry + exit nodes)
    pub async fn connect_multi_hop(
        &self,
        entry_node_id: &str,
        exit_node_id: &str,
        device_name: &str,
        client_public_key: &str,
    ) -> Result<MultiHopConnectResponse, ApiError> {
        let payload = MultiHopConnectRequest {
            entry_node_id: entry_node_id.to_string(),
            exit_node_id: exit_node_id.to_string(),
            device_name: Some(device_name.to_string()),
            client_public_key: Some(client_public_key.to_string()),
        };

        self.post(endpoints::vpn::MULTI_HOP_CONNECT, &payload, true).await
    }

    // ========================================================================
    // Port Forwarding
    // ========================================================================

    /// List active port forwards for the current connection
    pub async fn get_port_forwards(&self) -> Result<Vec<PortForward>, ApiError> {
        self.get(endpoints::vpn::PORT_FORWARDS, true).await
    }

    /// Create a new port forward
    pub async fn create_port_forward(
        &self,
        internal_port: u16,
        protocol: &str,
        preferred_port: Option<u16>,
    ) -> Result<CreatePortForwardResponse, ApiError> {
        let payload = CreatePortForwardRequest {
            internal_port,
            protocol: protocol.to_string(),
            preferred_port,
        };

        self.post(endpoints::vpn::PORT_FORWARDS, &payload, true).await
    }

    /// Delete a port forward
    pub async fn delete_port_forward(&self, id: &str) -> Result<(), ApiError> {
        self.delete::<serde_json::Value>(&format!("{}/{}", endpoints::vpn::PORT_FORWARDS, id), true).await?;
        Ok(())
    }

    // ========================================================================
    // HTTP Helpers
    // ========================================================================

    /// H-1 FIX: Internal helper that makes a request and handles 401 with automatic
    /// token refresh + retry. Prevents users from being silently logged out when
    /// access tokens expire mid-session.
    async fn request_with_retry<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&(dyn erased_serde::Serialize + Sync)>,
        auth: bool,
    ) -> Result<T, ApiError> {
        let result = self.do_request::<T>(&method, path, body, auth).await;
        
        // If we got a 401 and we have a refresh token, try refreshing
        if matches!(&result, Err(ApiError::Unauthorized)) && auth {
            let has_refresh = self.refresh_token.read().await.is_some();
            if has_refresh {
                tracing::info!("Got 401 — attempting transparent token refresh");
                match self.refresh_token_internal().await {
                    Ok(_) => {
                        tracing::info!("Token refreshed successfully, retrying request");
                        // Retry the original request with the new token
                        return self.do_request::<T>(&method, path, body, auth).await;
                    }
                    Err(e) => {
                        tracing::warn!("Token refresh failed: {}", e);
                        // Return the original 401 error
                        return Err(ApiError::Unauthorized);
                    }
                }
            }
        }
        
        result
    }

    /// Internal: perform a single HTTP request (no retry)
    async fn do_request<T: DeserializeOwned>(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: Option<&(dyn erased_serde::Serialize + Sync)>,
        auth: bool,
    ) -> Result<T, ApiError> {
        let url = format!("{}{}", API_BASE_URL, path);
        let mut request = self.client.request(method.clone(), &url);

        if method == reqwest::Method::POST {
            request = request.header("X-Desktop-Client", "birdo-windows");
        }

        if let Some(b) = body {
            request = request.json(b);
        }

        if auth {
            let token = self
                .access_token
                .read()
                .await
                .clone()
                .ok_or(ApiError::NotAuthenticated)?;
            request = request.bearer_auth(token.as_str());
        }

        let response = request.send().await.map_err(|e| ApiError::Network(e.to_string()))?;
        self.handle_response(response).await
    }

    /// Internal: refresh access token (used by retry interceptor)
    async fn refresh_token_internal(&self) -> Result<(), ApiError> {
        let refresh = self
            .refresh_token
            .read()
            .await
            .clone()
            .ok_or(ApiError::NotAuthenticated)?;

        let payload = RefreshRequest {
            refresh_token: (*refresh).clone(),
        };

        // Use do_request directly to avoid infinite retry loop
        let response: RefreshResponse = self.do_request(
            &reqwest::Method::POST,
            endpoints::auth::REFRESH,
            Some(&payload),
            false,
        ).await?;

        *self.access_token.write().await = Some(Zeroizing::new(response.access_token));
        // FIX C-1: Also update refresh token if rotated
        if let Some(new_refresh) = response.refresh_token {
            *self.refresh_token.write().await = Some(Zeroizing::new(new_refresh));
        }
        Ok(())
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, auth: bool) -> Result<T, ApiError> {
        self.request_with_retry(reqwest::Method::GET, path, None, auth).await
    }

    async fn post<B: Serialize + Sync, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        auth: bool,
    ) -> Result<T, ApiError> {
        self.request_with_retry(reqwest::Method::POST, path, Some(body), auth).await
    }

    async fn delete<T: DeserializeOwned>(&self, path: &str, auth: bool) -> Result<T, ApiError> {
        self.request_with_retry(reqwest::Method::DELETE, path, None, auth).await
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ApiError> {
        // SEC-C1: Verify certificate pin before processing the response.
        self.verify_certificate_pin(&response)?;

        let status = response.status();

        match status {
            StatusCode::OK | StatusCode::CREATED => {
                response.json().await.map_err(|e| ApiError::Parse(e.to_string()))
            }
            StatusCode::UNAUTHORIZED => {
                // Try to refresh token
                Err(ApiError::Unauthorized)
            }
            StatusCode::FORBIDDEN => Err(ApiError::Forbidden),
            StatusCode::NOT_FOUND => Err(ApiError::NotFound),
            StatusCode::TOO_MANY_REQUESTS => Err(ApiError::RateLimited),
            StatusCode::INTERNAL_SERVER_ERROR | StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => {
                Err(ApiError::ServerError(status.as_u16()))
            }
            _ => {
                // P1-7: Try to parse a typed error code from the response body
                let error_text = response.text().await.unwrap_or_default();
                if let Ok(body) = serde_json::from_str::<super::types::ApiErrorBody>(&error_text) {
                    if let Some(code) = body.error_code {
                        return Err(ApiError::Protocol(code));
                    }
                }
                tracing::debug!("Unhandled HTTP {}: {}", status, error_text);
                Err(ApiError::Unknown(format!("HTTP {}", status.as_u16())))
            }
        }
    }

    /// SEC-C1: Verify the leaf certificate's SHA-256 hash against pinned values.
    ///
    /// NOTE: reqwest only exposes the leaf via `peer_certificate()`, NOT the full
    /// chain. Only leaf cert hashes should be in CERT_PINS_SHA256.
    ///
    /// If `CERT_PINS_SHA256` is empty (development mode), this logs a warning
    /// and allows the connection.  In production, populate the array and this
    /// function will reject connections whose certificate doesn't match any pin.
    fn verify_certificate_pin(&self, response: &reqwest::Response) -> Result<(), ApiError> {
        if CERT_PINS_SHA256.is_empty() {
            // Development mode — pinning disabled.  Log once per session
            // via tracing (deduplication is handled at the subscriber level).
            tracing::warn!(
                "SEC-C1: CERT_PINS_SHA256 is empty — certificate pinning is DISABLED. \
                 Populate the array before public release."
            );
            return Ok(());
        }

        // reqwest exposes TLS info only if `.tls_info(true)` was set on the builder.
        let tls_info = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .ok_or_else(|| {
                ApiError::CertificatePinningFailed(
                    "TLS info unavailable — cannot verify pin".into(),
                )
            })?;

        let peer_cert_der = tls_info.peer_certificate().ok_or_else(|| {
            ApiError::CertificatePinningFailed(
                "No peer certificate in TLS info".into(),
            )
        })?;

        // Compute SHA-256 of the full DER-encoded certificate.
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(peer_cert_der);
            base64::engine::general_purpose::STANDARD
                .encode(hasher.finalize())
        };

        if CERT_PINS_SHA256.iter().any(|pin| *pin == hash) {
            Ok(())
        } else {
            tracing::error!(
                "SEC-C1: Certificate pin mismatch! Computed hash: {}. \
                 This may indicate a MITM attack or an un-pinned certificate rotation.",
                hash,
            );
            Err(ApiError::CertificatePinningFailed(format!(
                "Peer cert hash {} does not match any pinned value",
                hash,
            )))
        }
    }
}

impl Default for BirdoApi {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for BirdoApi {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            access_token: Arc::clone(&self.access_token),
            refresh_token: Arc::clone(&self.refresh_token),
        }
    }
}
