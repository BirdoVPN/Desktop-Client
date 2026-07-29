//! API client implementation
//!
//! Handles all HTTP communication with the Birdo VPN backend.

use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use super::endpoints;
use super::error::ApiError;
use super::types::*;

// H-1: erased_serde is used for the generic retry interceptor
// that needs to pass serializable bodies through a trait object.
use erased_serde;

/// Production API URL
/// This should match the CSP in tauri.conf.json: connect-src https://*.birdo.app
/// As of subdomain-based routing, the backend is reachable via api.birdo.app
/// (Caddy reverse-proxies api.birdo.app -> backend:4000 directly, no /api prefix).
const API_BASE_URL: &str = "https://api.birdo.app";
const USER_AGENT: &str = concat!("Birdo-Desktop/", env!("CARGO_PKG_VERSION"), " (Windows)");

// SEC-C1: TLS certificate pinning lives in `super::cert_pin`. It pins the
// **CA-chain SPKI** (the stable intermediate/root public keys, matching the
// Android client) via a custom rustls verifier, so Cloudflare/Google leaf
// rotations NO LONGER require a desktop release. See src/api/cert_pin.rs.

pub struct BirdoApi {
    client: Client,
    /// F-23 FIX: Tokens wrapped in Zeroizing<String> so old values are securely
    /// wiped from memory when replaced, matching the SensitiveKey treatment
    /// of VPN private keys in wireguard_new.rs.
    access_token: Arc<RwLock<Option<Zeroizing<String>>>>,
    refresh_token: Arc<RwLock<Option<Zeroizing<String>>>>,
    /// Guard to prevent concurrent token refresh attempts (H-1 race fix)
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl BirdoApi {
    /// Create a new API client instance
    pub fn new() -> Self {
        // SEC-C1 FIX: TLS hardening — enforce HTTPS and install the CA-chain
        // SPKI pinning rustls config (see super::cert_pin). The custom rustls
        // ServerCertVerifier does full standard validation (chain/hostname/
        // expiry) AND pins the intermediate/root public keys during the
        // handshake — matching the Android client and surviving leaf rotations.
        // TLS 1.2 minimum + versions are set by the rustls config itself.
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            // Bound the TCP handshake separately from the overall request budget.
            // Without this, ONE unreachable address (e.g. an IPv6 candidate that
            // our own leak block rejects, or a black-holing middlebox) could eat
            // the entire 30 s timeout before reqwest ever tried the next address,
            // which is what made a server switch look frozen instead of simply
            // retrying over IPv4.
            .connect_timeout(Duration::from_secs(8))
            .user_agent(USER_AGENT)
            .pool_max_idle_per_host(5)
            .https_only(true)
            // F5 FIX: resolve the control plane via the cert-pinned DoH resolver
            // (system-resolver fallback) so a censoring ISP / captive portal that
            // hijacks or blocks DNS for api.birdo.app can no longer block desktop
            // login — matching the Android client. See super::doh_resolver.
            .dns_resolver(std::sync::Arc::new(
                super::doh_resolver::DohApiResolver::new(),
            ))
            .use_preconfigured_tls(super::cert_pin::rustls_config())
            .build()
            // SEC-C1 FIX: Do NOT fall back to Client::new() — that would
            // silently downgrade to an unpinned, un-hardened client.
            .expect("Failed to build hardened HTTP client — cannot proceed without TLS safeguards");

        Self {
            client,
            access_token: Arc::new(RwLock::new(None)),
            refresh_token: Arc::new(RwLock::new(None)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
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

    /// Return the current access token (for commands like the speed test that
    /// hit Bearer-authed endpoints with the shared hardened client).
    pub async fn access_token_value(&self) -> Option<String> {
        self.access_token
            .read()
            .await
            .as_ref()
            .map(|t| t.to_string())
    }

    /// Return a clone of the hardened reqwest Client for reuse by other commands.
    /// This avoids creating secondary un-hardened clients that bypass TLS pinning.
    pub fn http_client(&self) -> Client {
        self.client.clone()
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
        let result: LoginResult = self
            .post(endpoints::auth::LOGIN_DESKTOP, &payload, false)
            .await?;

        // Only store tokens if login succeeded (not 2FA challenge)
        if let LoginResult::Success { ref tokens, .. } = result {
            self.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }

        Ok(result)
    }

    /// Native SSO handoff exchange. Swaps the web broker's single-use, PKCE-bound
    /// code (delivered to our loopback redirect after the Google/GitHub flow) for
    /// real tokens. Returns the same LoginResult shape as password login, so a 2FA
    /// challenge is handled by the identical downstream path.
    pub async fn native_exchange(
        &self,
        code: &str,
        code_verifier: &str,
        device_id: &str,
    ) -> Result<LoginResult, ApiError> {
        let payload = NativeExchangeRequest {
            code: code.to_string(),
            code_verifier: code_verifier.to_string(),
            device_id: device_id.to_string(),
        };

        let result: LoginResult = self
            .post(endpoints::auth::NATIVE_EXCHANGE, &payload, false)
            .await?;

        if let LoginResult::Success { ref tokens, .. } = result {
            self.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }

        Ok(result)
    }

    /// FIX C-2: Verify TOTP code for 2FA challenge.
    /// Called after login returns LoginResult::TwoFactorChallenge.
    pub async fn verify_2fa(
        &self,
        challenge_token: &str,
        totp_code: &str,
    ) -> Result<TwoFactorVerifyResponse, ApiError> {
        let payload = TwoFactorVerifyRequest {
            challenge_token: challenge_token.to_string(),
            token: totp_code.to_string(),
        };

        let response: TwoFactorVerifyResponse = self
            .post(endpoints::auth::TWO_FACTOR_VERIFY, &payload, false)
            .await?;

        // Store tokens from successful 2FA verification
        if let Some(ref tokens) = response.tokens {
            self.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }

        Ok(response)
    }

    /// Refresh access token
    /// FIX C-1: Updated to persist the new refresh token when server returns one
    /// (server now returns tokens in JSON body for desktop clients).
    pub async fn refresh_token(&self) -> Result<RefreshResponse, ApiError> {
        // H-1 FIX: Serialize all token refresh operations (including this public
        // entry point) so concurrent callers cannot race and overwrite each
        // other's tokens with stale values.
        let _guard = self.refresh_lock.lock().await;

        let refresh = self
            .refresh_token
            .read()
            .await
            .clone()
            .ok_or(ApiError::NotAuthenticated)?;

        let payload = RefreshRequest {
            refresh_token: (*refresh).clone(),
        };

        let response: RefreshResponse =
            self.post(endpoints::auth::REFRESH, &payload, false).await?;

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
        let _ = self
            .post::<_, serde_json::Value>(endpoints::auth::LOGOUT, &(), true)
            .await;
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
        )
        .await?;
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

    /// Get a single-use nonce for the Ed25519 client attestation
    pub async fn get_attestation_nonce(&self) -> Result<AttestationNonceResponse, ApiError> {
        self.get(endpoints::vpn::ATTESTATION_NONCE, true).await
    }

    /// Best-effort desktop attestation (`BIRDO-DESKTOP-ATTEST-v1`).
    ///
    /// Returns None without a round-trip on builds compiled without the signing
    /// key (dev / fork), and swallows a failed nonce fetch: while the server
    /// policy is `off`/`log` an unreachable nonce endpoint must never be the
    /// reason a connect fails — same best-effort contract as the Android client.
    ///
    /// Called from `connect_vpn` / `connect_multi_hop` rather than the command
    /// layer so quick-connect and auto-reconnect's unattended re-dial are signed
    /// too; an unsigned re-dial would be refused under `enforce` exactly when the
    /// user is not watching.
    async fn desktop_attestation(&self) -> Option<super::attestation::DesktopAttestation> {
        if !super::attestation::is_configured() {
            return None;
        }

        match self.get_attestation_nonce().await {
            Ok(response) => super::attestation::sign(&response.nonce),
            Err(e) => {
                tracing::warn!(
                    "Attestation nonce fetch failed, connecting unattested: {}",
                    e
                );
                None
            }
        }
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
        pq_client_public_key: Option<String>,
    ) -> Result<ConnectResponse, ApiError> {
        let attestation = self.desktop_attestation().await;

        let payload = ConnectRequest {
            server_node_id: Some(server_id.to_string()),
            device_name: Some(device_name.to_string()),
            preferred_region: None,
            client_public_key,
            stealth_mode,
            quantum_protection,
            pq_client_public_key,
            desktop_attest_nonce: attestation.as_ref().map(|a| a.nonce.clone()),
            desktop_attest_kid: attestation.as_ref().map(|a| a.kid.clone()),
            desktop_attest_sig: attestation.as_ref().map(|a| a.signature.clone()),
            desktop_attest_platform: attestation.as_ref().map(|a| a.platform.to_string()),
            desktop_attest_version: attestation.as_ref().map(|a| a.version.to_string()),
        };

        self.post(endpoints::vpn::CONNECT, &payload, true).await
    }

    /// Disconnect from VPN (revoke key)
    pub async fn disconnect_vpn(&self, key_id: &str) -> Result<(), ApiError> {
        self.delete::<serde_json::Value>(&endpoints::vpn::connection(key_id), true)
            .await?;
        Ok(())
    }

    /// Report connection status to server (heartbeat)
    /// FIX-2-13: Called periodically by auto_reconnect health check loop
    /// P1-9: Now returns HeartbeatResponse so callers can act on valid/serverOnline
    pub async fn heartbeat(&self, key_id: &str) -> Result<HeartbeatResponse, ApiError> {
        self.post::<_, HeartbeatResponse>(&endpoints::vpn::heartbeat(key_id), &(), true)
            .await
    }

    /// P2-15: Report connection quality telemetry to the backend.
    /// Fire-and-forget — callers should not block on failure.
    pub async fn report_quality(&self, report: &QualityReport) -> Result<(), ApiError> {
        let _: serde_json::Value = self
            .post(endpoints::vpn::QUALITY_REPORT, report, true)
            .await
            .or_else(|e| {
                // 204 No Content is expected — treat parse errors as success
                if matches!(e, ApiError::Parse(_)) {
                    Ok(serde_json::Value::Null)
                } else {
                    Err(e)
                }
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

    /// Get per-user monthly bandwidth usage + cap for the data-usage meter.
    /// Distinct from `get_vpn_stats` (local live-tunnel throughput).
    pub async fn get_usage_stats(&self) -> Result<super::types::UsageStats, ApiError> {
        self.get(endpoints::vpn::USAGE_STATS, true).await
    }

    /// Redeem a voucher code (30/90-day time-extension). Authenticated.
    /// On an invalid/used/expired code the backend returns a non-2xx status,
    /// which surfaces here as an `ApiError` for the command layer to map.
    pub async fn redeem_voucher(
        &self,
        code: &str,
    ) -> Result<super::types::RedeemVoucherResponse, ApiError> {
        let payload = super::types::RedeemVoucherRequest {
            code: code.to_string(),
        };
        self.post(endpoints::vouchers::REDEEM, &payload, true).await
    }

    // ========================================================================
    // Anonymous Login
    // ========================================================================

    /// Login to an EXISTING anonymous account by its 24-digit ID (+ optional
    /// password set on the website). The endpoint never creates accounts.
    pub async fn login_anonymous(
        &self,
        anonymous_id: &str,
        password: Option<String>,
        device_id: &str,
    ) -> Result<AnonymousLoginResult, ApiError> {
        let payload = AnonymousLoginRequest {
            anonymous_id: anonymous_id.to_string(),
            password,
            device_id: device_id.to_string(),
        };

        let result: AnonymousLoginResult = self
            .post(endpoints::auth::LOGIN_ANONYMOUS, &payload, false)
            .await?;

        if let Some(ref tokens) = result.tokens {
            self.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
        }

        Ok(result)
    }

    /// Create a BRAND-NEW anonymous account in-app (native clients). The server
    /// mints the 24-digit ID and returns tokens, so the app is signed in
    /// immediately — the no-email privacy path without a website round-trip.
    /// Requires the X-Desktop-Client header, which `do_request` adds to all POSTs.
    pub async fn register_anonymous(
        &self,
        device_id: &str,
        device_name: Option<String>,
    ) -> Result<AnonymousLoginResult, ApiError> {
        let payload = crate::api::types::AnonymousRegisterRequest {
            device_id: device_id.to_string(),
            device_name,
            device_type: "DESKTOP".to_string(),
            platform: match std::env::consts::OS {
                "windows" => "WINDOWS",
                "macos" => "MACOS",
                "linux" => "LINUX",
                _ => "UNKNOWN",
            }
            .to_string(),
            app_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        };

        let result: AnonymousLoginResult = self
            .post(endpoints::auth::REGISTER_ANONYMOUS, &payload, false)
            .await?;

        if let Some(ref tokens) = result.tokens {
            self.set_tokens(tokens.access_token.clone(), tokens.refresh_token.clone())
                .await;
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
    #[allow(clippy::too_many_arguments)] // mirrors the backend endpoint's parameter surface 1:1
    pub async fn connect_multi_hop(
        &self,
        entry_node_id: &str,
        exit_node_id: &str,
        device_name: &str,
        client_public_key: &str,
        stealth_mode: bool,
        quantum_protection: bool,
        pq_client_public_key: Option<String>,
    ) -> Result<MultiHopConnectResponse, ApiError> {
        let attestation = self.desktop_attestation().await;

        let payload = MultiHopConnectRequest {
            entry_node_id: entry_node_id.to_string(),
            exit_node_id: exit_node_id.to_string(),
            device_name: Some(device_name.to_string()),
            client_public_key: Some(client_public_key.to_string()),
            stealth_mode: Some(stealth_mode),
            quantum_protection: Some(quantum_protection),
            pq_client_public_key,
            desktop_attest_nonce: attestation.as_ref().map(|a| a.nonce.clone()),
            desktop_attest_kid: attestation.as_ref().map(|a| a.kid.clone()),
            desktop_attest_sig: attestation.as_ref().map(|a| a.signature.clone()),
            desktop_attest_platform: attestation.as_ref().map(|a| a.platform.to_string()),
            desktop_attest_version: attestation.as_ref().map(|a| a.version.to_string()),
        };

        self.post(endpoints::vpn::MULTI_HOP_CONNECT, &payload, true)
            .await
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

        self.post(endpoints::vpn::PORT_FORWARDS, &payload, true)
            .await
    }

    /// Delete a port forward
    pub async fn delete_port_forward(&self, id: &str) -> Result<(), ApiError> {
        self.delete::<serde_json::Value>(
            &format!("{}/{}", endpoints::vpn::PORT_FORWARDS, id),
            true,
        )
        .await?;
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
                // H-1 FIX: Serialize token refresh attempts to prevent concurrent
                // refreshes from racing and overwriting each other's tokens.
                let _guard = self.refresh_lock.lock().await;
                // Re-check: another thread may have already refreshed while we waited
                let retry_first = self.do_request::<T>(&method, path, body, auth).await;
                if !matches!(&retry_first, Err(ApiError::Unauthorized)) {
                    return retry_first;
                }
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

        let response = request
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
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
        let response: RefreshResponse = self
            .do_request(
                &reqwest::Method::POST,
                endpoints::auth::REFRESH,
                Some(&payload),
                false,
            )
            .await?;

        *self.access_token.write().await = Some(Zeroizing::new(response.access_token.clone()));
        // FIX C-1: Also update refresh token if rotated
        if let Some(new_refresh) = response.refresh_token.clone() {
            *self.refresh_token.write().await = Some(Zeroizing::new(new_refresh));
        }

        // Persist the rotated pair to the OS keystore.
        //
        // The server ROTATES refresh tokens and treats a second use of a consumed
        // one as token THEFT — which revokes the whole session server-side. This
        // path (the 401 retry interceptor) is the common in-session refresh, so if
        // the rotated token stays in memory only, the keystore keeps the CONSUMED
        // one and the next app launch replays it: the user is force-signed-out and
        // the backend records a theft event against a legitimate client.
        //
        // Latent until now only because the keystore was a mock that persisted
        // nothing; making persistence work makes this reachable, so the two must
        // ship together. Best-effort: a keystore failure must not fail the request
        // that triggered the refresh — the in-memory tokens are still valid for
        // this session — but it is logged loudly because it costs the next one.
        {
            use crate::storage::credentials::{CredentialKey, CredentialStore};
            // `None` means the server did not rotate, so the stored refresh
            // token is still current and must be left alone.
            let refresh_to_store = response.refresh_token.clone();
            if let Err(e) =
                CredentialStore::store(CredentialKey::AccessToken, &response.access_token)
            {
                tracing::error!("Could not persist refreshed access token ({e})");
            }
            if let Some(rotated) = refresh_to_store {
                if let Err(e) = CredentialStore::store(CredentialKey::RefreshToken, &rotated) {
                    tracing::error!(
                        "Could not persist ROTATED refresh token ({e}) — the next launch will \
                         replay a consumed token and the session will be revoked"
                    );
                }
            }
        }
        Ok(())
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, auth: bool) -> Result<T, ApiError> {
        self.request_with_retry(reqwest::Method::GET, path, None, auth)
            .await
    }

    async fn post<B: Serialize + Sync, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        auth: bool,
    ) -> Result<T, ApiError> {
        self.request_with_retry(reqwest::Method::POST, path, Some(body), auth)
            .await
    }

    async fn delete<T: DeserializeOwned>(&self, path: &str, auth: bool) -> Result<T, ApiError> {
        self.request_with_retry(reqwest::Method::DELETE, path, None, auth)
            .await
    }

    /// Map a non-2xx response to an `ApiError`.
    ///
    /// Split out of `handle_response` so it can be unit-tested without standing
    /// up an HTTP server: the 401 rule below is load-bearing for session
    /// survival and was silently broken for a long time precisely because
    /// nothing could assert on it.
    ///
    /// Ordering is the whole point of this function:
    ///
    ///  1. A typed `error_code` always wins — it is a deliberate protocol signal.
    ///  2. **401 maps to `ApiError::Unauthorized` before anything else**, because
    ///     that variant is the ONLY thing `request_with_retry` keys on to run the
    ///     transparent token refresh. The backend registers GlobalExceptionFilter
    ///     globally and it puts a non-empty `message` on EVERY error
    ///     ("Unauthorized" for a 401 from JwtAuthGuard) — so when the
    ///     backend-message shortcut in step 3 ran first, every 401 collapsed into
    ///     `Unknown("Unauthorized")` and the refresh interceptor became
    ///     unreachable code. Symptom: roughly an hour after launch, when the 1h
    ///     access token expired, Connect / server list / heartbeat all failed
    ///     with "Unknown error: Unauthorized" while a valid 30-day refresh token
    ///     sat unused in the OS keystore, and only a full restart recovered.
    ///  3. Any other status keeps the backend's message. Deliberate: those
    ///     `ApiError` variants carry no payload, so mapping 403 to
    ///     `ApiError::Forbidden` would replace a specific, actionable explanation
    ///     ("Stealth mode requires an Operative or Sovereign subscription") with
    ///     a bare "Access denied".
    pub(crate) fn classify_error_response(status: StatusCode, error_text: &str) -> ApiError {
        let body = serde_json::from_str::<super::types::ApiErrorBody>(error_text).ok();

        if let Some(code) = body.as_ref().and_then(|b| b.error_code.clone()) {
            return ApiError::Protocol(code);
        }

        if status == StatusCode::UNAUTHORIZED {
            return ApiError::Unauthorized;
        }

        if let Some(message) = body.as_ref().and_then(|b| b.message.as_deref()) {
            let message = message.trim();
            if !message.is_empty() {
                return ApiError::Unknown(message.to_string());
            }
        }

        match status {
            StatusCode::FORBIDDEN => ApiError::Forbidden,
            StatusCode::NOT_FOUND => ApiError::NotFound,
            StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited,
            StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE => ApiError::ServerError(status.as_u16()),
            _ => {
                tracing::debug!("Unhandled HTTP {}: {}", status, error_text);
                ApiError::Unknown(format!("HTTP {}", status.as_u16()))
            }
        }
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ApiError> {
        // SEC-C1: certificate pinning now happens during the TLS handshake
        // (see super::cert_pin) — no post-response check is required.
        let status = response.status();

        if matches!(status, StatusCode::OK | StatusCode::CREATED) {
            return response
                .json()
                .await
                .map_err(|e| ApiError::Parse(e.to_string()));
        }

        // Parse the body once for typed protocol errors and backend-provided messages.
        let error_text = response.text().await.unwrap_or_else(|e| {
            // The body read itself failed (broken stream/timeout). We still fall
            // through to status-based mapping, but surface the underlying I/O
            // error so it is not silently masked as a bare "HTTP {status}".
            tracing::warn!(
                "Failed to read error response body for HTTP {}: {}",
                status,
                e
            );
            String::new()
        });
        Err(Self::classify_error_response(status, &error_text))
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
            refresh_lock: Arc::clone(&self.refresh_lock),
        }
    }
}
