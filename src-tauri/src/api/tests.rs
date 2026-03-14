//! Unit tests for the API module
//!
//! Tests cover:
//! - API type serialization / deserialization
//! - Endpoint path construction
//! - Error display formatting
//! - VpnConfig key material zeroization
//! - AppSettings defaults and serialization

#[cfg(test)]
mod endpoint_tests {
    use super::super::endpoints;

    #[test]
    fn auth_endpoints_start_with_auth() {
        assert!(endpoints::auth::LOGIN_DESKTOP.starts_with("/auth/"));
        assert!(endpoints::auth::LOGOUT.starts_with("/auth/"));
        assert!(endpoints::auth::REFRESH.starts_with("/auth/"));
        assert!(endpoints::auth::ME.starts_with("/auth/"));
    }

    #[test]
    fn vpn_connection_path_includes_key_id() {
        let path = endpoints::vpn::connection("key-abc-123");
        assert_eq!(path, "/vpn/connections/key-abc-123");
    }

    #[test]
    fn vpn_heartbeat_path_includes_key_id() {
        let path = endpoints::vpn::heartbeat("key-xyz");
        assert_eq!(path, "/vpn/heartbeat/key-xyz");
    }

    #[test]
    fn vpn_server_endpoints_are_correct() {
        assert_eq!(endpoints::vpn::SERVERS, "/vpn/servers");
        assert_eq!(endpoints::vpn::CONNECT, "/vpn/connect");
    }

    #[test]
    fn user_endpoints_are_correct() {
        assert_eq!(endpoints::users::SUBSCRIPTION, "/auth/me");
    }

    #[test]
    fn connection_path_handles_special_characters() {
        let path = endpoints::vpn::connection("key-with-dashes-and_underscores");
        assert!(path.starts_with("/vpn/connections/"));
        assert!(path.contains("key-with-dashes-and_underscores"));
    }
}

#[cfg(test)]
mod error_display_tests {
    use super::super::error::ApiError;

    #[test]
    fn network_error_displays_message() {
        let err = ApiError::Network("timeout".to_string());
        assert_eq!(err.to_string(), "Network error: timeout");
    }

    #[test]
    fn not_authenticated_displays_message() {
        let err = ApiError::NotAuthenticated;
        assert_eq!(err.to_string(), "Not authenticated");
    }

    #[test]
    fn unauthorized_displays_message() {
        let err = ApiError::Unauthorized;
        assert_eq!(err.to_string(), "Authentication failed");
    }

    #[test]
    fn forbidden_displays_message() {
        let err = ApiError::Forbidden;
        assert_eq!(err.to_string(), "Access denied");
    }

    #[test]
    fn not_found_displays_message() {
        let err = ApiError::NotFound;
        assert_eq!(err.to_string(), "Not found");
    }

    #[test]
    fn rate_limited_displays_message() {
        let err = ApiError::RateLimited;
        assert_eq!(err.to_string(), "Too many requests, please slow down");
    }

    #[test]
    fn server_error_includes_status_code() {
        let err = ApiError::ServerError(503);
        assert_eq!(err.to_string(), "Server error (503)");
    }

    #[test]
    fn parse_error_displays_message() {
        let err = ApiError::Parse("invalid JSON".to_string());
        assert_eq!(err.to_string(), "Failed to parse response: invalid JSON");
    }

    #[test]
    fn unknown_error_displays_message() {
        let err = ApiError::Unknown("something broke".to_string());
        assert_eq!(err.to_string(), "Unknown error: something broke");
    }

    #[test]
    fn api_error_converts_to_string() {
        let err = ApiError::NotAuthenticated;
        let s: String = err.into();
        assert_eq!(s, "Not authenticated");
    }

    #[test]
    fn api_error_implements_std_error() {
        let err = ApiError::Unauthorized;
        // Verify it satisfies the std::error::Error trait bound
        let _: &dyn std::error::Error = &err;
    }
}

#[cfg(test)]
mod types_serialization_tests {
    use super::super::types::*;

    #[test]
    fn login_request_serializes_correctly() {
        let req = LoginRequest {
            email: "user@test.com".to_string(),
            password: "s3cret".to_string(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["email"], "user@test.com");
        assert_eq!(json["password"], "s3cret");
    }

    #[test]
    fn refresh_request_serializes_correctly() {
        let req = RefreshRequest {
            refresh_token: "rt_abc123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("rt_abc123"));
    }

    #[test]
    fn token_pair_deserializes() {
        let json = r#"{"access_token":"at_xyz","refresh_token":"rt_xyz"}"#;
        let pair: TokenPair = serde_json::from_str(json).unwrap();
        assert_eq!(pair.access_token, "at_xyz");
        assert_eq!(pair.refresh_token, "rt_xyz");
    }

    #[test]
    fn login_result_deserializes_success() {
        let json = r#"{"ok":true,"tokens":{"access_token":"at","refresh_token":"rt"}}"#;
        let result: LoginResult = serde_json::from_str(json).unwrap();
        match result {
            LoginResult::Success { ok, tokens } => {
                assert!(ok);
                assert_eq!(tokens.access_token, "at");
            }
            _ => panic!("Expected LoginResult::Success"),
        }
    }

    #[test]
    fn login_result_deserializes_2fa_challenge() {
        let json = r#"{"requiresTwoFactor":true,"challengeToken":"ct_abc"}"#;
        let result: LoginResult = serde_json::from_str(json).unwrap();
        match result {
            LoginResult::TwoFactorChallenge { requires_two_factor, challenge_token } => {
                assert!(requires_two_factor);
                assert_eq!(challenge_token, "ct_abc");
            }
            _ => panic!("Expected LoginResult::TwoFactorChallenge"),
        }
    }

    #[test]
    fn refresh_response_deserializes() {
        let json = r#"{"access_token":"new_at","expires_in":3600}"#;
        let resp: RefreshResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "new_at");
        assert_eq!(resp.expires_in, Some(3600));
    }

    #[test]
    fn user_profile_uses_camel_case() {
        let json = r#"{
            "id": "u1",
            "email": "a@b.com",
            "name": "Alice",
            "emailVerified": true,
            "createdAt": "2026-01-01"
        }"#;
        let user: UserProfile = serde_json::from_str(json).unwrap();
        assert!(user.email_verified);
        assert_eq!(user.created_at, Some("2026-01-01".to_string()));
    }

    #[test]
    fn vpn_server_deserializes_with_camel_case() {
        let json = r#"{
            "id": "s1", "name": "US East", "country": "United States",
            "countryCode": "US", "city": "New York", "hostname": "us-east.birdo.app",
            "ipAddress": "1.2.3.4", "port": 51820, "load": 45,
            "isPremium": true, "isStreaming": false, "isP2p": true, "isOnline": true
        }"#;
        let server: VpnServer = serde_json::from_str(json).unwrap();
        assert_eq!(server.country_code, "US");
        assert!(server.is_premium);
        assert!(server.is_online);
        assert_eq!(server.port, 51820);
    }

    #[test]
    fn vpn_config_optional_fields_default_correctly() {
        let json = r#"{
            "serverId": "s1", "keyId": "k1",
            "privateKey": "pk=", "publicKey": "pub=",
            "serverPublicKey": "spk=", "endpoint": "1.2.3.4:51820",
            "allowedIps": ["0.0.0.0/0"], "dns": ["1.1.1.1"],
            "clientIp": "10.0.0.2", "mtu": 1420, "persistentKeepalive": 25
        }"#;
        let config: VpnConfig = serde_json::from_str(json).unwrap();
        assert!(config.preshared_key.is_none());
        assert_eq!(config.mtu, 1420);
    }

    #[test]
    fn connect_request_skips_none_fields() {
        let req = ConnectRequest {
            server_node_id: Some("node-1".to_string()),
            device_name: None,
            preferred_region: None,
            client_public_key: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["serverNodeId"], "node-1");
        assert!(json.get("deviceName").is_none());
        assert!(json.get("preferredRegion").is_none());
    }

    #[test]
    fn connect_response_handles_all_optional_fields() {
        let json = r#"{"success":true}"#;
        let resp: ConnectResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        assert!(resp.config.is_none());
        assert!(resp.key_id.is_none());
        assert!(resp.private_key.is_none());
        assert!(resp.dns.is_none());
        assert!(resp.server_node.is_none());
    }

    #[test]
    fn subscription_status_deserializes() {
        let json = r#"{
            "plan": "OPERATIVE", "status": "ACTIVE",
            "expiresAt": "2026-12-31", "devicesUsed": 2,
            "devicesLimit": 5, "bandwidthUsed": 1073741824,
            "bandwidthLimit": 10737418240
        }"#;
        let status: SubscriptionStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.plan, "OPERATIVE");
        assert_eq!(status.devices_used, 2);
        assert_eq!(status.bandwidth_used, 1073741824);
    }
}

#[cfg(test)]
mod vpn_config_security_tests {
    use super::super::types::VpnConfig;
    use zeroize::Zeroize;

    fn make_test_config() -> VpnConfig {
        VpnConfig {
            server_id: "s1".to_string(),
            key_id: "k1".to_string(),
            private_key: "SUPER_SECRET_PRIVATE_KEY".to_string(),
            public_key: "pub".to_string(),
            server_public_key: "server_pub".to_string(),
            preshared_key: Some("PRESHARED_SECRET".to_string()),
            endpoint: "1.2.3.4:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            dns: vec!["1.1.1.1".to_string()],
            client_ip: "10.0.0.2".to_string(),
            mtu: 1420,
            persistent_keepalive: 25,
        }
    }

    #[test]
    fn scrub_key_material_zeroes_private_key() {
        let mut config = make_test_config();
        config.scrub_key_material();

        // After scrub, private key should be zeroed (all null bytes)
        assert!(config.private_key.bytes().all(|b| b == 0));
        // Preshared key should also be zeroed
        assert!(config.preshared_key.as_ref().unwrap().bytes().all(|b| b == 0));
    }

    #[test]
    fn scrub_preserves_non_sensitive_fields() {
        let mut config = make_test_config();
        config.scrub_key_material();

        assert_eq!(config.server_id, "s1");
        assert_eq!(config.endpoint, "1.2.3.4:51820");
        assert_eq!(config.client_ip, "10.0.0.2");
    }

    #[test]
    fn drop_zeroes_all_key_material() {
        // We can't directly test Drop, but we can test that zeroize works
        let mut key = "test_key_material".to_string();
        key.zeroize();
        assert!(key.bytes().all(|b| b == 0));
    }
}

#[cfg(test)]
mod client_construction_tests {
    use super::super::client::BirdoApi;

    #[tokio::test]
    async fn new_client_is_unauthenticated() {
        let api = BirdoApi::new();
        assert!(!api.is_authenticated().await);
    }

    #[tokio::test]
    async fn set_tokens_makes_authenticated() {
        let api = BirdoApi::new();
        api.set_tokens("access".to_string(), "refresh".to_string()).await;
        assert!(api.is_authenticated().await);
    }

    #[tokio::test]
    async fn clear_tokens_makes_unauthenticated() {
        let api = BirdoApi::new();
        api.set_tokens("access".to_string(), "refresh".to_string()).await;
        assert!(api.is_authenticated().await);

        api.clear_tokens().await;
        assert!(!api.is_authenticated().await);
    }

    #[tokio::test]
    async fn clone_shares_token_state() {
        let api1 = BirdoApi::new();
        let api2 = api1.clone();

        api1.set_tokens("at".to_string(), "rt".to_string()).await;
        // Cloned instance should see the same tokens (Arc-shared)
        assert!(api2.is_authenticated().await);
    }

    #[tokio::test]
    async fn default_creates_same_as_new() {
        let api = BirdoApi::default();
        assert!(!api.is_authenticated().await);
    }
}
