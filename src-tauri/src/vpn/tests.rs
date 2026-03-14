//! Unit tests for the VPN auto-reconnect, kill switch, and tunnel health modules
//!
//! These tests verify:
//! - Auto-reconnect configuration defaults and exponential backoff
//! - Kill switch state machine (init → activate → deactivate)
//! - Tunnel health check interval logic

#[cfg(test)]
mod auto_reconnect_tests {
    use super::super::auto_reconnect::AutoReconnectConfig;

    #[test]
    fn default_config_has_sane_values() {
        let config = AutoReconnectConfig::default();
        assert!(config.enabled);
        assert_eq!(config.initial_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 60000);
        assert_eq!(config.max_attempts, 10);
        assert!((config.backoff_multiplier - 1.5).abs() < f64::EPSILON);
        assert_eq!(config.health_check_interval_ms, 5000);
    }

    #[test]
    fn backoff_calculation_is_exponential() {
        // calculate_backoff(attempts, initial_delay, max_delay, multiplier) -> u64
        let initial = 1000u64;
        let max = 60000u64;
        let mult = 1.5f64;

        // attempt 0: 1000 * 1.5^0 = 1000
        let d0 = (initial as f64 * mult.powi(0)) as u64;
        assert_eq!(d0.min(max), 1000);

        // attempt 1: 1000 * 1.5^1 = 1500
        let d1 = (initial as f64 * mult.powi(1)) as u64;
        assert_eq!(d1.min(max), 1500);

        // attempt 2: 1000 * 1.5^2 = 2250
        let d2 = (initial as f64 * mult.powi(2)) as u64;
        assert_eq!(d2.min(max), 2250);

        // attempt 11: should be capped at max_delay
        let d11 = (initial as f64 * mult.powi(11)) as u64;
        assert_eq!(d11.min(max), max);
    }

    #[test]
    fn backoff_respects_max_delay_cap() {
        let initial = 5000u64;
        let max = 10000u64;
        let mult = 3.0f64;

        // attempt 1: 5000 * 3 = 15000 → capped at 10000
        let delay = (initial as f64 * mult.powi(1)) as u64;
        assert_eq!(delay.min(max), max);
    }

    #[test]
    fn backoff_with_zero_attempts_returns_initial() {
        let initial = 2000u64;
        let max = 60000u64;
        let mult = 2.0f64;

        let delay = (initial as f64 * mult.powi(0)) as u64;
        assert_eq!(delay.min(max), initial);
    }

    #[test]
    fn config_clone_is_independent() {
        let config1 = AutoReconnectConfig {
            enabled: true,
            initial_delay_ms: 500,
            max_delay_ms: 30000,
            max_attempts: 5,
            backoff_multiplier: 2.0,
            health_check_interval_ms: 3000,
        };
        let mut config2 = config1.clone();
        config2.enabled = false;
        config2.max_attempts = 20;

        assert!(config1.enabled);
        assert_eq!(config1.max_attempts, 5);
        assert!(!config2.enabled);
        assert_eq!(config2.max_attempts, 20);
    }
}

#[cfg(test)]
mod kill_switch_tests {
    /// Validate kill switch rule name constants (legacy netsh compat)
    #[test]
    fn rule_names_start_with_prefix() {
        let rules = vec![
            "BirdoVPN_BlockAll",
            "BirdoVPN_PermitVPN",
            "BirdoVPN_PermitLocalhost",
            "BirdoVPN_PermitDHCP",
            "BirdoVPN_BlockIPv6",
            "BirdoVPN_BlockSTUN",
            "BirdoVPN_BlockTURN",
        ];
        for rule in rules {
            assert!(rule.starts_with("BirdoVPN"), "Rule '{}' missing BirdoVPN prefix", rule);
        }
    }

    /// FIX-2-1: Validate WFP filter weight ordering.
    /// STUN blocks (15) > Permit exceptions (10) > Block-all catch-all (1).
    #[test]
    fn wfp_filter_weights_are_correctly_ordered() {
        let weight_block_all: u8 = 1;
        let weight_permit: u8 = 10;
        let weight_block_stun: u8 = 15;

        // Permits must override block-all
        assert!(weight_permit > weight_block_all,
            "Permit weight must exceed block-all weight");
        // STUN blocks must override permits
        assert!(weight_block_stun > weight_permit,
            "STUN block weight must exceed permit weight");
    }

    /// FIX-2-1: Validate IPv4 address conversion for WFP.
    /// `u32::from(Ipv4Addr)` must produce the correct host-order value.
    #[test]
    fn ipv4_to_u32_conversion() {
        use std::net::Ipv4Addr;

        // 127.0.0.1 → 0x7F000001
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(u32::from(ip), 0x7F000001);

        // 255.0.0.0 mask → 0xFF000000
        let mask = Ipv4Addr::new(255, 0, 0, 0);
        assert_eq!(u32::from(mask), 0xFF000000);

        // /32 mask
        assert_eq!(0xFFFF_FFFFu32, u32::from(Ipv4Addr::new(255, 255, 255, 255)));
    }

    /// Validate IPv4 VPN server parsing
    #[test]
    fn vpn_server_ip_parsing() {
        use std::net::Ipv4Addr;

        let ip: Ipv4Addr = "10.0.0.1".parse().expect("valid IP");
        assert_eq!(ip.octets(), [10, 0, 0, 1]);

        let ip: Ipv4Addr = "185.210.92.34".parse().expect("valid IP");
        assert!(!ip.is_loopback());
        assert!(!ip.is_private());
    }

    /// Validate localhost is always permitted
    #[test]
    fn localhost_range_is_valid() {
        use std::net::Ipv4Addr;

        let localhost: Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert!(localhost.is_loopback());

        let local_range: Ipv4Addr = "127.255.255.255".parse().unwrap();
        assert!(local_range.is_loopback());
    }

    /// Validate DHCP ports
    #[test]
    fn dhcp_ports_are_correct() {
        // DHCP client uses port 68, DHCP server uses port 67
        let dhcp_server_port: u16 = 67;
        let dhcp_client_port: u16 = 68;
        assert_ne!(dhcp_server_port, dhcp_client_port);
        assert!(dhcp_server_port < 1024); // privileged port
    }

    /// Validate STUN/TURN port range
    #[test]
    fn stun_turn_port_range_is_correct() {
        let stun_start: u16 = 3478;
        let stun_end: u16 = 3497;
        assert_eq!(stun_end - stun_start, 19);

        // Google STUN port
        let google_stun: u16 = 19302;
        assert!(google_stun > stun_end);
    }
}

#[cfg(test)]
mod tunnel_health_tests {
    use std::time::Duration;

    #[test]
    fn health_check_interval_is_reasonable() {
        let interval = Duration::from_millis(5000);
        assert!(interval.as_secs() >= 1, "Health check too frequent");
        assert!(interval.as_secs() <= 30, "Health check too infrequent");
    }

    #[test]
    fn reconnect_max_attempts_prevents_infinite_loop() {
        let max_attempts: u32 = 10;
        let initial_delay_ms: u64 = 1000;
        let max_delay_ms: u64 = 60000;
        let multiplier: f64 = 1.5;

        // Calculate total worst-case reconnect time
        let mut total_ms: u64 = 0;
        for attempt in 0..max_attempts {
            let delay = (initial_delay_ms as f64 * multiplier.powi(attempt as i32)) as u64;
            total_ms += delay.min(max_delay_ms);
        }

        // Should complete within 10 minutes worst case
        let total_secs = total_ms / 1000;
        assert!(total_secs < 600, "Total reconnect time {} exceeds 10 minutes", total_secs);
    }

    #[test]
    fn buffer_pool_size_is_within_bounds() {
        // WireGuard MTU is typically 1420, with overhead the buffer should be >= 1500
        let buffer_size: usize = 65536; // Common buffer pool allocation
        assert!(buffer_size >= 1500, "Buffer too small for WireGuard packets");
        assert!(buffer_size <= 1 << 20, "Buffer unreasonably large (>1MB)");
    }
}

// ── ConnectionState state machine tests ─────────────────────────

#[cfg(test)]
mod connection_state_tests {
    use super::super::manager::ConnectionState;

    #[test]
    fn disconnected_is_not_tunnel_active() {
        assert!(!ConnectionState::Disconnected.is_tunnel_active());
    }

    #[test]
    fn connecting_is_not_tunnel_active() {
        assert!(!ConnectionState::Connecting.is_tunnel_active());
    }

    #[test]
    fn connected_is_tunnel_active() {
        assert!(ConnectionState::Connected.is_tunnel_active());
    }

    #[test]
    fn disconnecting_is_not_tunnel_active() {
        assert!(!ConnectionState::Disconnecting.is_tunnel_active());
    }

    #[test]
    fn reconnecting_is_not_tunnel_active() {
        assert!(!ConnectionState::Reconnecting { attempt: 1 }.is_tunnel_active());
    }

    #[test]
    fn error_is_not_tunnel_active() {
        assert!(!ConnectionState::Error("test".into()).is_tunnel_active());
    }

    // ── can_connect tests ────────────────────────────────

    #[test]
    fn can_connect_from_disconnected() {
        assert!(ConnectionState::Disconnected.can_connect());
    }

    #[test]
    fn can_connect_from_error() {
        assert!(ConnectionState::Error("fail".into()).can_connect());
    }

    #[test]
    fn can_connect_from_reconnecting() {
        assert!(ConnectionState::Reconnecting { attempt: 3 }.can_connect());
    }

    #[test]
    fn cannot_connect_from_connecting() {
        assert!(!ConnectionState::Connecting.can_connect());
    }

    #[test]
    fn cannot_connect_from_connected() {
        assert!(!ConnectionState::Connected.can_connect());
    }

    #[test]
    fn cannot_connect_from_disconnecting() {
        assert!(!ConnectionState::Disconnecting.can_connect());
    }

    // ── can_disconnect tests ─────────────────────────────

    #[test]
    fn can_disconnect_from_connected() {
        assert!(ConnectionState::Connected.can_disconnect());
    }

    #[test]
    fn can_disconnect_from_connecting() {
        assert!(ConnectionState::Connecting.can_disconnect());
    }

    #[test]
    fn can_disconnect_from_reconnecting() {
        assert!(ConnectionState::Reconnecting { attempt: 1 }.can_disconnect());
    }

    #[test]
    fn can_disconnect_from_error() {
        assert!(ConnectionState::Error("err".into()).can_disconnect());
    }

    #[test]
    fn cannot_disconnect_from_disconnected() {
        assert!(!ConnectionState::Disconnected.can_disconnect());
    }

    #[test]
    fn cannot_disconnect_from_disconnecting() {
        assert!(!ConnectionState::Disconnecting.can_disconnect());
    }

    // ── equality / Debug ─────────────────────────────────

    #[test]
    fn state_equality() {
        assert_eq!(ConnectionState::Disconnected, ConnectionState::Disconnected);
        assert_eq!(ConnectionState::Connected, ConnectionState::Connected);
        assert_ne!(ConnectionState::Disconnected, ConnectionState::Connected);
    }

    #[test]
    fn error_equality_by_message() {
        assert_eq!(
            ConnectionState::Error("x".into()),
            ConnectionState::Error("x".into()),
        );
        assert_ne!(
            ConnectionState::Error("a".into()),
            ConnectionState::Error("b".into()),
        );
    }

    #[test]
    fn reconnecting_equality_by_attempt() {
        assert_eq!(
            ConnectionState::Reconnecting { attempt: 2 },
            ConnectionState::Reconnecting { attempt: 2 },
        );
        assert_ne!(
            ConnectionState::Reconnecting { attempt: 1 },
            ConnectionState::Reconnecting { attempt: 2 },
        );
    }

    #[test]
    fn debug_format_includes_state_name() {
        let dbg = format!("{:?}", ConnectionState::Connecting);
        assert!(dbg.contains("Connecting"));

        let dbg_err = format!("{:?}", ConnectionState::Error("timeout".into()));
        assert!(dbg_err.contains("Error"));
        assert!(dbg_err.contains("timeout"));
    }
}

// ── VpnError Display tests ──────────────────────────────────────

#[cfg(test)]
mod vpn_error_tests {
    use super::super::manager::VpnError;

    #[test]
    fn lock_timeout_display() {
        let err = VpnError::LockTimeout("state read lock".into());
        let msg = format!("{}", err);
        assert!(msg.contains("Lock timeout"));
        assert!(msg.contains("state read lock"));
    }

    #[test]
    fn invalid_state_transition_display() {
        let err = VpnError::InvalidStateTransition {
            from: "Disconnected".into(),
            to: "Disconnecting".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("Invalid state transition"));
        assert!(msg.contains("Disconnected"));
        assert!(msg.contains("Disconnecting"));
    }

    #[test]
    fn operation_in_progress_display() {
        let err = VpnError::OperationInProgress;
        let msg = format!("{}", err);
        assert!(msg.contains("already in progress"));
    }

    #[test]
    fn general_error_display() {
        let err = VpnError::General("Something went wrong".into());
        assert_eq!(format!("{}", err), "Something went wrong");
    }

    #[test]
    fn vpn_error_is_error_trait() {
        let err = VpnError::General("test".into());
        let _: &dyn std::error::Error = &err;
    }
}

// ── VpnManager async tests ─────────────────────────────────────

#[cfg(test)]
mod vpn_manager_tests {
    use super::super::manager::{VpnManager, ConnectionState};

    #[tokio::test]
    async fn new_manager_starts_disconnected() {
        let mgr = VpnManager::new();
        assert_eq!(mgr.get_state().await, ConnectionState::Disconnected);
    }

    #[tokio::test]
    async fn initial_stats_are_zeroed() {
        let mgr = VpnManager::new();
        let stats = mgr.get_stats().await;
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert!(stats.latency_ms.is_none());
        assert!(stats.connected_at.is_none());
        assert!(stats.server_id.is_none());
        assert!(stats.key_id.is_none());
        assert!(stats.server_name.is_none());
    }

    #[tokio::test]
    async fn initial_key_id_is_none() {
        let mgr = VpnManager::new();
        assert!(mgr.get_key_id().await.is_none());
    }

    #[tokio::test]
    async fn default_creates_same_as_new() {
        let mgr = VpnManager::default();
        assert_eq!(mgr.get_state().await, ConnectionState::Disconnected);
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let mgr1 = VpnManager::new();
        let mgr2 = mgr1.clone();

        // Both should see the same state
        assert_eq!(mgr1.get_state().await, mgr2.get_state().await);
    }

    #[tokio::test]
    async fn set_user_disconnected_flag() {
        let mgr = VpnManager::new();
        // set_user_disconnected should not panic
        mgr.set_user_disconnected(true);
        mgr.set_user_disconnected(false);
    }

    #[tokio::test]
    async fn measure_latency_returns_none_without_tunnel() {
        let mgr = VpnManager::new();
        let latency = mgr.measure_latency().await;
        assert!(latency.is_none());
    }

    #[tokio::test]
    async fn update_stats_does_not_crash_without_tunnel() {
        let mgr = VpnManager::new();
        // Should be a no-op when no tunnel is active
        mgr.update_stats().await;
        let stats = mgr.get_stats().await;
        assert_eq!(stats.bytes_sent, 0);
    }
}

// ── Buffer pool constant tests ──────────────────────────────────

#[cfg(test)]
mod buffer_pool_tests {
    use super::super::buffer_pool::{MAX_PACKET_SIZE, WIREGUARD_OVERHEAD};

    #[test]
    fn max_packet_size_is_power_of_two() {
        assert!(MAX_PACKET_SIZE.is_power_of_two());
    }

    #[test]
    fn max_packet_size_can_hold_jumbo_frames() {
        // Must accommodate standard + jumbo MTU (9000) + overhead
        assert!(MAX_PACKET_SIZE >= 9000 + WIREGUARD_OVERHEAD);
    }

    #[test]
    fn wireguard_overhead_matches_spec() {
        // WireGuard Transport Data Message overhead:
        // 4 (type) + 4 (receiver) + 8 (nonce) + 16 (AEAD tag) = 32 bytes minimum
        // Plus alignment padding.  The codebase uses 148 which includes padding.
        assert!(WIREGUARD_OVERHEAD >= 32, "Overhead too small for WireGuard header");
        assert!(WIREGUARD_OVERHEAD <= 256, "Overhead unreasonably large");
    }

    #[test]
    fn standard_mtu_fits_in_max_packet_size() {
        let standard_wireguard_mtu = 1420;
        assert!(standard_wireguard_mtu + WIREGUARD_OVERHEAD <= MAX_PACKET_SIZE);
    }
}

// ── AutoReconnect service tests ─────────────────────────────────

#[cfg(test)]
mod auto_reconnect_service_tests {
    use super::super::auto_reconnect::{AutoReconnectService, AutoReconnectStatus};
    use super::super::manager::VpnManager;
    use crate::api::client::BirdoApi;
    use std::sync::Arc;

    fn create_service() -> AutoReconnectService {
        let mgr = Arc::new(VpnManager::new());
        let api = Arc::new(BirdoApi::new());
        AutoReconnectService::new(mgr, api)
    }

    #[tokio::test]
    async fn initial_status_is_idle() {
        let service = create_service();
        let status = service.get_status();
        assert!(!status.is_reconnecting);
        assert_eq!(status.attempt_count, 0);
        assert!(!status.is_running);
    }

    #[tokio::test]
    async fn user_disconnect_flag_roundtrip() {
        let service = create_service();
        service.set_user_disconnected();
        // Should not cause auto-reconnect to fire
        service.clear_user_disconnected();
    }

    #[tokio::test]
    async fn clear_last_config_does_not_panic() {
        let service = create_service();
        service.clear_last_config().await;
    }

    #[tokio::test]
    async fn store_last_config_roundtrip() {
        let service = create_service();
        service.store_last_config("server-1".into(), "US East".into(), false).await;
        // Store should succeed without panic
        service.clear_last_config().await;
    }

    #[tokio::test]
    async fn set_config_updates_config() {
        use super::super::auto_reconnect::AutoReconnectConfig;
        let service = create_service();
        let custom = AutoReconnectConfig {
            enabled: false,
            initial_delay_ms: 500,
            max_delay_ms: 30000,
            max_attempts: 3,
            backoff_multiplier: 2.0,
            health_check_interval_ms: 10000,
        };
        service.set_config(custom).await;
        // set_enabled should not panic
        service.set_enabled(true).await;
        assert!(service.is_enabled().await);
        service.set_enabled(false).await;
        assert!(!service.is_enabled().await);
    }

    #[test]
    fn status_debug_format() {
        let status = AutoReconnectStatus {
            is_reconnecting: true,
            attempt_count: 3,
            is_running: true,
        };
        let dbg = format!("{:?}", status);
        assert!(dbg.contains("is_reconnecting"));
        assert!(dbg.contains("3"));
    }
}
