//! Tauri command handlers
//! 
//! This module exposes Rust functions as IPC commands that can be called from the frontend.

pub mod auth;
pub mod biometric;
pub mod killswitch;
pub mod servers;
pub mod settings;
pub mod speed_test;
pub mod split_tunnel;
pub mod updater;
pub mod vpn;
pub mod vpn_multi_hop;
pub mod vpn_port_forward;
