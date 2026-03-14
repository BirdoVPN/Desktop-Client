//! Tauri command handlers
//! 
//! This module exposes Rust functions as IPC commands that can be called from the frontend.

pub mod auth;
pub mod killswitch;
pub mod servers;
pub mod settings;
pub mod updater;
pub mod vpn;
