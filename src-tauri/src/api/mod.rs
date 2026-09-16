//! API client module
//!
//! HTTP client for communicating with the Birdo VPN backend.

pub mod attestation;
pub mod cert_pin;
pub mod client;
pub mod doh_resolver;
pub mod endpoints;
pub mod error;
pub mod types;
pub mod upgrade_gate;

#[cfg(test)]
mod tests;
// K5: serialized connect bodies validated against contract/vpn-protocol.schema.json.
#[cfg(test)]
mod contract_tests;

pub use client::BirdoApi;
// ApiError is used internally but re-exported for module consumers
pub use error::ApiError;
