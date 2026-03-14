//! API client module
//!
//! HTTP client for communicating with the Birdo VPN backend.

pub mod client;
pub mod endpoints;
pub mod error;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::BirdoApi;
// ApiError is used internally but re-exported for module consumers
#[allow(unused_imports)]
pub use error::ApiError;
