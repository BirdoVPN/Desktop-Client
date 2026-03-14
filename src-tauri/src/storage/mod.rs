//! Secure storage module
//!
//! Uses Windows Credential Manager for storing sensitive data.

pub mod credentials;

pub use credentials::CredentialStore;
