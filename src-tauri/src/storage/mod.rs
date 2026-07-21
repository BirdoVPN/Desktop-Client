//! Secure storage module
//!
//! Stores sensitive data in the platform's native keystore: Windows Credential
//! Manager, macOS Keychain, or the Linux Secret Service (GNOME Keyring/KWallet).
//! The backend is selected at COMPILE time by the per-target `keyring` features
//! in Cargo.toml — see the guard at the top of `credentials.rs`.

pub mod credentials;

pub use credentials::CredentialStore;
