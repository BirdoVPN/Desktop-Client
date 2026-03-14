//! Crash telemetry scaffolding (I-1)
//!
//! Provides a trait-based abstraction for crash/error reporting.
//! The default implementation writes to local crash files (already done
//! in `main.rs::write_crash_report`). When you're ready to add Sentry
//! or another service, implement `TelemetryBackend` for it.
//!
//! # v1.0 Note
//! Remote telemetry (Sentry) is intentionally deferred post-v1.0.
//! Local-only crash logging is sufficient for the initial release.
//! Remote reporting will be added in a future update behind an opt-in toggle.
//!
//! # Privacy
//! A VPN client must NEVER send telemetry by default. All remote reporting
//! must be opt-in via an explicit user setting in the UI.

#![allow(dead_code)]

use std::collections::HashMap;

/// Severity level for telemetry events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Application crashed — unrecoverable
    Fatal,
    /// Something went wrong but the app can continue
    Error,
    /// Unexpected but non-breaking condition
    Warning,
    /// Informational breadcrumb
    Info,
}

/// A telemetry event (crash report, error, breadcrumb)
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    pub severity: Severity,
    pub message: String,
    pub location: Option<String>,
    pub backtrace: Option<String>,
    /// Arbitrary key-value context (e.g., connection_state, server_id)
    pub tags: HashMap<String, String>,
}

/// Trait for telemetry backends (local file, Sentry, etc.)
pub trait TelemetryBackend: Send + Sync {
    /// Report an event. Implementations must respect the user's opt-in setting.
    fn report(&self, event: &TelemetryEvent);

    /// Record a breadcrumb for context on the next crash
    fn breadcrumb(&self, message: &str, category: &str);

    /// Check if remote reporting is enabled (user opted in)
    fn is_remote_enabled(&self) -> bool;
}

/// Local-only backend — writes crash files to disk, never phones home.
/// This is the default and is always active.
pub struct LocalTelemetry;

impl TelemetryBackend for LocalTelemetry {
    fn report(&self, event: &TelemetryEvent) {
        match event.severity {
            Severity::Fatal => tracing::error!(
                "TELEMETRY [FATAL]: {} at {:?}",
                event.message,
                event.location
            ),
            Severity::Error => tracing::error!("TELEMETRY [ERROR]: {}", event.message),
            Severity::Warning => tracing::warn!("TELEMETRY [WARN]: {}", event.message),
            Severity::Info => tracing::info!("TELEMETRY [INFO]: {}", event.message),
        }
        // The actual file write is handled by main.rs::write_crash_report for Fatal.
    }

    fn breadcrumb(&self, message: &str, category: &str) {
        tracing::debug!("BREADCRUMB [{}]: {}", category, message);
    }

    fn is_remote_enabled(&self) -> bool {
        false // Local backend never sends remotely
    }
}

/// Placeholder for a future Sentry/remote backend (deferred post-v1.0).
/// Uncomment and implement when adding a crash reporting service.
/// Remote reporting must be opt-in — see Privacy note above.
///
/// ```rust,ignore
/// pub struct SentryTelemetry {
///     dsn: String,
///     user_opted_in: Arc<AtomicBool>,
/// }
///
/// impl TelemetryBackend for SentryTelemetry {
///     fn report(&self, event: &TelemetryEvent) {
///         if !self.is_remote_enabled() { return; }
///         // sentry::capture_message(&event.message, ...);
///     }
///     fn breadcrumb(&self, message: &str, category: &str) {
///         if !self.is_remote_enabled() { return; }
///         // sentry::add_breadcrumb(|| { ... });
///     }
///     fn is_remote_enabled(&self) -> bool {
///         self.user_opted_in.load(Ordering::Relaxed)
///     }
/// }
/// ```

/// Global telemetry instance — starts as local-only.
/// Replace with a composite backend when remote reporting is added.
static TELEMETRY: once_cell::sync::Lazy<Box<dyn TelemetryBackend>> =
    once_cell::sync::Lazy::new(|| Box::new(LocalTelemetry));

/// Report a telemetry event through the global backend
pub fn report(event: TelemetryEvent) {
    TELEMETRY.report(&event);
}

/// Record a breadcrumb for crash context
pub fn breadcrumb(message: &str, category: &str) {
    TELEMETRY.breadcrumb(message, category);
}
