//! What a crash report is allowed to contain, and the proof that nothing else
//! gets out.
//!
//! # Why this is an ALLOWLIST
//!
//! The previous scrubber removed PII from four fields of an outgoing event:
//! `message`, `logentry`, `exception[].value` and `breadcrumbs[].message`. A
//! `sentry::protocol::Event` has twenty-six. The eight that were neither
//! scrubbed nor empty by construction — `tags`, `extra`, `breadcrumbs[].data`,
//! `transaction`, `culprit`, `request`, `user`, `modules` — were a denylist with
//! holes, and a denylist over a struct someone else versions grows a new hole on
//! every dependency bump.
//!
//! So [`scrub_event`] does not edit the incoming event. It **builds a new one**
//! out of a fixed list of fields and lets `..Default::default()` empty the rest.
//! A field added by a future SDK upgrade is dropped by construction, and the
//! only way to start sending something new is to write its name in this file.
//!
//! # What is kept, and why each one is safe
//!
//! | field | why it may leave the device |
//! | --- | --- |
//! | `event_id`, `timestamp`, `level`, `platform`, `sdk` | routing metadata the ingest endpoint needs; no user content |
//! | `release`, `environment` | our own version string and the literal `production` |
//! | `fingerprint`, `logger` | grouping; we never set either, so this is the SDK default marker |
//! | `server_name` | pinned to the literal `redacted` — see `main.rs` for why a `None` is NOT safe here |
//! | `message`, `logentry` | scrubbed; `logentry.params` are raw interpolation values of unknown shape, so they are cleared rather than guessed at |
//! | `exception[].{ty,module,stacktrace,thread_id,mechanism}` | code identifiers and frames |
//! | `exception[].value` | the panic payload — scrubbed |
//! | `breadcrumbs[].{ty,category,level,timestamp}` | our own literals |
//! | `breadcrumbs[].message` | scrubbed |
//! | `contexts` | filtered to `os` / `device` / `runtime` / `rust` — OS version, CPU arch, rustc version. `sentry-contexts` builds `device` from model/family/arch only, and its `server_name()` (the hostname) goes to `options.server_name`, which we pin |
//!
//! Everything else is dropped: `user`, `request`, `tags`, `extra`,
//! `transaction`, `culprit`, `modules`, `dist`, `template`, `threads`, the
//! top-level `stacktrace`, `debug_meta`, and **every breadcrumb `data` map**.
//!
//! # Transactions do not come through here
//!
//! `before_send` is invoked at exactly one place in `sentry-core-0.48.3`
//! (`client/mod.rs:373`, inside the event path). A transaction reaches Sentry
//! through `Transaction::finish_with_timestamp` → `client.send_envelope(...)`
//! (`performance.rs:868-899`) and never passes a `before_send` — the Rust SDK
//! has no `before_send_transaction` at all. So a transaction's name and its span
//! descriptions would be an UNSCRUBBED channel sitting next to this one. That is
//! the mistake the Android client shipped (`tracesSampleRate = 1.0` beside a
//! `beforeSend`-only scrubber), so here performance data is off twice over —
//! see [`never_sample_a_transaction`].

use sentry::protocol::{Context, Event, Map};

use super::redact::sanitize_always;

/// Context keys that may leave the device. Everything `sentry-contexts` puts on
/// an event is in here, so this is a fence rather than a filter today — it
/// exists so that an integration added later cannot widen the payload silently.
const ALLOWED_CONTEXTS: &[&str] = &["os", "device", "runtime", "rust"];

/// Rebuild an outgoing event from the allowlist above.
///
/// Runs as `before_send`, i.e. at the last point before the event leaves the
/// device, so it covers every capture path regardless of which hook ran first.
/// That matters here: `sentry::init` installs sentry's own panic integration,
/// which chains AHEAD of `setup_panic_hook` and sees the raw payload.
pub fn scrub_event(event: Event<'static>) -> Event<'static> {
    let mut contexts: Map<String, Context> = Map::new();
    for key in ALLOWED_CONTEXTS {
        if let Some(ctx) = event.contexts.get(*key) {
            contexts.insert((*key).to_string(), ctx.clone());
        }
    }

    let mut logentry = event.logentry;
    if let Some(entry) = logentry.as_mut() {
        entry.message = sanitize_always(&entry.message);
        // Positional params are raw interpolation values of unknown shape.
        entry.params.clear();
    }

    let mut exception = event.exception;
    for e in exception.values.iter_mut() {
        if let Some(value) = e.value.take() {
            e.value = Some(sanitize_always(&value));
        }
    }

    let mut breadcrumbs = event.breadcrumbs;
    for b in breadcrumbs.values.iter_mut() {
        if let Some(msg) = b.message.take() {
            b.message = Some(sanitize_always(&msg));
        }
        // Arbitrary key/value pairs any present or future `add_breadcrumb` call
        // site could fill with anything. There is no shape to scrub against, so
        // the map goes.
        b.data.clear();
    }

    Event {
        // Identity and routing.
        event_id: event.event_id,
        timestamp: event.timestamp,
        level: event.level,
        platform: event.platform,
        sdk: event.sdk,
        release: event.release,
        environment: event.environment,
        fingerprint: event.fingerprint,
        logger: event.logger,
        // Pinned in `ClientOptions`; carried through so a per-event value can
        // never override it with a hostname.
        server_name: Some("redacted".into()),
        // Content, scrubbed.
        message: event.message.map(|m| sanitize_always(&m)),
        logentry,
        exception,
        breadcrumbs,
        contexts,
        // EVERYTHING ELSE IS DROPPED. Do not replace this with a field list:
        // the point is that a field this file has never heard of defaults to
        // empty instead of egressing.
        ..Default::default()
    }
}

/// Never sample a transaction, whatever anybody upstream decided.
///
/// `traces_sample_rate: 0.0` alone is NOT enough. `sentry-core-0.48.3`
/// `performance.rs:613-616`:
///
/// ```text
/// match (traces_sampler, traces_sample_rate) {
///     (Some(traces_sampler), _) => traces_sampler(ctx),
///     (None, traces_sample_rate) => ctx.sampled.map(f32::from).unwrap_or(traces_sample_rate),
/// }
/// ```
///
/// With no sampler, an inherited `ctx.sampled == Some(true)` — what
/// `TransactionContext::continue_from_headers` sets from an upstream
/// `sentry-trace` header — WINS over a rate of 0.0. A sampler takes priority
/// over both arms, so this is the half that actually cannot be overridden.
pub fn never_sample_a_transaction(_ctx: &sentry::TransactionContext) -> f32 {
    0.0
}

/// Report a SECURITY-RELEVANT, non-panic condition to Sentry.
///
/// WHY THIS EXISTS. Crash reporting reached this app through the `panic`
/// integration only: a condition that does not crash the process — a
/// certificate-pin mismatch, say — was written with `tracing::error!` and went
/// no further than the local log. `sentry` is built here WITHOUT the `tracing`
/// feature and `main.rs` installs no sentry layer in the subscriber, so nothing
/// bridges the two, and no amount of `tracing::error!` will ever leave the
/// device. That is how a pin set can be dark in the field for as long as it
/// takes somebody to ask a user for a log file.
///
/// CONTRACT FOR CALLERS — `message` must contain NO user data. It is a literal
/// or a formatted string built only from compile-time constants and counts.
/// Never pass a hostname being resolved, a server name, an IP, a path or an
/// error string from the network stack. `scrub_event` sanitises what it can
/// recognise, but the guarantee here is the caller's: this is an errors-only,
/// PII-free channel by owner decision.
pub fn report_security_event(message: &str) {
    sentry::capture_message(message, sentry::Level::Error);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry::protocol::{Breadcrumb, Exception, LogEntry, Request, User, Value};

    /// A hostname, an IPv4, an IPv6 and an email in one string, so a scrub that
    /// only handles some of them still fails.
    const DIRTY: &str = "connect to de-fra-01.birdo.app (185.199.110.153 / \
                         2606:4700:4700::1111) failed for user@example.com";

    fn assert_clean(what: &str, s: &str) {
        assert!(
            !s.contains("birdo.app"),
            "{}: hostname survived — {}",
            what,
            s
        );
        assert!(
            !s.contains("185.199.110.153"),
            "{}: IPv4 survived — {}",
            what,
            s
        );
        assert!(
            !s.contains("2606:4700:4700::1111"),
            "{}: IPv6 survived — {}",
            what,
            s
        );
        assert!(
            !s.contains("user@example.com"),
            "{}: email survived — {}",
            what,
            s
        );
    }

    /// The scrubber has to run for the fields it keeps. Asserted per field
    /// rather than on the event as a whole, so a fix applied to one of them
    /// cannot make the others look covered.
    #[test]
    fn every_kept_free_text_field_is_scrubbed() {
        let mut event = Event::new();
        event.message = Some(DIRTY.to_string());
        event.logentry = Some(LogEntry {
            message: DIRTY.to_string(),
            params: vec![Value::from(DIRTY)],
        });
        event.exception = vec![Exception {
            ty: "panic".into(),
            value: Some(DIRTY.to_string()),
            ..Default::default()
        }]
        .into();
        event.breadcrumbs = vec![Breadcrumb {
            message: Some(DIRTY.to_string()),
            ..Default::default()
        }]
        .into();

        let out = scrub_event(event);

        assert_clean("message", out.message.as_deref().expect("message kept"));
        let entry = out.logentry.expect("logentry kept");
        assert_clean("logentry.message", &entry.message);
        assert!(
            entry.params.is_empty(),
            "logentry.params are raw interpolation values and must be cleared, not scrubbed"
        );
        assert_clean(
            "exception.value",
            out.exception.values[0]
                .value
                .as_deref()
                .expect("exception value kept"),
        );
        assert_clean(
            "breadcrumb.message",
            out.breadcrumbs.values[0]
                .message
                .as_deref()
                .expect("breadcrumb message kept"),
        );
    }

    /// The allowlist half: a field nobody scrubs must not be a field anybody
    /// sends. Every one of these was populated on the way in.
    #[test]
    fn the_unscrubbable_fields_are_dropped_entirely() {
        let mut event = Event::new();
        event.user = Some(User {
            email: Some("user@example.com".into()),
            ip_address: None,
            id: Some("acct_123".into()),
            ..Default::default()
        });
        event.request = Some(Request {
            url: "https://de-fra-01.birdo.app/connect".parse().ok(),
            ..Default::default()
        });
        event.tags.insert("exit_node".into(), DIRTY.into());
        event.extra.insert("endpoint".into(), Value::from(DIRTY));
        event.transaction = Some(DIRTY.to_string());
        event.culprit = Some(DIRTY.to_string());
        event.modules.insert("m".into(), DIRTY.into());
        event.server_name = Some("Johns-MacBook-Pro".into());
        event.breadcrumbs = vec![Breadcrumb {
            message: Some("connecting".into()),
            data: {
                let mut m = Map::new();
                m.insert("endpoint".into(), Value::from(DIRTY));
                m
            },
            ..Default::default()
        }]
        .into();

        let out = scrub_event(event);

        assert!(out.user.is_none(), "user must never leave the device");
        assert!(out.request.is_none(), "request URLs name the exit node");
        assert!(out.tags.is_empty(), "tags");
        assert!(out.extra.is_empty(), "extra");
        assert!(out.transaction.is_none(), "transaction");
        assert!(out.culprit.is_none(), "culprit");
        assert!(out.modules.is_empty(), "modules");
        assert_eq!(
            out.server_name.as_deref(),
            Some("redacted"),
            "a hostname routinely embeds the owner's real name"
        );
        assert!(
            out.breadcrumbs.values[0].data.is_empty(),
            "breadcrumb data is arbitrary key/value and has no shape to scrub against"
        );
    }

    /// Metadata the report is useless without must survive, or the allowlist has
    /// been drawn too tight and the next crash arrives unattributable.
    #[test]
    fn the_metadata_a_report_needs_survives() {
        let mut event = Event::new();
        let id = event.event_id;
        let ts = event.timestamp;
        event.release = Some("1.4.39".into());
        event.environment = Some("production".into());
        event.level = sentry::Level::Fatal;
        event.exception = vec![Exception {
            ty: "panic".into(),
            value: Some("assertion failed".into()),
            ..Default::default()
        }]
        .into();
        event.contexts.insert(
            "os".into(),
            sentry::protocol::OsContext {
                name: Some("Windows".into()),
                version: Some("11".into()),
                ..Default::default()
            }
            .into(),
        );
        // Not on the allowlist.
        event.contexts.insert(
            "app".into(),
            sentry::protocol::AppContext {
                app_name: Some("whatever".into()),
                ..Default::default()
            }
            .into(),
        );

        let out = scrub_event(event);

        assert_eq!(out.event_id, id, "the event id must not be regenerated");
        assert_eq!(out.timestamp, ts, "nor the timestamp");
        assert_eq!(out.release.as_deref(), Some("1.4.39"));
        assert_eq!(out.environment.as_deref(), Some("production"));
        assert_eq!(out.level, sentry::Level::Fatal);
        assert_eq!(out.exception.values[0].ty, "panic");
        assert!(out.contexts.contains_key("os"), "OS version is the whole");
        assert!(
            !out.contexts.contains_key("app"),
            "a context nobody has reviewed must not ride along"
        );
    }

    /// Performance data is off twice over, and this is the half that cannot be
    /// overridden by an inherited sampling decision.
    #[test]
    fn never_sample_a_transaction_returns_zero_for_an_inherited_yes() {
        let ctx = sentry::TransactionContext::new("name", "op");
        assert_eq!(never_sample_a_transaction(&ctx), 0.0);

        let mut sampled = sentry::TransactionContext::new("name", "op");
        sampled.set_sampled(true);
        assert_eq!(
            never_sample_a_transaction(&sampled),
            0.0,
            "an upstream sentry-trace header must not be able to turn tracing on: \
             performance.rs:615 lets ctx.sampled override traces_sample_rate, and only \
             a traces_sampler outranks it"
        );
    }
}
