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
//! | `tags` | **one** key, `birdo.pq.impl`, and only when its value is the exact `PQ_IMPL_NAME` constant this binary was compiled with — see [`ALLOWED_TAGS`]. Any other key, and that key with any other value, is dropped |
//!
//! Everything else is dropped: `user`, `request`, every other `tag`, `extra`,
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
//!
//! # Crash reporting is OPT-IN (audit 2026-09-29, C-3 / D-12 / P1-6)
//!
//! Until 1.4.44 `main()` called `sentry::init` on every launch, before the
//! consent screen, with no way to switch it off. Now:
//!
//! - Nothing is initialised at startup unless the persisted setting
//!   `crash_reports_enabled` is true (`main.rs` `setup()` →
//!   [`set_opted_in`]). The setting defaults to FALSE for new installs and for
//!   every upgraded one, whatever 1.4.44 did.
//! - With it off, no Sentry client exists: sentry's panic hook is never
//!   installed, [`report_security_event`] returns before touching the SDK, and
//!   nothing can reach the network.
//! - Turning it on (consent screen or Settings) takes effect immediately —
//!   [`set_opted_in`] builds the client and binds it to the process hub — so
//!   the UI needs no "restart" note.
//! - Turning it off takes effect immediately too: the client stays bound (the
//!   panic integration cannot be uninstalled), but [`gate_and_scrub`], the
//!   `before_send` hook, drops every event while the flag is off. Sentry's
//!   client reports (dropped-event counters) are only ever attached to an
//!   outgoing envelope, so a dropped event sends nothing either.
//! - No release-health sessions: the SDK's `release-health` feature is not
//!   compiled (Cargo.toml), so no session envelope exists in this binary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use sentry::protocol::{Context, Event, Map};

use super::redact::sanitize_always;

/// The user's crash-reporting choice, mirrored from settings. OFF until
/// [`set_opted_in`] says otherwise.
static OPTED_IN: AtomicBool = AtomicBool::new(false);

/// The one Sentry client this process ever builds (the panic integration
/// installs its hook once per process, so it is built at most once).
static CLIENT: OnceLock<Arc<sentry::Client>> = OnceLock::new();

/// Apply the user's choice. `true` builds and binds the client on first use;
/// `false` makes [`gate_and_scrub`] drop everything from now on.
pub fn set_opted_in(enabled: bool) {
    OPTED_IN.store(enabled, Ordering::SeqCst);
    if enabled {
        CLIENT.get_or_init(|| {
            let client = Arc::new(sentry::Client::from(sentry::apply_defaults(
                client_options(),
            )));
            // Bind to the PROCESS hub explicitly. `sentry::init` binds to the
            // CURRENT thread's hub, which is only the process hub when called
            // on the thread that first touched sentry — true for the old
            // top-of-main() call, not for a Settings toggle arriving on a
            // command thread. Nothing touches sentry before this point (see the
            // module docs), so every thread hub created later inherits it.
            let hub = sentry::Hub::main();
            hub.bind_client(Some(client.clone()));
            // Name the ML-KEM implementation this binary links, so a native
            // fault in the BirdoPQ path can be attributed from the report
            // alone (the 1.4.25 Android SIGILL). The scrubber only lets this
            // key out with exactly this value (`ALLOWED_TAGS`).
            hub.configure_scope(|scope| {
                scope.set_tag("birdo.pq.impl", crate::vpn::birdo_pq::PQ_IMPL_NAME);
            });
            client
        });
    }
    tracing::info!(
        "Crash reporting {}",
        if enabled {
            "enabled by the user"
        } else {
            "off"
        }
    );
}

/// Whether the user has opted in to crash reports.
pub fn is_opted_in() -> bool {
    OPTED_IN.load(Ordering::SeqCst)
}

/// How long an exit waits for queued reports to go out.
pub const EXIT_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Send whatever is still queued before the process exits (second-pass #17).
///
/// The old top-of-`main()` `sentry::init` returned a guard that flushed on
/// drop; building the client lazily on opt-in lost that, so a
/// [`report_security_event`] raised just before quitting could be dropped
/// with the transport thread. Called from the exit paths in `main.rs`.
/// A no-op when no client was ever built (never opted in): it does not touch
/// the SDK at all then. Blocks for at most [`EXIT_FLUSH_TIMEOUT`].
pub fn flush_on_exit() {
    if let Some(client) = CLIENT.get() {
        if !client.flush(Some(EXIT_FLUSH_TIMEOUT)) {
            tracing::warn!("Crash reports still queued at exit were not all sent");
        }
    }
}

/// `before_send`: drop everything while the user is opted out, otherwise
/// rebuild the event from the allowlist ([`scrub_event`]).
pub fn gate_and_scrub(event: Event<'static>) -> Option<Event<'static>> {
    gate(is_opted_in(), event)
}

/// The pure half of [`gate_and_scrub`], so both branches are testable without
/// flipping the process-wide flag under other tests.
fn gate(opted_in: bool, event: Event<'static>) -> Option<Event<'static>> {
    if !opted_in {
        return None;
    }
    Some(scrub_event(event))
}

/// Every client option, stated explicitly (see `docs/SENTRY-SETUP.md` §7).
fn client_options() -> sentry::ClientOptions {
    (
        // The DSN is public — it only identifies the project. Empty in debug
        // builds, which makes the client a no-op; `build.rs` refuses a release
        // build without one.
        option_env!("SENTRY_DSN").unwrap_or(""),
        // sentry 0.49 made `ClientOptions` #[non_exhaustive], so every option
        // is set through the builder.
        sentry::ClientOptions::new()
            .release(env!("CARGO_PKG_VERSION"))
            .environment(if cfg!(debug_assertions) {
                "development"
            } else {
                "production"
            })
            // Scrub PII: no usernames, IPs, or email in breadcrumbs
            .send_default_pii(false)
            // SEC-PII: the `contexts` integration fills a None server_name with
            // the machine hostname (`ContextIntegration::setup` only assigns
            // when `options.server_name.is_none()`), and consumer hostnames
            // routinely embed the owner's real name ("Johns-MacBook-Pro").
            // `send_default_pii: false` does NOT gate that path. A pre-set
            // value short-circuits it.
            .server_name("redacted")
            // The opt-in gate, then the ALLOWLIST. `before_send` is the last
            // point before an event leaves the device, and it covers every
            // capture path — sentry's own panic integration chains AHEAD of
            // `setup_panic_hook` and sees the raw payload, so neither the gate
            // nor the scrub can live in a hook.
            .before_send(gate_and_scrub)
            // 0.49: `sample_rate` became `EventSamplingStrategy::FixedRate`;
            // 1.0 is also the default, kept explicit so the intent is visible.
            .sample_rate(1.0)
            // NO PERFORMANCE DATA — `before_send` does not run for
            // transactions (see the module docs), so they are never sampled.
            // `auto_session_tracking` needs no setting: its setter only exists
            // under the `release-health` feature, which is not compiled, so
            // the session flusher is absent from this binary altogether.
            // `enable_logs` is #[deprecated] in 0.49 and only gates the
            // `tracing`/`log` integrations, neither of which is compiled.
            .traces_sampler(never_sample_a_transaction),
    )
        .into()
}

/// Context keys that may leave the device. Everything `sentry-contexts` puts on
/// an event is in here, so this is a fence rather than a filter today — it
/// exists so that an integration added later cannot widen the payload silently.
const ALLOWED_CONTEXTS: &[&str] = &["os", "device", "runtime", "rust"];

/// Tag keys that may leave the device, each paired with the ONLY values it may
/// carry. A tag survives only when both the key and the value match — an
/// allowed key carrying any other string is dropped — so widening this list
/// admits a fixed set of literals, never a channel.
///
/// `birdo.pq.impl` names the ML-KEM implementation linked into this build
/// (`vpn::birdo_pq::PQ_IMPL_NAME`, a compile-time constant), mirroring the
/// same tag on Android. It exists because the 1.4.25 Android SIGILL took as
/// long as it did to pin on PQClean's assembly precisely because no crash
/// report could say which implementation had faulted. The value is a
/// build-time fact about the binary, not a probe of the device and not
/// user content.
const ALLOWED_TAGS: &[(&str, &[&str])] =
    &[("birdo.pq.impl", &[crate::vpn::birdo_pq::PQ_IMPL_NAME])];

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

    // Key AND value must be on the list. `event.tags` is user-shaped input as
    // far as this file is concerned: any call site can `set_tag` anything.
    let mut tags: Map<String, String> = Map::new();
    for (key, allowed_values) in ALLOWED_TAGS {
        if let Some(value) = event.tags.get(*key) {
            if allowed_values.contains(&value.as_str()) {
                tags.insert((*key).to_string(), value.clone());
            }
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
        // Only what `ALLOWED_TAGS` admitted above, by key and by value.
        tags,
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
///
/// Like every other report it is sent ONLY if the user opted in to crash
/// reports; otherwise it returns before touching the SDK at all.
pub fn report_security_event(message: &str) {
    if !is_opted_in() {
        return;
    }
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
        assert!(out.tags.is_empty(), "an unlisted tag key is dropped");
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

    /// Opt-in gate: while the user has not turned crash reports on, NOTHING
    /// leaves — not even a scrubbed event.
    #[test]
    fn nothing_is_sent_unless_the_user_opted_in() {
        let mut event = Event::new();
        event.message = Some("panic".into());
        assert!(gate(false, event.clone()).is_none(), "opted out must drop");
        let out = gate(true, event).expect("opted in must send");
        assert_eq!(
            out.server_name.as_deref(),
            Some("redacted"),
            "and still scrub"
        );
    }

    /// The process starts opted OUT, whatever an older build did: nothing in
    /// the test binary ever opts in, so the global must read false here.
    #[test]
    fn the_process_starts_opted_out() {
        assert!(!is_opted_in());
        assert!(gate_and_scrub(Event::new()).is_none());
    }

    /// Second-pass #17: the exit flush never builds a client, and so never
    /// touches the SDK, for a user who did not opt in.
    #[test]
    fn exit_flush_is_a_no_op_without_opt_in() {
        let started = std::time::Instant::now();
        flush_on_exit();
        assert!(CLIENT.get().is_none(), "flushing must not build a client");
        assert!(started.elapsed() < EXIT_FLUSH_TIMEOUT, "and must not wait");
    }

    /// The options the client is built with carry the gate itself, not just
    /// the scrubber, and no traces.
    #[test]
    fn client_options_wire_the_gate_and_disable_tracing() {
        let opts = client_options();
        assert!(!opts.send_default_pii);
        assert_eq!(opts.server_name.as_deref(), Some("redacted"));
        let before_send = opts.before_send.as_ref().expect("before_send is set");
        assert!(
            before_send(Event::new()).is_none(),
            "before_send must drop while opted out"
        );
        assert!(
            matches!(
                opts.traces_sampling_strategy,
                sentry::TracesSamplingStrategy::Function(_)
            ),
            "the never-sample function must outrank any inherited decision"
        );
        assert!(
            !opts.auto_session_tracking,
            "no release-health sessions: nothing may be sent on app start"
        );
    }

    /// The tag allowlist is a list of (key, value) literals, not of keys.
    /// Three cases, and only the first may survive.
    #[test]
    fn a_tag_survives_only_with_both_an_allowed_key_and_an_allowed_value() {
        use crate::vpn::birdo_pq::PQ_IMPL_NAME;

        // 1. allowed key + the exact allowed value: kept.
        let mut event = Event::new();
        event
            .tags
            .insert("birdo.pq.impl".into(), PQ_IMPL_NAME.into());
        let out = scrub_event(event);
        assert_eq!(
            out.tags.get("birdo.pq.impl").map(String::as_str),
            Some(PQ_IMPL_NAME),
            "the implementation name is the one tag a crash may carry"
        );
        assert_eq!(out.tags.len(), 1);

        // 2. allowed key, any other value: dropped. This is the case that
        //    stops the key becoming a channel — a call site cannot smuggle a
        //    string out by choosing the right key.
        let mut event = Event::new();
        event.tags.insert("birdo.pq.impl".into(), DIRTY.into());
        let out = scrub_event(event);
        assert!(
            out.tags.is_empty(),
            "an allowed key with an unlisted value must be dropped, not passed through"
        );

        // 3. any other key carrying the allowed value: dropped.
        let mut event = Event::new();
        event.tags.insert("pq_impl".into(), PQ_IMPL_NAME.into());
        let out = scrub_event(event);
        assert!(out.tags.is_empty(), "the value alone does not admit a tag");
    }
}
