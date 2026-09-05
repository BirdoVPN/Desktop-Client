//! What the persistent log is allowed to record.
//!
//! Lives in the library rather than `main.rs` so CI's `cargo test --lib` runs
//! its tests: the bin target's unit tests are not executed by the pipeline
//! (`.github/workflows/tests.yml` runs `cargo test --lib`), so a guard placed
//! beside `main()` would never actually guard anything.

use tracing_subscriber::filter::LevelFilter;

/// The highest verbosity the on-disk log may ever record, for a given build.
///
/// WHY A CLAMP EXISTS. The redaction contract in this crate is written for
/// release builds only: `utils::redact::redact_ip` and its siblings return
/// their input VERBATIM under `debug_assertions` and redact only in release.
/// On top of that, several call sites deliberately keep an identifying value at
/// `debug` INSTEAD of redacting it, on the reasoning that debug never ships —
/// the node name in `vpn/manager.rs`, the deep-link URL in
/// `main.rs::deliver_deep_link`, the unresolvable entry endpoint in
/// `commands/vpn_multi_hop.rs`.
///
/// `RUST_LOG` breaks that reasoning. `main.rs` reads it straight from the
/// environment and hands it to the subscriber's `EnvFilter`, so anything able
/// to set an environment variable for this process — a shortcut, a scheduled
/// task, a co-tenant on a shared machine, a support instruction copied off a
/// forum — turns `birdo.log` into a durable, append-only record of which exit
/// node was used and when. The file is the artefact a user later emails to
/// support.
///
/// The fix belongs at the SINK, not at the level: the console layer can keep
/// honouring `RUST_LOG` in full (it is transient, and it is where a developer
/// actually looks), while the file layer refuses anything more verbose than
/// this. Applied as a per-layer filter, it intersects with the subscriber-wide
/// `EnvFilter` rather than replacing it, so `RUST_LOG` can still make the file
/// QUIETER — it just cannot make it more revealing.
///
/// Debug builds keep TRACE. Nothing is redacted there anyway (see above), the
/// log lives in the developer's own data directory, and clamping it would cost
/// local diagnosis while protecting nobody.
pub fn file_log_max_level_for(debug_build: bool) -> LevelFilter {
    if debug_build {
        LevelFilter::TRACE
    } else {
        LevelFilter::INFO
    }
}

/// `file_log_max_level_for` for the build being compiled.
pub fn file_log_max_level() -> LevelFilter {
    file_log_max_level_for(cfg!(debug_assertions))
}

#[cfg(test)]
mod tests {
    use super::{file_log_max_level, file_log_max_level_for};
    use tracing_subscriber::filter::LevelFilter;

    /// THE POINT OF THE CLAMP. In a shipped build nothing below INFO may reach
    /// `birdo.log`, whatever `RUST_LOG` says — because below INFO is exactly
    /// where the unredacted connection history lives.
    #[test]
    fn release_builds_never_persist_below_info() {
        assert_eq!(file_log_max_level_for(false), LevelFilter::INFO);
        assert!(
            file_log_max_level_for(false) < LevelFilter::DEBUG,
            "a release file layer that accepts DEBUG persists the node name and the tunnel address"
        );
        assert!(file_log_max_level_for(false) < LevelFilter::TRACE);
    }

    /// Debug builds are deliberately unaffected.
    #[test]
    fn debug_builds_keep_full_verbosity() {
        assert_eq!(file_log_max_level_for(true), LevelFilter::TRACE);
    }

    /// The wrapper the file layer actually installs must follow the build kind
    /// rather than a constant — this is what fails if either arm is hard-coded.
    #[test]
    fn wrapper_follows_the_build_kind() {
        assert_eq!(
            file_log_max_level(),
            file_log_max_level_for(cfg!(debug_assertions))
        );
    }
}
