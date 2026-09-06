# Sentry Setup — Birdo VPN Desktop (Windows / macOS / Linux)

> **What was actually wrong.** The `sentry` crate, the `before_send` scrubber
> and `option_env!("SENTRY_DSN")` have been in this repo for months, and every
> release job already passed the secret. What was missing was everything that
> makes that *verifiable*: nothing failed when the DSN was absent (a
> `cargo:warning` that scrolls past in a 12-minute build), the env sat at **step**
> level so any build step added later would silently miss it, transactions were
> never explicitly disabled, and the scrubber covered four of the twelve fields
> an event can carry.
>
> After this change a **release** build refuses to compile without a usable DSN.

---

## 0. What is wired, and what is yours

| Piece | File | State |
| --- | --- | --- |
| DSN read at build time (`option_env!`) | `src-tauri/src/main.rs` | wired |
| Release build **fails** without a usable DSN | `src-tauri/build.rs` | wired |
| CI passes the secret at **job** level to all 5 build jobs | `.github/workflows/{release,build-windows,build-linux}.yml` | wired |
| Runtime init + client options | `src-tauri/src/main.rs` | wired |
| Allowlist scrubber (`before_send`) | `src-tauri/src/utils/crash_report.rs` | wired |
| Tracing off twice over (`traces_sample_rate` + `traces_sampler`) | same | wired |
| The DSN value itself | Sentry.io | **YOURS — steps 1-3** |
| Symbolicated stack traces (debug-file upload) | — | **not wired, see step 6** |

---

## 1. Create a **new** project — do not reuse Android or backend

Birdo already has two live Sentry projects in org **`o4510635638980608`** (EU
region):

| project id | what sends to it |
| --- | --- |
| `4510869977497680` | Android client (`BirdoVPN/Mobile-Client`) |
| `4510932258390096` | backend / web (`/opt/birdo/deploy/.env`) |

**The desktop client must have its own third project.** Crash streams from
different platforms must not be mixed: release versions, stack-frame formats,
issue grouping and alert rules are all per-project, and a shared project makes
"is this regression Windows-only?" unanswerable.

**Click path:** sentry.io → sign in → **Projects** → **Create Project** →
platform **Rust** (not "Tauri", there is no such platform; the Rust SDK is what
`src-tauri` links) → project name `birdo-vpn-desktop` → assign a team → **Create
Project**.

Ignore the onboarding snippet entirely. This repo initialises Sentry by hand in
`main.rs` and deliberately sets options the snippet does not. Copy only the DSN.

> The org is already EU-region, so the new project inherits it and its DSN host
> ends `.ingest.de.sentry.io`. That is how you tell an EU DSN from a US one.

## 2. Find the DSN

**Settings** (gear, bottom left) → **Projects** → `birdo-vpn-desktop` → **Client
Keys (DSN)**.

```
https://<32-hex-public-key>@o4510635638980608.ingest.de.sentry.io/<project-id>
```

Copy the whole line including `https://`. The `<project-id>` at the end must be
the **new** one — if it reads `4510869977497680` or `4510932258390096` you have
copied the Android or backend key.

A DSN is not a secret in the cryptographic sense — it is compiled into the
shipped binary and anyone can extract it with `strings` — but it is write
credentials against your error quota, so it lives in a repo secret rather than
in the tree.

## 3. Set the repo secret

```bash
gh secret set SENTRY_DSN --repo BirdoVPN/Desktop-Client < dsn.txt && rm dsn.txt
```

or interactively (`gh secret set SENTRY_DSN --repo BirdoVPN/Desktop-Client`,
paste, then Ctrl-Z + Enter on Windows / Ctrl-D on Unix), or in the web UI:
**Settings → Secrets and variables → Actions → New repository secret**, name
`SENTRY_DSN`.

Verify it exists — this prints the name and update time, never the value:

```bash
gh secret list --repo BirdoVPN/Desktop-Client | grep SENTRY_DSN
```

> **A `SENTRY_DSN` secret already exists on this repo** (set 2026-09-05). Nothing
> in the repository records which project it points at, and a DSN copied from
> the Android or backend project would look identical to CI and would silently
> merge desktop crashes into another platform's stream. Confirm its project id
> against step 2 and overwrite it if it is not the desktop project's.

### Which builds get a DSN

| Build | DSN? | Why |
| --- | --- | --- |
| `cargo build` / `npm run tauri dev` (debug) | No | `sentry::init` is a no-op with an empty DSN and `build.rs` only gates `PROFILE == "release"`. Developing needs no secret. |
| `cargo test --lib` | No | Same. |
| CI `release.yml` → `build-windows` | **Yes** | job-level `env` |
| CI `release.yml` → `build-linux` (matrix) | **Yes** | job-level `env` |
| CI `release.yml` → `build-macos` (matrix, signed **and** unsigned-fallback steps) | **Yes** | job-level `env` — this job has **two** `tauri build` steps, which is exactly why the env is at job level |
| CI `build-windows.yml` → `build` | **Yes** | job-level `env` |
| CI `build-linux.yml` → `build-linux` | **Yes** | job-level `env` |
| `release` jobs in all three workflows | N/A | they download and publish artifacts; they never compile |

## 4. Local development

Nothing is required for debug builds.

To build a **release** locally you must either supply a DSN:

```bash
SENTRY_DSN=https://…@o4510635638980608.ingest.de.sentry.io/… npm run tauri build
```

or opt out explicitly, which prints a loud banner and must never be used for a
shipped artifact:

```bash
BIRDO_ALLOW_MISSING_SENTRY_DSN=1 npm run tauri build
```

`BIRDO_ALLOW_MISSING_SENTRY_DSN` is never set in CI.

## 5. Verify

### 5a. The gate actually fails (this is the part worth checking)

```bash
cd src-tauri
cargo build --release          # with no SENTRY_DSN in the environment
```

Expected: the build **fails** in `build.rs` with
`SENTRY_DSN is not set — refusing to build a release artifact that cannot
report crashes.` If it *succeeds*, something is still feeding a DSN in — check
your environment and `BIRDO_ALLOW_MISSING_SENTRY_DSN`.

With one present, the build script prints
`Sentry: release build has a DSN — crash reporting is ARMED.`

> `build.rs` declares `cargo:rerun-if-env-changed=SENTRY_DSN`. Without that line
> the gate would be evaluated once and then cached: setting the secret for the
> first time would not re-run the build script, and CI (which restores
> `target/` through `Swatinem/rust-cache`) would keep passing while shipping an
> inert reporter. The crate body needs no such declaration — cargo tracks
> `option_env!` itself, which was verified by measurement: building the same
> crate three times with `SENTRY_DSN` unset, then `hello`, then `world`
> recompiled and produced each value.

### 5b. The DSN reached the artifact

```bash
strings src-tauri/target/release/birdo-vpn-desktop.exe | grep -c 'ingest\.de\.sentry\.io'
```

Expected: at least `1`.

### 5c. A real event arrives

The app has no on-demand crash trigger. The honest test is a deliberate panic:

1. Temporarily add `panic!("sentry smoke test");` to the top of `fn main()`.
2. Build a **release** artifact with a DSN and run it.
3. Sentry → **Issues**. The event appears within ~30 s, tagged
   `release: 1.4.39`, `environment: production`.
4. **Remove the panic. Do not commit it.**

While you are there, confirm the privacy posture on the event itself:

- **User** section: empty. No email, no IP, no account id.
- **Server name**: `redacted`, never a hostname.
- **Additional Data / Tags**: empty — the allowlist drops both.
- **Performance / Traces**: empty. Tracing is off twice over.
- Any IP or hostname in the message shows as a redaction marker.

### 5d. CI

Re-run a build job. Its log contains
`Sentry: release build has a DSN — crash reporting is ARMED.` before the bundle
is produced. With the secret missing the job fails in `build.rs`, before signing.

## 6. Optional — readable stack traces

**Not wired.** `[profile.release]` sets `strip = true`, `lto = true` and
`codegen-units = 1` (`src-tauri/Cargo.toml`). Sentry will receive the panic
message and the breadcrumbs, but the **backtrace frames are likely to be
largely unsymbolicated** — this was reasoned about, not measured, so treat it as
a prediction to check on the first real crash rather than a fact.

There is a second, verified gap in the same area:
`sentry_panic::PanicIntegration::event_from_panic_info`
(`sentry-panic-0.48.3/src/lib.rs:107-135`) builds the event from
`message_from_panic_info(info)` and `current_stacktrace()` **only** — it never
reads `PanicHookInfo::location()`. So the `file:line:col` that
`setup_panic_hook` writes to `birdo.log` does **not** reach Sentry. Supplying it
would mean `default_integrations: false` plus a hand-built integration list with
a custom extractor, because the crate documents that "the `PanicIntegration` can
not [be defined multiple times], and it will not pick up custom panic extractors
when it is defined multiple times" (`sentry-0.48.3/src/defaults.rs:25-27`). That
is a deliberate follow-up, not something to slip into this change.

Two ways to fix it, both deliberate decisions for the owner rather than
something to change quietly:

1. `strip = "debuginfo"` keeps the symbol table at the cost of binary size, and
   changes the bytes that get Authenticode-signed.
2. Upload debug files with `sentry-cli upload-dif` (Windows PDBs, macOS dSYMs,
   Linux ELF debug sections). This needs an org-scoped **auth token**
   (`project:releases` + `org:read`), not the DSN — a DSN grants event
   ingestion only. It also pulls a tool into the job that signs the release,
   which is a supply-chain trade this repo has not made anywhere else (every
   action in these workflows is SHA-pinned). Add it with a pin, deliberately,
   if the missing names ever actually get in the way.

## 7. Privacy posture — what a crash report may and may not contain

Birdo's privacy policy states that no connection logs are kept. A crash reporter
that exports a destination host or a tunnel address contradicts that policy
exactly as a server-side log line would, and this estate has already had one
incident of that class (ufw logging customer destinations; 63,400 records
purged). So the configuration states every relevant switch **explicitly**,
including the ones whose SDK default is already safe — a default is someone
else's decision and it can change in a version bump.

### An allowlist, not a denylist

`before_send` does not strip fields from the incoming event. It **builds a new
event** out of a fixed list of fields and lets `..Default::default()` empty
everything else. A field added by a future SDK upgrade is therefore dropped by
construction rather than egressing until someone notices it.

**Kept:** `event_id`, `timestamp`, `level`, `platform`, `release`,
`environment`, `sdk`, `fingerprint`, `logger`, `server_name` (pinned to
`redacted`), the message, the log entry (with positional params cleared), each
exception's type / module / stacktrace / mechanism with its **value scrubbed**,
each breadcrumb's type / category / level / timestamp with its **message
scrubbed**, and the `os` / `device` / `runtime` / `rust` contexts.

**Dropped outright:** `user`, `request`, `tags`, `extra`, `transaction`,
`culprit`, `modules`, `dist`, `template`, `threads`, the top-level `stacktrace`,
and **every breadcrumb `data` map** (arbitrary key/value pairs any future
`add_breadcrumb` call site could fill with anything).

### Scrubbing

Every free-text field that survives goes through
`utils::redact::sanitize_always` — the same regex set the local log and the
frontend error path use, so the two cannot drift. It removes IPv4, IPv6, email
addresses, bare multi-label hostnames, JWTs and long base64 runs (WireGuard and
ML-KEM key material), HTML and `at …` stack-trace lines.

`sanitize_error` is a deliberate pass-through under `debug_assertions`, so that
one is **not** what the reporter calls: `sanitize_always` is the shared
implementation and `sanitize_error` is the debug-aware wrapper around it. One
implementation, two thin wrappers — the same shape `tunnel_dns::parse_dns_config`
uses for the v4/v6 twins, and for the same reason.

### Performance data is off twice over

- `traces_sample_rate: 0.0`
- `traces_sampler: |_| 0.0`

Both, because **`before_send` does not run for transactions**. In
`sentry-core-0.48.3` `before_send` is invoked at exactly one place
(`client/mod.rs:373`, inside the event path), while a transaction reaches Sentry
through `Transaction::finish_with_timestamp` →
`client.send_envelope(...)` (`performance.rs:868-885`) — it never passes the
scrubber. Span descriptions and transaction names would therefore be an
**unscrubbed** egress channel sitting next to a carefully scrubbed one. That is
the exact mistake found on the Android side (`tracesSampleRate = 1.0` with a
`beforeSend`-only scrubber), so it is closed here by inspection rather than by
assumption.

`traces_sample_rate` alone is not sufficient. `performance.rs:615` reads

```rust
(None, traces_sample_rate) => ctx.sampled.map(f32::from).unwrap_or(traces_sample_rate)
```

so an inherited `sampled = Some(true)` on a `TransactionContext` **overrides** a
rate of 0.0. A `traces_sampler` takes priority over both (`performance.rs:614`),
which is why one is set even though it looks redundant.

`enable_logs` is pinned `false` for the same class of reason: its default is
`true` in this version, and it is only inert because the `logs` cargo feature is
off — feature unification in a future dependency could turn it on without
anybody editing this file.

### The webview is deliberately NOT wired

`@sentry/browser` is not installed and the React `ErrorBoundary`
(`src/components/ErrorBoundary.tsx`) still only writes to the console, so a
crash in the UI layer produces no Sentry event. That is a real gap, and it is
left open on purpose:

1. **It cannot reach Sentry as things stand.** `tauri.conf.json` pins
   `connect-src 'self' https://birdo.app https://*.birdo.app`. The browser SDK
   would need `https://*.ingest.de.sentry.io` added to the CSP of a VPN
   client's webview — a permanent widening of the one place the UI is allowed
   to talk to.
2. **It would be a second scrubber.** The browser SDK ships its own
   `beforeSend`, its own breadcrumb integrations (`fetch`/`xhr` breadcrumbs
   record request **URLs**) and its own defaults. Two independently-configured
   privacy filters over the same product is precisely the twin drift this repo
   keeps paying for.

The right shape is a small Tauri command that forwards a scrubbed message into
the **existing** Rust client — one SDK, one DSN, one scrubber, no CSP change —
and it deserves its own issue and its own review rather than being appended to
this one.

### Known gap, accepted

`sentry::init` is called before `setup_panic_hook`, so sentry's own panic
integration runs **ahead** of the local hook and sees the raw payload. That is
fine — nothing is transmitted until `before_send`, which is the last point
before the event leaves the device — but it does mean the raw message reaches
sentry's in-process buffers. Nothing writes it to disk.
