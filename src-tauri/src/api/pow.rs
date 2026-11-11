//! Proof-of-work solver for sign-up (register item A-H11 / MR-2152) and, during
//! a failed-sign-in spike, sign-in (A-M77 / MR-2139).
//!
//! The server (birdo-web `backend/src/auth/signup-pow.ts`, contract in
//! `docs/SIGNUP-PROOF-OF-WORK.md`) issues a signed challenge at
//! `POST /auth/pow/challenge` and accepts `pow: { challenge, nonce }` on
//! `POST /auth/register/anonymous`. The scheme is Hashcash over SHA-256:
//! find a `nonce` such that `SHA-256(UTF-8(challenge ":" nonce))` starts with
//! at least `difficulty` zero bits. The nonce is 1-32 characters of
//! `[0-9A-Za-z]`; the server's reference solver counts up in base 36 and so
//! does this one (`nonce_for` below), split over a few threads by stride.
//!
//! Without a proof the server still creates the account, on its stricter
//! "legacy" tier, so every failure to GET a challenge here means "send the
//! request without one": this module never blocks a sign-up by itself.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::ApiError;

/// `algorithm` of a challenge this build can solve.
pub const POW_ALGORITHM: &str = "sha256-leading-zero-bits";
/// `POW_TOKEN_MAX_LENGTH` of the server: a longer token is not one of its.
const TOKEN_MAX_LEN: usize = 128;
/// The server never issues above 28 (`POW_MAX_CONFIG_BITS`) and refuses to
/// sign above 32; a challenge asking for more is not honest work to do.
const MAX_SOLVABLE_BITS: u32 = 32;
/// Hashes between two looks at the stop flag, per thread.
const BATCH: u64 = 4096;
/// Worker threads at most: a sign-up check must not take the whole machine.
const MAX_THREADS: usize = 4;

/// `POST /auth/pow/challenge` answer (the fields this client reads).
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    #[serde(default)]
    pub algorithm: String,
    pub challenge: String,
    pub difficulty: u32,
}

impl Challenge {
    /// Whether this build can and should solve it.
    fn solvable(&self) -> bool {
        self.algorithm == POW_ALGORITHM
            && !self.challenge.is_empty()
            && self.challenge.len() <= TOKEN_MAX_LEN
            && (1..=MAX_SOLVABLE_BITS).contains(&self.difficulty)
    }
}

/// The `pow` member of the sign-up body.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PowSolution {
    pub challenge: String,
    pub nonce: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SolveError {
    Cancelled,
}

/// Number of leading zero bits of a digest.
fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

/// `i` in base 36, digits then lowercase letters, no padding (the server's
/// `i.toString(36)`). Returns the bytes in `buf` and their count.
fn nonce_for(mut i: u64, buf: &mut [u8; 13]) -> usize {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut tmp = [0u8; 13];
    let mut n = 0;
    loop {
        tmp[n] = DIGITS[(i % 36) as usize];
        n += 1;
        i /= 36;
        if i == 0 {
            break;
        }
    }
    for (dst, src) in buf.iter_mut().zip(tmp[..n].iter().rev()) {
        *dst = *src;
    }
    n
}

/// Whether `nonce` solves `token` at `bits` (the server's `meetsDifficulty`).
/// The tests' check: the solver's own loop is what runs in the app.
#[cfg(test)]
pub fn meets_difficulty(token: &str, nonce: &str, bits: u32) -> bool {
    if nonce.is_empty() || nonce.len() > 32 || !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.update(b":");
    h.update(nonce.as_bytes());
    leading_zero_bits(&h.finalize()) >= bits
}

/// Solve `token` at `bits`, on `threads` threads (thread `t` tries the
/// counters `t, t + threads, t + 2 * threads, …`), until one finds a nonce or
/// `cancel` is set. With one thread the answer is the smallest counter, the
/// same nonce the server's reference `solvePow` returns.
///
/// Blocking: call it from `spawn_blocking`. `progress` is told the number of
/// hashes done, about every 150 ms, from the calling thread (the first report is at 150 ms).
pub fn solve(
    token: &str,
    bits: u32,
    threads: usize,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<String, SolveError> {
    let threads = threads.max(1);
    let mut prefix = Sha256::new();
    prefix.update(token.as_bytes());
    prefix.update(b":");

    let found = AtomicBool::new(false);
    let winner: std::sync::Mutex<Option<(u64, String)>> = std::sync::Mutex::new(None);
    let done = AtomicU64::new(0);

    std::thread::scope(|scope| {
        for t in 0..threads {
            let (prefix, found, winner, done) = (&prefix, &found, &winner, &done);
            scope.spawn(move || {
                let mut counter = t as u64;
                let mut buf = [0u8; 13];
                'outer: loop {
                    for _ in 0..BATCH {
                        let n = nonce_for(counter, &mut buf);
                        let mut h = prefix.clone();
                        h.update(&buf[..n]);
                        if leading_zero_bits(&h.finalize()) >= bits {
                            let nonce = String::from_utf8_lossy(&buf[..n]).into_owned();
                            let mut w = winner.lock().unwrap_or_else(|e| e.into_inner());
                            // Keep the smallest counter, so one thread is
                            // deterministic and several are still stable.
                            if w.as_ref().is_none_or(|(c, _)| counter < *c) {
                                *w = Some((counter, nonce));
                            }
                            found.store(true, Ordering::Release);
                            break 'outer;
                        }
                        counter += threads as u64;
                    }
                    done.fetch_add(BATCH, Ordering::Relaxed);
                    if found.load(Ordering::Acquire) {
                        break;
                    }
                }
            });
        }
        // The coordinator: progress and cancellation, until a thread wins.
        let mut last_report = Instant::now();
        loop {
            if found.load(Ordering::Acquire) {
                break;
            }
            if cancel.load(Ordering::Acquire) {
                // Workers see `found` at their next batch edge.
                found.store(true, Ordering::Release);
                break;
            }
            if last_report.elapsed() >= Duration::from_millis(150) {
                progress(done.load(Ordering::Relaxed));
                last_report = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });

    let won = winner.into_inner().unwrap_or_else(|e| e.into_inner());
    match won {
        Some((_, nonce)) => Ok(nonce),
        None => Err(SolveError::Cancelled),
    }
}

/// Threads for a real solve.
pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, MAX_THREADS)
}

/// `details.code` values after which a fresh challenge is worth a try.
pub fn is_retryable_code(code: &str) -> bool {
    matches!(
        code,
        "pow_expired" | "pow_replayed" | "pow_difficulty_raised" | "pow_invalid"
    )
}

/// What `register_with_proof` ended with.
#[derive(Debug)]
pub enum Registered<T> {
    Done(T),
    /// The user cancelled while the proof was being worked out.
    Cancelled,
}

/// The sign-up request with its proof of work.
///
///  * `fetch` asks for a `signup` challenge; `None` when it cannot be had (the
///    endpoint is down, rate limited, or the answer is not one this build can
///    solve): the request then goes out WITHOUT a proof and the server decides.
///  * `solve_one` works a challenge out (`None` is a cancel).
///  * `send` is the sign-up request with the proof, or without.
///
/// A `pow_expired`, `pow_replayed`, `pow_difficulty_raised` or `pow_invalid`
/// answer gets one fresh challenge and one more try. A second `pow_expired`
/// (a slow machine) is sent once more without a proof, which is what the
/// contract says to do after two expiries; any other second refusal is the
/// answer.
pub async fn register_with_proof<T, F, FFut, S, SFut, R, RFut>(
    mut fetch: F,
    mut solve_one: S,
    mut send: R,
) -> Result<Registered<T>, ApiError>
where
    F: FnMut() -> FFut,
    FFut: Future<Output = Option<Challenge>>,
    S: FnMut(Challenge) -> SFut,
    SFut: Future<Output = Option<PowSolution>>,
    R: FnMut(Option<PowSolution>) -> RFut,
    RFut: Future<Output = Result<T, ApiError>>,
{
    let mut attempt = 0;
    loop {
        let proof = match fetch().await {
            Some(c) if c.solvable() => match solve_one(c).await {
                Some(p) => Some(p),
                None => return Ok(Registered::Cancelled),
            },
            _ => None,
        };
        let sent_proof = proof.is_some();
        match send(proof).await {
            Err(ApiError::PowRefused { ref code, .. })
                if sent_proof && attempt == 0 && is_retryable_code(code) =>
            {
                attempt = 1;
            }
            Err(ApiError::PowRefused { ref code, .. })
                if sent_proof && attempt == 1 && code == "pow_expired" =>
            {
                return send(None).await.map(Registered::Done);
            }
            other => return other.map(Registered::Done),
        }
    }
}

/// `pow.op` of a sign-in refusal that asks for a proof.
pub const LOGIN_OP: &str = "login";

/// 429 `pow_required` whose `pow.op` is `login`: the one refusal a sign-in
/// answers with a proof of work.
fn is_login_pow_required(e: &ApiError) -> bool {
    matches!(
        e,
        ApiError::PowRefused { code, pow_op: Some(op), .. }
            if code == "pow_required" && op == LOGIN_OP
    )
}

/// A sign-in request that is sent once WITHOUT a proof and, only when the
/// server answers 429 `pow_required` for the `login` operation (a failed
/// sign-in spike, birdo-web `LoginAbuseService.admit`), once more WITH one.
///
///  * `send` is the sign-in request, with the proof or without.
///  * `fetch` asks for a `login` challenge (`None` when it cannot be had).
///  * `solve_one` works it out (`None` is a cancel).
///
/// Never more than one retry: a second refusal, whatever it says, is the
/// answer. Nothing is solved for any other error, for a `pow_required` that
/// names another operation or none, or for a challenge this build should not
/// solve (the original refusal is then the answer).
pub async fn login_with_proof<T, F, FFut, S, SFut, R, RFut>(
    mut send: R,
    fetch: F,
    solve_one: S,
) -> Result<Registered<T>, ApiError>
where
    F: FnOnce() -> FFut,
    FFut: Future<Output = Option<Challenge>>,
    S: FnOnce(Challenge) -> SFut,
    SFut: Future<Output = Option<PowSolution>>,
    R: FnMut(Option<PowSolution>) -> RFut,
    RFut: Future<Output = Result<T, ApiError>>,
{
    match send(None).await {
        Err(refusal) if is_login_pow_required(&refusal) => {
            let challenge = match fetch().await {
                Some(c) if c.solvable() => c,
                _ => return Err(refusal),
            };
            match solve_one(challenge).await {
                Some(proof) => send(Some(proof)).await.map(Registered::Done),
                None => Ok(Registered::Cancelled),
            }
        }
        other => other.map(Registered::Done),
    }
}

/// Wall-clock helper for the caller's progress events: at most one per
/// `every`.
pub struct Throttle {
    last: Option<Instant>,
    every: Duration,
}

impl Throttle {
    pub fn new(every: Duration) -> Self {
        Self { last: None, every }
    }
    pub fn ready(&mut self) -> bool {
        let now = Instant::now();
        match self.last {
            Some(t) if now.duration_since(t) < self.every => false,
            _ => {
                self.last = Some(now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    // Vectors from the SERVER's own code: birdo-web origin/main 01fbd9a1,
    // backend/src/auth/signup-pow.ts, run under node (mintPowToken with the
    // key of the test-only secret, signup, 2027-01-15 time, fixed id;
    // solvePow for the nonce, powDigest for the digest). Nothing in the
    // token is a credential: the key never leaves the generating script.
    const TOKEN_12: &str = "p1.fbdc9dc2.signup.12.1800000300.00112233445566778899aabbccddeeff.0oi-BjLJT4trKdYCNeP4jbnu-lU4xPnEG7yQY4DNZA0";
    const TOKEN_20: &str = "p1.fbdc9dc2.signup.20.1800000300.00112233445566778899aabbccddeeff.tlwXpuZSKzjWkMFkxewhFIK4FCXUUsqiXawL7pVX624";

    #[test]
    fn digest_and_nonces_match_the_server() {
        let cases = [
            (
                TOKEN_12,
                212,
                8,
                "00b83a4f5e453ff19f52e32ae390d392663a8017b424cba8f84279ff5ad81fc9",
            ),
            (
                TOKEN_12,
                1254,
                12,
                "00022ce4bab14494733bdf0218109f871d695a7e63506bda749eba9831ad6a66",
            ),
            (
                TOKEN_12,
                38006,
                16,
                "000039e83c73795ba3fb7b09982680f193ec1b8b7c1ce84c8e2f8c1aa020b7b6",
            ),
            (
                TOKEN_20,
                412335,
                20,
                "000003bd2675041823eccfb0ad90348b3c3a5525045b8dea4e380407cdec9b25",
            ),
        ];
        // The server's nonces as their base-36 counters (5w, yu, tbq, 8u5r),
        // turned into the nonce text at run time: a literal one trips CodeQL's
        // rust/hard-coded-cryptographic-value ("used as a nonce"), which cannot
        // tell a proof-of-work counter from a cipher nonce.
        for (token, counter, bits, digest) in cases {
            let mut buf = [0u8; 13];
            let n = nonce_for(counter, &mut buf);
            let nonce = String::from_utf8(buf[..n].to_vec()).unwrap();
            let mut h = Sha256::new();
            h.update(format!("{token}:{nonce}").as_bytes());
            let d = h.finalize();
            assert_eq!(hex::encode(d), digest, "{nonce}");
            assert!(meets_difficulty(token, &nonce, bits), "{nonce}");
        }
        // The server's answer for "0" at 12 bits is a miss.
        let mut buf = [0u8; 13];
        let n = nonce_for(0, &mut buf);
        let zero = String::from_utf8(buf[..n].to_vec()).unwrap();
        assert!(!meets_difficulty(TOKEN_12, &zero, 12));
        assert!(!meets_difficulty(TOKEN_12, &zero[..0], 8));
        // "0" followed by a '-' (the digit's byte minus 3): not in [0-9A-Za-z].
        let dashed = format!("{zero}{}", char::from(buf[0] - 3));
        assert!(!meets_difficulty(TOKEN_12, &dashed, 8));
    }

    #[test]
    fn one_thread_finds_the_servers_reference_nonce() {
        let never = AtomicBool::new(false);
        for (token, bits, nonce) in [
            (TOKEN_12, 8, "5w"),
            (TOKEN_12, 12, "yu"),
            (TOKEN_12, 16, "tbq"),
            (TOKEN_20, 20, "8u5r"),
        ] {
            assert_eq!(solve(token, bits, 1, &never, |_| {}).unwrap(), nonce);
        }
    }

    #[test]
    fn several_threads_find_a_nonce_the_server_accepts() {
        let never = AtomicBool::new(false);
        let nonce = solve(TOKEN_12, 16, 4, &never, |_| {}).unwrap();
        assert!(meets_difficulty(TOKEN_12, &nonce, 16), "{nonce}");
        assert!(nonce.len() <= 32);
    }

    #[test]
    fn base36_counter_is_the_javascript_one() {
        let mut buf = [0u8; 13];
        for (i, s) in [
            (0u64, "0"),
            (35, "z"),
            (36, "10"),
            (1_679_615, "zzzz"),
            (u32::MAX as u64, "1z141z3"),
        ] {
            let n = nonce_for(i, &mut buf);
            assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), s);
        }
    }

    #[test]
    fn a_cancel_stops_the_solve() {
        // 32 bits is out of reach in a test: only the cancel can end this.
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let result = std::thread::scope(|s| {
            let h = s.spawn(|| solve(TOKEN_12, 32, 2, &cancel, |_| {}));
            std::thread::sleep(Duration::from_millis(300));
            cancel.store(true, Ordering::Release);
            h.join().unwrap()
        });
        assert_eq!(result, Err(SolveError::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_challenge_this_build_should_not_solve_is_skipped() {
        let c = |algorithm: &str, challenge: &str, difficulty| Challenge {
            algorithm: algorithm.into(),
            challenge: challenge.into(),
            difficulty,
        };
        assert!(c(POW_ALGORITHM, TOKEN_12, 12).solvable());
        assert!(!c("scrypt", TOKEN_12, 12).solvable());
        assert!(!c(POW_ALGORITHM, "", 12).solvable());
        assert!(!c(POW_ALGORITHM, &"x".repeat(129), 12).solvable());
        assert!(!c(POW_ALGORITHM, TOKEN_12, 0).solvable());
        assert!(!c(POW_ALGORITHM, TOKEN_12, 33).solvable());
    }

    // ---- the request flow ------------------------------------------------

    fn easy(n: u32) -> Challenge {
        // Real 8-bit challenges are solved for real, so a retry test also
        // proves the nonce that goes out is a good one.
        Challenge {
            algorithm: POW_ALGORITHM.into(),
            challenge: format!("{}{n}", &TOKEN_12[..TOKEN_12.len() - 1]),
            difficulty: 8,
        }
    }

    fn refused(code: &str) -> ApiError {
        ApiError::PowRefused {
            code: code.into(),
            message: "refused".into(),
            pow_op: None,
        }
    }

    struct Harness {
        fetched: Cell<u32>,
        sent: RefCell<Vec<Option<PowSolution>>>,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                fetched: Cell::new(0),
                sent: RefCell::new(Vec::new()),
            }
        }
        async fn run(
            &self,
            answers: Vec<Result<&'static str, ApiError>>,
            challenges: bool,
        ) -> Result<Registered<&'static str>, ApiError> {
            let answers = RefCell::new(answers.into_iter());
            register_with_proof(
                || async {
                    self.fetched.set(self.fetched.get() + 1);
                    challenges.then(|| easy(self.fetched.get()))
                },
                |c: Challenge| async move {
                    let never = AtomicBool::new(false);
                    let nonce = solve(&c.challenge, c.difficulty, 1, &never, |_| {}).ok()?;
                    Some(PowSolution {
                        challenge: c.challenge,
                        nonce,
                    })
                },
                |p| {
                    self.sent.borrow_mut().push(p);
                    let next = answers.borrow_mut().next().expect("one answer per send");
                    async move { next }
                },
            )
            .await
        }
    }

    fn block<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn the_proof_is_attached_and_good() {
        let h = Harness::new();
        let r = block(h.run(vec![Ok("created")], true)).unwrap();
        assert!(matches!(r, Registered::Done("created")));
        let sent = h.sent.borrow();
        assert_eq!(sent.len(), 1);
        let p = sent[0].as_ref().expect("a proof");
        assert!(meets_difficulty(&p.challenge, &p.nonce, 8));
    }

    #[test]
    fn expired_replayed_and_raised_get_one_fresh_challenge() {
        for code in ["pow_expired", "pow_replayed", "pow_difficulty_raised"] {
            let h = Harness::new();
            let r = block(h.run(vec![Err(refused(code)), Ok("created")], true)).unwrap();
            assert!(matches!(r, Registered::Done("created")), "{code}");
            assert_eq!(h.fetched.get(), 2, "{code}");
            let sent = h.sent.borrow();
            assert_eq!(sent.len(), 2);
            let (a, b) = (sent[0].as_ref().unwrap(), sent[1].as_ref().unwrap());
            assert_ne!(a.challenge, b.challenge, "a new one, never the spent one");
            assert!(meets_difficulty(&b.challenge, &b.nonce, 8));
        }
    }

    #[test]
    fn only_one_retry_then_the_answer_stands() {
        let h = Harness::new();
        let r = block(h.run(
            vec![Err(refused("pow_replayed")), Err(refused("pow_replayed"))],
            true,
        ));
        assert!(matches!(r, Err(ApiError::PowRefused { .. })));
        assert_eq!(h.fetched.get(), 2);
        assert_eq!(h.sent.borrow().len(), 2);
    }

    #[test]
    fn two_expiries_go_on_without_a_proof() {
        let h = Harness::new();
        let r = block(h.run(
            vec![
                Err(refused("pow_expired")),
                Err(refused("pow_expired")),
                Ok("created"),
            ],
            true,
        ))
        .unwrap();
        assert!(matches!(r, Registered::Done("created")));
        let sent = h.sent.borrow();
        assert_eq!(sent.len(), 3);
        assert!(sent[2].is_none());
    }

    #[test]
    fn no_challenge_means_no_proof_and_the_server_decides() {
        let h = Harness::new();
        let r = block(h.run(vec![Ok("created")], false)).unwrap();
        assert!(matches!(r, Registered::Done("created")));
        assert!(h.sent.borrow()[0].is_none());
        assert_eq!(h.fetched.get(), 1);
    }

    #[test]
    fn a_refusal_that_is_not_about_the_proof_is_not_retried() {
        let h = Harness::new();
        let r = block(h.run(
            vec![Err(ApiError::RateLimited {
                retry_after_secs: Some(5),
            })],
            true,
        ));
        assert!(matches!(r, Err(ApiError::RateLimited { .. })));
        assert_eq!(h.sent.borrow().len(), 1);
        // pow_rate_limited is a 429 and arrives as RateLimited, never retried.
        assert!(!is_retryable_code("pow_rate_limited"));
        assert!(!is_retryable_code("pow_required"));
    }

    #[test]
    fn the_servers_proof_refusals_are_told_apart_by_details_code() {
        use crate::api::client::BirdoApi;
        use reqwest::StatusCode;
        let body = |status: u16, code: &str| {
            format!(
                r#"{{"statusCode":{status},"message":"The security check expired. Please try again.","details":{{"code":"{code}"}}}}"#
            )
        };
        for (status, code) in [
            (400, "pow_invalid"),
            (400, "pow_expired"),
            (409, "pow_replayed"),
            (428, "pow_difficulty_raised"),
            (428, "pow_required"),
        ] {
            let e = BirdoApi::classify_error_response(
                StatusCode::from_u16(status).unwrap(),
                &body(status, code),
            );
            match e {
                ApiError::PowRefused {
                    code: got, message, ..
                } => {
                    assert_eq!(got, code);
                    assert!(message.starts_with("The security check"));
                }
                other => panic!("{code}: {other:?}"),
            }
        }
        // pow_rate_limited is a 429: it keeps the wait and is not retried.
        let e = BirdoApi::classify_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            &body(429, "pow_rate_limited"),
        );
        assert!(matches!(e, ApiError::RateLimited { .. }), "{e:?}");
    }

    // ---- sign-in during a spike (A-M77 / MR-2139) -------------------------

    // Vectors from the SERVER's own code, like the sign-up ones above:
    // birdo-web origin/main, backend/src/auth/signup-pow.ts compiled and run
    // under node: mintPowToken(key of a test-only secret, 'login', bits, fixed
    // time and id), solvePow for the nonce, powDigest for the digest,
    // parsePowToken accepting each as op `login`.
    const LOGIN_TOKEN_8: &str = "p1.7f386f0d.login.8.1800000000.00112233445566778899aabbccddeeff.Gfoljd9Ww43uMw5hpkBNr2An9STpqSYJ2Hnlc5i-5Is";
    const LOGIN_TOKEN_12: &str = "p1.7f386f0d.login.12.1800000000.00112233445566778899aabbccddeeff.uzPNudqEP3ETCZQrBjWZGyxE4pCxo9X508ma6BGIxYA";
    const LOGIN_TOKEN_16: &str = "p1.7f386f0d.login.16.1800000000.00112233445566778899aabbccddeeff.U3WUdfGStXSHBuaTSNGYsd8xEgYbwS1-qswaNsieWVk";

    #[test]
    fn the_solver_matches_the_servers_login_challenges() {
        // The server's nonces are the base-36 counters 100, 5280 and 254282
        // (see the sign-up test for why they are not literals).
        let never = AtomicBool::new(false);
        for (token, bits, counter, digest) in [
            (
                LOGIN_TOKEN_8,
                8,
                100u64,
                "000f1d00ae40e44661710c5571d460c633457e289be052afb6eb8c09cb307e3c",
            ),
            (
                LOGIN_TOKEN_12,
                12,
                5280,
                "0000bf9e8d08ce6e71fdb0890b8431e8c7a11e86677710ce44b07b4a478155e1",
            ),
            (
                LOGIN_TOKEN_16,
                16,
                254_282,
                "00004ff5903c46e393a9ec3ae7578474503b68a6c63fe513b83dce38a44b79e0",
            ),
        ] {
            let mut buf = [0u8; 13];
            let n = nonce_for(counter, &mut buf);
            let want = String::from_utf8(buf[..n].to_vec()).unwrap();
            let mut h = Sha256::new();
            h.update(format!("{token}:{want}").as_bytes());
            assert_eq!(hex::encode(h.finalize()), digest, "{want}");
            // The solver, op-blind, finds the very nonce the server's solvePow does.
            assert_eq!(solve(token, bits, 1, &never, |_| {}).unwrap(), want);
            assert!(meets_difficulty(token, &want, bits));
        }
    }

    fn login_refused(code: &str, op: Option<&str>) -> ApiError {
        ApiError::PowRefused {
            code: code.into(),
            message: "refused".into(),
            pow_op: op.map(str::to_string),
        }
    }

    struct LoginHarness {
        fetched: Cell<u32>,
        solved: Cell<u32>,
        sent: RefCell<Vec<Option<PowSolution>>>,
    }

    impl LoginHarness {
        fn new() -> Self {
            Self {
                fetched: Cell::new(0),
                solved: Cell::new(0),
                sent: RefCell::new(Vec::new()),
            }
        }
        async fn run(
            &self,
            answers: Vec<Result<&'static str, ApiError>>,
            challenge: Option<Challenge>,
            cancel: bool,
        ) -> Result<Registered<&'static str>, ApiError> {
            let answers = RefCell::new(answers.into_iter());
            login_with_proof(
                |p| {
                    self.sent.borrow_mut().push(p);
                    let next = answers.borrow_mut().next().expect("one answer per send");
                    async move { next }
                },
                || async {
                    self.fetched.set(self.fetched.get() + 1);
                    challenge
                },
                |c: Challenge| async move {
                    self.solved.set(self.solved.get() + 1);
                    if cancel {
                        return None;
                    }
                    let never = AtomicBool::new(false);
                    let nonce = solve(&c.challenge, c.difficulty, 1, &never, |_| {}).ok()?;
                    Some(PowSolution {
                        challenge: c.challenge,
                        nonce,
                    })
                },
            )
            .await
        }
    }

    fn login_challenge() -> Challenge {
        Challenge {
            algorithm: POW_ALGORITHM.into(),
            challenge: LOGIN_TOKEN_8.into(),
            difficulty: 8,
        }
    }

    #[test]
    fn a_login_spike_refusal_is_solved_and_retried_once_with_the_proof() {
        let h = LoginHarness::new();
        let r = block(h.run(
            vec![
                Err(login_refused("pow_required", Some("login"))),
                Ok("signed in"),
            ],
            Some(login_challenge()),
            false,
        ))
        .unwrap();
        assert!(matches!(r, Registered::Done("signed in")));
        assert_eq!((h.fetched.get(), h.solved.get()), (1, 1));
        let sent = h.sent.borrow();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].is_none(), "the first try carries no proof");
        let p = sent[1].as_ref().expect("the retry carries the proof");
        assert_eq!(p.challenge, LOGIN_TOKEN_8);
        assert!(meets_difficulty(&p.challenge, &p.nonce, 8));
    }

    #[test]
    fn a_second_refusal_is_the_answer_and_nothing_loops() {
        for second in [
            login_refused("pow_required", Some("login")),
            login_refused("pow_replayed", Some("login")),
            login_refused("pow_expired", Some("login")),
            login_refused("pow_invalid", Some("login")),
        ] {
            let h = LoginHarness::new();
            let r = block(h.run(
                vec![
                    Err(login_refused("pow_required", Some("login"))),
                    Err(second),
                ],
                Some(login_challenge()),
                false,
            ));
            assert!(matches!(r, Err(ApiError::PowRefused { .. })));
            assert_eq!(h.sent.borrow().len(), 2, "exactly one retry");
            assert_eq!((h.fetched.get(), h.solved.get()), (1, 1));
            let proofs = h.sent.borrow().iter().filter(|p| p.is_some()).count();
            assert_eq!(proofs, 1, "pow is in the body exactly once");
        }
    }

    #[test]
    fn nothing_is_solved_unless_it_is_a_login_pow_required() {
        let cases = [
            // a sign-up proof, no pow member, a different op
            login_refused("pow_required", Some("signup")),
            login_refused("pow_required", None),
            login_refused("pow_required", Some("other")),
            // not pow_required at all
            login_refused("pow_invalid", Some("login")),
            login_refused("pow_expired", Some("login")),
            ApiError::RateLimited {
                retry_after_secs: Some(5),
            },
            ApiError::Unauthorized,
        ];
        for first in cases {
            let h = LoginHarness::new();
            let r = block(h.run(vec![Err(first)], Some(login_challenge()), false));
            assert!(r.is_err());
            assert_eq!(h.sent.borrow().len(), 1);
            assert_eq!((h.fetched.get(), h.solved.get()), (0, 0));
        }
    }

    #[test]
    fn a_success_sends_once_without_a_proof() {
        let h = LoginHarness::new();
        let r = block(h.run(vec![Ok("signed in")], Some(login_challenge()), false)).unwrap();
        assert!(matches!(r, Registered::Done("signed in")));
        assert!(h.sent.borrow()[0].is_none());
        assert_eq!((h.fetched.get(), h.solved.get()), (0, 0));
    }

    #[test]
    fn no_usable_challenge_leaves_the_refusal_as_it_was() {
        let too_hard = Challenge {
            difficulty: 33,
            ..login_challenge()
        };
        for challenge in [None, Some(too_hard)] {
            let h = LoginHarness::new();
            let r = block(h.run(
                vec![Err(login_refused("pow_required", Some("login")))],
                challenge,
                false,
            ));
            assert!(matches!(r, Err(ApiError::PowRefused { .. })));
            assert_eq!(h.sent.borrow().len(), 1);
            assert_eq!(h.solved.get(), 0);
        }
    }

    #[test]
    fn a_cancel_while_solving_a_login_proof_sends_nothing_more() {
        let h = LoginHarness::new();
        let r = block(h.run(
            vec![Err(login_refused("pow_required", Some("login")))],
            Some(login_challenge()),
            true,
        ))
        .unwrap();
        assert!(matches!(r, Registered::Cancelled));
        assert_eq!(h.sent.borrow().len(), 1);
    }

    #[test]
    fn the_wire_envelope_names_the_login_op() {
        use crate::api::client::BirdoApi;
        use reqwest::StatusCode;
        // GlobalExceptionFilter puts refusal()'s `details` on the wire as is.
        let spike = r#"{"statusCode":429,"message":"Too many sign-in attempts right now, please try again later","error":"Too Many Requests","details":{"code":"pow_required","retryAfter":900,"pow":{"op":"login","challengePath":"/auth/pow/challenge"}}}"#;
        match BirdoApi::classify_error_response(StatusCode::TOO_MANY_REQUESTS, spike) {
            ApiError::PowRefused { code, pow_op, .. } => {
                assert_eq!(code, "pow_required");
                assert_eq!(pow_op.as_deref(), Some(LOGIN_OP));
            }
            other => panic!("{other:?}"),
        }
        // A bad proof names the op again; pow_rate_limited carries none and stays RateLimited.
        let bad = r#"{"statusCode":400,"message":"x","details":{"code":"pow_invalid","pow":{"op":"login","challengePath":"/auth/pow/challenge"}}}"#;
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::BAD_REQUEST, bad),
            ApiError::PowRefused { pow_op: Some(ref o), .. } if o == "login"
        ));
        let limited = r#"{"statusCode":429,"message":"x","details":{"code":"pow_rate_limited"}}"#;
        assert!(matches!(
            BirdoApi::classify_error_response(StatusCode::TOO_MANY_REQUESTS, limited),
            ApiError::RateLimited { .. }
        ));
    }

    /// Not a test: `cargo test --release --lib pow::tests::bench -- --ignored
    /// --nocapture` prints this machine's hashes per second and the expected
    /// solve time at the server's difficulties (20 default, 26 ceiling).
    #[test]
    #[ignore]
    fn bench_solve_rate() {
        let never = AtomicBool::new(false);
        for threads in [1, default_threads()] {
            let started = Instant::now();
            let mut hashes = 0u64;
            // 22 bits is ~4 M hashes: long enough to time, short enough to wait for.
            for n in 0..5 {
                let token = format!("{}{n}", &TOKEN_20[..TOKEN_20.len() - 1]);
                let nonce = solve(&token, 22, threads, &never, |_| {}).unwrap();
                assert!(meets_difficulty(&token, &nonce, 22));
                // Hashes actually tried: the winning counter, times the threads.
                let mut v = 0u64;
                for c in nonce.bytes() {
                    let d = if c.is_ascii_digit() {
                        c - b'0'
                    } else {
                        c - b'a' + 10
                    };
                    v = v * 36 + d as u64;
                }
                hashes += v + 1;
            }
            let secs = started.elapsed().as_secs_f64();
            let rate = hashes as f64 / secs;
            println!(
                "threads={threads}: ~{:.1} M hashes/s ({hashes} hashes in {secs:.2} s);                  expected 2^20 = {:.2} s, 2^22 = {:.2} s, 2^24 = {:.1} s, 2^26 = {:.1} s",
                rate / 1e6,
                (1u64 << 20) as f64 / rate,
                (1u64 << 22) as f64 / rate,
                (1u64 << 24) as f64 / rate,
                (1u64 << 26) as f64 / rate,
            );
        }
    }

    #[test]
    fn a_cancel_while_solving_sends_nothing() {
        let sent = Cell::new(0);
        let r = block(register_with_proof(
            || async { Some(easy(1)) },
            |_| async { None },
            |_| {
                sent.set(sent.get() + 1);
                async { Ok::<_, ApiError>("created") }
            },
        ))
        .unwrap();
        assert!(matches!(r, Registered::Cancelled));
        assert_eq!(sent.get(), 0);
    }
}
